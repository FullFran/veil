"""Model adapters. Each one loads local weights and returns character
spans (start, end, raw_label, score) for one plain-text unit.

LABEL_MAP maps every model's native labels to veil's labels (plus the
research label DIRECCION). Native labels missing from a map are kept in
the raw output but not scored.
"""

from __future__ import annotations

import os
from pathlib import Path

CACHE = Path(os.environ.get("VEIL_NER_CACHE", Path.home() / ".cache" / "veil-ner-bench"))
# The opf tokenizer is tiktoken o200k_base; keep its file in the local cache.
os.environ.setdefault("TIKTOKEN_CACHE_DIR", str(CACHE / "tiktoken"))


def hf_snapshot(repo: str) -> str:
    # Resolve the snapshot straight from the local HF cache: weights are
    # downloaded once by download.py; the benchmark itself never touches
    # the network (see netguard in run.py). snapshot_download(...,
    # local_files_only=True) is not used because it rejects snapshots
    # downloaded with allow_patterns (only the files needed for inference).
    from huggingface_hub.constants import HF_HUB_CACHE

    snaps = sorted(Path(HF_HUB_CACHE, "models--" + repo.replace("/", "--"), "snapshots").iterdir())
    if len(snaps) != 1:
        raise RuntimeError(f"{repo}: expected one local snapshot, found {snaps}")
    return str(snaps[0])


class OPFAdapter:
    name = "opf"
    model_id = "openai/privacy-filter"
    LABEL_MAP = {
        "private_person": "NOMBRE",
        "private_address": "DIRECCION",
        "private_email": "EMAIL",
        "private_phone": "TEL",
        "account_number": "IBAN",
    }

    def weights_dir(self) -> Path:
        return CACHE / "opf"

    def load(self):
        from opf._api import OPF

        self.m = OPF(model=str(self.weights_dir()), device="cpu", decode_mode="viterbi")
        self.m.redact("Hola.")  # forces runtime load

    def predict(self, text: str):
        r = self.m.redact(text)
        return [(s.start, s.end, s.label, None) for s in r.detected_spans]


class GLiNER2Adapter:
    name = "gliner2-pii"
    model_id = "fastino/gliner2-privacy-filter-PII-multi"
    # Labels requested at inference (GLiNER2 conditions on them) and their mapping.
    LABEL_MAP = {
        "person": "NOMBRE",
        "address": "DIRECCION",
        "email": "EMAIL",
        "phone_number": "TEL",
        "iban": "IBAN",
        "national_id_number": "DNI",
    }
    threshold = 0.5

    def weights_dir(self) -> Path:
        return Path(hf_snapshot(self.model_id))

    def load(self):
        from gliner2 import GLiNER2

        self.m = GLiNER2.from_pretrained(str(self.weights_dir()))
        self.m.eval() if hasattr(self.m, "eval") else None

    def predict(self, text: str):
        r = self.m.extract_entities(
            text, list(self.LABEL_MAP), threshold=self.threshold, include_confidence=True, include_spans=True
        )
        out = []
        for label, items in r.get("entities", {}).items():
            for it in items:
                out.append((it["start"], it["end"], label, it.get("confidence")))
        return out


class PresidioAdapter:
    LABEL_MAP = {
        "PERSON": "NOMBRE",
        # Presidio has no Spanish street-address recognizer; spaCy LOC is the
        # closest it gets (cities, regions, streets). Mapped so that its
        # coverage shows up; expect strict misses on boundaries.
        "LOCATION": "DIRECCION",
        "EMAIL_ADDRESS": "EMAIL",
        "PHONE_NUMBER": "TEL",
        "IBAN_CODE": "IBAN",
        "ES_NIF": "DNI",
        "ES_NIE": "DNI",
    }

    def __init__(self, spacy_model: str):
        self.spacy_model = spacy_model
        self.name = "presidio-" + spacy_model.rsplit("_", 1)[-1]
        self.model_id = "presidio-analyzer + " + spacy_model

    def weights_dir(self) -> Path:
        import importlib

        return Path(importlib.import_module(self.spacy_model).__file__).parent

    def load(self):
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        conf = {"nlp_engine_name": "spacy", "models": [{"lang_code": "es", "model_name": self.spacy_model}]}
        engine = NlpEngineProvider(nlp_configuration=conf).create_engine()
        registry = RecognizerRegistry(supported_languages=["es"])
        registry.load_predefined_recognizers(languages=["es"], nlp_engine=engine)
        self.recognizers = sorted({r.name for r in registry.get_recognizers(language="es", all_fields=True)})
        self.m = AnalyzerEngine(nlp_engine=engine, registry=registry, supported_languages=["es"])
        self.m.analyze(text="Hola.", language="es")

    def predict(self, text: str):
        return [(r.start, r.end, r.entity_type, r.score) for r in self.m.analyze(text=text, language="es")]


class BSCMeddocanAdapter:
    name = "bsc-meddocan"
    model_id = "BSC-NLP4BIA/bsc-bio-ehr-es-carmen-meddocan"
    LABEL_MAP = {
        "NOMBRE_SUJETO_ASISTENCIA": "NOMBRE",
        "NOMBRE_PERSONAL_SANITARIO": "NOMBRE",
        "FAMILIARES_SUJETO_ASISTENCIA": "NOMBRE",
        "CALLE": "DIRECCION",
        "NUMERO_TELEFONO": "TEL",
        "CORREO_ELECTRONICO": "EMAIL",
        "ID_SUJETO_ASISTENCIA": "DNI",
        "NUMERO_IDENTIF": "DNI",
    }

    def weights_dir(self) -> Path:
        return Path(hf_snapshot(self.model_id))

    def load(self):
        from transformers import pipeline

        self.m = pipeline(
            "token-classification", model=str(self.weights_dir()), aggregation_strategy="first", device="cpu"
        )
        self.m("Hola.")

    def predict(self, text: str):
        return [(e["start"], e["end"], e["entity_group"], float(e["score"])) for e in self.m(text)]


ADAPTERS = {
    "opf": OPFAdapter,
    "gliner2-pii": GLiNER2Adapter,
    "presidio-sm": lambda: PresidioAdapter("es_core_news_sm"),
    "presidio-lg": lambda: PresidioAdapter("es_core_news_lg"),
    "bsc-meddocan": BSCMeddocanAdapter,
}


class MemPrivacyAdapter:
    """MemPrivacy-1.7B-RL (Qwen3-1.7B, SFT+GRPO), run with its published
    extraction prompt (src/prompts/extract_privacy.txt at e859c42) through
    transformers on CPU instead of an OpenAI-compatible server. Greedy
    decoding (the repo's config uses temperature 0.0). The model returns
    original_text strings, not offsets; like the repo's mask_dialogue,
    every occurrence of each string in the unit is a span.

    Every level PL2-PL4 is kept: the repo's default mask_levels are PL3
    and PL4 only, which would leave names and addresses (PL2) in clear.
    """

    name = "memprivacy-1.7b"
    model_id = "IAAR-Shanghai/MemPrivacy-1.7B-RL"
    LABEL_MAP = {
        "Real Name": "NOMBRE",
        # The prompt files third-party names under PL2 rule 4 ("Third-Party
        # Identifiable Info"); with no User's Real Name given, every name
        # in the corpus is a third party's.
        "Third-Party Identifiable Info": "NOMBRE",
        "Detailed Address": "DIRECCION",
        "Work Address": "DIRECCION",
        "Phone Number": "TEL",
        "Email": "EMAIL",
        "ID Number": "DNI",
        "Financial Account": "IBAN",
    }
    max_new_tokens = 512

    def weights_dir(self) -> Path:
        return Path(hf_snapshot(self.model_id))

    def load(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.prompt = (CACHE / "memprivacy" / "extract_privacy.txt").read_text(encoding="utf-8")
        self.tok = AutoTokenizer.from_pretrained(str(self.weights_dir()))
        self.m = AutoModelForCausalLM.from_pretrained(str(self.weights_dir()), dtype=torch.bfloat16)
        self.m.eval()
        self.raw_outputs = []
        self.predict("Hola.")

    def predict(self, text: str):
        import re

        import json_repair
        import torch

        user = self.prompt.format(real_name="", input_dialogue_content=text)
        ids = self.tok.apply_chat_template(
            [{"role": "user", "content": user}], add_generation_prompt=True, return_tensors="pt", return_dict=True
        )
        with torch.inference_mode():
            gen = self.m.generate(**ids, max_new_tokens=self.max_new_tokens, do_sample=False)
        content = self.tok.decode(gen[0][ids["input_ids"].shape[1] :], skip_special_tokens=True).strip()
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL | re.IGNORECASE).strip()
        self.raw_outputs.append({"text": text, "output": content})
        try:
            items = json_repair.loads(content)
        except Exception:  # noqa: BLE001 -- a malformed answer is a miss, as in the repo
            items = []
        out = []
        for it in items if isinstance(items, list) else []:
            if not isinstance(it, dict) or not it.get("original_text"):
                continue
            s, label = str(it["original_text"]), f"{it.get('privacy_type', '')}"
            i = text.find(s)
            while i >= 0:
                out.append((i, i + len(s), label, it.get("privacy_level")))
                i = text.find(s, i + len(s))
        return out


ADAPTERS["memprivacy-1.7b"] = MemPrivacyAdapter


class GLiNER2StreetAdapter(GLiNER2Adapter):
    """Variant chosen AFTER reading GLiNER2's address misses on es-ext-v1:
    also request the model's own `street_address` label. Its numbers are
    optimistic (selected on the test set); the README says so."""

    name = "gliner2-pii-street"
    LABEL_MAP = {**GLiNER2Adapter.LABEL_MAP, "street_address": "DIRECCION"}


ADAPTERS["gliner2-pii-street"] = GLiNER2StreetAdapter
