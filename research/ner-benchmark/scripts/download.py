"""Download every model's weights once, into caches outside the repo.

Usage: python -I scripts/download.py

This is the only step that uses the network, and it only downloads
weights and the MemPrivacy prompt; no corpus text leaves the machine.
Pinned revisions are the ones the README's numbers were measured with.
"""

from __future__ import annotations

import shutil
import urllib.request
from pathlib import Path

from huggingface_hub import snapshot_download

from models import CACHE

# repo -> (revision, allow_patterns)
HF = {
    "fastino/gliner2-privacy-filter-PII-multi": (None, None),
    "BSC-NLP4BIA/bsc-bio-ehr-es-carmen-meddocan": (None, ["*.json", "*.txt", "model.safetensors"]),
    "IAAR-Shanghai/MemPrivacy-1.7B-RL": ("c1df3f4de54fce0f763c36411bdb855650a71500", None),
}
MEMPRIVACY_PROMPT = (
    "https://raw.githubusercontent.com/MemTensor/MemPrivacy/"
    "e859c42134bf003567eb99160b6bd3f19506ea00/src/prompts/extract_privacy.txt"
)


def main() -> None:
    for repo, (rev, patterns) in HF.items():
        print(repo, snapshot_download(repo, revision=rev, allow_patterns=patterns))
    # OpenAI Privacy Filter: the opf package expects the "original/" subtree
    # (PyTorch checkpoint + Viterbi calibration) as its checkpoint directory.
    tmp = CACHE / "opf-download"
    snapshot_download("openai/privacy-filter", allow_patterns=["original/*"], local_dir=tmp)
    dest = CACHE / "opf"
    if dest.exists():
        shutil.rmtree(dest)
    (tmp / "original").rename(dest)
    shutil.rmtree(tmp)
    print("openai/privacy-filter", dest)
    import tiktoken

    tiktoken.get_encoding("o200k_base")  # cached under TIKTOKEN_CACHE_DIR (set in models.py)
    mp = CACHE / "memprivacy"
    mp.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(MEMPRIVACY_PROMPT, mp / "extract_privacy.txt")  # noqa: S310 -- fixed https URL
    print("memprivacy prompt", mp / "extract_privacy.txt")


if __name__ == "__main__":
    main()
