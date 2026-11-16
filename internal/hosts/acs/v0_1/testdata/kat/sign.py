import base64, hashlib, hmac, json, sys
import rfc8785
env = json.load(open(sys.argv[1], encoding="utf-8"))
secret = bytes(range(32))
sid = env["params"]["metadata"]["session_id"]
prk = hmac.new(b"\x00" * 32, secret, hashlib.sha256).digest()
key = hmac.new(prk, sid.encode() + b"\x01", hashlib.sha256).digest()
canon = rfc8785.dumps(env)
sig = base64.b64encode(hmac.new(key, canon, hashlib.sha256).digest()).decode()
env["params"]["signature"] = {"algorithm": "HMAC-SHA256", "value": sig, "key_id": "2026-11"}
sys.stdout.write(json.dumps(env, indent=2, ensure_ascii=False) + "\n")
sys.stderr.write(canon.decode() + "\n")
