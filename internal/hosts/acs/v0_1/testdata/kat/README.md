# Known answers for JCS and HMAC-SHA256

Produced outside veil, with the `rfc8785` Python package (version 0.1.4, the
one the ACS reference adapters use) and the HKDF/HMAC steps of ACS
Specification section 10, by `sign.py`:

```sh
uv run --no-project --with rfc8785==0.1.4 python -I sign.py jcs-input.json > jcs-signed.json 2> jcs-canonical.txt
uv run --no-project --with rfc8785==0.1.4 python -I sign.py ../../spec/examples/readme-file-read.request.json > readme-file-read.signed.json
```

The secret is the specification's example secret, the bytes 0 through 31,
under the `key_id` `2026-11`. `jcs-canonical.txt` is the canonical form of
`jcs-input.json` (no trailing newline), which exercises key order by UTF-16
code unit, ES6 number formatting and string escaping.
