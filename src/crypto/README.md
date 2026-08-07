# Crypto

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inalenga **practical cryptography for hacking/CTFs**: jinsi ya kutambua kwa haraka mifumo ya kawaida, kuchagua tools zinazofaa, na kutumia mashambulizi yanayojulikana.

Ikiwa uko hapa kwa ajili ya kuficha data ndani ya files, nenda kwenye sehemu ya **Stego**.

## Jinsi ya kutumia sehemu hii

Crypto challenges hulipa kasi: ainisha primitive, tambua unachodhibiti (oracle/leak/nonce reuse), kisha tumia template ya shambulizi inayojulikana.

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, na KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS na certificates
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto katika malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Mengineyo
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Usanidi wa haraka

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (mara nyingi ni muhimu kwa lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
