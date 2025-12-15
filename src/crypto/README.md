# Crypto

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inalenga kwenye **kriptografia ya vitendo kwa hacking/CTFs**: jinsi ya kutambua haraka mifumo ya kawaida, kuchagua zana sahihi, na kutumia mashambulizi yaliyojulikana.

Ikiwa uko hapa kwa kuficha data ndani ya faili, nenda kwenye sehemu ya **Stego**.

## Jinsi ya kutumia sehemu hii

Changamoto za Crypto zinathamini kasi: ainisha primitive, tambua unachodhibiti (oracle/leak/nonce reuse), kisha tumia kiolezo cha shambulio kilichojulikana.

### Mtiririko wa CTF
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

### Mengine
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Usanidi wa haraka

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Maktaba: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (mara nyingi muhimu kwa lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
