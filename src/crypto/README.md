# Crypto

{{#include ../banners/hacktricks-training.md}}

This section focuses on **praktiese kriptografie vir hacking/CTFs**: hoe om vinnig algemene patrone te herken, die regte gereedskap te kies, en bekende aanvalle toe te pas.

If you're here for hiding data inside files, go to the **Stego** section.

## Hoe om hierdie afdeling te gebruik

Crypto-uitdagings beloon spoed: klassifiseer die primitief, identifiseer wat jy beheer (oracle/leak/nonce reuse), en pas dan 'n bekende aanvalspatroon toe.

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto in malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Misc
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Vinnige opstelling

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Biblioteke: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (dikwels noodsaaklik vir lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
