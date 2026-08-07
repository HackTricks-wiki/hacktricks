# Kriptografie

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling fokus op **praktiese kriptografie vir hacking/CTFs**: hoe om algemene patrone vinnig te herken, die regte tools te kies en bekende aanvalle toe te pas.

As jy hier is om data binne lêers weg te steek, gaan na die **Stego**-afdeling.

## Hoe om hierdie afdeling te gebruik

Crypto challenges beloon spoed: klassifiseer die primitive, identifiseer waaroor jy beheer het (oracle/leak/nonce reuse), en pas dan ’n bekende aanvaltemplate toe.

### CTF-werkvloei
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Simmetriese kriptografie
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs en KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Publieksleutel-kriptografie
{{#ref}}
public-key/README.md
{{#endref}}

### TLS en sertifikate
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Kriptografie in malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Diverse
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Vinnige opstelling

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Biblioteke: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (dikwels noodsaaklik vir lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
