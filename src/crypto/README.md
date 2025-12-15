# Crypto

{{#include ../banners/hacktricks-training.md}}

Ta sekcja skupia się na **praktycznej kryptografii dla hacking/CTFs**: jak szybko rozpoznawać typowe wzorce, wybrać odpowiednie narzędzia i zastosować znane ataki.

Jeśli szukasz informacji o ukrywaniu danych w plikach, przejdź do sekcji **Stego**.

## Jak korzystać z tej sekcji

Crypto challenges reward speed: classify the primitive, identify what you control (oracle/leak/nonce reuse), then apply a known attack template.

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

## Szybka konfiguracja

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Biblioteki: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (często niezbędny do lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
