# Crypto

{{#include ../banners/hacktricks-training.md}}

Ta sekcja koncentruje się na **praktycznej kryptografii dla hacking/CTF**: jak szybko rozpoznawać typowe wzorce, wybierać właściwe narzędzia i stosować znane ataki.

Jeśli szukasz informacji o ukrywaniu danych w plikach, przejdź do sekcji **Stego**.

## Jak korzystać z tej sekcji

Wyzwania Crypto nagradzają szybkość: sklasyfikuj prymityw, ustal, nad czym masz kontrolę (oracle/leak/ponowne użycie nonce), a następnie zastosuj znany szablon ataku.

### Workflow CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Kryptografia symetryczna
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs i KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Kryptografia klucza publicznego
{{#ref}}
public-key/README.md
{{#endref}}

### TLS i certyfikaty
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto w malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Różne
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Szybka konfiguracja

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Biblioteki: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (często niezbędny do lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
