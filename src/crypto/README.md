# Kriptografija

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se fokusira na **praktičnu kriptografiju za hacking/CTF-ove**: kako brzo prepoznati uobičajene obrasce, izabrati odgovarajuće alate i primeniti poznate napade.

Ako ste ovde zbog skrivanja podataka unutar datoteka, pređite na odeljak **Stego**.

## Kako koristiti ovaj odeljak

Crypto izazovi nagrađuju brzinu: klasifikujte primitiv, utvrdite čime možete da upravljate (oracle/leak/ponovna upotreba nonce-a), a zatim primenite poznati obrazac napada.

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Simetrična kriptografija
{{#ref}}
symmetric/README.md
{{#endref}}

### Hash-evi, MAC-ovi i KDF-ovi
{{#ref}}
hashes/README.md
{{#endref}}

### Kriptografija sa javnim ključem
{{#ref}}
public-key/README.md
{{#endref}}

### TLS i sertifikati
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto u malware-u
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Razno
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Brzo podešavanje

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Biblioteke: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (često neophodan za lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
