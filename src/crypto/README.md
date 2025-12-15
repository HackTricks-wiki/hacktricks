# Crypto

{{#include ../banners/hacktricks-training.md}}

Ova sekcija se fokusira na **praktičnu kriptografiju za hacking/CTFs**: kako brzo prepoznati uobičajene obrasce, odabrati prave alate i primeniti poznate napade.

Ako ste ovde da sakrijete podatke u fajlovima, idite u **Stego** sekciju.

## Kako koristiti ovu sekciju

Crypto izazovi nagrađuju brzinu: klasifikujte primitiv, identifikujte šta kontrolišete (oracle/leak/nonce reuse), a zatim primenite poznati šablon napada.

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

## Brzo podešavanje

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (često neophodan za lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
