# Crypto

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt konzentriert sich auf **praktische Kryptographie für hacking/CTFs**: wie man schnell gängige Muster erkennt, die richtigen Tools auswählt und bekannte Angriffe anwendet.

Wenn du hier bist, um Daten in Dateien zu verstecken, gehe zum **Stego**-Abschnitt.

## Wie man diesen Abschnitt nutzt

Crypto challenges belohnen Schnelligkeit: klassifiziere das Primitive, identifiziere, was du kontrollierst (oracle/leak/nonce reuse), und wende dann eine bekannte Angriffsvorlage an.

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

## Schnelle Einrichtung

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (often essential for lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
