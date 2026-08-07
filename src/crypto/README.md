# Kryptografie

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt konzentriert sich auf **praktische Kryptografie für Hacking/CTFs**: wie man gängige Muster schnell erkennt, die richtigen Tools auswählt und bekannte Angriffe anwendet.

Wenn du hier bist, um Daten in Dateien zu verstecken, gehe zum Abschnitt **Stego**.

## Verwendung dieses Abschnitts

Crypto-Challenges belohnen Schnelligkeit: Primitive klassifizieren, identifizieren, was du kontrollierst (Oracle/Leak/Nonce-Reuse), und anschließend eine bekannte Angriffsvorlage anwenden.

### CTF-Workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetrische Kryptografie
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs und KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Kryptografie mit öffentlichen Schlüsseln
{{#ref}}
public-key/README.md
{{#endref}}

### TLS und Zertifikate
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Kryptografie in Malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Verschiedenes
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Schnelle Einrichtung

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Bibliotheken: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (oft unverzichtbar für Lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
