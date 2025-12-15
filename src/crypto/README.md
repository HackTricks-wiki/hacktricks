# Crypto

{{#include ../banners/hacktricks-training.md}}

Cette section se concentre sur la **cryptographie pratique pour hacking/CTFs** : comment reconnaître rapidement les schémas courants, choisir les bons outils et appliquer des attaques connues.

Si vous êtes ici pour cacher des données dans des fichiers, allez à la section **Stego**.

## Comment utiliser cette section

Les défis Crypto récompensent la rapidité : classifiez la primitive, identifiez ce que vous contrôlez (oracle/leak/nonce reuse), puis appliquez un modèle d'attaque connu.

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

## Configuration rapide

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Bibliothèques: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (souvent essentiel pour lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
