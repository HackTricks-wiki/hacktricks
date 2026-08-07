# Crypto

{{#include ../banners/hacktricks-training.md}}

Cette section se concentre sur la **cryptographie pratique pour le hacking/les CTF** : comment reconnaître rapidement les motifs courants, choisir les bons outils et appliquer des attaques connues.

Si vous cherchez à dissimuler des données dans des fichiers, consultez la section **Stego**.

## Comment utiliser cette section

Les challenges de Crypto récompensent la rapidité : classifiez la primitive, identifiez ce que vous contrôlez (oracle/leak/réutilisation de nonce), puis appliquez un modèle d'attaque connu.

### Workflow CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Cryptographie symétrique
{{#ref}}
symmetric/README.md
{{#endref}}

### Fonctions de hachage, MACs et KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Cryptographie à clé publique
{{#ref}}
public-key/README.md
{{#endref}}

### TLS et certificats
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto dans les malwares
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Divers
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configuration rapide

- Python : `python3 -m venv .venv && source .venv/bin/activate`
- Bibliothèques : `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (souvent essentiel pour les réseaux, RSA et ECC) : <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
