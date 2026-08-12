# Crypto

{{#include ../banners/hacktricks-training.md}}

Cette section se concentre sur la cryptographie pratique pour les security tests et les CTFs : reconnaître les patterns courants, sélectionner les outils adaptés et appliquer les attaques connues.

Pour les techniques qui dissimulent des données dans des fichiers, consultez la section **Stego**.

## Comment utiliser cette section

Commencez par identifier la primitive et ses paramètres. Déterminez ensuite ce que l'attaquant contrôle ou observe, comme une oracle, une valeur leakée ou une réutilisation de nonce, avant de sélectionner une attaque.

### Workflow CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Cryptographie symétrique

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs et KDFs

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

### Cryptographie dans les malwares

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Divers

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configuration rapide

Créez un environnement Python isolé et installez les packages couramment utilisés. La documentation de PyCryptodome recommande d'installer `pycryptodome` avec `pip` ; SageMath fournit des instructions d'installation distinctes pour chaque plateforme prise en charge.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath est souvent utile pour les calculs algébriques, sur les réseaux, RSA et les courbes elliptiques.<sup>[[2]](#references)</sup>

## References

- [1] [Documentation PyCryptodome - Installation](https://www.pycryptodome.org/src/installation)
- [2] [Documentation SageMath - Guide d'installation](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
