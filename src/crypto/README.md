# Cryptographie

{{#include ../banners/hacktricks-training.md}}

Cette section porte sur la cryptographie appliquée aux tests de sécurité et aux CTF : reconnaître les motifs courants, choisir les outils adaptés et appliquer des attaques connues.

Pour les techniques qui dissimulent des données dans des fichiers, consultez la section **Stego**.

## Comment utiliser cette section

Commencez par identifier la primitive et ses paramètres. Déterminez ensuite ce que l’attaquant contrôle ou observe, comme un oracle, une valeur divulguée ou une réutilisation de nonce, avant de choisir une attaque.

### Déroulement d’un CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Cryptographie symétrique

{{#ref}}
symmetric/README.md
{{#endref}}

### Hachages, MAC et KDF

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

## Installation rapide

Créez un environnement Python isolé et installez les packages couramment utilisés. La documentation de PyCryptodome recommande d’installer `pycryptodome` avec `pip` ; SageMath fournit des instructions d’installation distinctes pour chaque plateforme prise en charge.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath est souvent utile pour les calculs algébriques, sur les réseaux, RSA et les courbes elliptiques.<sup>[[2]](#references)</sup>

## References

- [1] [Documentation de PyCryptodome - Installation](https://www.pycryptodome.org/src/installation)
- [2] [Documentation de SageMath - Guide d’installation](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
