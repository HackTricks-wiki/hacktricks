{{#include ../../banners/hacktricks-training.md}}

Pour une évaluation de phishing, il peut parfois être utile de **cloner complètement un site web**.

Notez que vous pouvez également ajouter des payloads au site cloné, comme un hook BeEF pour "contrôler" l'onglet de l'utilisateur.

Il existe différents outils que vous pouvez utiliser à cet effet :

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Outil d'ingénierie sociale
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
