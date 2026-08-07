# Cloner un site web

{{#include ../../banners/hacktricks-training.md}}


Lors d'une évaluation de phishing, il peut parfois être utile de **cloner/dumper complètement un site web**.

Notez que vous pouvez également ajouter des payloads au site web cloné, comme un hook BeEF, afin de « contrôler » l'onglet de l'utilisateur.

Vous pouvez utiliser différents outils à cette fin :

## wget
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit d'ingénierie sociale
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
