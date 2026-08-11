# Cloner un site web

{{#include ../../banners/hacktricks-training.md}}

Pour une évaluation de phishing, il peut parfois être utile de **cloner/dumper complètement un site web**.

Notez que vous pouvez également ajouter des payloads au site web cloné, comme un hook BeEF pour « contrôler » l’onglet de l’utilisateur.

Vous pouvez utiliser différents outils à cette fin :

## wget

La commande suivante utilise les modes de mise en miroir, de téléchargement des ressources nécessaires à la page, de conversion des liens et d’ajustement des extensions de Wget, puis sert les fichiers téléchargés depuis le répertoire actuel avec le module `http.server` de Python sur le port 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Le repository goclone décrit l’utilitaire comme permettant de télécharger un site web dans un répertoire local tout en préservant sa structure de liens relatifs, et documente l’invocation `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Boîte à outils de Social Engineering

Le dépôt de Social-Engineer Toolkit (SET) présente SET comme un framework open source de penetration testing destiné aux évaluations autorisées d'ingénierie sociale.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Manuel de GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Documentation Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Dépôt goclone](https://github.com/imthaghost/goclone)
- [4] [Dépôt Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
