# Cloner un site web

Lors d'une évaluation de phishing, il peut parfois être utile de **cloner/dumper complètement un site web**.

Notez que vous pouvez également ajouter des payloads au site web cloné, comme un hook BeEF pour « contrôler » l'onglet de l'utilisateur.

Vous pouvez utiliser différents outils à cette fin :

## wget

La commande suivante utilise les modes de mirroring, page-requisite, link-conversion et extension-adjustment de Wget, puis sert les fichiers téléchargés depuis le répertoire courant avec le module `http.server` de Python sur le port 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Le dépôt goclone décrit l’utilitaire comme permettant de télécharger un site web dans un répertoire local tout en préservant sa structure relative des liens, et documente l’invocation `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit d'ingénierie sociale

Le dépôt de Social-Engineer Toolkit (SET) présente SET comme un framework open source de pentesting destiné aux évaluations d'ingénierie sociale autorisées.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Manuel de GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Documentation de `http.server` de Python](https://docs.python.org/3/library/http.server.html)
- [3] [Dépôt goclone](https://github.com/imthaghost/goclone)
- [4] [Dépôt de Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
