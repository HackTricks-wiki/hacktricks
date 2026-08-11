# Kloning van 'n webwerf

{{#include ../../banners/hacktricks-training.md}}

Vir 'n phishing-assessment kan dit soms nuttig wees om 'n webwerf volledig te **clone/dump**.

Let daarop dat jy ook sekere payloads by die gekloonde webwerf kan voeg, soos 'n BeEF hook om die gebruiker se tab te "beheer".

Daar is verskillende tools wat jy hiervoor kan gebruik:

## wget

Die volgende opdrag gebruik Wget se mirroring-, page-requisite-, link-conversion- en extension-adjustment-modusse, en bedien dan die afgelaaide lêers vanaf die huidige gids met Python se `http.server`-module op poort 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Die goclone-bewaarplek beskryf die hulpmiddel as iets wat ’n webwerf na ’n plaaslike gids aflaai terwyl die relatiewe skakelstruktuur daarvan behoue bly, en dokumenteer die `goclone <url>`-aanroep.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Sosiale-ingenieurswese-gereedskapstel

Die Social-Engineer Toolkit (SET)-repository identifiseer SET as 'n open-source penetration-testing framework vir gemagtigde sosiale-ingenieurswese-assesserings.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget-handleiding](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server`-dokumentasie](https://docs.python.org/3/library/http.server.html)
- [3] [goclone-bewaarplek](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit-bewaarplek](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
