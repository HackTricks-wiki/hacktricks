# Kloning van ’n webwerf

{{#include ../../banners/hacktricks-training.md}}


Vir ’n phishing-assessering kan dit soms nuttig wees om ’n webwerf volledig te **kloon/af te laai**.

Let daarop dat jy ook sommige payloads by die gekloonde webwerf kan voeg, soos ’n BeEF hook om die gebruiker se oortjie te “beheer”.

Daar is verskillende tools wat jy hiervoor kan gebruik:

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
## Sosiale Ingenieurswese Toolit
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
