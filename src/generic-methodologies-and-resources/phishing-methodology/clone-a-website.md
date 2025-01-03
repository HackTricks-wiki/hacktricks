{{#include ../../banners/hacktricks-training.md}}

Vir 'n phishing-assessering kan dit soms nuttig wees om 'n webwerf heeltemal te **kloneer**.

Let daarop dat jy ook 'n paar payloads aan die geklonde webwerf kan voeg, soos 'n BeEF-hook om die gebruiker se oortjie te "beheer".

Daar is verskillende gereedskap wat jy vir hierdie doel kan gebruik:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Sosiale Ingenieurskap Gereedskap
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
