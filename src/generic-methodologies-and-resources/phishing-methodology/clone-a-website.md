# Kloniranje veb-sajta

{{#include ../../banners/hacktricks-training.md}}


Tokom phishing procene ponekad može biti korisno potpuno **klonirati/izbaciti sadržaj veb-sajta**.

Imajte na umu da kloniranom veb-sajtu možete dodati i neke payload-e, kao što je BeEF hook, da biste „kontrolisali“ korisnički tab.

U tu svrhu možete koristiti različite alate:

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
## Komplet alata za društveni inženjering
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
