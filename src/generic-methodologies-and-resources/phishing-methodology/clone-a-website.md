{{#include ../../banners/hacktricks-training.md}}

Za phishing procenu ponekad može biti korisno potpuno **klonirati veb sajt**.

Imajte na umu da možete dodati i neke payload-ove na klonirani veb sajt, poput BeEF hook-a da "kontrolišete" karticu korisnika.

Postoje različiti alati koje možete koristiti u tu svrhu:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Alat za socijalni inženjering
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
