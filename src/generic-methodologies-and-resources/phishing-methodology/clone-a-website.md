# Ku-clone Website

{{#include ../../banners/hacktricks-training.md}}


Kwa ajili ya phishing assessment, wakati mwingine inaweza kuwa muhimu **ku-clone/dump website** kabisa.

Kumbuka kwamba unaweza pia kuongeza payloads kwenye website iliyo-clone kama vile BeEF hook ili "kudhibiti" tab ya mtumiaji.

Kuna tools tofauti unazoweza kutumia kwa madhumuni haya:

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
## Social Engineering Toolit
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
