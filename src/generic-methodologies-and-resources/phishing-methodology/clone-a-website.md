# Clonando um Website

{{#include ../../banners/hacktricks-training.md}}


Para uma avaliação de phishing, às vezes pode ser útil **clonar/despejar completamente um website**.

Observe que você também pode adicionar alguns payloads ao website clonado, como um hook do BeEF para "controlar" a aba do usuário.

Existem diferentes ferramentas que você pode usar para essa finalidade:

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
## Kit de Ferramentas de Engenharia Social
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
