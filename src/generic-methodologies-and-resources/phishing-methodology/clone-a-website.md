# Clonación de un sitio web

{{#include ../../banners/hacktricks-training.md}}


Para una evaluación de phishing, a veces puede ser útil **clonar/volcar completamente un sitio web**.

Ten en cuenta que también puedes añadir algunos payloads al sitio web clonado, como un hook de BeEF para "controlar" la pestaña del usuario.

Hay diferentes herramientas que puedes utilizar para este propósito:

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
## Kit de ingeniería social
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
