{{#include ../../banners/hacktricks-training.md}}

Para una evaluación de phishing, a veces puede ser útil **clonar completamente un sitio web**.

Ten en cuenta que también puedes agregar algunos payloads al sitio web clonado, como un gancho de BeEF para "controlar" la pestaña del usuario.

Hay diferentes herramientas que puedes usar para este propósito:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Herramienta de Ingeniería Social
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
