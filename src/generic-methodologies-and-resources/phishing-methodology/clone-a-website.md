{{#include ../../banners/hacktricks-training.md}}

Para uma avaliação de phishing, às vezes pode ser útil **clonar um site** completamente.

Observe que você também pode adicionar alguns payloads ao site clonado, como um hook do BeEF para "controlar" a aba do usuário.

Existem diferentes ferramentas que você pode usar para esse propósito:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Ferramenta de Engenharia Social
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
