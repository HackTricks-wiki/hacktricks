{{#include ../../banners/hacktricks-training.md}}

Per una valutazione di phishing, a volte potrebbe essere utile **clonare completamente un sito web**.

Nota che puoi anche aggiungere alcuni payload al sito web clonato, come un hook di BeEF per "controllare" la scheda dell'utente.

Ci sono diversi strumenti che puoi utilizzare a questo scopo:

## wget
```text
wget -mk -nH
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
