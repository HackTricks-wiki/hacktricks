# Clonare un sito web

{{#include ../../banners/hacktricks-training.md}}


Per una valutazione di phishing a volte può essere utile **clonare/effettuare il dump completo di un sito web**.

Nota che puoi anche aggiungere alcuni payload al sito web clonato, come un hook BeEF per "controllare" la scheda dell'utente.

Esistono diversi tool che puoi utilizzare a questo scopo:

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
## Toolkit di Social Engineering
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
