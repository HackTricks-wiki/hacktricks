# Клонування вебсайту

{{#include ../../banners/hacktricks-training.md}}


Під час оцінювання фішингу іноді може бути корисно повністю **клонувати/завантажити вебсайт**.

Зверніть увагу, що до клонованого вебсайту також можна додати payloads, наприклад BeEF hook, щоб «контролювати» вкладку користувача.

Для цього можна використовувати різні інструменти:

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
## Інструментарій соціальної інженерії
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
