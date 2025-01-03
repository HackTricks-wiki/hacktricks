{{#include ../../banners/hacktricks-training.md}}

Для оцінки фішингу іноді може бути корисно повністю **клонувати вебсайт**.

Зверніть увагу, що ви також можете додати деякі payload'и до клонованого вебсайту, такі як BeEF hook, щоб "контролювати" вкладку користувача.

Існують різні інструменти, які ви можете використовувати для цієї мети:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Інструменти соціальної інженерії
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
