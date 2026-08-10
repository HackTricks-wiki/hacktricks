# Клонування вебсайту

Для phishing assessment іноді може бути корисно повністю **клонувати/здампити вебсайт**.

Зверніть увагу, що до клонованого вебсайту також можна додати payloads, наприклад BeEF hook, щоб "контролювати" вкладку користувача.

Для цього можна використовувати різні інструменти:

## wget

Наведена нижче команда використовує режими Wget для дзеркального копіювання, завантаження необхідних для сторінки ресурсів, перетворення посилань і коригування розширень, а потім обслуговує завантажені файли з поточного каталогу за допомогою модуля Python `http.server` на порту 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Репозиторій goclone описує утиліту як таку, що завантажує вебсайт до локального каталогу, зберігаючи структуру відносних посилань, і документує виклик `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Інструментарій соціальної інженерії

Репозиторій Social-Engineer Toolkit (SET) визначає SET як open-source фреймворк для penetration-testing під час авторизованих оцінювань із використанням соціальної інженерії.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Посібник GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Документація Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Репозиторій goclone](https://github.com/imthaghost/goclone)
- [4] [Репозиторій Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
