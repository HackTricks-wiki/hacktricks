# Викрадення конфіденційної інформації з вебсторінки

{{#include ../banners/hacktricks-training.md}}

Якщо **вебсторінка відображає конфіденційну інформацію на основі поточної сесії** — наприклад, cookies, дані облікового запису або дані кредитної картки, — зловмисник може спробувати її ексфільтрувати. Основні техніки включають:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): неправильна конфігурація CORS може дозволити шкідливому origin читати конфіденційні відповіді через cross-origin запити.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): XSS-вразливість у цільовому origin може дозволити інжектованому JavaScript читати та ексфільтрувати інформацію.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): якщо ін'єкція скриптів недоступна, інжектовані HTML-елементи все одно можуть захоплювати конфіденційний вміст.
- [**Clickjacking**](../pentesting-web/clickjacking.md): якщо захист від фреймів відсутній, зловмисник може обманом змусити користувача взаємодіяти з конфіденційною сторінкою. Пов'язане дослідження демонструє цю техніку.<sup>[[1]](#references)</sup>

## References

- [1] [Прикладовий servlet Apache призводить до розкриття інформації](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
