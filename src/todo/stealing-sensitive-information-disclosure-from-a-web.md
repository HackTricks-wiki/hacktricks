# Викрадення розкритої конфіденційної інформації з вебсайту

{{#include ../banners/hacktricks-training.md}}

Якщо в якийсь момент ви знайдете **вебсторінку, яка відображає конфіденційну інформацію на основі вашої сесії**: можливо, вона відображає cookies, або виводить платіжні чи CC-дані, або будь-яку іншу конфіденційну інформацію, ви можете спробувати її викрасти.\
Тут наведено основні способи, якими можна спробувати цього досягти:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Якщо ви можете обійти CORS-заголовки, то зможете викрасти інформацію, виконуючи Ajax-запит із malicious page.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Якщо ви знайдете XSS-вразливість на сторінці, то зможете використати її для викрадення інформації.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Якщо ви не можете інжектити XSS-теги, то все одно можете викрасти інформацію за допомогою інших звичайних HTML-тегів.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Якщо захисту від цієї атаки немає, ви можете обманом змусити користувача надіслати вам конфіденційні дані (приклад [тут](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Посилання

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
