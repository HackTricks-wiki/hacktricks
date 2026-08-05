# Інші Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

У багатьох випадках back-end довіряє **Host header** для виконання певних дій. Наприклад, він може використовувати його значення як **домен, на який потрібно надіслати скидання пароля**. Тому, коли ви отримуєте email із посиланням для скидання пароля, використовується домен, указаний вами в Host header. Потім ви можете запитати скидання пароля для інших користувачів і змінити домен на контрольований вами, щоб викрасти їхні коди скидання пароля. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Зверніть увагу, що, можливо, вам навіть не потрібно чекати, поки користувач натисне посилання для скидання пароля, щоб отримати токен, оскільки, можливо, **spam filters або інші проміжні пристрої/боти натиснуть його, щоб проаналізувати**.

### Session booleans

Іноді після успішного проходження певної перевірки back-end **просто додає boolean зі значенням "True" до атрибута безпеки вашої сесії**. Потім інший endpoint перевіряє, чи успішно ви пройшли цю перевірку.\
Однак, якщо ви **пройшли перевірку** і вашій сесії було надано значення "True" в атрибуті безпеки, ви можете спробувати **отримати доступ до інших ресурсів**, які **залежать від того самого атрибута**, але до яких ви **не повинні мати дозволу**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Функціональність реєстрації

Спробуйте зареєструватися під уже існуючим користувачем. Також спробуйте використовувати еквівалентні символи (крапки, багато пробілів і Unicode).

### Takeover emails

Зареєструйте email, а до його підтвердження змініть email. Якщо новий email для підтвердження буде надіслано на першу зареєстровану адресу, ви зможете виконати takeover будь-якого email. Або, якщо ви можете активувати другу email-адресу, підтвердивши першу, ви також зможете виконати takeover будь-якого акаунта.

### Доступ до внутрішнього servicedesk компаній через atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Розробники можуть забути вимкнути різні параметри debugging у production environment. Наприклад, HTTP `TRACE` method призначений для діагностики. Якщо його увімкнено, web server відповідатиме на запити з використанням `TRACE` method, відображаючи у відповіді точний отриманий запит. Така поведінка часто є безпечною, але іноді призводить до розкриття інформації, наприклад назв внутрішніх authentication headers, які reverse proxies можуть додавати до запитів.![Зображення для допису](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Зображення для допису](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
