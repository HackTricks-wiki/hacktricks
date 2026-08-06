# Інші Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

У багатьох випадках back-end довіряє **Host header** для виконання певних дій. Наприклад, він може використовувати його значення як **домен для надсилання скидання пароля**. Тож коли ви отримуєте email із посиланням для скидання пароля, використовується домен, який ви вказали в Host header.Then, ви можете запросити скидання пароля інших користувачів і змінити домен на контрольований вами, щоб викрасти їхні коди скидання пароля. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Зверніть увагу, що, можливо, вам навіть не потрібно чекати, поки користувач натисне на посилання для скидання пароля, щоб отримати token, оскільки його можуть натиснути **spam filters або інші проміжні пристрої/bots для аналізу**.

### Session booleans

Іноді, коли ви успішно проходите певну перевірку, back-end **просто додає boolean зі значенням "True" до security attribute вашої session**. Після цього інший endpoint знатиме, чи успішно ви пройшли цю перевірку.\
Однак якщо ви **проходите перевірку**, а вашій session надається значення "True" у security attribute, ви можете спробувати **отримати доступ до інших ресурсів**, які **залежать від того самого attribute**, але до яких ви **не повинні мати permissions**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Спробуйте зареєструватися як уже existent користувач. Також спробуйте використати equivalent characters (крапки, багато пробілів і Unicode).

### Takeover emails

Зареєструйте email, до його підтвердження змініть email, а потім, якщо новий confirmation email буде надіслано на перший зареєстрований email, ви зможете takeover будь-який email. Або якщо ви можете enable другий email, підтвердивши перший, ви також зможете takeover будь-який account.

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Розробники можуть забути вимкнути різні debugging options у production environment. Наприклад, HTTP `TRACE` method призначений для діагностичних цілей. Якщо його увімкнено, web server відповідатиме на requests, що використовують `TRACE` method, відображаючи у відповіді точний request, який було отримано. Така поведінка часто є нешкідливою, але іноді призводить до information disclosure, наприклад розкриття назв internal authentication headers, які reverse proxies можуть додавати до requests.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
