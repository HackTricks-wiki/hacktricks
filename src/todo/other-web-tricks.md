# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Several times the back-end trust the **Host header** to perform some actions. For example, it could use its value as the **domain to send a password reset**. So when you receive an email with a link to reset your password, the domain being used is the one you put in the Host header.Then, you can request the password reset of other users and change the domain to one controlled by you to steal their password reset codes. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Note that it's possible that you don't even need to wait for the user to click on the reset password link to get the token, as maybe even **spam filters or other intermediary devices/bots will click on it to analyze it**.

### Session booleans

Some times when you complete some verification correctly the back-end will **just add a boolean with the value "True" to a security attribute your session**. Then, a different endpoint will know if you successfully passed that check.\
However, if you **pass the check** and your sessions is granted that "True" value in the security attribute, you can try to **access other resources** that **depends on the same attribute** but that you **shouldn't have permissions** to access. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Register functionality

Try to register as an already existent user. Try also using equivalent characters (dots, lots of spaces and Unicode).

### Takeover emails

Register an email, before confirming it change the email, then, if the new confirmation email is sent to the first registered email,you can takeover any email. Or if you can enable the second email confirming the firt one, you can also takeover any account.

### Access Internal servicedesk of companies using atlassian



{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Developers might forget to disable various debugging options in the production environment. For example, the HTTP `TRACE` method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the `TRACE` method by echoing in the response the exact request that was received. This behaviour is often harmless, but occasionally leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
