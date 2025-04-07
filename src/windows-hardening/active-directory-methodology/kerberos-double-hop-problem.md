# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Проблема "Double Hop" Kerberos виникає, коли зловмисник намагається використовувати **Kerberos authentication across two** **hops**, наприклад, використовуючи **PowerShell**/**WinRM**.

Коли відбувається **authentication** через **Kerberos**, **credentials** **не** кешуються в **memory.** Тому, якщо ви запустите mimikatz, ви **не знайдете credentials** користувача на машині, навіть якщо він виконує процеси.

Це відбувається тому, що при підключенні з Kerberos виконуються такі кроки:

1. User1 надає credentials, і **domain controller** повертає Kerberos **TGT** користувачу User1.
2. User1 використовує **TGT** для запиту **service ticket** для **connect** до Server1.
3. User1 **connects** до **Server1** і надає **service ticket**.
4. **Server1** **не має** **credentials** User1 в кеші або **TGT** User1. Тому, коли User1 з Server1 намагається увійти на другий сервер, він **не може аутентифікуватися**.

### Unconstrained Delegation

Якщо **unconstrained delegation** увімкнено на ПК, цього не станеться, оскільки **Server** отримає **TGT** кожного користувача, який до нього звертається. Більше того, якщо використовується unconstrained delegation, ви, ймовірно, зможете **compromise the Domain Controller** з його допомогою.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Інший спосіб уникнути цієї проблеми, який є [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), це **Credential Security Support Provider**. Від Microsoft:

> Аутентифікація CredSSP делегує облікові дані користувача з локального комп'ютера на віддалений комп'ютер. Ця практика підвищує ризик безпеки віддаленої операції. Якщо віддалений комп'ютер буде скомпрометовано, коли облікові дані передаються йому, ці облікові дані можуть бути використані для контролю мережевої сесії.

Рекомендується **CredSSP** вимкнути на виробничих системах, чутливих мережах та подібних середовищах через проблеми безпеки. Щоб визначити, чи **CredSSP** увімкнено, можна виконати команду `Get-WSManCredSSP`. Ця команда дозволяє **перевірити статус CredSSP** і може бути виконана віддалено, якщо **WinRM** увімкнено.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Щоб вирішити проблему подвійного стрибка, пропонується метод, що включає вкладений `Invoke-Command`. Це не вирішує проблему безпосередньо, але пропонує обхідний шлях без необхідності спеціальних налаштувань. Цей підхід дозволяє виконати команду (`hostname`) на вторинному сервері через команду PowerShell, виконану з початкової атакуючої машини або через раніше встановлену PS-Session з першим сервером. Ось як це робиться:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Альтернативно, встановлення PS-Session з першим сервером і виконання `Invoke-Command` з використанням `$cred` рекомендується для централізації завдань.

### Реєстрація конфігурації PSSession

Рішення для обходу проблеми подвійного стрибка передбачає використання `Register-PSSessionConfiguration` з `Enter-PSSession`. Цей метод вимагає іншого підходу, ніж `evil-winrm`, і дозволяє створити сесію, яка не страждає від обмеження подвійного стрибка.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Для локальних адміністраторів на проміжній цілі, переадресація портів дозволяє надсилати запити на кінцевий сервер. Використовуючи `netsh`, можна додати правило для переадресації портів, разом з правилом брандмауера Windows для дозволу переадресованого порту.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` може бути використаний для пересилання запитів WinRM, потенційно як менш помітний варіант, якщо моніторинг PowerShell є проблемою. Нижче наведено команду, яка демонструє його використання:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Встановлення OpenSSH на першому сервері дозволяє обійти проблему подвійного стрибка, що особливо корисно для сценаріїв з jump box. Цей метод вимагає CLI-встановлення та налаштування OpenSSH для Windows. Коли він налаштований для автентифікації за паролем, це дозволяє проміжному серверу отримати TGT від імені користувача.

#### Кроки встановлення OpenSSH

1. Завантажте та перемістіть останній реліз OpenSSH у zip-форматі на цільовий сервер.
2. Розпакуйте та запустіть скрипт `Install-sshd.ps1`.
3. Додайте правило брандмауера для відкриття порту 22 та перевірте, чи працюють служби SSH.

Щоб вирішити помилки `Connection reset`, можливо, потрібно оновити дозволи, щоб дозволити всім читати та виконувати доступ до каталогу OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Посилання

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
