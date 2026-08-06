# Проблема Kerberos "Double Hop"

{{#include ../../banners/hacktricks-training.md}}


## Вступ

Проблема Kerberos "Double Hop" виникає, коли зловмисник намагається використовувати **Kerberos authentication через два** **hops**, наприклад за допомогою **PowerShell**/**WinRM**.

Коли через **Kerberos** відбувається **authentication**, **credentials** **не** кешуються в **memory.** Тому, якщо ви запустите mimikatz, ви **не знайдете credentials** користувача на машині, навіть якщо він запускає процеси.

Це відбувається тому, що під час підключення через Kerberos виконуються такі кроки:<sup>[[1]](#references)</sup>

1. User1 надає credentials, а **domain controller** повертає User1 Kerberos **TGT**.
2. User1 використовує **TGT**, щоб запросити **service ticket** для **підключення** до Server1.
3. User1 **підключається** до **Server1** і надає **service ticket**.
4. **Server1** **не має** кешованих **credentials** User1 або його **TGT**. Тому, коли User1 із Server1 намагається увійти на другий сервер, він **не може пройти authentication**.

### Unconstrained Delegation

Якщо на PC увімкнено **unconstrained delegation**, цього не станеться, оскільки **Server** **отримає** **TGT** кожного користувача, який до нього підключається. Крім того, якщо використовується unconstrained delegation, ви, ймовірно, зможете **скомпрометувати Domain Controller** із нього.\
[**Більше інформації на сторінці unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Ще одним способом уникнути цієї проблеми, який є [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), є **Credential Security Support Provider**. Від Microsoft:

> Автентифікація CredSSP делегує credentials користувача з локального комп'ютера на віддалений комп'ютер. Така практика підвищує ризик для безпеки віддаленої операції. Якщо віддалений комп'ютер скомпрометовано після передавання йому credentials, ці credentials можна використати для керування мережевим сеансом.

Настійно рекомендується вимикати **CredSSP** у production-системах, чутливих мережах і подібних середовищах через проблеми з безпекою. Щоб визначити, чи увімкнено **CredSSP**, можна виконати команду `Get-WSManCredSSP`. Ця команда дає змогу **перевірити статус CredSSP** і навіть може виконуватися віддалено за умови, що **WinRM** увімкнено.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** зберігає TGT користувача на вихідній робочій станції, водночас дозволяючи RDP-сеансу запитувати нові service tickets Kerberos на наступному hop. Увімкніть **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** і виберіть **Require Remote Credential Guard**, після чого підключайтеся за допомогою `mstsc.exe /remoteGuard /v:server1`, а не переходьте на CredSSP.

Microsoft порушила роботу RCG для multi-hop access у Windows 11 22H2+ до встановлення **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Встановіть оновлення на client і intermediary server, інакше другий hop усе одно завершиться помилкою.<sup>[[5]](#references)</sup> Швидка перевірка hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
With those builds installed, the RDP hop can satisfy downstream Kerberos challenges without exposing reusable secrets on the first server.

## Обхідні шляхи

### Invoke Command

Щоб вирішити проблему double hop, пропонується метод із використанням вкладеного `Invoke-Command`. Він не вирішує проблему безпосередньо, але забезпечує обхідний шлях без потреби у спеціальних налаштуваннях. Цей підхід дає змогу виконати команду (`hostname`) на вторинному сервері через команду PowerShell, виконану з початкової атакувальної машини, або через раніше встановлений PS-Session із першим сервером. Ось як це робиться:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Альтернативно, для централізації завдань рекомендується встановити PS-Session із першим сервером і виконати `Invoke-Command` за допомогою `$cred`.

### Реєстрація конфігурації PSSession

Одне з рішень для обходу проблеми double hop полягає у використанні `Register-PSSessionConfiguration` разом із `Enter-PSSession`. Цей метод потребує іншого підходу, ніж `evil-winrm`, і дає змогу створити сесію, на яку не поширюється обмеження double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Для локальних адміністраторів на проміжній цілі port forwarding дає змогу надсилати запити до кінцевого сервера. За допомогою `netsh` можна додати правило для port forwarding, а також правило брандмауера Windows, щоб дозволити порт, через який пересилаються запити.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` можна використовувати для пересилання запитів WinRM, потенційно як менш помітний варіант, якщо моніторинг PowerShell викликає занепокоєння.<sup>[[2]](#references)</sup> Наведена нижче команда демонструє його використання:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Встановлення OpenSSH на першому сервері забезпечує обхідне рішення для проблеми double-hop, особливо корисне у сценаріях із jump box. Цей метод потребує встановлення та налаштування OpenSSH для Windows через CLI. Якщо налаштувати Password Authentication, проміжний сервер зможе отримати TGT від імені користувача.<sup>[[2]](#references)</sup>

#### Кроки встановлення OpenSSH

1. Завантажте zip-архів з останнім релізом OpenSSH і перемістіть його на цільовий сервер.
2. Розпакуйте архів і запустіть скрипт `Install-sshd.ps1`.
3. Додайте правило брандмауера, щоб відкрити порт 22, і перевірте, чи запущені SSH-сервіси.

Щоб усунути помилки `Connection reset`, можливо, потрібно оновити дозволи, надавши всім користувачам доступ на читання та виконання для каталогу OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Розширений)

**LSA Whisperer** (2024) відкриває виклик пакета `msv1_0!CacheLogon`, щоб додати відомий NT hash до наявного *network logon* замість створення нової сесії за допомогою `LogonUser`. Впровадивши hash у сесію logon, яку WinRM/PowerShell уже відкрив на hop #1, цей хост може автентифікуватися до hop #2 без зберігання явних облікових даних або генерації додаткових подій 4624.<sup>[[6]](#references)</sup>

1. Отримайте виконання коду всередині LSASS (вимкнувши/зловживаючи PPL або запустивши це на контрольованій вами lab VM).
2. Перелічіть сесії logon (наприклад, `lsa.exe sessions`) і отримайте LUID, що відповідає вашому remoting context.
3. Заздалегідь обчисліть NT hash і передайте його до `CacheLogon`, а після завершення очистьте його.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Після заповнення кешу повторно запустіть `Invoke-Command`/`New-PSSession` із переходу #1: LSASS повторно використає впроваджений хеш для проходження викликів Kerberos/NTLM під час другого переходу, акуратно обходячи обмеження double hop. Компроміс полягає у більшій кількості телеметрії (виконання коду в LSASS), тому використовуйте цей підхід у середовищах із жорсткими обмеженнями, де CredSSP/RCG заборонені.

## Посилання

- [1] [Розуміння Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Обхідні шляхи для Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Ще одне рішення для багатопереходового віддаленого керування PowerShell](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Як вирішити проблему багатопереходового керування PowerShell без використання CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 квітня 2024 року — KB5036896 (збірка ОС 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
