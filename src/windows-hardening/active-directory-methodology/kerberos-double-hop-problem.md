# Проблема подвійного переходу Kerberos

{{#include ../../banners/hacktricks-training.md}}


## Вступ

Проблема Kerberos "Double Hop" виникає, коли нападник намагається використовувати **Kerberos authentication across two** **hops**, наприклад через **PowerShell**/**WinRM**.

Коли відбувається **authentication** через **Kerberos**, **credentials** **aren't** cached in **memory.** Тому, якщо запустити mimikatz, ви **не знайдете облікові дані** користувача на машині, навіть якщо він виконує процеси.

Це тому, що при підключенні через Kerberos відбуваються такі кроки:

1. User1 вводить облікові дані, і контролер домену повертає Kerberos **TGT** для User1.
2. User1 використовує **TGT** щоб запросити **service ticket** для **підключення** до Server1.
3. User1 **підключається** до **Server1** і надає **service ticket**.
4. **Server1** **doesn't** have **credentials** of User1 cached or the **TGT** of User1. Тому, коли User1 з Server1 намагається увійти на другий сервер, він **не може аутентифікуватися**.

### Unconstrained Delegation

Якщо на ПК увімкнено **unconstrained delegation**, цього не відбудеться, оскільки **Server** отримає **TGT** кожного користувача, який до нього звертається. Крім того, якщо використовується unconstrained delegation, ви, ймовірно, зможете **компрометувати Domain Controller** через це.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Ще один спосіб уникнути цієї проблеми, який є [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), — це **Credential Security Support Provider**. За Microsoft:

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

Надзвичайно рекомендовано вимикати **CredSSP** на production-системах, у чутливих мережах та подібних середовищах через проблеми з безпекою. Щоб визначити, чи увімкнено **CredSSP**, можна виконати команду `Get-WSManCredSSP`. Ця команда дозволяє **перевірити стан CredSSP** і може бути виконана віддалено, за умови, що **WinRM** увімкнено.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** зберігає TGT користувача на початковій робочій станції, одночасно дозволяючи RDP-сеансу запитувати нові Kerberos service tickets на наступному хопі. Увімкніть **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** і виберіть **Require Remote Credential Guard**, потім підключайтеся за допомогою `mstsc.exe /remoteGuard /v:server1` замість відкату до CredSSP.

Microsoft порушила роботу RCG для багатохопового доступу в Windows 11 22H2+ до квітневих накопичувальних оновлень 2024 року (KB5036896/KB5036899/KB5036894). Застосуйте оновлення на клієнті та проміжному сервері, інакше другий хоп все одно не спрацює. Швидка перевірка hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
З встановленими цими збірками, RDP hop може задовольняти нижележачі виклики Kerberos, не розкриваючи повторно використовувані секрети на першому сервері.

## Обхідні методи

### Invoke Command

Щоб вирішити проблему double hop, представлено метод із вкладеним `Invoke-Command`. Це безпосередньо не вирішує проблему, але пропонує обхідний шлях без потреби в додаткових конфігураціях. Підхід дозволяє виконати команду (`hostname`) на вторинному сервері через PowerShell-команду, виконану з початкової атакуючої машини або через попередньо встановлену PS-Session з першим сервером. Ось як це робиться:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Як альтернативу, рекомендується встановити PS-Session з першим сервером і виконати `Invoke-Command`, використовуючи `$cred`, щоб централізувати завдання.

### Register PSSession Configuration

Рішення для обходу проблеми double hop передбачає використання `Register-PSSessionConfiguration` разом з `Enter-PSSession`. Цей метод потребує іншого підходу, ніж `evil-winrm`, і дозволяє створити сесію, яка не страждає від обмеження double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Для локальних адміністраторів на intermediary target, port forwarding дозволяє надсилати запити на кінцевий сервер. Використовуючи `netsh`, можна додати правило для port forwarding, а також правило Windows firewall, щоб дозволити переспрямований порт.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` може бути використаний для переспрямування запитів WinRM, потенційно як менш помітний варіант, якщо моніторинг PowerShell викликає занепокоєння. Команда нижче демонструє його використання:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Встановлення OpenSSH на першому сервері дозволяє обійти проблему double-hop, особливо корисно у сценаріях jump box. Цей метод вимагає встановлення через CLI та налаштування OpenSSH для Windows. При конфігурації з Password Authentication це дозволяє проміжному серверу отримати TGT від імені користувача.

#### Кроки встановлення OpenSSH

1. Завантажте та перемістіть архів останнього релізу OpenSSH (zip) на цільовий сервер.
2. Розпакуйте та запустіть скрипт `Install-sshd.ps1`.
3. Додайте правило брандмауера, щоб відкрити порт 22, та перевірте, що SSH-служби працюють.

Щоб вирішити помилки `Connection reset`, можливо, доведеться оновити права доступу, дозволивши групі Everyone права читання та виконання для каталогу OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) відкриває виклик пакета `msv1_0!CacheLogon`, щоб ви могли підставити відомий NT hash у існуючий *network logon* замість створення нового сеансу через `LogonUser`. Інжектуючи хеш у сеанс входу, який WinRM/PowerShell уже відкрив на hop #1, цей хост може автентифікуватися на hop #2 без зберігання явних облікових даних або генерації додаткових подій 4624.

1. Отримайте виконання коду всередині LSASS (або відключіть/зловживайте PPL або запустіть на lab VM під вашим контролем).
2. Перелічіть сеанси входу (наприклад `lsa.exe sessions`) і захопіть LUID, що відповідає вашому remoting context.
3. Заздалегідь обчисліть NT hash і передайте його в `CacheLogon`, потім очистіть його після завершення.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Після ініціалізації кеша, повторно запустіть `Invoke-Command`/`New-PSSession` з hop #1: LSASS повторно використає інжектований хеш, щоб задовольнити Kerberos/NTLM виклики для другого хопа, акуратно обходячи обмеження double hop. Компроміс — підвищена телеметрія (виконання коду в LSASS), тому застосовуйте це лише в середовищах з високим рівнем контролю, де CredSSP/RCG заборонені.

## Посилання

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
