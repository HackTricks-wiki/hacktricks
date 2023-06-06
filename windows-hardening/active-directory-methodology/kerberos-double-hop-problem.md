# Problema de Duplo Salto do Kerberos

O problema de "Duplo Salto" do Kerberos ocorre quando um atacante tenta usar a autenticação do **Kerberos** em **dois saltos**, por exemplo, usando o **PowerShell**/**WinRM**.

Quando ocorre uma **autenticação** através do **Kerberos**, as **credenciais** **não são** armazenadas em **memória**. Portanto, se você executar o mimikatz, **não encontrará as credenciais** do usuário na máquina, mesmo que ele esteja executando processos.

Isso ocorre porque, ao se conectar com o Kerberos, esses são os passos:

1. O usuário fornece as credenciais e o **controlador de domínio** retorna um **TGT** do Kerberos para o usuário.
2. O usuário usa o **TGT** para solicitar um **ticket de serviço** para **conectar-se** ao Servidor1.
3. O usuário se **conecta** ao **Servidor1** e fornece o **ticket de serviço**.
4. O **Servidor1** **não tem** as **credenciais** do usuário ou o **TGT** do usuário armazenado em cache. Portanto, quando o usuário do Servidor1 tenta fazer login em um segundo servidor, ele **não consegue se autenticar**.

### Delegação Irrestrita

Se a **delegação irrestrita** estiver habilitada no PC, isso não acontecerá, pois o **Servidor** receberá um **TGT** de cada usuário que acessá-lo. Além disso, se a delegação irrestrita for usada, você provavelmente poderá **comprometer o Controlador de Domínio** a partir dela.\
[**Mais informações na página de delegação irrestrita**](unconstrained-delegation.md).

### CredSSP

Outra opção sugerida para **administradores de sistemas** para evitar esse problema, que é [**notavelmente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), é o **Provedor de Suporte de Segurança de Credenciais**. Habilitar o CredSSP tem sido uma solução mencionada em vários fóruns ao longo dos anos. Da Microsoft:

_"A autenticação do CredSSP delega as credenciais do usuário do computador local para um computador remoto. Essa prática aumenta o risco de segurança da operação remota. Se o computador remoto for comprometido, quando as credenciais forem passadas para ele, as credenciais poderão ser usadas para controlar a sessão de rede."_

Se você encontrar o **CredSSP habilitado** em sistemas de produção, redes sensíveis, etc., é recomendável desativá-lo. Uma maneira rápida de **verificar o status do CredSSP** é executando `Get-WSManCredSSP`. O comando pode ser executado remotamente se o WinRM estiver habilitado.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
    Get-WSManCredSSP
}
```
## Soluções alternativas

### Invoke Command <a href="#invoke-command" id="invoke-command"></a>

Este método é uma espécie de _"trabalhar com"_ o problema de duplo salto, não necessariamente resolvê-lo. Não depende de nenhuma configuração e você pode simplesmente executá-lo a partir do seu computador de ataque. É basicamente um **`Invoke-Command`** aninhado.

Isso irá **executar** o **`hostname`** no **segundo servidor:**
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
    Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Você também pode ter uma **PS-Session** estabelecida com o **primeiro servidor** e simplesmente **executar** o **`Invoke-Command`** com `$cred` de lá em vez de aninhá-lo. No entanto, executá-lo a partir do seu computador de ataque centraliza as tarefas:
```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```
### Registrar Configuração de Sessão PSSession

Se em vez de usar **`evil-winrm`** você puder usar o cmdlet **`Enter-PSSession`**, você pode então usar **`Register-PSSessionConfiguration`** e reconectar para contornar o problema de duplo salto:
```powershell
# Register a new PS Session configuration
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
# Restar WinRM
Restart-Service WinRM
# Get a PSSession
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
# Check that in this case the TGT was sent and is in memory of the PSSession
klist
# In this session you won't have the double hop problem anymore
```
### Encaminhamento de Porta <a href="#portproxy" id="portproxy"></a>

Como temos o Administrador Local no alvo intermediário **bizintel: 10.35.8.17**, você pode adicionar uma regra de encaminhamento de porta para enviar suas solicitações para o servidor final/terceiro **secdev: 10.35.8.23**.

Você pode rapidamente usar o **netsh** para criar um comando em uma linha e adicionar a regra.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```
Então, **o primeiro servidor** está ouvindo na porta 5446 e encaminhará as solicitações que atingirem a porta 5446 para **o segundo servidor** na porta 5985 (também conhecida como WinRM).

Em seguida, abra um buraco no firewall do Windows, o que também pode ser feito com um comando netsh rápido.
```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
Agora estabeleça a sessão, que nos encaminhará para **o primeiro servidor**.

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

Encaminhar as solicitações do WinRM também parece funcionar ao usar o **`winrs.exe`**. Essa pode ser uma opção melhor se você estiver ciente de que o PowerShell está sendo monitorado. O comando abaixo traz de volta "secdev" como resultado do `hostname`.
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
Assim como o `Invoke-Command`, isso pode ser facilmente programado para que o invasor possa simplesmente emitir comandos do sistema como um argumento. Um exemplo genérico de script em lote _winrm.bat_:

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

Este método requer a instalação do [OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH) no primeiro servidor. A instalação do OpenSSH para Windows pode ser feita **completamente via CLI** e não leva muito tempo - além disso, não é detectado como malware!

Claro que em certas circunstâncias pode não ser viável, muito complicado ou pode ser um risco geral de OpSec.

Este método pode ser especialmente útil em uma configuração de jump box - com acesso a uma rede de outra forma inacessível. Uma vez estabelecida a conexão SSH, o usuário/invasor pode disparar quantos `New-PSSession` forem necessários contra a rede segmentada sem explodir no problema de duplo salto.

Quando configurado para usar **Autenticação de Senha** no OpenSSH (não chaves ou Kerberos), o **tipo de logon é 8** também conhecido como _logon de texto claro de rede_. Isso não significa que sua senha é enviada em texto claro - ela é, na verdade, criptografada pelo SSH. Ao chegar, ela é descriptografada em texto claro por meio de seu [pacote de autenticação](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN) para que sua sessão possa solicitar TGTs suculentos!

Isso permite que o servidor intermediário solicite e obtenha um TGT em seu nome para armazenar localmente no servidor intermediário. Sua sessão pode então usar este TGT para autenticar (PS remoto) em servidores adicionais.

#### Cenário de Instalação do OpenSSH

Baixe o último [zip de lançamento do OpenSSH do github](https://github.com/PowerShell/Win32-OpenSSH/releases) em sua máquina de ataque e mova-o (ou baixe-o diretamente na jump box).

Descompacte o zip para onde desejar. Em seguida, execute o script de instalação - `Install-sshd.ps1`

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

Por último, adicione uma regra de firewall para **abrir a porta 22**. Verifique se os serviços SSH estão instalados e inicie-os. Ambos os serviços precisarão estar em execução para que o SSH funcione.

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

Se você receber um erro de `Conexão redefinida`, atualize as permissões para permitir que **Todos: Leitura e Execução** no diretório raiz do OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referências

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
