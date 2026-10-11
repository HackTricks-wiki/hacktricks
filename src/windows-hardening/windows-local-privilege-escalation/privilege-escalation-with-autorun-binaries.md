# Escalação de privilégios com Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** pode ser usado para executar programas na **inicialização**. Veja quais binários estão programados para serem executados na inicialização com:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Tarefas agendadas

**Tarefas** podem ser agendadas para serem executadas com uma **frequência específica**. Use os seguintes comandos para ver quais binários estão agendados para execução:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Uma tarefa habilitada que é executada como SYSTEM merece ser revisada, mesmo quando sua definição e seu arquivo de ação estão protegidos. [O Task Scheduler exige permissão de execução na tarefa para iniciá-la sob demanda](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Se um usuário com poucos privilégios tiver essa permissão, inspecione a ação exata, especialmente scripts do PowerShell que modificam ACLs do Active Directory ou redefinem configurações de proteção de contas. Verifique a configuração `AllowDemandStart` da tarefa e confira as entradas e os efeitos do script; a permissão para iniciar uma tarefa fixa, por si só, não implica execução arbitrária de código.

## Pastas

Todos os binários localizados nas **pastas de Inicialização serão executados na inicialização**. As pastas de inicialização comuns estão listadas a seguir, mas a pasta de inicialização é indicada no registro. [Leia isto para saber onde.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

A entrada Startup de um usuário com privilégios mais elevados pode iniciar um script protegido que abre repetidamente arquivos de um diretório no qual outro usuário pode gravar. Antes de tratar esse diretório como um caminho para elevação de privilégios, verifique a **identidade real usada no logon** da entrada, o diretório de entrada do script e suas ACLs, além da ação exata. Em particular, [`hh.exe` abre arquivos HTML Help compilados (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); um script que passa arquivos fornecidos pelo chamador para esse programa cruza uma fronteira de confiança de conteúdo, mesmo que verifique o nome do arquivo ou os primeiros bytes. [As políticas do HTML Help podem restringir atalhos executáveis](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), portanto, confirme a política instalada e o comportamento do conteúdo acessível. A extensão `.chm` ou os bytes mágicos, por si só, não comprovam a execução de código com privilégios mais elevados. Inspecione o autorun, a linha de comando do processo e as permissões do caminho sem abrir o arquivo não confiável durante a enumeração.

A mesma fronteira de conteúdo existe quando uma pessoa com privilégios mais elevados **abre manualmente** um `.chm` de uma pasta de documentação que outro usuário pode substituir. Confirme o arquivo exato e as permissões de gravação do diretório pai, a identidade real do visualizador e o evento de abertura, além da política efetiva do HTML Help. Uma pasta gravável ou um pedido para revisar a documentação não comprova que a identidade com privilégios mais elevados abriu conteúdo controlado pelo atacante.

> **OBS**: Vulnerabilidades de *path traversal* durante a extração de arquivos (como a explorada no WinRAR anterior à versão 7.13 – CVE-2025-8088) podem ser usadas para **depositar payloads diretamente nessas pastas Startup durante a descompactação**, resultando na execução de código no próximo logon do usuário. Para uma análise aprofundada dessa técnica, veja:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registro

> [!TIP]
> [Nota daqui](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): A entrada de registro **Wow6432Node** indica que você está executando uma versão de 64 bits do Windows. O sistema operacional usa essa chave para exibir uma visualização separada de HKEY_LOCAL_MACHINE\SOFTWARE para aplicativos de 32 bits executados em versões de 64 bits do Windows.

### Execuções

**Entradas AutoRun comumente conhecidas**:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

As chaves de registro conhecidas como **Run** e **RunOnce** são projetadas para executar programas automaticamente sempre que um usuário faz logon no sistema. A linha de comando atribuída como valor de dados de uma chave é limitada a 260 caracteres ou menos.<sup>[[2]](#references)</sup>

**Execuções de serviços** (podem controlar a inicialização automática de serviços durante a inicialização do sistema):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

No Windows Vista e em versões posteriores, as chaves de registro **Run** e **RunOnce** não são geradas automaticamente. As entradas nessas chaves podem iniciar programas diretamente ou especificá-los como dependências. Por exemplo, para carregar um arquivo DLL no logon, seria possível usar a chave de registro **RunOnceEx** junto com uma chave "Depend". Isso é demonstrado pela adição de uma entrada de registro para executar "C:\temp\evil.dll" durante a inicialização do sistema:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Se você puder escrever em qualquer uma das chaves do Registro mencionadas no **HKLM**, poderá escalar privilégios quando outro usuário fizer login.

> [!TIP]
> **Exploit 2**: Se você puder sobrescrever qualquer um dos binários indicados em qualquer uma das chaves do Registro no **HKLM**, poderá modificar esse binário com um backdoor quando outro usuário fizer login e escalar privilégios.

```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```

### Caminho de inicialização

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Os atalhos colocados na pasta **Startup** iniciarão automaticamente serviços ou aplicativos durante o logon do usuário ou a reinicialização do sistema. O local da pasta **Startup** é definido no registro para os escopos **Local Machine** e **Current User**. Isso significa que qualquer atalho adicionado a esses locais de **Startup** fará com que o serviço ou programa vinculado seja iniciado após o processo de logon ou reinicialização, tornando esse um método simples para agendar a execução automática de programas.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Se você puder sobrescrever qualquer [User] Shell Folder em **HKLM**, poderá apontá-la para uma pasta controlada por você e colocar um backdoor que será executado sempre que um usuário fizer logon no sistema, escalando privilégios.

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Esse valor do registro por usuário pode apontar para um script ou comando executado quando o usuário faz logon. É principalmente uma primitiva de **persistence**, pois só é executada no contexto do usuário afetado, mas ainda vale a pena verificá-la durante revisões de post-exploitation e autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Se você puder gravar nesse valor para o usuário atual, poderá disparar novamente a execução no próximo logon interativo sem precisar de direitos de admin. Se puder gravá-lo no hive de outro usuário, poderá obter execução de código quando esse usuário fizer logon.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notas:

- Prefira caminhos completos para arquivos `.bat`, `.cmd`, `.ps1` ou outros arquivos de inicialização que já sejam legíveis pelo usuário-alvo.
- Isso persiste até que o valor seja removido, mesmo após logoff/reinicialização.
- Diferentemente de `HKLM\...\Run`, isso **não** concede elevação por si só; é uma persistência no escopo do usuário.

### Chaves do Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalmente, a chave **Userinit** é definida como **userinit.exe**. No entanto, se essa chave for modificada, o executável especificado também será iniciado pelo **Winlogon** quando o usuário fizer logon. Da mesma forma, a chave **Shell** deve apontar para **explorer.exe**, que é o shell padrão do Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Se você puder sobrescrever o valor do registro ou o binário, poderá escalar privilégios.

### Configurações de política

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Verifique a chave **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Alterando o Prompt de Comando do Modo de Segurança

No Registro do Windows, em `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, há um valor **`AlternateShell`** definido por padrão como `cmd.exe`. Isso significa que, ao escolher "Modo de Segurança com Prompt de Comando" durante a inicialização (pressionando F8), `cmd.exe` é usado. Porém, é possível configurar o computador para iniciar automaticamente nesse modo sem precisar pressionar F8 e selecioná-lo manualmente.

Etapas para criar uma opção de inicialização que inicie automaticamente no "Modo de Segurança com Prompt de Comando":<sup>[[5]](#references)</sup>

1. Altere os atributos do arquivo `boot.ini` para remover as flags somente leitura, sistema e oculto: `attrib c:\boot.ini -r -s -h`
2. Abra `boot.ini` para edição.
3. Insira uma linha como: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salve as alterações em `boot.ini`.
5. Reaplique os atributos originais do arquivo: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Alterar a chave do Registro **AlternateShell** permite configurar um command shell personalizado, potencialmente para obter acesso não autorizado.
- **Exploit 2 (Permissões de gravação em PATH):** Ter permissões de gravação em qualquer parte da variável de sistema **PATH**, especialmente antes de `C:\Windows\system32`, permite executar um `cmd.exe` personalizado, que pode funcionar como um backdoor se o sistema for iniciado no Modo de Segurança.
- **Exploit 3 (Permissões de gravação em PATH e boot.ini):** Ter acesso de gravação a `boot.ini` permite iniciar automaticamente no Modo de Segurança, facilitando o acesso não autorizado na próxima reinicialização.

Para verificar a configuração atual de **AlternateShell**, use estes comandos:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Componente instalado

Active Setup é um recurso do Windows que **é iniciado antes de o ambiente da área de trabalho ser totalmente carregado**. Ele prioriza a execução de determinados comandos, que precisam ser concluídos antes de o logon do usuário prosseguir. Esse processo ocorre antes mesmo de outras entradas de inicialização, como as das seções de registro Run ou RunOnce, serem acionadas.

Active Setup é gerenciado pelas seguintes chaves do registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Nessas chaves, existem várias subchaves, cada uma correspondente a um componente específico. Os valores das chaves de maior interesse incluem:

- **IsInstalled:**
  - `0` indica que o comando do componente não será executado.
  - `1` significa que o comando será executado uma vez para cada usuário, comportamento padrão caso o valor `IsInstalled` esteja ausente.
- **StubPath:** Define o comando a ser executado pelo Active Setup. Pode ser qualquer linha de comando válida, como iniciar o `notepad`.

**Informações de segurança:**

- Modificar ou gravar em uma chave cujo valor **`IsInstalled`** seja `"1"` e que tenha um **`StubPath`** específico pode levar à execução não autorizada de comandos, potencialmente para escalonamento de privilégios.
- Alterar o arquivo binário referenciado em qualquer valor **`StubPath`** também pode permitir o escalonamento de privilégios, desde que haja permissões suficientes.

Para inspecionar as configurações de **`StubPath`** nos componentes do Active Setup, estes comandos podem ser usados:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Visão geral dos Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) são módulos DLL que adicionam recursos extras ao Internet Explorer da Microsoft. Eles são carregados no Internet Explorer e no Windows Explorer a cada inicialização. No entanto, sua execução pode ser bloqueada definindo a chave **NoExplorer** como 1, impedindo que sejam carregados nas instâncias do Windows Explorer.<sup>[[1]](#references)</sup>

Os BHOs são compatíveis com o Windows 10 por meio do Internet Explorer 11, mas não são compatíveis com o Microsoft Edge, o navegador padrão nas versões mais recentes do Windows.

Para explorar os BHOs registrados em um sistema, você pode inspecionar as seguintes chaves do registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Cada BHO é representado por seu **CLSID** no registro, que serve como identificador exclusivo. Informações detalhadas sobre cada CLSID podem ser encontradas em `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Para consultar os BHOs no registro, estes comandos podem ser utilizados:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Extensões do Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Observe que o registro conterá 1 nova entrada para cada DLL, representada pelo **CLSID**. Você pode encontrar as informações do CLSID em `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Drivers de fontes

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Comando de abertura

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Manipuladores COM do menu de contexto

Os manipuladores do menu de contexto do Explorer são extensões do shell registradas em chaves como `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` e `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. O valor padrão de um manipulador, ou às vezes o nome da chave, é um CLSID. Siga esse CLSID até `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; o valor padrão dessa chave indica o nome da DLL carregada quando o manipulador é invocado.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Verifique as visualizações de registro de 32 e 64 bits. `HKCR` mescla registros de classes por usuário e de todo o computador, então verifique qual chave subjacente um processo resolverá. Uma identidade de baixo privilégio que possa alterar um valor `InprocServer32` de todo o computador pode redirecionar um processo mais privilegiado para outra DLL, mas a escalação exige que esse processo invoque o handler. Um caminho de DLL gravável pode criar um risco semelhante, mesmo quando o próprio valor do registro está protegido.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Observe que todos os locais onde você pode encontrar autoruns já são pesquisados pelo [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). No entanto, para obter uma lista mais abrangente de arquivos executados automaticamente, você pode usar o [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) do Sysinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Mais

**Encontre mais Autoruns, como registros, em** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mecanismos comuns de persistência de malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Execução automática na inicialização ou no logon: chaves de execução do Registro / pasta de inicialização](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Scripts de inicialização na inicialização ou no logon: script de logon (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – categorias de inicialização automática (Solução de problemas com as ferramentas Windows Sysinternals, 2ª edição)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Como posso adicionar uma opção de inicialização que inicie um shell alternativo?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Resumo do Metasploit de 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [PR #21032 do Metasploit – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
