# Escalonamento de privilégios com Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** pode ser usado para executar programas na **inicialização**. Veja quais binários estão programados para serem executados na inicialização com:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tarefas agendadas

**Tarefas** podem ser agendadas para serem executadas em uma **frequência específica**. Use os seguintes comandos para ver quais binários estão agendados para execução:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Pastas

Todos os binários localizados nas **pastas de inicialização serão executados na inicialização**. As pastas de inicialização comuns são as listadas a seguir, mas a pasta de inicialização é indicada no registro. [Leia isto para saber onde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **PARA SUA INFORMAÇÃO**: Vulnerabilidades de *path traversal* na extração de arquivos (como a explorada no WinRAR anterior à versão 7.13 – CVE-2025-8088) podem ser usadas para **depositar payloads diretamente dentro dessas pastas Startup durante a descompressão**, resultando em execução de código no próximo logon do usuário. Para uma análise aprofundada dessa técnica, consulte:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Nota a partir daqui](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): A entrada de registro **Wow6432Node** indica que você está executando uma versão de 64 bits do Windows. O sistema operacional usa essa chave para exibir uma visualização separada de HKEY_LOCAL_MACHINE\SOFTWARE para aplicativos de 32 bits executados em versões de 64 bits do Windows.

### Execuções

**AutoRun** comumente conhecido no registro:

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

As chaves de registro conhecidas como **Run** e **RunOnce** são projetadas para executar programas automaticamente sempre que um usuário fizer logon no sistema. A linha de comando atribuída como valor de dados de uma chave é limitada a 260 caracteres ou menos.<sup>[[2]](#references)</sup>

**Execuções de serviços** (podem controlar a inicialização automática de serviços durante o boot):

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

No Windows Vista e em versões posteriores, as chaves de registro **Run** e **RunOnce** não são geradas automaticamente. As entradas nessas chaves podem iniciar programas diretamente ou especificá-los como dependências. Por exemplo, para carregar um arquivo DLL no logon, pode-se usar a chave de registro **RunOnceEx** junto com uma chave "Depend". Isso é demonstrado adicionando uma entrada de registro para executar "C:\temp\evil.dll" durante a inicialização do sistema:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Se você puder escrever em qualquer um dos registros mencionados dentro de **HKLM**, poderá escalar privilégios quando um usuário diferente fizer login.

> [!TIP]
> **Exploit 2**: Se você puder sobrescrever qualquer um dos binários indicados em qualquer um dos registros dentro de **HKLM**, poderá modificar esse binário com um backdoor quando um usuário diferente fizer login e escalar privilégios.
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

Os atalhos colocados na pasta **Startup** acionarão automaticamente serviços ou aplicações para serem iniciados durante o logon do usuário ou a reinicialização do sistema. A localização da pasta **Startup** é definida no registro para os escopos **Local Machine** e **Current User**. Isso significa que qualquer atalho adicionado a esses locais **Startup** especificados garantirá que o serviço ou programa vinculado seja iniciado após o processo de logon ou reinicialização, tornando esse um método simples para agendar a execução automática de programas.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Se você puder sobrescrever qualquer [User] Shell Folder em **HKLM**, poderá apontá-la para uma pasta controlada por você e inserir um backdoor que será executado sempre que um usuário fizer logon no sistema, escalando privilégios.
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

Este valor do registro por usuário pode apontar para um script ou comando executado quando o usuário faz logon. Ele é principalmente um primitivo de **persistence**, pois é executado apenas no contexto do usuário afetado, mas ainda vale a pena verificá-lo durante revisões de post-exploitation e autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Se você puder gravar nesse valor para o usuário atual, poderá reativar a execução no próximo logon interativo sem precisar de direitos de administrador. Se puder gravá-lo no hive de outro usuário, poderá obter code execution quando esse usuário fizer logon.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Observações:

- Prefira caminhos completos para arquivos `.bat`, `.cmd`, `.ps1` ou outros arquivos de launcher que já possam ser lidos pelo usuário-alvo.
- Isso persiste após logoff/reinicialização até que o valor seja removido.
- Ao contrário de `HKLM\...\Run`, isso **não** concede elevação por si só; trata-se de persistência no escopo do usuário.

### Chaves do Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalmente, a chave **Userinit** é definida como **userinit.exe**. No entanto, se essa chave for modificada, o executável especificado também será iniciado pelo **Winlogon** no logon do usuário. Da mesma forma, a chave **Shell** deve apontar para **explorer.exe**, que é o shell padrão do Windows.<sup>[[1]](#references)</sup>
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

No Registro do Windows, em `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, há um valor **`AlternateShell`** definido por padrão como `cmd.exe`. Isso significa que, quando você escolhe "Modo de Segurança com Prompt de Comando" durante a inicialização (pressionando F8), `cmd.exe` é usado. No entanto, é possível configurar o computador para iniciar automaticamente nesse modo sem precisar pressionar F8 e selecioná-lo manualmente.

Etapas para criar uma opção de inicialização que inicie automaticamente no "Modo de Segurança com Prompt de Comando":<sup>[[5]](#references)</sup>

1. Altere os atributos do arquivo `boot.ini` para remover os sinalizadores somente leitura, sistema e oculto: `attrib c:\boot.ini -r -s -h`
2. Abra `boot.ini` para edição.
3. Insira uma linha como: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salve as alterações em `boot.ini`.
5. Reaplique os atributos originais do arquivo: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Alterar a chave de Registro **AlternateShell** permite configurar um shell de comando personalizado, potencialmente para acesso não autorizado.
- **Exploit 2 (Permissões de escrita no PATH):** Ter permissões de escrita em qualquer parte da variável **PATH** do sistema, especialmente antes de `C:\Windows\system32`, permite executar um `cmd.exe` personalizado, que poderia funcionar como um backdoor se o sistema fosse iniciado no Modo de Segurança.
- **Exploit 3 (Permissões de escrita no PATH e no boot.ini):** Ter acesso de escrita a `boot.ini` permite iniciar automaticamente o Modo de Segurança, facilitando o acesso não autorizado na próxima reinicialização.

Para verificar a configuração atual de **AlternateShell**, use estes comandos:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Componente instalado

Active Setup é um recurso do Windows que **é iniciado antes que o ambiente de desktop seja totalmente carregado**. Ele prioriza a execução de determinados comandos, que devem ser concluídos antes que o logon do usuário prossiga. Esse processo ocorre até mesmo antes que outras entradas de inicialização, como as das seções de registro Run ou RunOnce, sejam acionadas.

O Active Setup é gerenciado por meio das seguintes chaves de registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Dentro dessas chaves, existem várias subchaves, cada uma correspondente a um componente específico. Os valores das chaves de particular interesse incluem:

- **IsInstalled:**
- `0` indica que o comando do componente não será executado.
- `1` significa que o comando será executado uma vez para cada usuário, que é o comportamento padrão caso o valor `IsInstalled` esteja ausente.
- **StubPath:** Define o comando a ser executado pelo Active Setup. Pode ser qualquer linha de comando válida, como iniciar o `notepad`.

**Informações de segurança:**

- Modificar ou gravar em uma chave onde **`IsInstalled`** esteja definido como `"1"` com um **`StubPath`** específico pode levar à execução não autorizada de comandos, potencialmente para privilege escalation.
- Alterar o arquivo binário referenciado em qualquer valor de **`StubPath`** também pode permitir privilege escalation, desde que haja permissões suficientes.

Para inspecionar as configurações de **`StubPath`** nos componentes do Active Setup, estes comandos podem ser usados:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Visão geral dos Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) são módulos DLL que adicionam recursos extras ao Internet Explorer da Microsoft. Eles são carregados no Internet Explorer e no Windows Explorer a cada inicialização. No entanto, sua execução pode ser bloqueada definindo a chave **NoExplorer** como 1, impedindo que sejam carregados com as instâncias do Windows Explorer.<sup>[[1]](#references)</sup>

Os BHOs são compatíveis com o Windows 10 por meio do Internet Explorer 11, mas não são compatíveis com o Microsoft Edge, o navegador padrão nas versões mais recentes do Windows.

Para examinar os BHOs registrados em um sistema, você pode inspecionar as seguintes chaves do Registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Cada BHO é representado por seu **CLSID** no Registro, servindo como um identificador exclusivo. Informações detalhadas sobre cada CLSID podem ser encontradas em `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Para consultar os BHOs no Registro, estes comandos podem ser utilizados:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Extensões do Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Observe que o registro conterá 1 nova entrada de registro para cada dll, e ela será representada pelo **CLSID**. Você pode encontrar as informações do CLSID em `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Drivers de fontes

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Abrir comando

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Observe que todos os locais onde você pode encontrar autoruns já são pesquisados pelo [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). No entanto, para obter uma lista mais abrangente de arquivos autoexecutados, você pode usar o [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)do systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mais

**Encontre mais Autoruns, como registros, em** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mecanismos comuns de persistência de malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Execução automática na inicialização ou no logon: chaves Run do Registro / pasta de inicialização](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Scripts de inicialização na inicialização ou no logon: script de logon (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Categorias de inicialização automática (Solução de problemas com as ferramentas Windows Sysinternals, 2ª edição)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Como posso adicionar uma opção de inicialização que inicia um shell alternativo?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Resumo do Metasploit de 03/04/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [PR #21032 do Metasploit – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
