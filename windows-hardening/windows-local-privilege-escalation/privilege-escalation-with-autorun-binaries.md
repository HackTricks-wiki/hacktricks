# Escalada de Privilégios com Autoruns

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em **carreira de hacking** e hackear o impossível - **estamos contratando!** (_fluência em polonês escrita e falada é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** pode ser usado para executar programas na **inicialização**. Veja quais binários estão programados para serem executados na inicialização com:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tarefas Agendadas

**Tarefas** podem ser agendadas para serem executadas com **certa frequência**. Veja quais binários estão agendados para serem executados com:
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

Todos os binários localizados nas **pastas de inicialização serão executados na inicialização**. As pastas de inicialização comuns são as listadas a seguir, mas a pasta de inicialização é indicada no registro. [Leia isso para saber onde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registro

{% hint style="info" %}
Nota: A entrada do registro **Wow6432Node** indica que você está executando uma versão do Windows de 64 bits. O sistema operacional usa essa chave para exibir uma visualização separada de HKEY\_LOCAL\_MACHINE\SOFTWARE para aplicativos de 32 bits que são executados em versões do Windows de 64 bits.
{% endhint %}

### Execuções

Registro de AutoRun comumente conhecido:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

As chaves de registro Run e RunOnce fazem com que os programas sejam executados cada vez que um usuário faz login. O valor de dados para uma chave é uma linha de comando não superior a 260 caracteres.

**Execuções de serviço** (podem controlar a inicialização automática de serviços durante a inicialização):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Não é criado por padrão no Windows Vista e posterior. As entradas da chave de execução do registro podem fazer referência a programas diretamente ou listá-los como uma dependência. Por exemplo, é possível carregar uma DLL no logon usando uma chave "Depend" com RunOnceEx: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"`

{% hint style="info" %}
**Exploração 1**: Se você puder escrever dentro de qualquer um dos registros mencionados dentro do **HKLM**, poderá elevar privilégios quando um usuário diferente fizer login.
{% endhint %}

{% hint style="info" %}
**Exploração 2**: Se você puder sobrescrever qualquer um dos binários indicados em qualquer um dos registros dentro do **HKLM**, poderá modificar esse binário com uma porta dos fundos quando um usuário diferente fizer login e elevar privilégios.
{% endhint %}
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
### Caminho de Inicialização

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Qualquer atalho criado para o local apontado pela subchave Startup iniciará o serviço durante o logon/reinício. A localização de inicialização é especificada tanto na Máquina Local quanto no Usuário Atual.

{% hint style="info" %}
Se você puder sobrescrever qualquer pasta \[Usuário] Shell em **HKLM**, poderá apontá-la para uma pasta controlada por você e colocar uma backdoor que será executada sempre que um usuário fizer login no sistema, escalando privilégios.
{% endhint %}
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
### Chaves do Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalmente, a chave **Userinit** aponta para userinit.exe, mas se essa chave puder ser alterada, então esse exe também será iniciado pelo Winlogon.\
A chave **Shell** deve apontar para explorer.exe.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Se você puder sobrescrever o valor do registro ou o binário, poderá elevar os privilégios.
{% endhint %}

### Configurações de Política

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Verifique a chave **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

Caminho: **`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`**

Sob a chave do registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot` está o valor **AlternateShell**, que por padrão é definido como `cmd.exe` (o prompt de comando). Quando você pressiona F8 durante a inicialização e seleciona "Modo de segurança com prompt de comando", o sistema usa esse shell alternativo.\
No entanto, você pode criar uma opção de inicialização para que não precise pressionar F8 e selecionar "Modo de segurança com prompt de comando".

1. Edite os atributos do arquivo boot.ini (c:\boot.ini) para tornar o arquivo não somente leitura, não sistema e não oculto (attrib c:\boot.ini -r -s -h).
2. Abra o boot.ini.
3. Adicione uma linha semelhante à seguinte: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salve o arquivo.
5. Reaplique as permissões corretas (attrib c:\boot.ini +r +s +h).

Informações da [qui](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell).

{% hint style="info" %}
**Exploração 1:** Se você puder modificar essa chave do registro, poderá apontar sua backdoor.
{% endhint %}

{% hint style="info" %}
**Exploração 2 (permissões de gravação no PATH)**: Se você tiver permissão de gravação em qualquer pasta do sistema **PATH** antes de _C:\Windows\system32_ (ou se puder alterá-lo), poderá criar um arquivo cmd.exe e se alguém iniciar a máquina no Modo de segurança, sua backdoor será executada.
{% endhint %}

{% hint style="info" %}
**Exploração 3 (permissões de gravação no PATH e permissões de gravação no boot.ini)**: Se você puder escrever no boot.ini, poderá automatizar a inicialização em modo de segurança para a próxima reinicialização.
{% endhint %}
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Componente Instalado

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

O Active Setup é executado antes da área de trabalho aparecer. Os comandos iniciados pelo Active Setup são executados sincronamente, bloqueando o logon enquanto estão sendo executados. O Active Setup é executado antes de quaisquer entradas de registro Run ou RunOnce serem avaliadas.

Dentro dessas chaves, você encontrará mais chaves e cada uma delas terá alguns valores interessantes. Os mais interessantes são:

* **IsInstalled:**
  * 0: O comando do componente não será executado.
  * 1: O comando do componente será executado uma vez por usuário. Este é o padrão (se o valor IsInstalled não existir).
* **StubPath**
  * Formato: Qualquer linha de comando válida, por exemplo, "notepad"
  * Este é o comando que é executado se o Active Setup determinar que este componente precisa ser executado durante o logon.

{% hint style="info" %}
Se você pudesse escrever/sobrescrever em qualquer chave com _**IsInstalled == "1"**_ a chave **StubPath**, você poderia apontá-la para uma backdoor e elevar privilégios. Além disso, se você pudesse sobrescrever qualquer **binário** apontado por qualquer chave **StubPath**, você poderia ser capaz de elevar privilégios.
{% endhint %}
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Objetos de Ajuda do Navegador

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Um **Objeto de Ajuda do Navegador** (**BHO**) é um módulo DLL projetado como um plugin para o navegador da web Internet Explorer da Microsoft para fornecer funcionalidades adicionais. Esses módulos são executados para cada nova instância do Internet Explorer e para cada nova instância do Windows Explorer. No entanto, um BHO pode ser impedido de ser executado por cada instância do Explorer definindo a chave **NoExplorer** como 1.

Os BHOs ainda são suportados a partir do Windows 10, por meio do Internet Explorer 11, enquanto os BHOs não são suportados no navegador da web padrão Microsoft Edge.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
Observe que o registro conterá 1 novo registro para cada dll e será representado pelo **CLSID**. Você pode encontrar as informações do CLSID em `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Extensões do Internet Explorer

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Observe que o registro conterá 1 novo registro para cada dll e será representado pelo **CLSID**. Você pode encontrar as informações do CLSID em `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Drivers de Fonte

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Comando Abrir

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opções de Execução de Arquivos de Imagem

As Opções de Execução de Arquivos de Imagem (Image File Execution Options) é uma funcionalidade do Windows que permite a um usuário definir um depurador para um aplicativo específico. Isso pode ser usado para fins legítimos, como depurar um aplicativo durante o desenvolvimento, mas também pode ser explorado por um atacante para obter privilégios elevados.

O método mais comum de exploração das Opções de Execução de Arquivos de Imagem é adicionando uma entrada de registro para um aplicativo legítimo que execute um binário malicioso como depurador. Quando o aplicativo legítimo é executado, o binário malicioso também é executado com os mesmos privilégios do aplicativo. Isso pode permitir que o atacante execute comandos com privilégios elevados no sistema.

Para explorar essa vulnerabilidade, o atacante precisa ter acesso de gravação ao registro do Windows. Isso pode ser alcançado com privilégios de administrador ou por meio de uma vulnerabilidade de escalonamento de privilégios local.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Observe que todos os sites onde você pode encontrar autoruns já são pesquisados pelo [winpeas.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). No entanto, para uma lista mais abrangente de arquivos autoexecutados, você pode usar o [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) do SysInternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mais

Encontre mais Autoruns como registros em [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Referências

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em **carreira de hacking** e hackear o inquebrável - **estamos contratando!** (_fluência em polonês escrita e falada é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
