# Locais de Auto Inicialização do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Aqui estão os locais no sistema que podem levar à **execução** de um binário **sem** **interação** **do usuário**.

### Launchd

**`launchd`** é o **primeiro** **processo** executado pelo kernel do OX S na inicialização e o último a finalizar no desligamento. Ele deve sempre ter o **PID 1**. Este processo irá **ler e executar** as configurações indicadas nos **plists ASEP** em:

* `/Library/LaunchAgents`: Agentes por usuário instalados pelo administrador
* `/Library/LaunchDaemons`: Daemons em todo o sistema instalados pelo administrador
* `/System/Library/LaunchAgents`: Agentes por usuário fornecidos pela Apple.
* `/System/Library/LaunchDaemons`: Daemons em todo o sistema fornecidos pela Apple.

Quando um usuário faz login, os plists localizados em `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` são iniciados com as **permissões dos usuários logados**.

A **principal diferença entre agentes e daemons é que os agentes são carregados quando o usuário faz login e os daemons são carregados na inicialização do sistema** (já que existem serviços como ssh que precisam ser executados antes que qualquer usuário acesse o sistema). Além disso, os agentes podem usar a GUI enquanto os daemons precisam ser executados em segundo plano.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/username/malware</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```
Existem casos em que um **agente precisa ser executado antes do login do usuário**, esses são chamados de **PreLoginAgents**. Por exemplo, isso é útil para fornecer tecnologia assistiva no login. Eles também podem ser encontrados em `/Library/LaunchAgents` (veja [**aqui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) um exemplo).

\{% hint style="info" %\} Novos arquivos de configuração de Daemons ou Agents serão **carregados após a próxima reinicialização ou usando** `launchctl load <target.plist>` Também é possível carregar arquivos .plist sem essa extensão com `launchctl -F <file>` (no entanto, esses arquivos plist não serão carregados automaticamente após a reinicialização).\
Também é possível **descarregar** com `launchctl unload <target.plist>` (o processo apontado por ele será encerrado),

Para **garantir** que não há **nada** (como uma substituição) **impedindo** um **Agente** ou **Daemon** **de** **ser executado**, execute: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist` \{% endhint %\}

Liste todos os agentes e daemons carregados pelo usuário atual:
```bash
launchctl list
```
### Cron

Liste os trabalhos cron do **usuário atual** com:
```bash
crontab -l
```
Você também pode ver todos os trabalhos cron dos usuários em **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (necessita de privilégios de root).

No MacOS, várias pastas que executam scripts com **certa frequência** podem ser encontradas em:
```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Aqui você pode encontrar os trabalhos regulares do **cron**, os trabalhos do **at** (não muito usados) e os trabalhos **periódicos** (principalmente usados para limpar arquivos temporários). Os trabalhos periódicos diários podem ser executados, por exemplo, com: `periodic daily`.

Os scripts periódicos (**`/etc/periodic`**) são executados por causa dos **launch daemons** configurados em `/System/Library/LaunchDaemons/com.apple.periodic*`. Note que se um script for armazenado em `/etc/periodic/` como uma forma de **escalar privilégios**, ele será **executado** como o **proprietário do arquivo**.
```bash
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist
```
### kext

Para instalar um KEXT como um item de inicialização, ele precisa ser **instalado em um dos seguintes locais**:

* `/System/Library/Extensions`
  * Arquivos KEXT incorporados ao sistema operacional OS X.
* `/Library/Extensions`
  * Arquivos KEXT instalados por software de terceiros.

Você pode listar os arquivos kext atualmente carregados com:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Para mais informações sobre [**extensões de kernel, verifique esta seção**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers).

### **Itens de Login**

Em Preferências do Sistema -> Usuários e Grupos -> **Itens de Login** você pode encontrar **itens a serem executados quando o usuário fizer login**.\
É possível listá-los, adicionar e remover a partir da linha de comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}' 

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"' 
```
Esses itens são armazenados no arquivo /Users/\<username>/Library/Application Support/com.apple.backgroundtaskmanagementagent

### Em

"As tarefas em" são usadas para **agendar tarefas em horários específicos**.\
Essas tarefas diferem do cron no sentido de que **são tarefas únicas** que são **removidas após a execução**. No entanto, elas **sobrevivem a uma reinicialização do sistema** e, portanto, não podem ser descartadas como uma ameaça potencial.

Por **padrão**, elas estão **desativadas**, mas o usuário **root** pode **ativá-las** com:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Isso criará um arquivo às 13:37:
```bash
echo hello > /tmp/hello | at 1337
```
Se as tarefas AT não estiverem habilitadas, as tarefas criadas não serão executadas.

### Hooks de Login/Logout

Eles estão obsoletos, mas podem ser usados para executar comandos quando um usuário faz login.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
```
Esta configuração é armazenada em `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```
Para deletá-lo:
```bash
defaults delete com.apple.loginwindow LoginHook
```
No exemplo anterior, criamos e excluímos um **LoginHook**, também é possível criar um **LogoutHook**.

O usuário root é armazenado em `/private/var/root/Library/Preferences/com.apple.loginwindow.plist`

### Emond

A Apple introduziu um mecanismo de registro chamado **emond**. Parece que nunca foi totalmente desenvolvido e o desenvolvimento pode ter sido **abandonado** pela Apple por outros mecanismos, mas ainda está **disponível**.

Este serviço pouco conhecido pode **não ser muito útil para um administrador de Mac**, mas para um ator de ameaça, uma boa razão seria usá-lo como um mecanismo de **persistência que a maioria dos administradores do macOS provavelmente não saberia** procurar. Detectar o uso malicioso do emond não deve ser difícil, pois o System LaunchDaemon para o serviço procura scripts para serem executados em apenas um lugar:
```bash
ls -l /private/var/db/emondClients
```
{% hint style="danger" %}
**Como isso não é muito usado, qualquer coisa nessa pasta deve ser suspeita**
{% endhint %}

### Itens de inicialização

\{% hint style="danger" %\} **Isso está obsoleto, portanto, nada deve ser encontrado nos seguintes diretórios.** \{% endhint %\}

Um **StartupItem** é um **diretório** que é **colocado** em uma dessas duas pastas. `/Library/StartupItems/` ou `/System/Library/StartupItems/`

Depois de colocar um novo diretório em uma dessas duas localizações, **mais dois itens** precisam ser colocados dentro desse diretório. Esses dois itens são um **script rc** e um **plist** que contém algumas configurações. Este plist deve ser chamado de "**StartupParameters.plist**".{% endtab %}
{% endtabs %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```
{% endtab %}

Você pode encontrar serviços que são iniciados automaticamente no macOS em várias localizações. Aqui estão algumas das principais:

## /Library/LaunchAgents e /Library/LaunchDaemons

Essas pastas contêm arquivos .plist que especificam os serviços que devem ser iniciados automaticamente quando um usuário faz login (LaunchAgents) ou quando o sistema é iniciado (LaunchDaemons). Esses arquivos podem ser modificados para iniciar serviços maliciosos.

## /System/Library/LaunchAgents e /System/Library/LaunchDaemons

Essas pastas contêm arquivos .plist que especificam serviços que são iniciados automaticamente pelo sistema. Eles são protegidos pelo SIP (System Integrity Protection) e, portanto, não podem ser modificados por usuários não autorizados.

## ~/Library/LaunchAgents

Esta pasta contém arquivos .plist que especificam serviços que devem ser iniciados automaticamente quando um usuário faz login. Eles são específicos para cada usuário e podem ser modificados para iniciar serviços maliciosos.

## /Library/StartupItems

Esta pasta contém scripts de inicialização que são executados durante o processo de inicialização do sistema. Eles são obsoletos desde o macOS 10.5 e foram substituídos pelos arquivos .plist nas pastas LaunchAgents e LaunchDaemons.

## /Library/Application Support

Algumas aplicações podem instalar arquivos de inicialização nesta pasta para iniciar serviços automaticamente. Esses arquivos podem ser modificados para iniciar serviços maliciosos.

## /etc/rc.common

Este arquivo contém scripts de inicialização que são executados durante o processo de inicialização do sistema. Eles são obsoletos desde o macOS 10.10 e foram substituídos pelos arquivos .plist nas pastas LaunchAgents e LaunchDaemons.
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### /etc/rc.common

{% hint style="danger" %}
**Isso não funciona em versões modernas do MacOS**
{% endhint %}

Também é possível colocar aqui **comandos que serão executados na inicialização.** Exemplo de um script rc.common regular:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```
### Perfis

Os perfis de configuração podem forçar um usuário a usar determinadas configurações do navegador, configurações de proxy DNS ou configurações de VPN. Muitos outros payloads são possíveis, o que os torna propensos a abusos.

Você pode enumerá-los executando:
```bash
ls -Rl /Library/Managed\ Preferences/
```
### Outras técnicas e ferramentas de persistência

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
