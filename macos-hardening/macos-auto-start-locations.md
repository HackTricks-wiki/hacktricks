# Ubicaciones de inicio automático de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Aquí se encuentran las ubicaciones en el sistema que podrían llevar a la **ejecución** de un binario **sin** **interacción** **del usuario**.

### Launchd

**`launchd`** es el **primer** **proceso** ejecutado por el kernel de OX S al inicio y el último en finalizar al apagar. Siempre debe tener el **PID 1**. Este proceso **leerá y ejecutará** las configuraciones indicadas en los **plists ASEP** en:

* `/Library/LaunchAgents`: agentes por usuario instalados por el administrador
* `/Library/LaunchDaemons`: demonios de todo el sistema instalados por el administrador
* `/System/Library/LaunchAgents`: agentes por usuario proporcionados por Apple.
* `/System/Library/LaunchDaemons`: demonios de todo el sistema proporcionados por Apple.

Cuando un usuario inicia sesión, los plists ubicados en `/Users/$USER/Library/LaunchAgents` y `/Users/$USER/Library/LaunchDemons` se inician con los **permisos de los usuarios registrados**.

La **principal diferencia entre agentes y demonios es que los agentes se cargan cuando el usuario inicia sesión y los demonios se cargan al inicio del sistema** (ya que hay servicios como ssh que deben ejecutarse antes de que cualquier usuario acceda al sistema). Además, los agentes pueden usar la GUI mientras que los demonios deben ejecutarse en segundo plano.
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
Hay casos en los que un **agente debe ser ejecutado antes de que el usuario inicie sesión**, estos se llaman **PreLoginAgents**. Por ejemplo, esto es útil para proporcionar tecnología de asistencia en el inicio de sesión. También se pueden encontrar en `/Library/LaunchAgents` (ver [**aquí**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un ejemplo).

\{% hint style="info" %\} Los nuevos archivos de configuración de Daemons o Agents se cargarán después del próximo reinicio o usando `launchctl load <target.plist>`. También es posible cargar archivos .plist sin esa extensión con `launchctl -F <file>` (sin embargo, esos archivos plist no se cargarán automáticamente después del reinicio).\
También es posible **descargar** con `launchctl unload <target.plist>` (el proceso al que apunta se terminará).

Para **asegurarse** de que no hay **nada** (como una anulación) **impidiendo** que un **Agente** o **Daemon** **se ejecute**, ejecute: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist` \{% endhint %\}

Liste todos los agentes y demonios cargados por el usuario actual:
```bash
launchctl list
```
### Cron

Lista los trabajos cron del **usuario actual** con:
```bash
crontab -l
```
También se pueden ver todos los trabajos programados de los usuarios en **`/usr/lib/cron/tabs/`** y **`/var/at/tabs/`** (se necesita ser root).

En MacOS se pueden encontrar varias carpetas que ejecutan scripts con **cierta frecuencia** en:
```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Aquí puedes encontrar los trabajos regulares de **cron**, los trabajos de **at** (poco utilizados) y los trabajos **periódicos** (principalmente utilizados para limpiar archivos temporales). Los trabajos periódicos diarios se pueden ejecutar, por ejemplo, con: `periodic daily`.

Los scripts periódicos (**`/etc/periodic`**) se ejecutan debido a los **launch daemons** configurados en `/System/Library/LaunchDaemons/com.apple.periodic*`. Ten en cuenta que si un script se almacena en `/etc/periodic/` como una forma de **escalado de privilegios**, se **ejecutará** como el **propietario del archivo**.
```bash
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist
```
### kext

Para instalar un KEXT como elemento de inicio, debe estar **instalado en una de las siguientes ubicaciones**:

* `/System/Library/Extensions`
  * Archivos KEXT integrados en el sistema operativo OS X.
* `/Library/Extensions`
  * Archivos KEXT instalados por software de terceros.

Puede listar los archivos kext cargados actualmente con:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Para obtener más información sobre las [**extensiones de kernel, consulte esta sección**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers).

### **Elementos de inicio de sesión**

En Preferencias del Sistema -> Usuarios y grupos -> **Elementos de inicio de sesión** se pueden encontrar **elementos que se ejecutan cuando el usuario inicia sesión**.\
Es posible listarlos, agregarlos y eliminarlos desde la línea de comandos:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}' 

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"' 
```
Estos elementos se almacenan en el archivo /Users/\<username>/Library/Application Support/com.apple.backgroundtaskmanagementagent

### At

Las "tareas At" se utilizan para **programar tareas en momentos específicos**.\
Estas tareas difieren de cron en que **son tareas únicas** que se **eliminan después de ejecutarse**. Sin embargo, **sobrevivirán a un reinicio del sistema** por lo que no se pueden descartar como una posible amenaza.

Por **defecto** están **deshabilitadas** pero el usuario **root** puede **habilitarlas** con:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Esto creará un archivo a las 13:37:
```bash
echo hello > /tmp/hello | at 1337
```
Si las tareas AT no están habilitadas, las tareas creadas no se ejecutarán.

### Hooks de inicio/salida de sesión

Están obsoletos, pero se pueden usar para ejecutar comandos cuando un usuario inicia sesión.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
```
Esta configuración se almacena en `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Para eliminarlo:
```bash
defaults delete com.apple.loginwindow LoginHook
```
En el ejemplo anterior hemos creado y eliminado un **LoginHook**, también es posible crear un **LogoutHook**.

El usuario root se almacena en `/private/var/root/Library/Preferences/com.apple.loginwindow.plist`

### Emond

Apple introdujo un mecanismo de registro llamado **emond**. Parece que nunca se desarrolló por completo y el desarrollo puede haber sido **abandonado** por Apple en favor de otros mecanismos, pero sigue **disponible**.

Este servicio poco conocido puede **no ser de mucha utilidad para un administrador de Mac**, pero para un actor de amenazas una muy buena razón sería usarlo como un mecanismo de **persistencia que la mayoría de los administradores de macOS probablemente no conocerían**. Detectar el uso malintencionado de emond no debería ser difícil, ya que el System LaunchDaemon del servicio busca scripts para ejecutar en un solo lugar:
```bash
ls -l /private/var/db/emondClients
```
{% hint style="danger" %}
**Como esto no se usa mucho, cualquier cosa en esa carpeta debería ser sospechosa**
{% endhint %}

### Elementos de inicio

\{% hint style="danger" %\} **Esto está obsoleto, por lo que no se debe encontrar nada en los siguientes directorios.** \{% endhint %\}

Un **StartupItem** es un **directorio** que se **coloca** en una de estas dos carpetas. `/Library/StartupItems/` o `/System/Library/StartupItems/`

Después de colocar un nuevo directorio en una de estas dos ubicaciones, se deben colocar **dos elementos más** dentro de ese directorio. Estos dos elementos son un **script rc** y un **plist** que contiene algunas configuraciones. Este plist debe llamarse "**StartupParameters.plist**". 
{% endtab %}
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

{% tab title="superservicename" %}

## Ubicación de inicio automático de macOS

### Introducción

En macOS, hay varias ubicaciones donde se pueden colocar archivos para que se inicien automáticamente al arrancar el sistema. Estos archivos pueden ser scripts, binarios o aplicaciones. En este documento, se describen las ubicaciones comunes donde se pueden encontrar estos archivos.

### Ubicaciones comunes

#### /Library/LaunchAgents

Esta ubicación contiene archivos .plist que se ejecutan en el inicio del usuario actual. Estos archivos se ejecutan con los permisos del usuario actual y no requieren privilegios de administrador para instalarse.

#### /Library/LaunchDaemons

Esta ubicación contiene archivos .plist que se ejecutan en el inicio del sistema. Estos archivos se ejecutan con privilegios de administrador y, por lo tanto, requieren privilegios de administrador para instalarse.

#### /System/Library/LaunchAgents

Esta ubicación contiene archivos .plist que se ejecutan en el inicio del usuario actual. Estos archivos son proporcionados por Apple y se ejecutan con los permisos del usuario actual.

#### /System/Library/LaunchDaemons

Esta ubicación contiene archivos .plist que se ejecutan en el inicio del sistema. Estos archivos son proporcionados por Apple y se ejecutan con privilegios de administrador.

### Conclusión

Es importante conocer las ubicaciones comunes donde se pueden encontrar archivos de inicio automático en macOS. Esto puede ayudar a identificar posibles puntos de entrada para un atacante o para solucionar problemas de inicio automático.
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
**Esto no funciona en versiones modernas de MacOS**
{% endhint %}

También es posible colocar aquí **comandos que se ejecutarán al inicio.** Ejemplo de un script rc.common regular:
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
### Perfiles

Los perfiles de configuración pueden obligar a un usuario a utilizar ciertas configuraciones de navegador, configuraciones de proxy DNS o configuraciones de VPN. Muchos otros payloads son posibles, lo que los hace propensos a ser abusados.

Puedes enumerarlos ejecutando:
```bash
ls -Rl /Library/Managed\ Preferences/
```
### Otras técnicas y herramientas de persistencia

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
