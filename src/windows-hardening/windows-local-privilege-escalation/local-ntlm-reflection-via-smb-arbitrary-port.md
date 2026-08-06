# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

हाल के Windows builds ने **alternative TCP ports के लिए SMB client support** पेश किया। इस feature का abuse करके **local NTLM authentication** को **SYSTEM local privilege escalation** में बदला जा सकता है, जब attacker यह कर सके:<sup>[[1]](#references)</sup>

1. किसी **non-445 port** पर attacker-controlled listener से SMB connection खोलना
2. उस TCP connection को active बनाए रखना
3. किसी **privileged local client** को **उसी SMB share path** को access करने के लिए coerce करना
4. परिणामस्वरूप होने वाली **local NTLM authentication** को machine की वास्तविक SMB service पर relay करना

यही **CVE-2026-24294** के पीछे का primitive है, जिसे **March 2026** में patch किया गया।<sup>[[1]](#references)[[4]](#references)</sup>

## यह क्यों काम करता है

पुरानी CMTI / serialized-SPN reflection trick यहां cover की गई है:

{{#ref}}
../ntlm/README.md
{{#endref}}

इस नए variant को marshalled hostname की आवश्यकता नहीं होती। इसके बजाय, यह SMB client के दो behaviours का abuse करता है:<sup>[[1]](#references)</sup>

- **Windows 11 24H2** और **Windows Server 2025** पर उपलब्ध **Alternative port support**, जिसे users `net use \\host\share /tcpport:<port>` के माध्यम से access कर सकते हैं
- **SMB connection reuse / multiplexing**, जिसमें कई authenticated sessions एक ही TCP connection का उपयोग कर सकते हैं

इसका अर्थ है कि low-privileged user पहले SMB client से high port पर मौजूद attacker SMB server तक TCP connection बना सकता है, और फिर किसी privileged service को **ठीक उसी UNC path** को access करने के लिए coerce कर सकता है। यदि Windows मौजूदा TCP connection को reuse करने का निर्णय लेता है, तो privileged NTLM exchange attacker-controlled transport पर भेजा जाता है और उसे local SMB server पर relay किया जा सकता है।<sup>[[1]](#references)</sup>

## Preconditions

- Target SMB alternative ports support करता हो:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** या बाद का version
- Attacker चुने गए high port पर local या remote SMB server चला सकता हो
- Attacker किसी privileged service को UNC path access करने के लिए coerce कर सकता हो
- Privileged authentication **NTLM local authentication** होनी चाहिए
- Target relayable होना चाहिए:<sup>[[1]](#references)</sup>
- Synacktiv ने बताया कि यह default रूप से **Windows Server 2025** पर काम करता है
- उनकी chain **Windows 11 24H2** पर काम नहीं करती थी, क्योंकि वहां outbound SMB signing default रूप से enforced है

## Userland और internals

Command line से यह feature सरल दिखाई देता है:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically, client undocumented `lpUseOptions` data के साथ `WNetAddConnection4W` का उपयोग करता है। Relevant option `TraP` (transport parameters) है, जो अंततः FSCTL के माध्यम से kernel SMB client तक पहुंचता है और `mrxsmb` द्वारा parse किया जाता है।<sup>[[1]](#references)[[3]](#references)</sup>

महत्वपूर्ण practical notes:<sup>[[1]](#references)</sup>

- **UNC syntax में अब भी कोई port field नहीं है**
- **`net use` per-logon-session होता है**
- Bypass अब भी काम करता है क्योंकि **TCP connection और SMB session अलग-अलग objects हैं**
- यदि exploit पहले बनाए गए TCP connection को SMB client द्वारा reuse करने पर निर्भर करता है, तो **उसी share path का reuse करना अनिवार्य है**

## Exploitation flow

### 1. Attacker-controlled SMB transport बनाएं

High port पर SMB server चलाएं और Windows को उससे connect कराएं:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Server आपके नियंत्रण वाले किसी भी credential pair को स्वीकार कर सकता है, उदाहरण के लिए `user:user`। इस step का लक्ष्य अभी privilege escalation नहीं है, बल्कि Windows SMB client को आपके listener के लिए एक reusable TCP connection खोलने और बनाए रखने के लिए तैयार करना है।<sup>[[1]](#references)</sup>

### 2. किसी privileged service को उसी UNC path पर coerce करें

**PetitPotam** जैसे coercion primitive का उपयोग करके **उसी** `\\192.168.56.3\share` path के विरुद्ध request भेजें। यदि coerced client privileged है और target name local (`localhost` या local IP/host) है, तो Windows **NTLM local authentication** करता है।

क्योंकि TCP connection reuse होता है, वह privileged NTLM exchange सीधे वास्तविक local SMB server पर जाने के बजाय attacker SMB service तक पहुंचता है।<sup>[[1]](#references)</sup>

### 3. Privileged authentication को local SMB पर वापस relay करें

Attacker-controlled SMB service privileged NTLM exchange को `ntlmrelayx.py` तक forward करती है, जो इसे machine के वास्तविक SMB listener पर relay करके `NT AUTHORITY\SYSTEM` के रूप में एक session प्राप्त करता है।<sup>[[1]](#references)</sup>

Public writeup में दिए गए सामान्य tools:<sup>[[1]](#references)</sup>

- Reused TCP connection पर privileged auth प्राप्त करने के लिए custom port पर `smbserver.py`
- Captured NTLM को local SMB पर relay करने के लिए `ntlmrelayx.py`
- Privileged authentication को force करने के लिए `PetitPotam.exe` या कोई अन्य coercion primitive

## Operator notes

- यह एक **local privilege escalation** technique है, generic remote relay trick नहीं<sup>[[1]](#references)</sup>
- Attacker-controlled SMB service को share mount के लिए मूल रूप से उपयोग किए गए **उसी TCP connection** पर privileged authentication handle करना आवश्यक है<sup>[[1]](#references)</sup>
- यदि coerced access किसी **अलग share path** तक पहुंचता है, तो Windows एक अलग connection स्थापित कर सकता है और chain टूट जाती है<sup>[[1]](#references)</sup>
- SMB signing requirements relay को रोक सकती हैं, भले ही arbitrary-port step काम कर रहा हो<sup>[[1]](#references)</sup>
- यदि आपके पास केवल Kerberos material है या आप local NTLM force नहीं कर सकते, तो यह exact variant पर्याप्त नहीं है<sup>[[1]](#references)</sup>

## Detection and hardening

- **March 2026 Patch Tuesday** का **CVE-2026-24294** patch करें<sup>[[4]](#references)</sup>
- **non-default SMB ports** का उपयोग करने वाले `net use` या `New-SmbMapping` पर नज़र रखें<sup>[[1]](#references)</sup>
- Workstations या servers से **high TCP ports** पर होने वाले असामान्य outbound SMB पर alert लगाएं<sup>[[1]](#references)</sup>
- **EFSRPC / PetitPotam-style** triggers जैसे coercion opportunities की समीक्षा करें<sup>[[1]](#references)</sup>
- जहां संभव हो SMB signing लागू करें; Synacktiv ने विशेष रूप से बताया है कि इसने Windows 11 24H2 पर उनके relay को block किया<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
