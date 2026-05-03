# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Recent Windows builds ने **SMB client support for alternative TCP ports** पेश किया। इस feature का दुरुपयोग **local NTLM authentication** को **SYSTEM local privilege escalation** में बदला जा सकता है, जब attacker:

1. एक **non-445 port** पर attacker-controlled listener से SMB connection खोल सके
2. उस TCP connection को alive रख सके
3. एक **privileged local client** को उसी **SMB share path** तक पहुंचने के लिए मजबूर कर सके
4. परिणामी **local NTLM authentication** को machine की real SMB service तक relay कर सके

यही primitive **CVE-2026-24294** के पीछे है, जिसे **March 2026** में patched किया गया।

## Why it works

पुराना CMTI / serialized-SPN reflection trick यहां covered है:

{{#ref}}
../ntlm/README.md
{{#endref}}

यह नया variant **marshalled hostname** की जरूरत नहीं रखता। इसके बजाय यह दो SMB client behaviours का abuse करता है:

- **Alternative port support** on **Windows 11 24H2** and **Windows Server 2025**, जिसे users के लिए `net use \\host\share /tcpport:<port>` के जरिए exposed किया गया है
- **SMB connection reuse / multiplexing**, जहां multiple authenticated sessions same TCP connection पर जा सकते हैं

इसका मतलब है कि low-privileged user पहले SMB client से attacker SMB server पर high port के लिए एक TCP connection बना सकता है, फिर एक privileged service को **exact same UNC path** access करने के लिए coerce कर सकता है। अगर Windows existing TCP connection reuse करने का फैसला करता है, तो privileged NTLM exchange attacker-controlled transport पर भेजा जाता है और उसे local SMB server तक relay किया जा सकता है।

## Preconditions

- Target SMB alternative ports support करता हो:
- **Windows 11 24H2** या बाद का
- **Windows Server 2025** या बाद का
- Attacker किसी चुने हुए high port पर local या remote SMB server चला सके
- Attacker एक privileged service को UNC path access करने के लिए coerce कर सके
- Privileged authentication **NTLM local authentication** होनी चाहिए
- Target relayable होना चाहिए:
- Synacktiv ने report किया कि यह **Windows Server 2025** पर default रूप से काम करता है
- उनका chain **Windows 11 24H2** पर काम नहीं करता था क्योंकि वहां outbound SMB signing default रूप से enforced है

## Userland and internals

Command line से यह feature simple लगता है:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
प्रोग्रामmatically, client `WNetAddConnection4W` को undocumented `lpUseOptions` data के साथ उपयोग करता है। Relevant option `TraP` (transport parameters) है, जो अंततः एक FSCTL के through kernel SMB client तक पहुँचता है और `mrxsmb` द्वारा parse किया जाता है।

Important practical notes:

- **UNC syntax still has no port field**
- **`net use` is per-logon-session**
- The bypass still works because **the TCP connection and the SMB session are separate objects**
- Reusing the **same share path** mandatory है अगर exploit इस पर depend करता है कि SMB client previously created TCP connection को reuse करे

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Run an SMB server on a high port and make Windows connect to it:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
सर्वर आपके नियंत्रण में किसी भी credential pair को स्वीकार कर सकता है, उदाहरण के लिए `user:user`। इस चरण का लक्ष्य अभी privilege escalation नहीं है, बल्कि केवल Windows SMB client को आपके listener के लिए एक reusable TCP connection खोलने और उसे बनाए रखने के लिए मजबूर करना है।

### 2. एक privileged service को उसी UNC path पर मजबूर करें

**PetitPotam** जैसे coercion primitive का उपयोग **उसी** `\\192.168.56.3\share` path के खिलाफ करें। अगर coerced client privileged है और target name local है (`localhost` या local IP/host), तो Windows **NTLM local authentication** करता है।

क्योंकि TCP connection reuse होता है, वह privileged NTLM exchange सीधे real local SMB server पर जाने के बजाय attacker SMB service तक पहुंचता है।

### 3. privileged authentication को वापस local SMB पर relay करें

attacker-controlled SMB service privileged NTLM exchange को `ntlmrelayx.py` तक forward करता है, जो उसे machine के real SMB listener पर relay करता है और `NT AUTHORITY\SYSTEM` के रूप में session प्राप्त करता है।

public writeup से typical tooling:

- reused TCP connection के जरिए privileged auth receive करने के लिए custom port पर `smbserver.py`
- captured NTLM को local SMB पर relay करने के लिए `ntlmrelayx.py`
- privileged authentication को force करने के लिए `PetitPotam.exe` या कोई और coercion primitive

## Operator notes

- यह एक **local privilege escalation** technique है, कोई generic remote relay trick नहीं
- attacker-controlled SMB service को मूल रूप से share mount के लिए उपयोग किए गए **same TCP connection** पर privileged authentication handle करनी चाहिए
- अगर coerced access किसी **different share path** पर hit करता है, तो Windows एक अलग connection establish कर सकता है और chain टूट जाती है
- SMB signing requirements relay को तोड़ सकती हैं, भले ही arbitrary-port step काम कर जाए
- अगर आपके पास केवल Kerberos material है या आप local NTLM force नहीं कर सकते, तो यह exact variant पर्याप्त नहीं है

## Detection and hardening

- **March 2026 Patch Tuesday** से **CVE-2026-24294** patch करें
- `net use` या `New-SmbMapping` के **non-default SMB ports** इस्तेमाल पर नजर रखें
- workstations या servers से **high TCP ports** की ओर unusual outbound SMB पर alert करें
- **EFSRPC / PetitPotam-style** triggers जैसी coercion opportunities की समीक्षा करें
- जहां संभव हो SMB signing enforce करें; Synacktiv ने specifically बताया कि इससे Windows 11 24H2 पर उनका relay block हो गया

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
