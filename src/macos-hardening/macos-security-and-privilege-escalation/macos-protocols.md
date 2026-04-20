# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

ये सामान्य macOS services हैं जिन्हें remotely access किया जा सकता है।\
आप इन्हें `System Settings` --> `Sharing` में enable/disable कर सकते हैं

- **VNC**, जिसे “Screen Sharing” कहा जाता है (tcp:5900)
- **SSH**, जिसे “Remote Login” कहा जाता है (tcp:22)
- **Apple Remote Desktop** (ARD), या “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, जिसे “Remote Apple Event” कहा जाता है (tcp:3031)

देखें कि इनमें से कोई enabled है या नहीं, running:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### स्थानीय रूप से sharing configuration का enumerating

जब आपके पास Mac पर पहले से local code execution हो, तो **configured state** जांचें, सिर्फ listening sockets नहीं। `systemsetup` और `launchctl` आमतौर पर बताते हैं कि service administratively enabled है या नहीं, जबकि `kickstart` और `system_profiler` effective ARD/Sharing configuration की पुष्टि करने में मदद करते हैं:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### ARD का Pentesting

Apple Remote Desktop (ARD) [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) का macOS के लिए अनुकूलित एक उन्नत संस्करण है, जो अतिरिक्त features प्रदान करता है। ARD में एक उल्लेखनीय vulnerability control screen password के authentication method में है, जो password के केवल पहले 8 characters का उपयोग करता है, जिससे यह Hydra या [GoRedShell](https://github.com/ahhh/GoRedShell/) जैसे tools के साथ [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) के लिए prone हो जाता है, क्योंकि इसमें default rate limits नहीं होते।

Vulnerable instances की पहचान **nmap** के `vnc-info` script से की जा सकती है। `VNC Authentication (2)` support करने वाली services विशेष रूप से 8-character password truncation के कारण brute force attacks के लिए susceptible होती हैं।

Privilege escalation, GUI access, या user monitoring जैसे विभिन्न administrative tasks के लिए ARD enable करने हेतु, निम्न command का उपयोग करें:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD बहुमुखी control levels प्रदान करता है, जिसमें observation, shared control, और full control शामिल हैं, और sessions user password बदलने के बाद भी persist रहती हैं। यह Unix commands को सीधे भेजने की अनुमति देता है, और administrative users के लिए उन्हें root के रूप में execute करता है। Task scheduling और Remote Spotlight search उल्लेखनीय features हैं, जो multiple machines पर sensitive files के लिए remote, low-impact searches को आसान बनाते हैं।

Operator perspective से, **Monterey 12.1+ ने managed fleets में remote-enablement workflows बदल दिए**। अगर आप पहले से victim के MDM को control करते हैं, तो Apple का `EnableRemoteDesktop` command newer systems पर remote desktop functionality activate करने का अक्सर सबसे clean तरीका होता है। अगर आपके पास host पर पहले से foothold है, तो `kickstart` अभी भी command line से ARD privileges inspect या reconfigure करने के लिए useful है।

### Pentesting Remote Apple Events (RAE / EPPC)

Apple इस feature को modern System Settings में **Remote Application Scripting** कहता है। अंदर से यह **Apple Event Manager** को remotely **EPPC** के over **TCP/3031** पर `com.apple.AEServer` service के जरिए expose करता है। Palo Alto Unit 42 ने इसे फिर से एक practical **macOS lateral movement** primitive के रूप में highlight किया, क्योंकि valid credentials plus enabled RAE service operator को remote Mac पर scriptable applications control करने देते हैं।

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
अगर आपके पास पहले से target पर admin/root है और आप इसे enable करना चाहते हैं:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
दूसरे Mac से basic connectivity test:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
व्यवहार में, abuse case केवल Finder तक सीमित नहीं है। कोई भी **scriptable application** जो आवश्यक Apple events स्वीकार करता है, एक remote attack surface बन जाता है, जिससे internal macOS networks पर credential theft के बाद RAE विशेष रूप से interesting हो जाता है।

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|गलत session rendering के कारण *गलत* desktop या window transmit हो सकता था, जिससे sensitive information का leakage हो सकता था|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|screen sharing access वाला एक user **किसी दूसरे user की screen** देख सकता था क्योंकि state-management issue था|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* जब strictly required न हो, *Screen Sharing*/*Remote Management* disable करें।
* macOS को fully patched रखें (Apple आम तौर पर last three major releases के लिए security fixes ship करता है)।
* एक **Strong Password** का उपयोग करें *और* संभव हो तो *“VNC viewers may control screen with password”* option को **disabled** रखें।
* TCP 5900/3283 को Internet पर expose करने के बजाय service को VPN के पीछे रखें।
* `ARDAgent` को local subnet तक सीमित करने के लिए Application Firewall rule जोड़ें:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, Apple द्वारा डिज़ाइन की गई technology, **same network पर मौजूद devices को एक-दूसरे की offered services detect करने** देती है। इसे Rendezvous, **Zero Configuration**, या Zeroconf के रूप में भी जाना जाता है; यह किसी device को TCP/IP network में join करने, **automatically एक IP address चुनने**, और अपनी services को अन्य network devices तक broadcast करने में सक्षम बनाती है।

Zero Configuration Networking, जो Bonjour द्वारा प्रदान किया जाता है, यह सुनिश्चित करता है कि devices:

- DHCP server न होने पर भी **Automatically एक IP Address obtain** कर सकें।
- DNS server की आवश्यकता के बिना **name-to-address translation** कर सकें।
- नेटवर्क पर उपलब्ध **services discover** कर सकें।

Bonjour का उपयोग करने वाले devices खुद को **169.254/16 range से एक IP address** assign करेंगे और नेटवर्क पर उसकी uniqueness verify करेंगे। Macs इस subnet के लिए routing table entry बनाए रखते हैं, जिसे `netstat -rn | grep 169` से verify किया जा सकता है।

DNS के लिए, Bonjour **Multicast DNS (mDNS) protocol** का उपयोग करता है। mDNS **port 5353/UDP** पर काम करता है, **standard DNS queries** का उपयोग करते हुए लेकिन **multicast address 224.0.0.251** को target करता है। यह approach सुनिश्चित करती है कि नेटवर्क पर सभी listening devices queries receive और respond कर सकें, जिससे उनके records update करना संभव होता है।

नेटवर्क में join करने पर, प्रत्येक device अपना नाम self-select करती है, आमतौर पर जो **.local** पर समाप्त होता है, जिसे hostname से लिया जा सकता है या randomly generated हो सकता है।

नेटवर्क के भीतर service discovery **DNS Service Discovery (DNS-SD)** द्वारा facilitated होती है। DNS SRV records के format का लाभ उठाते हुए, DNS-SD कई services को list करने के लिए **DNS PTR records** का उपयोग करता है। कोई client जो किसी specific service की तलाश कर रहा है, वह `<Service>.<Domain>` के लिए PTR record request करेगा, और बदले में `<Instance>.<Service>.<Domain>` के रूप में formatted PTR records की list प्राप्त करेगा यदि service multiple hosts पर available हो।

`dns-sd` utility का उपयोग **network services discover और advertise** करने के लिए किया जा सकता है। इसके उपयोग के कुछ उदाहरण नीचे दिए गए हैं:

### SSH Services की खोज

नेटवर्क पर SSH services खोजने के लिए, निम्न command का उपयोग किया जाता है:
```bash
dns-sd -B _ssh._tcp
```
यह कमांड \_ssh.\_tcp सेवाओं के लिए browsing शुरू करता है और timestamp, flags, interface, domain, service type, और instance name जैसी details output करता है।

### Advertising an HTTP Service

HTTP service advertise करने के लिए, आप उपयोग कर सकते हैं:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
यह कमांड पोर्ट 80 पर `/index.html` path के साथ "Index" नामक एक HTTP service register करता है।

इसके बाद network पर HTTP services search करने के लिए:
```bash
dns-sd -B _http._tcp
```
जब एक service शुरू होती है, तो वह subnet पर सभी devices को multicast करके अपनी presence की घोषणा करती है। इन services में रुचि रखने वाले devices को requests भेजने की जरूरत नहीं होती, बल्कि वे बस इन announcements को सुनते हैं।

एक अधिक user-friendly interface के लिए, Apple App Store पर उपलब्ध **Discovery - DNS-SD Browser** app आपके local network पर offered services को visualize कर सकती है।

वैकल्पिक रूप से, custom scripts लिखकर `python-zeroconf` library का उपयोग करके services को browse और discover किया जा सकता है। [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script `_http._tcp.local.` services के लिए एक service browser बनाने का demonstration करती है, जो added या removed services को print करती है:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### macOS-specific Bonjour hunting

macOS नेटवर्क्स पर, Bonjour अक्सर **remote administration surfaces** को बिना target को सीधे touch किए ढूँढने का सबसे आसान तरीका होता है। Apple Remote Desktop खुद Bonjour के जरिए clients discover कर सकता है, इसलिए वही discovery data attacker के लिए भी useful होती है।
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
बड़े पैमाने पर **mDNS spoofing, impersonation, and cross-subnet discovery** techniques के लिए, समर्पित page देखें:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### नेटवर्क पर Bonjour को enumerate करना

* **Nmap NSE** – एक single host द्वारा advertised services को discover करें:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script `_services._dns-sd._udp.local` query भेजता है और फिर हर advertised service type को enumerate करता है।

* **mdns_recon** – Python tool जो पूरी ranges scan करता है और *misconfigured* mDNS responders को ढूँढता है जो unicast queries का answer देते हैं (subnets/WAN के across reachable devices खोजने के लिए उपयोगी):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

यह local link के बाहर Bonjour के जरिए SSH expose करने वाले hosts वापस करेगा।

### Security considerations & recent vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* में एक logic error ने crafted packet को **denial-of-service** trigger करने दिया|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder* में एक correctness issue का दुरुपयोग **local privilege escalation** के लिए किया जा सकता था|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. UDP 5353 को *link-local* scope तक सीमित करें – wireless controllers, routers, और host-based firewalls पर इसे block या rate-limit करें।
2. जिन systems को service discovery की आवश्यकता नहीं है, उन पर Bonjour पूरी तरह disable करें:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. ऐसे environments में जहाँ Bonjour internal रूप से required है लेकिन network boundaries को कभी cross नहीं करना चाहिए, *AirPlay Receiver* profile restrictions (MDM) या mDNS proxy का उपयोग करें।
4. **System Integrity Protection (SIP)** enable करें और macOS को up to date रखें – ऊपर की दोनों vulnerabilities जल्दी patch की गई थीं, लेकिन full protection के लिए SIP का enabled होना जरूरी था।

### Bonjour को disable करना

यदि security या अन्य कारणों से Bonjour को disable करने की चिंता है, तो इसे following command का उपयोग करके बंद किया जा सकता है:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
