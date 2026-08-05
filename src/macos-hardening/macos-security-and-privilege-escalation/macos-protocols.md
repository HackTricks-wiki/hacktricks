# macOS Network Services और Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

ये macOS services को remotely access करने के सामान्य तरीके हैं।\
आप इन services को `System Settings` --> `Sharing` में enable/disable कर सकते हैं।

- **VNC**, जिसे “Screen Sharing” कहा जाता है (tcp:5900)
- **SSH**, जिसे “Remote Login” कहा जाता है (tcp:22)
- **Apple Remote Desktop** (ARD), या “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, जिसे “Remote Apple Event” कहा जाता है (tcp:3031)

किसी के enabled होने की जाँच इस तरह करें:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### स्थानीय रूप से sharing configuration की enumeration

जब आपके पास पहले से Mac पर local code execution हो, तो केवल listening sockets ही नहीं, बल्कि **configured state** भी check करें। `systemsetup` और `launchctl` आमतौर पर बताते हैं कि service प्रशासनिक रूप से enabled है या नहीं, जबकि `kickstart` और `system_profiler` effective ARD/Sharing configuration की पुष्टि करने में सहायता करते हैं:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD), macOS के लिए तैयार किया गया [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) का enhanced version है, जो अतिरिक्त features प्रदान करता है। ARD में एक उल्लेखनीय vulnerability इसकी control screen password की authentication method है, जो password के केवल पहले 8 characters का उपयोग करती है। इससे यह [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) के प्रति susceptible हो जाती है, और Hydra या [GoRedShell](https://github.com/ahhh/GoRedShell/) जैसे tools से attack किया जा सकता है, क्योंकि कोई default rate limits नहीं हैं।<sup>[[3]](#references)</sup>

Vulnerable instances की पहचान **nmap** की `vnc-info` script का उपयोग करके की जा सकती है। `VNC Authentication (2)` को support करने वाली services 8-character password truncation के कारण विशेष रूप से brute force attacks के प्रति susceptible होती हैं।

Privilege escalation, GUI access या user monitoring जैसे विभिन्न administrative tasks के लिए ARD enable करने हेतु, निम्न command का उपयोग करें:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD versatile control levels प्रदान करता है, जिनमें observation, shared control और full control शामिल हैं, तथा user password बदलने के बाद भी sessions जारी रहते हैं। यह Unix commands सीधे भेजने की सुविधा देता है और administrative users के लिए उन्हें root के रूप में execute करता है। Task scheduling और Remote Spotlight search उल्लेखनीय features हैं, जो कई machines पर sensitive files के लिए remote, low-impact searches को सुविधाजनक बनाते हैं।

Operator के दृष्टिकोण से, **Monterey 12.1+ ने managed fleets में remote-enablement workflows बदल दिए**। यदि आपके पास पहले से victim के MDM का control है, तो नए systems पर remote desktop functionality activate करने के लिए Apple का `EnableRemoteDesktop` command अक्सर सबसे साफ तरीका है। यदि host पर पहले से foothold है, तो command line से ARD privileges को inspect या reconfigure करने के लिए `kickstart` अभी भी उपयोगी है।

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

हालिया `screensharingd` research से पता चला कि Apple Screen Sharing हमेशा classic VNC auth का उपयोग नहीं करता: नए builds **RFB `003.889`** बोलते हैं और **security type `36`** advertise करते हैं, जिसमें पहले **SRP** authentication होता है और `ccsrp_server_verify_session` के सफल होने के बाद ही **ChaCha20-Poly1305** install किया जाता है। Public write-up के अनुसार यह bug **macOS Tahoe 26.6** (**July 27, 2026**) में fixed है।<sup>[[8]](#references)[[9]](#references)</sup>

याद रखने योग्य एक उपयोगी pattern **stale-status parser bypass** है: 4-byte length read सफल होने के बाद, हर oversized/error branch को नया error return करना चाहिए। प्रभावित builds में, big-endian SRP frame length **`>= 32768`** rejection path को पिछले `NetBufferRead` success (`0`) का पुनः उपयोग करने देता है, इसलिए caller session को authenticated set कर देता है, जबकि password proof run नहीं हुआ और transport crypto install नहीं हुआ। चूंकि unread bytes shared socket buffer में बने रहते हैं, attacker **malformed SRP data और post-auth RFB messages को उसी TCP burst में pipeline** कर सकता है और उन्हें **cleartext authenticated traffic** के रूप में parse करवा सकता है।<sup>[[8]](#references)</sup>

Bypass के बाद, Apple का proprietary **file-copy** message **`0x22`**, **root file read/write primitive** बन जाता है, क्योंकि `screensharingd` root के रूप में चलता है:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: arbitrary file read
- `kind=2` / `StartFileReceive`: arbitrary file write
- अलग-अलग `sid` values एक ही connection में कई transactions को pipeline करने देते हैं
- `kind=101` (`NewItem`) में, regular file के लिए byte `14` / `arg[0]` को `0x01` पर सेट करें, payload offset `+42` पर **non-zero** big-endian file size सेट करें, और payload offset `+0x5a` पर इच्छित Unix mode सेट करें (`0600`, यदि crontab को target कर रहे हों)

writable paths पर दिलचस्प post-write pivots में **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`**, और **`/var/root/.ssh/authorized_keys`** शामिल हैं। **SIP auth bypass या root file read को नहीं रोकता**, लेकिन यह कुछ write targets, जैसे **`/var/at`**, को block करता है; इसलिए cron-based execution केवल SIP disabled होने पर काम करता है। Default SIP-enabled hosts पर, तुरंत code execution के बजाय **"privileged auto-consumed files में root file write"** के रूप में सोचें।<sup>[[8]](#references)</sup>

उसी research से जुड़ा एक और SRP pitfall: servers को (RFC 5054 के अनुसार) केवल `A > 0` नहीं, बल्कि **`A mod N != 0`** validate करना चाहिए। **`A = N`** स्वीकार करने से shared secret को zero पर force किया जा सकता है और password verification कमजोर हो सकता है।<sup>[[8]](#references)[[10]](#references)</sup>

**Detection ideas**

- Security type `36` sessions, जिनमें पहला SRP frame length **`>= 32768`** हो
- ऐसे sessions जो किसी सफल SRP proof / cipher install से पहले cleartext **`0x22`** file-copy traffic process करना शुरू कर दें
- **TCP/5900** के विरुद्ध बार-बार होने वाले short-lived retries और एक ही burst में कई file-copy `sid` values
- Screen Sharing exposure के बाद **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`**, या **`/var/root/.ssh/authorized_keys`** का unexpected creation

### Pentesting Remote Apple Events (RAE / EPPC)

Apple modern System Settings में इस feature को **Remote Application Scripting** कहता है। Under the hood, यह **TCP/3031** पर `com.apple.AEServer` service के माध्यम से **EPPC** पर **Apple Event Manager** को remotely expose करता है। Palo Alto Unit 42 ने इसे फिर से एक practical **macOS lateral movement** primitive के रूप में highlight किया, क्योंकि valid credentials और enabled RAE service किसी operator को remote Mac पर scriptable applications चलाने की अनुमति देते हैं।<sup>[[6]](#references)</sup>

उपयोगी जाँचें:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
यदि आपके पास target पर पहले से admin/root है और आप इसे enable करना चाहते हैं:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
दूसरे Mac से बुनियादी connectivity test:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
व्यवहार में, abuse case केवल Finder तक सीमित नहीं है। कोई भी **scriptable application** जो आवश्यक Apple events स्वीकार करती है, एक remote attack surface बन जाती है। इससे internal macOS networks पर credential theft के बाद RAE विशेष रूप से महत्वपूर्ण हो जाता है।

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|गलत session rendering के कारण *गलत* desktop या window transmit हो सकता था, जिससे sensitive information का leak हो सकता था|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|state-management issue के कारण screen sharing access वाला user **किसी अन्य user की screen** देख सकता था|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* जब तक सख्त आवश्यकता न हो, *Screen Sharing*/*Remote Management* को disable रखें।
* macOS को पूरी तरह patched रखें (Apple आमतौर पर पिछले तीन major releases के लिए security fixes जारी करता है)।
* एक **Strong Password** का उपयोग करें और संभव होने पर *“VNC viewers may control screen with password”* option को **disabled** रखें।
* TCP 5900/3283 को Internet पर expose करने के बजाय service को VPN के पीछे रखें।
* `ARDAgent` को local subnet तक सीमित करने के लिए Application Firewall rule जोड़ें:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, Apple द्वारा design की गई technology, **एक ही network पर मौजूद devices को एक-दूसरे की offered services detect करने** की अनुमति देती है। इसे Rendezvous, **Zero Configuration**, या Zeroconf के नाम से भी जाना जाता है। यह किसी device को TCP/IP network से जुड़ने, **automatically एक IP address चुनने**, और अपनी services को अन्य network devices पर broadcast करने में सक्षम बनाता है।

Bonjour द्वारा प्रदान किया गया Zero Configuration Networking यह सुनिश्चित करता है कि devices:

- **DHCP server न होने पर भी automatically एक IP Address प्राप्त कर सकें।**
- DNS server की आवश्यकता के बिना **name-to-address translation** कर सकें।
- Network पर उपलब्ध **services discover** कर सकें।

Bonjour का उपयोग करने वाले devices स्वयं को **169.254/16 range से एक IP address assign** करेंगे और network पर उसकी uniqueness verify करेंगे। Macs इस subnet के लिए routing table entry बनाए रखते हैं, जिसे `netstat -rn | grep 169` के माध्यम से verify किया जा सकता है।

DNS के लिए Bonjour **Multicast DNS (mDNS) protocol** का उपयोग करता है। mDNS **port 5353/UDP** पर operate करता है और **standard DNS queries** का उपयोग करता है, लेकिन इन्हें **multicast address 224.0.0.251** पर target करता है। यह तरीका सुनिश्चित करता है कि network पर मौजूद सभी listening devices queries प्राप्त कर सकें और उनका response दे सकें, जिससे उनके records update हो सकें।

Network से जुड़ने पर प्रत्येक device स्वयं एक name चुनता है, जो आमतौर पर **.local** पर समाप्त होता है। यह name hostname से derived हो सकता है या randomly generated हो सकता है।

Network के भीतर service discovery **DNS Service Discovery (DNS-SD)** द्वारा facilitated होती है। DNS SRV records के format का उपयोग करते हुए, DNS-SD multiple services की listing सक्षम करने के लिए **DNS PTR records** का उपयोग करता है। किसी specific service की तलाश करने वाला client `<Service>.<Domain>` के लिए PTR record request करेगा। यदि service multiple hosts से available है, तो response में `<Instance>.<Service>.<Domain>` format में PTR records की list प्राप्त होगी।

`dns-sd` utility का उपयोग **network services discover और advertise करने** के लिए किया जा सकता है। इसके उपयोग के कुछ examples नीचे दिए गए हैं:

### Searching for SSH Services

Network पर SSH services search करने के लिए निम्नलिखित command का उपयोग किया जाता है:
```bash
dns-sd -B _ssh._tcp
```
यह command \_ssh.\_tcp services के लिए browsing शुरू करता है और timestamp, flags, interface, domain, service type और instance name जैसी details output करता है।

### HTTP Service का Advertising

HTTP service का advertising करने के लिए, आप इसका उपयोग कर सकते हैं:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
यह command `/index.html` path के साथ port 80 पर "Index" नाम की HTTP service register करता है।

इसके बाद network पर HTTP services खोजने के लिए:
```bash
dns-sd -B _http._tcp
```
जब कोई service शुरू होती है, तो वह अपनी उपस्थिति को multicast करके subnet के सभी devices के लिए अपनी availability की घोषणा करती है। इन services में रुचि रखने वाले devices को requests भेजने की आवश्यकता नहीं होती, बल्कि वे केवल इन announcements को सुनते हैं।

अधिक user-friendly interface के लिए, Apple App Store पर उपलब्ध **Discovery - DNS-SD Browser** app आपके local network पर offered services को visualize कर सकती है।

वैकल्पिक रूप से, `python-zeroconf` library का उपयोग करके services को browse और discover करने के लिए custom scripts लिखी जा सकती हैं। [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script `_http._tcp.local.` services के लिए service browser बनाने और added या removed services को print करने का प्रदर्शन करती है:
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

macOS networks में, target के साथ सीधे interact किए बिना **remote administration surfaces** खोजने के लिए Bonjour अक्सर सबसे आसान तरीका होता है। Apple Remote Desktop स्वयं Bonjour के माध्यम से clients को discover कर सकता है, इसलिए यही discovery data attacker के लिए भी उपयोगी होता है।
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
व्यापक **mDNS spoofing, impersonation, और cross-subnet discovery** तकनीकों के लिए dedicated page देखें:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### नेटवर्क पर Bonjour की Enumeration

* **Nmap NSE** – single host द्वारा advertised services discover करें:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script एक `_services._dns-sd._udp.local` query भेजती है और फिर प्रत्येक advertised service type की enumeration करती है।

* **mdns_recon** – Python tool जो पूरे ranges को scan करके *misconfigured* mDNS responders खोजता है, जो unicast queries का उत्तर देते हैं (यह subnets/WAN के पार reachable devices खोजने के लिए उपयोगी है):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

यह local link के बाहर Bonjour के माध्यम से SSH expose करने वाले hosts लौटाएगा।

### Security considerations और हाल की vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* में एक logic error के कारण crafted packet से **denial-of-service** trigger किया जा सकता था|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder* में correctness issue का उपयोग **local privilege escalation** के लिए किया जा सकता था|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. UDP 5353 को *link-local* scope तक सीमित करें – wireless controllers, routers और host-based firewalls पर इसे block या rate-limit करें।
2. जिन systems में service discovery की आवश्यकता नहीं है, उन पर Bonjour को पूरी तरह disable करें:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. ऐसे environments में जहां Bonjour internally आवश्यक है, लेकिन इसे network boundaries के पार कभी नहीं जाना चाहिए, *AirPlay Receiver* profile restrictions (MDM) या mDNS proxy का उपयोग करें।
4. **System Integrity Protection (SIP)** enable करें और macOS को up to date रखें – ऊपर दी गई दोनों vulnerabilities को जल्दी patch किया गया था, लेकिन full protection के लिए SIP के enabled होने पर निर्भर थीं।

### Bonjour को Disable करना

यदि security या अन्य कारणों से Bonjour को disable करने की चिंता हो, तो इसे निम्न command का उपयोग करके बंद किया जा सकता है:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## संदर्भ

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - macOS पर Lateral Movement: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - macOS Sonoma 14.7.2 की security content के बारे में](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - macOS Tahoe 26.6 की security content के बारे में](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - TLS Authentication के लिए Secure Remote Password (SRP) Protocol का उपयोग](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
