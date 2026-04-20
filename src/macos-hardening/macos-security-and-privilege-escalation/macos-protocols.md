# Huduma za Mtandao na Itifaki za macOS

{{#include ../../banners/hacktricks-training.md}}

## Huduma za Ufikiaji wa Mbali

Hizi ni huduma za kawaida za macOS za kuzifikia kwa mbali.\
Unaweza kuwezesha/kuzima huduma hizi katika `System Settings` --> `Sharing`

- **VNC**, inayojulikana kama “Screen Sharing” (tcp:5900)
- **SSH**, inayoitwa “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), au “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, inayojulikana kama “Remote Apple Event” (tcp:3031)

Angalia kama yoyote imewezeshwa kwa kuendesha:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Kuorodhesha usanidi wa kushiriki locally

Unapokuwa tayari una local code execution kwenye Mac, **kagua hali iliyosanidiwa**, si tu listening sockets. `systemsetup` na `launchctl` kwa kawaida huonyesha kama service imewezeshwa kiutawala, huku `kickstart` na `system_profiler` zikisaidia kuthibitisha effective ARD/Sharing configuration:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) ni toleo lililoimarishwa la [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) lililoundwa kwa ajili ya macOS, likitoa vipengele vya ziada. Udhaifu unaojulikana katika ARD ni njia yake ya uthibitishaji kwa control screen password, ambayo hutumia tu herufi 8 za kwanza za password, hivyo huifanya iwe rahisi kwa [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) kwa zana kama Hydra au [GoRedShell](https://github.com/ahhh/GoRedShell/), kwa kuwa hakuna default rate limits.

Instances zilizoathirika zinaweza kutambuliwa kwa kutumia script ya **nmap** `vnc-info`. Services zinazosaidia `VNC Authentication (2)` huwa hasa rahisi kushambuliwa kwa brute force kutokana na truncation ya password ya herufi 8.

Ili kuwezesha ARD kwa kazi mbalimbali za kiutawala kama privilege escalation, GUI access, au user monitoring, tumia amri ifuatayo:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD hutoa viwango vya udhibiti vinavyobadilika, ikijumuisha observation, shared control, na full control, huku sessions zikiendelea hata baada ya user password kubadilika. Inaruhusu kutuma Unix commands moja kwa moja, kuzitekeleza kama root kwa users wa administrative. Task scheduling na Remote Spotlight search ni features muhimu, zikifanya remote, low-impact searches kwa ajili ya sensitive files kwenye machines nyingi.

Kutoka kwa mtazamo wa operator, **Monterey 12.1+ ilibadilisha remote-enablement workflows** katika managed fleets. Ikiwa tayari unadhibiti MDM ya victim, command ya Apple `EnableRemoteDesktop` mara nyingi ndiyo njia safi zaidi ya kuwasha remote desktop functionality kwenye systems mpya. Ikiwa tayari una foothold kwenye host, `kickstart` bado ni useful kwa ku-inspect au ku-reconfigure ARD privileges kutoka command line.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple huita feature hii **Remote Application Scripting** katika System Settings za kisasa. Ndani, inafichua **Apple Event Manager** remotely kupitia **EPPC** kwenye **TCP/3031** kupitia service ya `com.apple.AEServer`. Palo Alto Unit 42 iliangazia tena hii kama **macOS lateral movement** practical primitive kwa sababu valid credentials pamoja na enabled RAE service huruhusu operator kuendesha scriptable applications kwenye remote Mac.

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Ikiwa tayari una admin/root kwenye target na unataka kuiwezesha:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Jaribio la muunganisho wa msingi kutoka Mac nyingine:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Kwa vitendo, kesi ya matumizi mabaya haijakomea Finder pekee. **scriptable application** yoyote inayokubali Apple events zinazohitajika inakuwa remote attack surface, jambo ambalo linafanya RAE kuvutia sana baada ya credential theft kwenye internal macOS networks.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|A user with screen sharing access may be able to view **another user's screen** because of a state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Disable *Screen Sharing*/*Remote Management* when not strictly required.
* Keep macOS fully patched (Apple generally ships security fixes for the last three major releases).
* Use a **Strong Password** *and* enforce the *“VNC viewers may control screen with password”* option **disabled** when possible.
* Put the service behind a VPN instead of exposing TCP 5900/3283 to the Internet.
* Add an Application Firewall rule to limit `ARDAgent` to the local subnet:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, teknolojia iliyoundwa na Apple, huruhusu **devices kwenye network moja kugundua services ambazo kila moja inatoa**. Pia inajulikana kama Rendezvous, **Zero Configuration**, au Zeroconf, na inawezesha device kujiunga na TCP/IP network, **kuchagua IP address kiotomatiki**, na kutangaza services zake kwa devices nyingine za network.

Zero Configuration Networking, inayotolewa na Bonjour, huhakikisha kuwa devices zinaweza:

- **Kupata IP Address kiotomatiki** hata bila DHCP server.
- Kufanya **name-to-address translation** bila kuhitaji DNS server.
- **Kugundua services** zinazopatikana kwenye network.

Devices zinazotumia Bonjour zitajipa **IP address kutoka range ya 169.254/16** na kuthibitisha upekee wake kwenye network. Macs hudumisha routing table entry kwa subnet hii, inayoweza kuthibitishwa kupitia `netstat -rn | grep 169`.

Kwa DNS, Bonjour hutumia **Multicast DNS (mDNS) protocol**. mDNS hufanya kazi juu ya **port 5353/UDP**, ikitumia **standard DNS queries** lakini ikilenga **multicast address 224.0.0.251**. Mbinu hii huhakikisha kuwa vifaa vyote vinavyosikiliza kwenye network vinaweza kupokea na kujibu queries, hivyo kurahisisha kusasisha records zao.

Baada ya kujiunga na network, kila device huchagua jina lenyewe, kwa kawaida likiishia na **.local**, ambalo linaweza kutokana na hostname au kuzalishwa kwa random.

Service discovery ndani ya network hurahisishwa na **DNS Service Discovery (DNS-SD)**. Kwa kutumia format ya DNS SRV records, DNS-SD hutumia **DNS PTR records** kuwezesha uorodheshaji wa services nyingi. Client inayotafuta service fulani itaomba PTR record kwa `<Service>.<Domain>`, na kurudishiwa orodha ya PTR records zilizo katika format `<Instance>.<Service>.<Domain>` ikiwa service inapatikana kutoka hosts nyingi.

Utility ya `dns-sd` inaweza kutumiwa kwa **kugundua na kutangaza network services**. Hapa kuna mifano ya matumizi yake:

### Searching for SSH Services

Ili kutafuta SSH services kwenye network, amri ifuatayo inatumika:
```bash
dns-sd -B _ssh._tcp
```
Hii amri huanzisha kuvinjari kwa huduma za \_ssh.\_tcp na hutoa maelezo kama vile timestamp, flags, interface, domain, aina ya huduma, na jina la instance.

### Kutoa Tangazo la Huduma ya HTTP

Ili kutoa tangazo la huduma ya HTTP, unaweza kutumia:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Amri hii husajili huduma ya HTTP yenye jina "Index" kwenye bandari 80 na njia ya `/index.html`.

Kisha ili kutafuta huduma za HTTP kwenye mtandao:
```bash
dns-sd -B _http._tcp
```
Wakati huduma inapoanza, hutangaza upatikanaji wake kwa vifaa vyote kwenye subnet kwa kutangaza uwepo wake kwa multicast. Vifaa vinavyopenda huduma hizi havihitaji kutuma maombi bali vinahitaji tu kusikiliza matangazo haya.

Kwa kiolesura kilicho rahisi zaidi kwa mtumiaji, app ya **Discovery - DNS-SD Browser** inayopatikana kwenye Apple App Store inaweza kuonyesha huduma zinazotolewa kwenye mtandao wako wa ndani.

Vinginevyo, scripts maalum zinaweza kuandikwa ili kuchunguza na kugundua huduma kwa kutumia library ya `python-zeroconf`. Script ya [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) inaonyesha kuunda service browser kwa huduma za `_http._tcp.local.`, ikichapisha huduma zilizoongezwa au kuondolewa:
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
### Uwindaji wa Bonjour mahususi kwa macOS

Katika mitandao ya macOS, Bonjour mara nyingi ndiyo njia rahisi zaidi ya kupata **remote administration surfaces** bila kugusa moja kwa moja lengo. Apple Remote Desktop yenyewe inaweza kugundua clients kupitia Bonjour, hivyo data hiyo hiyo ya ugunduzi ni muhimu kwa mshambulizi.
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
Kwa **mDNS spoofing, impersonation, na cross-subnet discovery** pana, angalia ukurasa maalum:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Kuchanganua Bonjour kwenye mtandao

* **Nmap NSE** – gundua huduma zinazotangazwa na host moja:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Script `dns-service-discovery` hutuma swali la `_services._dns-sd._udp.local` kisha huorodhesha kila aina ya huduma iliyotangazwa.

* **mdns_recon** – chombo cha Python kinachochanganua masafa yote kutafuta *misconfigured* mDNS responders wanaojibu unicast queries (faa kwa kupata vifaa vinavyofikiwa kupitia subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Hii itarudisha hosts zinazoonyesha SSH kupitia Bonjour nje ya link ya ndani.

### Mambo ya usalama na udhaifu wa hivi karibuni (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mwongozo wa kupunguza hatari**

1. Zuía UDP 5353 kwa scope ya *link-local* – izuie au punguza rate kwenye wireless controllers, routers, na host-based firewalls.
2. Lemaza Bonjour kabisa kwenye systems ambazo hazihitaji service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Kwa mazingira ambapo Bonjour inahitajika ndani lakini lazima isivuke network boundaries, tumia vizuizi vya *AirPlay Receiver* profile (MDM) au mDNS proxy.
4. Wezesha **System Integrity Protection (SIP)** na sasisha macOS kila wakati – udhaifu wote wawili hapo juu ulipatchiwa haraka lakini ulitegemea SIP iwe imewezeshwa kwa ulinzi kamili.

### Kuzima Bonjour

Kama kuna wasiwasi kuhusu usalama au sababu nyingine za kuzima Bonjour, inaweza kuzimwa kwa kutumia amri ifuatayo:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Marejeo

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
