# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Hizi ni services za kawaida za macOS za kuzifikia remotely.\
Unaweza kuwezesha/kuzima services hizi katika `System Settings` --> `Sharing`<sup>[[1]](#references)</sup>

- **VNC**, inayojulikana kama “Screen Sharing” (tcp:5900)
- **SSH**, inayoitwa “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), au “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, inayojulikana kama “Remote Apple Event” (tcp:3031)

Angalia ikiwa yoyote imewezeshwa kwa kuendesha:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Kuhesabu configuration ya sharing locally

Unapokuwa tayari una local code execution kwenye Mac, **kagua hali iliyosanidiwa**, si listening sockets pekee. `systemsetup` na `launchctl` kwa kawaida hukuonyesha kama service imewezeshwa kiutawala, huku `kickstart` na `system_profiler` zikisaidia kuthibitisha ARD/Sharing configuration inayotumika:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) ni toleo lililoboreshwa la [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) lililoundwa kwa ajili ya macOS, likitoa vipengele vya ziada. Udhaifu unaojulikana katika ARD ni mbinu yake ya authentication ya control screen password, ambayo hutumia only characters 8 za kwanza za password, hivyo kuifanya iwe katika hatari ya [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) kwa kutumia tools kama Hydra au [GoRedShell](https://github.com/ahhh/GoRedShell/), kwa kuwa hakuna default rate limits.<sup>[[2]](#references)</sup>

Instances zilizo katika hatari zinaweza kutambuliwa kwa kutumia script ya `vnc-info` ya **nmap**. Services zinazotumia `VNC Authentication (2)` huathirika zaidi na brute force attacks kutokana na password truncation ya characters 8.

Ili kuwezesha ARD kwa administrative tasks mbalimbali kama privilege escalation, GUI access, au user monitoring, tumia command ifuatayo:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD hutoa viwango mbalimbali vya udhibiti, ikiwemo observation, shared control, na full control, huku sessions zikiendelea hata baada ya mabadiliko ya user password. Huruhusu kutuma Unix commands moja kwa moja, na kuzitekeleza kama root kwa administrative users. Task scheduling na Remote Spotlight search ni features muhimu, zinazowezesha searches za mbali zenye athari ndogo kwa sensitive files kwenye machines nyingi.

Kwa mtazamo wa operator, **Monterey 12.1+ changed remote-enablement workflows** katika managed fleets. Ikiwa tayari unadhibiti victim's MDM, Apple's `EnableRemoteDesktop` command mara nyingi ndiyo njia safi zaidi ya ku-activate remote desktop functionality kwenye systems mpya zaidi. Ikiwa tayari una foothold kwenye host, `kickstart` bado ni muhimu kwa kukagua au kureconfigure ARD privileges kutoka command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Utafiti wa hivi karibuni wa `screensharingd` ulionyesha kuwa Apple Screen Sharing si mara zote hutumia classic VNC auth pekee: builds mpya zaidi hutumia **RFB `003.889`** na kutangaza **security type `36`**, ambapo **SRP** hufanya authentication kwanza, na **ChaCha20-Poly1305** huwekwa tu baada ya `ccsrp_server_verify_session` kufanikiwa. Public write-up inaripoti kuwa bug hiyo ilirekebishwa katika **macOS Tahoe 26.6** (**July 27, 2026**).<sup>[[8]](#references)[[9]](#references)</sup>

Pattern muhimu ya kukumbuka ni **stale-status parser bypass**: baada ya successful 4-byte length read, kila oversized/error branch lazima irudishe error mpya. Kwenye affected builds, big-endian SRP frame length **`>= 32768`** hufanya rejection path itumie tena previous `NetBufferRead` success (`0`), hivyo caller huweka session kuwa authenticated ingawa hakuna password proof iliyotekelezwa na hakuna transport crypto iliyowekwa. Kwa sababu unread bytes hubaki kwenye shared socket buffer, attacker anaweza **kupipeline malformed SRP data na post-auth RFB messages katika TCP burst moja** na kuzifanya ziparswe kama **cleartext authenticated traffic**.<sup>[[8]](#references)</sup>

Baada ya bypass, Apple's proprietary **file-copy** message **`0x22`** huwa **root file read/write primitive** kwa sababu `screensharingd` huendeshwa kama root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: usomaji wa faili kiholela
- `kind=2` / `StartFileReceive`: uandishi wa faili kiholela
- Thamani tofauti za `sid` hukuruhusu kuweka transactions kadhaa kwenye connection moja
- Katika `kind=101` (`NewItem`), weka byte `14` / `arg[0]` kuwa `0x01` kwa regular file, payload offset `+42` iwe saizi ya faili ya big-endian isiyo **sifuri**, na payload offset `+0x5a` iwe Unix mode inayohitajika (`0600` ikiwa inalengwa crontab)

Pivots za kuvutia baada ya write kwenye paths zinazoweza kuandikwa zinajumuisha **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`**, na **`/var/root/.ssh/authorized_keys`**. **SIP haizuii auth bypass au root file read**, lakini huzuia baadhi ya write targets kama **`/var/at`**, hivyo utekelezaji unaotegemea cron hufanya kazi tu SIP ikiwa imezimwa. Kwenye hosts za kawaida zenye SIP iliyowashwa, fikiria kwa mtazamo wa **"root file write ndani ya privileged auto-consumed files"** badala ya code execution ya papo hapo.<sup>[[8]](#references)</sup>

Tatizo jingine la SRP kutoka utafiti huo huo: servers lazima zithibitishe **`A mod N != 0`** (kulingana na RFC 5054), si **`A > 0`** pekee. Kukubali **`A = N`** kunaweza kulazimisha shared secret kuwa sifuri na kudhoofisha uthibitishaji wa password.<sup>[[8]](#references)[[10]](#references)</sup>

**Mawazo ya utambuzi**

- Sessions za Security type `36` ambapo urefu wa SRP frame ya kwanza ni **`>= 32768`**
- Sessions zinazoanza kuchakata traffic ya cleartext **`0x22`** ya file-copy kabla ya SRP proof kufanikiwa / cipher kusakinishwa
- Retries zinazorudiwa na zenye muda mfupi dhidi ya **TCP/5900**, pamoja na file-copy `sid` values nyingi katika burst moja
- Uundaji usiotarajiwa wa **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`**, au **`/var/root/.ssh/authorized_keys`** baada ya Screen Sharing exposure

### Pentesting Remote Apple Events (RAE / EPPC)

Apple huiita feature hii **Remote Application Scripting** katika System Settings za kisasa. Chini ya hood, hufichua **Apple Event Manager** kwa remote kupitia **EPPC** kwenye **TCP/3031** kwa kutumia service ya `com.apple.AEServer`. Palo Alto Unit 42 waliisisitiza tena kama primitive ya vitendo ya **macOS lateral movement**, kwa sababu credentials halali pamoja na RAE service iliyowashwa humruhusu operator kuendesha scriptable applications kwenye Mac ya remote.<sup>[[6]](#references)</sup>

Ukaguzi muhimu:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Ikiwa tayari una admin/root kwenye target na unataka kuiwezesha:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Jaribio la msingi la muunganisho kutoka Mac nyingine:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Kwa vitendo, abuse case haiishii kwenye Finder. **scriptable application** yoyote inayokubali Apple events zinazohitajika huwa remote attack surface, jambo linalofanya RAE iwe ya kuvutia hasa baada ya credential theft kwenye internal macOS networks.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Uwasilishaji usio sahihi wa session ungeweza kusababisha *desktop* au window **isiyo sahihi** kutumwa, na kusababisha kuvuja kwa taarifa nyeti|macOS Sonoma 14.2.1 (Dec 2023) <sup>[[3]](#references)</sup>|
|2024|CVE-2024-44248|Screen Sharing Server|Mtumiaji mwenye screen sharing access angeweza kuona **screen ya mtumiaji mwingine** kutokana na tatizo la state-management|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) <sup>[[7]](#references)</sup>|

**Hardening tips**

* Zima *Screen Sharing*/*Remote Management* wakati hazihitajiki kabisa.
* Weka macOS ikiwa na patches zote (kwa kawaida Apple hutoa security fixes kwa major releases tatu za mwisho).
* Tumia **Strong Password** *na ulazimishe option ya *“VNC viewers may control screen with password”* iwe **imezimwa** inapowezekana.
* Weka service nyuma ya VPN badala ya ku-expose TCP 5900/3283 kwenye Internet.
* Ongeza Application Firewall rule ili kuzuia `ARDAgent` kwenye local subnet pekee:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, teknolojia iliyoundwa na Apple, huruhusu **devices zilizo kwenye network moja kugundua services zinazotolewa na kila moja**. Pia inajulikana kama Rendezvous, **Zero Configuration**, au Zeroconf; huwezesha device kujiunga na TCP/IP network, **kuchagua IP address kiotomatiki**, na kutangaza services zake kwa devices nyingine za network.

Zero Configuration Networking, inayotolewa na Bonjour, huhakikisha kwamba devices zinaweza:

- **Kupata IP Address kiotomatiki** hata bila kuwepo kwa DHCP server.
- Kufanya **name-to-address translation** bila kuhitaji DNS server.
- **Kugundua services** zinazopatikana kwenye network.

Devices zinazotumia Bonjour zitajipangia **IP address kutoka kwenye range ya 169.254/16** na kuthibitisha upekee wake kwenye network. Macs hudumisha routing table entry ya subnet hii, ambayo inaweza kuthibitishwa kupitia `netstat -rn | grep 169`.

Kwa DNS, Bonjour hutumia **Multicast DNS (mDNS protocol)**. mDNS hufanya kazi kupitia **port 5353/UDP**, ikitumia **standard DNS queries** lakini ikilenga **multicast address 224.0.0.251**. Njia hii huhakikisha kwamba devices zote zinazosikiliza kwenye network zinaweza kupokea na kujibu queries, hivyo kuwezesha kusasisha records zao.

Baada ya kujiunga na network, kila device hujichagulia jina, kwa kawaida likiishia na **.local**, ambalo linaweza kutokana na hostname au kuzalishwa kwa nasibu.

Service discovery ndani ya network huwezeshwa na **DNS Service Discovery (DNS-SD)**. Kwa kutumia muundo wa DNS SRV records, DNS-SD hutumia **DNS PTR records** kuwezesha kuorodheshwa kwa services nyingi. Client anayetafuta service maalum ataomba PTR record ya `<Service>.<Domain>`, na kupokea orodha ya PTR records zilizoundwa kama `<Instance>.<Service>.<Domain>` ikiwa service hiyo inapatikana kutoka kwa hosts nyingi.

Utility ya `dns-sd` inaweza kutumika kwa **kugundua na kutangaza network services**. Hapa kuna mifano ya matumizi yake:

### Searching for SSH Services

Ili kutafuta SSH services kwenye network, command ifuatayo hutumika:
```bash
dns-sd -B _ssh._tcp
```
Amri hii huanzisha utafutaji wa huduma za \_ssh.\_tcp na kutoa maelezo kama vile timestamp, flags, interface, domain, aina ya huduma, na jina la instance.

### Kutangaza Huduma ya HTTP

Ili kutangaza huduma ya HTTP, unaweza kutumia:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Amri hii husajili huduma ya HTTP inayoitwa "Index" kwenye port 80 yenye path ya `/index.html`.

Kisha, kutafuta huduma za HTTP kwenye mtandao:
```bash
dns-sd -B _http._tcp
```
Huduma inapoanza, hutangaza upatikanaji wake kwa vifaa vyote vilivyo kwenye subnet kwa kutuma ujumbe wa multicast wa uwepo wake. Vifaa vinavyovutiwa na huduma hizi havihitaji kutuma maombi, bali husikiliza tu matangazo haya.

Kwa interface inayofaa zaidi kwa mtumiaji, app ya **Discovery - DNS-SD Browser** inayopatikana kwenye Apple App Store inaweza kuonyesha huduma zinazotolewa kwenye mtandao wako wa ndani.

Vinginevyo, scripts maalum zinaweza kuandikwa ili kuvinjari na kugundua huduma kwa kutumia library ya `python-zeroconf`. Script ya [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) inaonyesha jinsi ya kuunda service browser ya huduma za `_http._tcp.local.`, na kuchapisha huduma zilizoongezwa au kuondolewa:
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
### Utafutaji wa Bonjour maalum kwa macOS

Kwenye mitandao ya macOS, Bonjour mara nyingi ndiyo njia rahisi zaidi ya kupata **maeneo ya usimamizi wa mbali** bila kuwasiliana moja kwa moja na target. Apple Remote Desktop yenyewe inaweza kugundua clients kupitia Bonjour, kwa hivyo data hiyo hiyo ya ugunduzi ni muhimu kwa mshambuliaji.
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
Kwa mbinu pana zaidi za **mDNS spoofing, impersonation, na cross-subnet discovery**, angalia ukurasa maalum:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Kuhesabu Bonjour kwenye mtandao

* **Nmap NSE** – gundua services zinazotangazwa na host moja:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Script ya `dns-service-discovery` hutuma query ya `_services._dns-sd._udp.local` na kisha kuhesabu kila aina ya service inayotangazwa.

* **mdns_recon** – tool ya Python inayochanganua ranges nzima ikitafuta mDNS responders *misconfigured* wanaojibu unicast queries (ni muhimu kwa kupata devices zinazoweza kufikiwa kupitia subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Hii itarudisha hosts zinazoweka SSH wazi kupitia Bonjour nje ya local link.

### Mazingatio ya usalama na vulnerabilities za hivi karibuni (2024-2025)

| Mwaka | CVE | Severity | Tatizo | Imepatched katika |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Hitilafu ya logic katika *mDNSResponder* iliruhusu packet iliyoundwa mahsusi kusababisha **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) <sup>[[4]](#references)</sup>|
|2025|CVE-2025-31222|High|Tatizo la correctness katika *mDNSResponder* lingeweza kutumiwa kwa **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) <sup>[[5]](#references)</sup>|

**Mwongozo wa mitigation**

1. Zuia UDP 5353 kwenye scope ya *link-local* – izuie au punguza rate yake kwenye wireless controllers, routers, na host-based firewalls.
2. Zima Bonjour kabisa kwenye systems zisizohitaji service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Kwa environments ambako Bonjour inahitajika internally lakini haipaswi kamwe kuvuka network boundaries, tumia restrictions za *AirPlay Receiver* profile (MDM) au mDNS proxy.
4. Washa **System Integrity Protection (SIP)** na usasishe macOS mara kwa mara – vulnerabilities zote mbili hapo juu zilipatched haraka, lakini zilitegemea SIP kuwa enabled kwa protection kamili.

### Kuzima Bonjour

Ikiwa kuna concerns za security au sababu nyingine za kuzima Bonjour, inaweza kuzimwa kwa kutumia command ifuatayo:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Marejeo

- [1] [Mwongozo wa Hacker wa Mac](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [3] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [4] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [5] [NVD – CVE-2025-31222](https://nvd.nist.gov/vuln/detail/CVE-2025-31222)
- [6] [Palo Alto Unit 42 - Uhamishaji wa Kando kwenye macOS: Mbinu za Kipekee na Maarufu pamoja na Mifano ya Kwenye Mazingira Halisi](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Kuhusu maudhui ya usalama ya macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Kuhusu maudhui ya usalama ya macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Kutumia Secure Remote Password (SRP) Protocol kwa Uthibitishaji wa TLS](https://www.rfc-editor.org/rfc/rfc5054)
- [11] [Sanaa ya Mac Malware, Juzuu ya I: Uchambuzi - Patrick Wardle](https://taomm.org/vol1/analysis.html)

{{#include ../../banners/hacktricks-training.md}}
