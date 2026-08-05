# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Huduma za Ufikiaji wa Mbali

Hizi ni huduma za kawaida za macOS za kuziakses kwa mbali.\
Unaweza kuwezesha/kuzima huduma hizi katika `System Settings` --> `Sharing`

- **VNC**, inayojulikana kama “Screen Sharing” (tcp:5900)
- **SSH**, inayoitwa “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), au “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, inayojulikana kama “Remote Apple Event” (tcp:3031)

Angalia ikiwa huduma yoyote imewezeshwa kwa kuendesha:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Kuhesabu usanidi wa sharing ndani ya mfumo

Unapokuwa tayari una local code execution kwenye Mac, **kagua hali iliyosanidiwa**, si listening sockets pekee. `systemsetup` na `launchctl` kwa kawaida huonyesha ikiwa service imewezeshwa kiutawala, huku `kickstart` na `system_profiler` zikisaidia kuthibitisha usanidi halisi wa ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) ni toleo lililoboreshwa la [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) lililoundwa mahsusi kwa macOS, likitoa vipengele vya ziada. Udhaifu unaojulikana katika ARD ni mbinu yake ya authentication ya password ya control screen, ambayo hutumia tu herufi 8 za kwanza za password, hivyo kuifanya iwe katika hatari ya [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) kwa kutumia tools kama Hydra au [GoRedShell](https://github.com/ahhh/GoRedShell/), kwa kuwa hakuna rate limits za msingi.<sup>[3]</sup>

Instances zilizo katika hatari zinaweza kutambuliwa kwa kutumia script ya `vnc-info` ya **nmap**. Services zinazotumia `VNC Authentication (2)` ziko katika hatari zaidi ya brute force attacks kutokana na kukatwa kwa password hadi herufi 8.

Ili kuwezesha ARD kwa kazi mbalimbali za kiutawala kama privilege escalation, GUI access, au user monitoring, tumia command ifuatayo:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD hutoa viwango mbalimbali vya udhibiti, ikiwemo observation, shared control, na full control, huku sessions zikiendelea hata baada ya user password kubadilishwa. Inaruhusu kutuma Unix commands moja kwa moja, na kuzitekeleza kama root kwa administrative users. Task scheduling na Remote Spotlight search ni features muhimu, zinazowezesha searches za mbali zenye athari ndogo kwa sensitive files kwenye machines nyingi.

Kwa mtazamo wa operator, **Monterey 12.1+ ilibadilisha remote-enablement workflows** kwenye managed fleets. Ikiwa tayari una control ya victim's MDM, Apple's `EnableRemoteDesktop` command mara nyingi ndiyo njia safi zaidi ya ku-activate remote desktop functionality kwenye systems mpya zaidi. Ikiwa tayari una foothold kwenye host, `kickstart` bado ni muhimu kwa kukagua au kureconfigure ARD privileges kutoka command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Utafiti wa hivi karibuni wa `screensharingd` ulionyesha kuwa Apple Screen Sharing si classic VNC auth pekee kila wakati: builds mpya zaidi hutumia **RFB `003.889`** na kutangaza **security type `36`**, ambapo **SRP** hufanya authentication kwanza, na **ChaCha20-Poly1305** huwekwa tu baada ya `ccsrp_server_verify_session` kufanikiwa. Public write-up inaripoti kuwa bug hiyo ilirekebishwa katika **macOS Tahoe 26.6** (**July 27, 2026**).<sup>[8][9]</sup>

Pattern muhimu ya kukumbuka ni **stale-status parser bypass**: baada ya successful 4-byte length read, kila oversized/error branch lazima irudishe error mpya. Kwenye builds zilizoathirika, big-endian SRP frame length **`>= 32768`** husababisha rejection path kutumia tena previous `NetBufferRead` success (`0`), hivyo caller huweka session kama authenticated ingawa hakuna password proof iliyotekelezwa na hakuna transport crypto iliyowekwa. Kwa sababu unread bytes hubaki kwenye shared socket buffer, attacker anaweza **kupipeline malformed SRP data na post-auth RFB messages katika TCP burst moja** na kuzifanya ziparswe kama **cleartext authenticated traffic**.<sup>[8]</sup>

Baada ya bypass, Apple's proprietary **file-copy** message **`0x22`** huwa **root file read/write primitive** kwa sababu `screensharingd` huendeshwa kama root:<sup>[8]</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: kusoma faili kiholela
- `kind=2` / `StartFileReceive`: kuandika faili kiholela
- Thamani tofauti za `sid` hukuruhusu kuweka transactions kadhaa kwenye connection moja
- Katika `kind=101` (`NewItem`), weka byte `14` / `arg[0]` kuwa `0x01` kwa faili la kawaida, payload offset `+42` iwe ukubwa wa faili wa big-endian usio **zero**, na payload offset `+0x5a` iwe Unix mode inayohitajika (`0600` ikiwa inalengwa crontab)

Mivuto ya kuvutia baada ya kuandika kwenye paths zinazoweza kuandikwa inajumuisha **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`**, na **`/var/root/.ssh/authorized_keys`**. **SIP haizuii auth bypass au root file read**, lakini inazuia baadhi ya write targets kama **`/var/at`**, kwa hivyo execution inayotegemea cron hufanya kazi tu SIP ikiwa imezimwa. Kwenye hosts zilizo na SIP iliyowashwa kwa default, fikiria kwa mtazamo wa **"root file write into privileged auto-consumed files"** badala ya code execution ya papo hapo.<sup>[8]</sup>

Tatizo jingine la SRP kutoka utafiti huo huo: servers lazima zihakikishe **`A mod N != 0`** (kwa mujibu wa RFC 5054), si `A > 0` pekee. Kukubali **`A = N`** kunaweza kulazimisha shared secret kuwa zero na kudhoofisha password verification.<sup>[8][10]</sup>

**Mawazo ya Detection**

- Sessions za Security type `36` ambapo urefu wa SRP frame ya kwanza ni **`>= 32768`**
- Sessions zinazoanza kuchakata traffic ya file-copy iliyo wazi ya **`0x22`** kabla ya SRP proof / cipher install yoyote kufanikiwa
- Retries fupi zinazorudiwa dhidi ya **TCP/5900**, pamoja na file-copy `sid` values nyingi katika burst moja
- Uundaji usiotarajiwa wa **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`**, au **`/var/root/.ssh/authorized_keys`** baada ya Screen Sharing exposure

### Pentesting Remote Apple Events (RAE / EPPC)

Apple huiita feature hii **Remote Application Scripting** katika System Settings za kisasa. Chini ya hood, hufichua **Apple Event Manager** kwa mbali kupitia **EPPC** kwenye **TCP/3031**, kwa kutumia service ya `com.apple.AEServer`. Palo Alto Unit 42 iliisisitiza tena kama primitive ya vitendo ya **macOS lateral movement**, kwa sababu credentials halali pamoja na RAE service iliyowashwa humruhusu operator kuendesha scriptable applications kwenye Mac ya mbali.<sup>[6]</sup>

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
Jaribio la msingi la muunganisho kutoka kwenye Mac nyingine:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Kwa vitendo, abuse case hii haijazuiliwa kwa Finder. **scriptable application** yoyote inayokubali Apple events zinazohitajika huwa remote attack surface, jambo linalofanya RAE iwe ya kuvutia hasa baada ya credential theft kwenye internal macOS networks.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|A user with screen sharing access may be able to view **another user's screen** because of a state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Zima *Screen Sharing*/*Remote Management* wakati hazihitajiki kabisa.
* Weka macOS ikiwa na patches zote (Apple kwa kawaida hutoa security fixes kwa matoleo makuu matatu ya mwisho).
* Tumia **Strong Password** *na* ulazimishe chaguo la *“VNC viewers may control screen with password”* kuwa **disabled** inapowezekana.
* Weka service nyuma ya VPN badala ya ku-expose TCP 5900/3283 kwenye Internet.
* Ongeza Application Firewall rule ili kuzuia `ARDAgent` kwenye local subnet:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, teknolojia iliyoundwa na Apple, huruhusu **devices zilizo kwenye network moja kugundua services zinazotolewa na nyingine**. Pia inajulikana kama Rendezvous, **Zero Configuration**, au Zeroconf; huwezesha device kujiunga na TCP/IP network, **kuchagua IP address kiotomatiki**, na kutangaza services zake kwa network devices nyingine.

Zero Configuration Networking, inayotolewa na Bonjour, huhakikisha kwamba devices zinaweza:

- **Kupata IP Address kiotomatiki** hata bila kuwepo kwa DHCP server.
- Kufanya **name-to-address translation** bila kuhitaji DNS server.
- **Kugundua services** zinazopatikana kwenye network.

Devices zinazotumia Bonjour hujipangia **IP address kutoka kwenye range ya 169.254/16** na kuthibitisha kwamba address hiyo ni ya kipekee kwenye network. Macs hudumisha routing table entry ya subnet hii, ambayo inaweza kuthibitishwa kupitia `netstat -rn | grep 169`.

Kwa DNS, Bonjour hutumia **Multicast DNS (mDNS) protocol**. mDNS hufanya kazi kupitia **port 5353/UDP**, ikitumia **standard DNS queries** lakini ikilenga **multicast address 224.0.0.251**. Mbinu hii huhakikisha kwamba devices zote zinazosikiliza kwenye network zinaweza kupokea na kujibu queries hizo, hivyo kuwezesha kusasishwa kwa records zao.

Baada ya kujiunga na network, kila device huchagua jina lake yenyewe, kwa kawaida likiishia na **.local**, ambalo linaweza kutolewa kutoka hostname au kuzalishwa kwa nasibu.

Service discovery ndani ya network huwezeshwa na **DNS Service Discovery (DNS-SD)**. Ikitumia format ya DNS SRV records, DNS-SD hutumia **DNS PTR records** kuwezesha kuorodheshwa kwa services nyingi. Client inayotafuta service maalum itaomba PTR record ya `<Service>.<Domain>`, na kupokea orodha ya PTR records zilizo katika format ya `<Instance>.<Service>.<Domain>` ikiwa service hiyo inapatikana kutoka kwa hosts nyingi.

Utility ya `dns-sd` inaweza kutumika kwa **kugundua na kutangaza network services**. Hapa kuna mifano ya matumizi yake:

### Searching for SSH Services

Kutafuta SSH services kwenye network, command ifuatayo hutumika:
```bash
dns-sd -B _ssh._tcp
```
Amri hii inaanzisha utafutaji wa huduma za \_ssh.\_tcp na kutoa maelezo kama vile muhuri wa muda, flags, interface, domain, aina ya huduma, na jina la instance.

### Kutangaza Huduma ya HTTP

Ili kutangaza huduma ya HTTP, unaweza kutumia:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Amri hii husajili service ya HTTP inayoitwa "Index" kwenye port 80 yenye path ya `/index.html`.

Kisha kutafuta services za HTTP kwenye mtandao:
```bash
dns-sd -B _http._tcp
```
Huduma inapoanza, hutangaza upatikanaji wake kwa vifaa vyote vilivyo kwenye subnet kwa kutuma taarifa ya uwepo wake kwa multicast. Vifaa vinavyovutiwa na huduma hizi havihitaji kutuma maombi, bali husikiliza tu matangazo haya.

Kwa kiolesura rahisi zaidi kwa mtumiaji, app ya **Discovery - DNS-SD Browser** inayopatikana kwenye Apple App Store inaweza kuonyesha huduma zinazotolewa kwenye mtandao wako wa ndani.

Vinginevyo, unaweza kuandika scripts maalum za kuvinjari na kugundua huduma kwa kutumia library ya `python-zeroconf`. Script ya [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) inaonyesha jinsi ya kuunda service browser ya huduma za `_http._tcp.local.`, na kuchapisha huduma zilizoongezwa au kuondolewa:
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
### Utafutaji wa Bonjour mahususi kwa macOS

Kwenye mitandao ya macOS, Bonjour mara nyingi ndiyo njia rahisi zaidi ya kupata **maeneo ya usimamizi wa mbali** bila kuwasiliana moja kwa moja na target. Apple Remote Desktop yenyewe inaweza kugundua clients kupitia Bonjour, kwa hivyo data hiyo hiyo ya ugunduzi ni muhimu kwa mshambulizi.
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

### Kuhesabu Bonjour kupitia mtandao

* **Nmap NSE** – gundua huduma zinazotangazwa na host moja:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Script ya `dns-service-discovery` hutuma query ya `_services._dns-sd._udp.local`, kisha huhesabu kila aina ya huduma inayotangazwa.

* **mdns_recon** – tool ya Python inayochanganua ranges nzima kutafuta *misconfigured* mDNS responders zinazojibu queries za unicast (ni muhimu kwa kutafuta vifaa vinavyofikika katika subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Hii itarudisha hosts zinazowasilisha SSH kupitia Bonjour nje ya link ya ndani.

### Mazingatio ya usalama na vulnerabilities za hivi karibuni (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Hitilafu ya logic katika *mDNSResponder* iliruhusu packet iliyoundwa mahsusi kusababisha **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|Tatizo la correctness katika *mDNSResponder* lingeweza kutumiwa kwa **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mwongozo wa mitigation**

1. Zuia UDP 5353 kwenye scope ya *link-local* – izuie au ipunguze rate yake kwenye wireless controllers, routers, na host-based firewalls.
2. Disable Bonjour kabisa kwenye systems ambazo hazihitaji service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Kwa environments ambazo Bonjour inahitajika internally lakini lazima isivuke mipaka ya mtandao, tumia restrictions za *AirPlay Receiver* profile (MDM) au mDNS proxy.
4. Enable **System Integrity Protection (SIP)** na keep macOS up to date – vulnerabilities zote mbili hapo juu ziliwekwa patches haraka, lakini zilitegemea SIP kuwa enabled kwa ulinzi kamili.

### Kuzima Bonjour

Ikiwa kuna concerns kuhusu security au sababu nyingine za kuzima Bonjour, inaweza kuzimwa kwa kutumia command ifuatayo:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Marejeo

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD - CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD - CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Kuhusu maudhui ya usalama ya macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Kuhusu maudhui ya usalama ya macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Kutumia Secure Remote Password (SRP) Protocol kwa TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
