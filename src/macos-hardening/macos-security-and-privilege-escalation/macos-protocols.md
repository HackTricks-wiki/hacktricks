# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Huduma za Ufikiaji wa Mbali

Hizi ni huduma za kawaida za macOS za kuzi-access remotely.\
Unaweza kuwezesha/kuzima huduma hizi katika `System Settings` --> `Sharing`

- **VNC**, inayojulikana kama “Screen Sharing” (tcp:5900)
- **SSH**, inayoitwa “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), au “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, inayojulikana kama “Remote Apple Event” (tcp:3031)

Angalia ikiwa mojawapo imewezeshwa kwa ku-run:
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

Unapokuwa tayari una local code execution kwenye Mac, **kagua hali iliyosanidiwa**, si listening sockets pekee. `systemsetup` na `launchctl` kwa kawaida hukuonyesha ikiwa service imewezeshwa kiutawala, huku `kickstart` na `system_profiler` zikisaidia kuthibitisha usanidi halisi wa ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) ni toleo lililoboreshwa la [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) lililoundwa mahsusi kwa macOS, likitoa vipengele vya ziada. Udhaifu unaojulikana katika ARD ni mbinu yake ya authentication kwa control screen password, ambayo hutumia tu herufi 8 za kwanza za password, hivyo kuifanya iwe katika hatari ya [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) kwa kutumia tools kama Hydra au [GoRedShell](https://github.com/ahhh/GoRedShell/), kwa kuwa hakuna rate limits za msingi.<sup>[[3]](#references)</sup>

Instances zilizo hatarini zinaweza kutambuliwa kwa kutumia script ya `vnc-info` ya **nmap**. Services zinazounga mkono `VNC Authentication (2)` huwa katika hatari kubwa zaidi ya brute force attacks kutokana na password truncation ya herufi 8.

Ili kuwezesha ARD kwa administrative tasks mbalimbali kama privilege escalation, GUI access, au user monitoring, tumia command ifuatayo:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD hutoa viwango mbalimbali vya udhibiti, ikiwemo uangalizi, udhibiti wa pamoja, na udhibiti kamili, huku sessions zikiendelea hata baada ya mabadiliko ya password ya mtumiaji. Inaruhusu kutuma Unix commands moja kwa moja na kuzitekeleza kama root kwa watumiaji wa kiutawala. Kupanga tasks na Remote Spotlight search ni vipengele muhimu, vinavyowezesha searches za mbali zenye athari ndogo za kutafuta faili nyeti kwenye mashine nyingi.

Kwa mtazamo wa operator, **Monterey 12.1+ ilibadilisha workflows za kuwezesha ufikiaji wa mbali** kwenye fleets zinazosimamiwa. Ikiwa tayari unadhibiti MDM ya victim, command ya Apple `EnableRemoteDesktop` mara nyingi ndiyo njia safi zaidi ya kuwezesha utendaji wa remote desktop kwenye systems mpya. Ikiwa tayari una foothold kwenye host, `kickstart` bado ni muhimu kwa kukagua au kusanidi upya privileges za ARD kutoka command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Utafiti wa hivi karibuni kuhusu `screensharingd` ulionyesha kuwa Apple Screen Sharing si VNC auth ya kawaida kila wakati: builds mpya huzungumza **RFB `003.889`** na kutangaza **security type `36`**, ambapo **SRP** hufanya authentication kwanza na **ChaCha20-Poly1305** huwekwa tu baada ya `ccsrp_server_verify_session` kufanikiwa. Maandishi ya hadharani yanaripoti kuwa bug hiyo ilirekebishwa katika **macOS Tahoe 26.6** (**27 Julai 2026**).<sup>[[8]](#references)[[9]](#references)</sup>

Pattern muhimu ya kukumbuka ni **stale-status parser bypass**: baada ya kusoma length ya baiti 4 kwa mafanikio, kila branch ya oversized/error lazima irudishe error mpya. Kwenye builds zilizoathirika, SRP frame length ya big-endian **`>= 32768`** husababisha rejection path kutumia tena mafanikio ya awali ya `NetBufferRead` (`0`), hivyo caller huweka session kama authenticated ingawa hakuna password proof iliyotekelezwa na hakuna transport crypto iliyowekwa. Kwa sababu baiti ambazo hazijasomwa hubaki kwenye shared socket buffer, attacker anaweza **kupipeline malformed SRP data na post-auth RFB messages katika TCP burst ileile** na kuzifanya zichanganuliwe kama **cleartext authenticated traffic**.<sup>[[8]](#references)</sup>

Baada ya bypass hiyo, ujumbe wa Apple wa proprietary **file-copy** **`0x22`** huwa **primitive ya root ya kusoma/kuandika faili** kwa sababu `screensharingd` huendeshwa kama root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: kusoma file yoyote
- `kind=2` / `StartFileReceive`: kuandika file yoyote
- `sid` values tofauti huruhusu kupitisha transactions kadhaa kwa pamoja ndani ya connection moja
- Katika `kind=101` (`NewItem`), weka byte `14` / `arg[0]` kuwa `0x01` kwa regular file, payload offset `+42` kuwa file size ya big-endian isiyo **zero**, na payload offset `+0x5a` kuwa Unix mode inayohitajika (`0600` ikiwa inalengwa crontab)

Post-write pivots zinazovutia kwenye paths zinazoweza kuandikwa zinajumuisha **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`**, na **`/var/root/.ssh/authorized_keys`**. **SIP haizuii auth bypass au root file read**, lakini inazuia baadhi ya write targets kama **`/var/at`**, hivyo code execution inayotegemea cron hufanya kazi tu SIP ikiwa imezimwa. Kwenye hosts zenye SIP iliyowezeshwa kwa default, fikiria zaidi kuhusu **"root file write into privileged auto-consumed files"** badala ya code execution ya mara moja.<sup>[[8]](#references)</sup>

Tatizo lingine la SRP kutoka kwenye utafiti huo huo: servers lazima zithibitishe **`A mod N != 0`** (kulingana na RFC 5054), si `A > 0` pekee. Kukubali **`A = N`** kunaweza kulazimisha shared secret kuwa zero na kudhoofisha password verification.<sup>[[8]](#references)[[10]](#references)</sup>

**Detection ideas**

- Security type `36` sessions ambapo urefu wa SRP frame ya kwanza ni **`>= 32768`**
- Sessions zinazoanza kuchakata cleartext **`0x22`** file-copy traffic kabla ya SRP proof / cipher install yoyote iliyofanikiwa
- Retries fupi na zinazorudiwa dhidi ya **TCP/5900**, pamoja na file-copy `sid` values nyingi ndani ya burst moja
- Uundaji usiotarajiwa wa **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`**, au **`/var/root/.ssh/authorized_keys`** baada ya Screen Sharing exposure

### Pentesting Remote Apple Events (RAE / EPPC)

Apple huiita feature hii **Remote Application Scripting** katika System Settings za kisasa. Chini ya hood, inaweka wazi **Apple Event Manager** kwa mbali kupitia **EPPC** kwenye **TCP/3031**, kupitia service ya `com.apple.AEServer`. Palo Alto Unit 42 waliisisitiza tena kama primitive ya vitendo ya **macOS lateral movement**, kwa sababu valid credentials pamoja na RAE service iliyowezeshwa humruhusu operator kuendesha scriptable applications kwenye Mac ya mbali.<sup>[[6]](#references)</sup>

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
Jaribio la msingi la muunganisho kutoka Mac nyingine:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Kwa vitendo, hali ya abuse haiko kwenye Finder pekee. Programu yoyote **scriptable application** inayokubali Apple events zinazohitajika huwa remote attack surface, jambo linalofanya RAE ivutie hasa baada ya credential theft kwenye mitandao ya ndani ya macOS.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Uwasilishaji usio sahihi wa session ungeweza kusababisha *desktop* au window **isiyo sahihi** kutumwa, na hivyo kusababisha leak ya taarifa nyeti|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Mtumiaji aliye na access ya screen sharing anaweza kuona **screen ya mtumiaji mwingine** kwa sababu ya tatizo la state-management|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Disable *Screen Sharing*/*Remote Management* wakati hazihitajiki kabisa.
* Weka macOS ikiwa na patches zote (Apple kwa ujumla husambaza security fixes kwa major releases tatu za mwisho).
* Tumia **Strong Password** *na* enforce option ya *“VNC viewers may control screen with password”* ikiwa **disabled** inapowezekana.
* Weka service nyuma ya VPN badala ya ku-expose TCP 5900/3283 kwenye Internet.
* Ongeza Application Firewall rule ili kuzuia `ARDAgent` kwenye local subnet:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, teknolojia iliyoundwa na Apple, huruhusu **devices kwenye network moja kugundua services zinazotolewa na nyingine**. Pia inajulikana kama Rendezvous, **Zero Configuration**, au Zeroconf; huwezesha device kujiunga na TCP/IP network, **kuchagua IP address kiotomatiki**, na kutangaza services zake kwa devices nyingine za network.

Zero Configuration Networking, inayotolewa na Bonjour, huhakikisha kwamba devices zinaweza:

- **Kupata IP Address kiotomatiki** hata kama hakuna DHCP server.
- Kufanya **name-to-address translation** bila kuhitaji DNS server.
- **Kugundua services** zinazopatikana kwenye network.

Devices zinazotumia Bonjour zitajipa **IP address kutoka kwenye range ya 169.254/16** na kuthibitisha upekee wake kwenye network. Macs hudumisha routing table entry ya subnet hii, ambayo inaweza kuthibitishwa kupitia `netstat -rn | grep 169`.

Kwa DNS, Bonjour hutumia **Multicast DNS (mDNS) protocol**. mDNS hufanya kazi kupitia **port 5353/UDP**, ikitumia **standard DNS queries** lakini ikilenga **multicast address 224.0.0.251**. Mbinu hii huhakikisha kwamba devices zote zinazosikiliza kwenye network zinaweza kupokea na kujibu queries, na hivyo kuwezesha kusasisha records zao.

Baada ya kujiunga na network, kila device hujichagulia jina, ambalo kwa kawaida huishia na **.local**, na linaweza kutokana na hostname au kuzalishwa kwa nasibu.

Service discovery ndani ya network huwezeshwa na **DNS Service Discovery (DNS-SD)**. Ikitumia format ya DNS SRV records, DNS-SD hutumia **DNS PTR records** kuwezesha kuorodheshwa kwa services nyingi. Client anayetafuta service maalum ataomba PTR record ya `<Service>.<Domain>`, na kupokea orodha ya PTR records zilizo katika format ya `<Instance>.<Service>.<Domain>` ikiwa service hiyo inapatikana kutoka kwa hosts nyingi.

Utility ya `dns-sd` inaweza kutumika kwa **kugundua na kutangaza network services**. Hapa kuna baadhi ya mifano ya matumizi yake:

### Searching for SSH Services

Ili kutafuta SSH services kwenye network, command ifuatayo hutumiwa:
```bash
dns-sd -B _ssh._tcp
```
Amri hii huanzisha browsing ya huduma za \_ssh.\_tcp na kutoa maelezo kama vile timestamp, flags, interface, domain, aina ya service, na jina la instance.

### Kutangaza Huduma ya HTTP

Ili kutangaza huduma ya HTTP, unaweza kutumia:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Amri hii husajili service ya HTTP inayoitwa "Index" kwenye port 80 yenye path ya `/index.html`.

Kisha kutafuta services za HTTP kwenye network:
```bash
dns-sd -B _http._tcp
```
Huduma inapoanza, hutangaza upatikanaji wake kwa vifaa vyote vilivyo kwenye subnet kwa kutuma ujumbe wa multicast wa uwepo wake. Vifaa vinavyovutiwa na huduma hizi havihitaji kutuma maombi, bali husikiliza tu matangazo hayo.

Kwa kiolesura kinachofaa zaidi mtumiaji, app ya **Discovery - DNS-SD Browser**, inayopatikana kwenye Apple App Store, inaweza kuonyesha huduma zinazotolewa kwenye mtandao wako wa ndani.

Vinginevyo, unaweza kuandika scripts maalum za kuvinjari na kugundua huduma kwa kutumia library ya `python-zeroconf`. Script ya [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) inaonyesha jinsi ya kuunda service browser kwa huduma za `_http._tcp.local.`, na kuchapisha huduma zilizoongezwa au kuondolewa:
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

Kwenye mitandao ya macOS, Bonjour mara nyingi ndiyo njia rahisi zaidi ya kupata **nyuso za usimamizi wa mbali** bila kuigusa target moja kwa moja. Apple Remote Desktop yenyewe inaweza kugundua clients kupitia Bonjour, hivyo data hiyo hiyo ya ugunduzi ni muhimu kwa mshambuliaji.
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

* **mdns_recon** – tool ya Python inayochanganua ranges nzima kutafuta mDNS responders *misconfigured* wanaojibu unicast queries (inafaa kutafuta devices zinazofikika katika subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Hii itarudisha hosts zinazoonyesha SSH kupitia Bonjour nje ya local link.

### Mazingatio ya usalama na vulnerabilities za hivi karibuni (2024-2025)

| Mwaka | CVE | Ukali | Tatizo | Imepatched katika |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Kati|Logic error katika *mDNSResponder* iliruhusu packet iliyoundwa mahsusi kusababisha **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|Juu|Correctness issue katika *mDNSResponder* ingeweza kutumiwa kwa **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mwongozo wa mitigation**

1. Zuia UDP 5353 kwenye scope ya *link-local* – izuie au punguza kiwango chake kwenye wireless controllers, routers, na host-based firewalls.
2. Zima Bonjour kabisa kwenye systems ambazo hazihitaji service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Kwa mazingira ambayo Bonjour inahitajika internally lakini haipaswi kamwe kuvuka network boundaries, tumia restrictions za *AirPlay Receiver* profile (MDM) au mDNS proxy.
4. Washa **System Integrity Protection (SIP)** na usasishe macOS – vulnerabilities zote mbili hapo juu zilipatched haraka, lakini zilitegemea SIP kuwa imewashwa kwa ulinzi kamili.

### Kuzima Bonjour

Ikiwa kuna concerns za usalama au sababu nyingine za kuzima Bonjour, inaweza kuzimwa kwa kutumia command ifuatayo:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Marejeleo

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Uchambuzi - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Lateral Movement kwenye macOS: Mbinu za Kipekee na Maarufu pamoja na Mifano ya In-the-Wild](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Kuhusu maudhui ya usalama ya macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Kuhusu maudhui ya usalama ya macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Kutumia Secure Remote Password (SRP) Protocol kwa TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
