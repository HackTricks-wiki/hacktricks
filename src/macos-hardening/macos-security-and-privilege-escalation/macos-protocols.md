# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Dit is die algemene macOS-dienste om op afstand toegang daartoe te verkry.\
Jy kan hierdie dienste in `System Settings` --> `Sharing` aktiveer/deaktiveer

- **VNC**, bekend as “Screen Sharing” (tcp:5900)
- **SSH**, genaamd “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), of “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, bekend as “Remote Apple Event” (tcp:3031)

Kontroleer of enigeen geaktiveer is deur die volgende uit te voer:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Lys van deelkonfigurasie plaaslik

Wanneer jy reeds lokale code execution op 'n Mac het, **kontroleer die gekonfigureerde toestand**, nie net die luisterende sockets nie. `systemsetup` en `launchctl` sê gewoonlik vir jou of die diens administratief geaktiveer is, terwyl `kickstart` en `system_profiler` help om die effektiewe ARD/Sharing-konfigurasie te bevestig:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) is an enhanced version of [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) tailored for macOS, offering additional features. A notable vulnerability in ARD is its authentication method for the control screen password, which only uses the first 8 characters of the password, making it prone to [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) with tools like Hydra or [GoRedShell](https://github.com/ahhh/GoRedShell/), as there are no default rate limits.

Vulnerable instances can be identified using **nmap**'s `vnc-info` script. Services supporting `VNC Authentication (2)` are especially susceptible to brute force attacks due to the 8-character password truncation.

To enable ARD for various administrative tasks like privilege escalation, GUI access, or user monitoring, use the following command:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bied veelsydige beheer-vlakke, insluitend observasie, gedeelde beheer, en volle beheer, met sessies wat voortduur selfs nadat gebruikerwagwoordveranderings plaasvind. Dit laat toe om Unix commands direk te stuur, en dit uit te voer as root vir administratiewe gebruikers. Taakskedulering en Remote Spotlight search is noemenswaardige kenmerke, wat afstandlike, lae-impak soektogte vir sensitiewe lêers oor verskeie masjiene fasiliteer.

Van ’n operator-perspektief het **Monterey 12.1+ remote-enablement workflows** in managed fleets verander. As jy reeds beheer oor die slagoffer se MDM het, is Apple se `EnableRemoteDesktop` command dikwels die skoonste manier om remote desktop-funksionaliteit op nuwer stelsels te aktiveer. As jy reeds ’n foothold op die host het, is `kickstart` steeds nuttig om ARD privileges vanaf die command line te inspekteer of te herkonfigureer.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple noem hierdie funksie **Remote Application Scripting** in moderne System Settings. Onder die oppervlak stel dit die **Apple Event Manager** afstandlik bloot oor **EPPC** op **TCP/3031** via die `com.apple.AEServer` service. Palo Alto Unit 42 het dit weer uitgelig as ’n praktiese **macOS lateral movement** primitief omdat geldige credentials plus ’n geaktiveerde RAE service ’n operator toelaat om scriptable applications op ’n remote Mac te beheer.

Nuttige checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
As jy reeds admin/root op die teiken het en dit wil aktiveer:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Basiese konnektiwiteitstoets vanaf 'n ander Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
In praktyk is die abuse case nie beperk tot Finder nie. Enige **scriptable application** wat die vereiste Apple events aanvaar, word ’n remote attack surface, wat RAE veral interessant maak ná credential theft op interne macOS-netwerke.

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

Bonjour, an Apple-designed technology, allows **devices on the same network to detect each other's offered services**. Known also as Rendezvous, **Zero Configuration**, or Zeroconf, it enables a device to join a TCP/IP network, **automatically choose an IP address**, and broadcast its services to other network devices.

Zero Configuration Networking, provided by Bonjour, ensures that devices can:

- **Automatically obtain an IP Address** even in the absence of a DHCP server.
- Perform **name-to-address translation** without requiring a DNS server.
- **Discover services** available on the network.

Devices using Bonjour will assign themselves an **IP address from the 169.254/16 range** and verify its uniqueness on the network. Macs maintain a routing table entry for this subnet, verifiable via `netstat -rn | grep 169`.

For DNS, Bonjour utilizes the **Multicast DNS (mDNS) protocol**. mDNS operates over **port 5353/UDP**, employing **standard DNS queries** but targeting the **multicast address 224.0.0.251**. This approach ensures that all listening devices on the network can receive and respond to the queries, facilitating the update of their records.

Upon joining the network, each device self-selects a name, typically ending in **.local**, which may be derived from the hostname or randomly generated.

Service discovery within the network is facilitated by **DNS Service Discovery (DNS-SD)**. Leveraging the format of DNS SRV records, DNS-SD uses **DNS PTR records** to enable the listing of multiple services. A client seeking a specific service will request a PTR record for `<Service>.<Domain>`, receiving in return a list of PTR records formatted as `<Instance>.<Service>.<Domain>` if the service is available from multiple hosts.

The `dns-sd` utility can be employed for **discovering and advertising network services**. Here are some examples of its usage:

### Searching for SSH Services

To search for SSH services on the network, the following command is used:
```bash
dns-sd -B _ssh._tcp
```
Hierdie opdrag begin deur \_ssh.\_tcp-dienste te blaai en gee besonderhede uit soos tydstempel, vlae, koppelvlak, domein, diens tipe, en instansienaam.

### Adverteer van 'n HTTP-diens

Om 'n HTTP-diens te adverteer, kan jy gebruik:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Hierdie opdrag registreer ’n HTTP-diens genaamd "Index" op poort 80 met ’n pad van `/index.html`.

Om dan na HTTP-dienste op die netwerk te soek:
```bash
dns-sd -B _http._tcp
```
Wanneer ’n diens begin, kondig dit sy beskikbaarheid aan alle toestelle op die subnet aan deur sy teenwoordigheid te multicast. Toestelle wat in hierdie dienste belangstel, hoef nie versoeke te stuur nie, maar luister eenvoudig vir hierdie aankondigings.

Vir ’n meer gebruikersvriendelike koppelvlak kan die **Discovery - DNS-SD Browser**-app wat op die Apple App Store beskikbaar is, die dienste wat op jou plaaslike netwerk aangebied word, visualiseer.

Alternatiewelik kan pasgemaakte scripts geskryf word om dienste te browse en te ontdek met behulp van die `python-zeroconf`-biblioteek. Die [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script demonstreer hoe om ’n diens-blaaier vir `_http._tcp.local.`-dienste te skep, en druk bygevoegde of verwyderde dienste:
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
### macOS-spesifieke Bonjour-jag

Op macOS-netwerke is Bonjour dikwels die maklikste manier om **veraf-administrasie-oppervlaktes** te vind sonder om die teiken direk aan te raak. Apple Remote Desktop self kan kliënte deur Bonjour ontdek, so dieselfde ontdekkingsdata is nuttig vir ’n aanvaller.
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
Vir breër **mDNS spoofing, impersonation, and cross-subnet discovery** tegnieke, kyk na die toegewyde bladsy:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerating Bonjour oor die netwerk

* **Nmap NSE** – ontdek services wat deur 'n enkele host geadverteer word:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Die `dns-service-discovery` script stuur 'n `_services._dns-sd._udp.local` query en enumereer dan elke geadverteerde service type.

* **mdns_recon** – Python tool wat hele ranges skandeer op soek na *misconfigured* mDNS responders wat unicast queries antwoord (nuttig om devices te vind wat oor subnets/WAN bereikbaar is):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Dit sal hosts teruggee wat SSH via Bonjour buite die local link blootstel.

### Security considerations & recent vulnerabilities (2024-2025)

| Jaar | CVE | Severity | Issue | Gepatch in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. Beperk UDP 5353 tot *link-local* scope – blokkeer of rate-limit dit op wireless controllers, routers, en host-based firewalls.
2. Deaktiveer Bonjour heeltemal op systems wat nie service discovery benodig nie:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Vir environments waar Bonjour intern vereis word maar nooit netwerkgrense mag kruis nie, gebruik *AirPlay Receiver* profile restrictions (MDM) of 'n mDNS proxy.
4. Aktiveer **System Integrity Protection (SIP)** en hou macOS op datum – albei vulnerabilities hierbo is vinnig gepatch maar het daarop gesteun dat SIP geaktiveer is vir volle protection.

### Disabling Bonjour

As daar concerns is oor security of ander redes om Bonjour te deaktiveer, kan dit met die volgende command afgeskakel word:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Verwysings

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
