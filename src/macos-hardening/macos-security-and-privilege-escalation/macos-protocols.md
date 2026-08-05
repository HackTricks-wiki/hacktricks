# macOS-netwerkdienste en -protokolle

{{#include ../../banners/hacktricks-training.md}}

## Afstandtoegangdienste

Dit is die algemene macOS-dienste waartoe jy op afstand toegang kan verkry.\
Jy kan hierdie dienste in `System Settings` --> `Sharing` aktiveer/deaktiveer

- **VNC**, bekend as “Screen Sharing” (tcp:5900)
- **SSH**, genaamd “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), of “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, bekend as “Remote Apple Event” (tcp:3031)

Kontroleer of enige hiervan geaktiveer is deur die volgende uit te voer:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Enumerasie van deelkonfigurasie plaaslik

Wanneer jy reeds plaaslike code execution op ’n Mac het, **kontroleer die gekonfigureerde toestand**, nie net die listening sockets nie. `systemsetup` en `launchctl` dui gewoonlik aan of die diens administratief geaktiveer is, terwyl `kickstart` en `system_profiler help om die effektiewe ARD/Sharing-konfigurasie te bevestig:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) is 'n uitgebreide weergawe van [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) wat vir macOS aangepas is en bykomende funksies bied. 'n Noemenswaardige kwesbaarheid in ARD is die authentication-metode vir die control screen password, wat slegs die eerste 8 karakters van die password gebruik, wat dit vatbaar maak vir [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) met tools soos Hydra of [GoRedShell](https://github.com/ahhh/GoRedShell/), aangesien daar geen verstek-rate limits is nie.<sup>[[3]](#references)</sup>

Kwesbare instances kan met **nmap** se `vnc-info`-script geïdentifiseer word. Services wat `VNC Authentication (2)` ondersteun, is veral vatbaar vir brute force attacks weens die 8-karakter password truncation.

Om ARD vir verskeie administratiewe take soos privilege escalation, GUI access of user monitoring te enable, gebruik die volgende command:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bied veelsydige beheervlakke, insluitend waarneming, gedeelde beheer en volle beheer, met sessies wat voortduur selfs nadat gebruikerswagwoorde verander is. Dit laat toe dat Unix-opdragte direk gestuur word en dit as root uitgevoer word vir administratiewe gebruikers. Taakskedulering en Remote Spotlight search is noemenswaardige kenmerke wat afgeleë, lae-impak-soektogte na sensitiewe lêers oor verskeie masjiene moontlik maak.

Vanuit ’n operateursperspektief het **Monterey 12.1+ die remote-enablement-werkvloeie** in bestuurde vloote verander. As jy reeds beheer oor die slagoffer se MDM het, is Apple se `EnableRemoteDesktop`-opdrag dikwels die skoonste manier om remote desktop-funksionaliteit op nuwer stelsels te aktiveer. As jy reeds ’n foothold op die gasheer het, is `kickstart` steeds nuttig om ARD-voorregte vanaf die command line te inspekteer of te herkonfigureer.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Onlangse `screensharingd`-navorsing het getoon dat Apple Screen Sharing nie altyd net klassieke VNC-auth is nie: nuwer builds praat **RFB `003.889`** en adverteer **security type `36`**, waar **SRP** eers auth uitvoer en **ChaCha20-Poly1305** slegs geïnstalleer word nadat `ccsrp_server_verify_session` suksesvol is. Die openbare uiteensetting rapporteer dat die bug in **macOS Tahoe 26.6** (**27 Julie 2026**) reggestel is.<sup>[[8]](#references)[[9]](#references)</sup>

’n Nuttige patroon om te onthou is die **stale-status parser bypass**: ná ’n suksesvolle 4-byte-lengte-lees moet elke oversized/error-tak ’n vars error teruggee. Op geaffekteerde builds laat ’n big-endian SRP-raamlengte **`>= 32768`** die rejection-pad die vorige `NetBufferRead`-sukses (`0`) hergebruik, sodat die caller die sessie as geauthentiseerd stel hoewel geen wagwoordbewys uitgevoer is nie en geen transport crypto geïnstalleer is nie. Omdat ongeleesde grepe in die gedeelde socket buffer bly, kan ’n aanvaller **malformed SRP-data en post-auth RFB-boodskappe in dieselfde TCP-burst pipeline** en dit as **cleartext authenticated traffic** laat ontleed.<sup>[[8]](#references)</sup>

Ná die bypass word Apple se eie **file-copy**-boodskap **`0x22`** ’n **root file read/write primitive** omdat `screensharingd` as root loop:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: arbitrêre lêerlees
- `kind=2` / `StartFileReceive`: arbitrêre lêerskryf
- Verskillende `sid`-waardes laat jou toe om verskeie transaksies in een verbinding te pyplyn
- In `kind=101` (`NewItem`), stel byte `14` / `arg[0]` op `0x01` vir ’n gewone lêer, payload-offset `+42` op ’n **nie-nul** big-endian-lêergrootte, en payload-offset `+0x5a` op die verlangde Unix-modus (`0600` indien ’n crontab geteiken word)

Interessante post-write pivots op skryfbare paaie sluit **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`**, en **`/var/root/.ssh/authorized_keys`** in. **SIP keer nie die auth bypass of root-lêerlees nie**, maar dit blokkeer sommige skryf-teikens soos **`/var/at`**, dus werk cron-gebaseerde uitvoering slegs met SIP gedeaktiveer. Op standaard SIP-geaktiveerde gashere, dink eerder in terme van **"root-lêerskryf na bevoorregte outomaties-verbruikte lêers"** as onmiddellike kode-uitvoering.<sup>[[8]](#references)</sup>

Nog ’n SRP-strik vanuit dieselfde navorsing: bedieners moet **`A mod N != 0`** (volgens RFC 5054) valideer, nie net `A > 0` nie. Deur **`A = N`** te aanvaar, kan die gedeelde geheim na nul gedwing word en wagwoordverifikasie ondermyn word.<sup>[[8]](#references)[[10]](#references)</sup>

**Opsporingsidees**

- Security type `36`-sessies waar die eerste SRP-frame-lengte **`>= 32768`** is
- Sessies wat begin om cleartext **`0x22`**-file-copy-verkeer te verwerk voordat enige suksesvolle SRP-proof / cipher install plaasvind
- Herhaalde kortstondige retries teen **TCP/5900**, plus veelvuldige file-copy `sid`-waardes in een sarsie
- Onverwagte skepping van **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`**, of **`/var/root/.ssh/authorized_keys`** ná blootstelling van Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple noem hierdie funksie **Remote Application Scripting** in moderne System Settings. Onderliggend stel dit die **Apple Event Manager** op afstand bloot oor **EPPC** op **TCP/3031** via die `com.apple.AEServer`-diens. Palo Alto Unit 42 het dit weer uitgelig as ’n praktiese **macOS lateral movement**-primitive, omdat geldige credentials plus ’n geaktiveerde RAE-diens ’n operator toelaat om scriptable toepassings op ’n afgeleë Mac te beheer.<sup>[[6]](#references)</sup>

Nuttige kontroles:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
As jy reeds admin/root op die teiken het en dit wil aktiveer:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Basiese verbindingstoets vanaf ’n ander Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
In die praktyk is die misbruikgeval nie tot Finder beperk nie. Enige **scriptable application** wat die vereiste Apple events aanvaar, word ’n remote attack surface, wat RAE veral interessant maak ná credential theft op interne macOS-netwerke.

#### Onlangse Screen-Sharing / ARD-kwesbaarhede (2023-2025)

| Jaar | CVE | Komponent | Impak | Reggestel in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Verkeerde sessieweergawe kon veroorsaak dat die *verkeerde* desktop of venster versend word, wat tot die lek van sensitiewe inligting kon lei|macOS Sonoma 14.2.1 (Des 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|’n Gebruiker met screen sharing-toegang kon moontlik **’n ander gebruiker se skerm sien** weens ’n toestandbestuurskwessie|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Okt-Des 2024) |

**Hardening-wenke**

* Deaktiveer *Screen Sharing*/*Remote Management* wanneer dit nie streng vereis word nie.
* Hou macOS volledig gepatch (Apple lewer oor die algemeen security fixes vir die laaste drie major releases).
* Gebruik ’n **Strong Password** *en* forseer die *“VNC viewers may control screen with password”*-opsie om **gedeaktiveer** te wees waar moontlik.
* Plaas die diens agter ’n VPN in plaas daarvan om TCP 5900/3283 aan die Internet bloot te stel.
* Voeg ’n Application Firewall-reël by om `ARDAgent` tot die plaaslike subnet te beperk:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour-protokol

Bonjour, ’n Apple-ontwerpte tegnologie, laat **toestelle op dieselfde netwerk toe om mekaar se aangebiedde dienste op te spoor**. Dit staan ook as Rendezvous, **Zero Configuration** of Zeroconf bekend en stel ’n toestel in staat om by ’n TCP/IP-netwerk aan te sluit, **outomaties ’n IP-adres te kies** en sy dienste aan ander netwerktoestelle uit te saai.

Zero Configuration Networking, wat deur Bonjour verskaf word, verseker dat toestelle kan:

- **Outomaties ’n IP-adres verkry**, selfs in die afwesigheid van ’n DHCP-bediener.
- **Naam-na-adres-vertaling** uitvoer sonder dat ’n DNS-bediener vereis word.
- **Dienste ontdek** wat op die netwerk beskikbaar is.

Toestelle wat Bonjour gebruik, ken aan hulself ’n **IP-adres uit die 169.254/16-reeks toe** en verifieer die uniekheid daarvan op die netwerk. Macs handhaaf ’n roetetabelinskrywing vir hierdie subnet, wat via `netstat -rn | grep 169` geverifieer kan word.

Vir DNS gebruik Bonjour die **Multicast DNS (mDNS)-protokol**. mDNS werk oor **poort 5353/UDP** en gebruik **standaard DNS-navrae**, maar rig dit aan die **multicast-adres 224.0.0.251**. Hierdie benadering verseker dat alle toestelle op die netwerk wat luister, die navrae kan ontvang en daarop kan reageer, wat die opdatering van hul rekords vergemaklik.

Wanneer elke toestel by die netwerk aansluit, kies dit self ’n naam, wat gewoonlik op **.local** eindig en van die hostname afgelei of lukraak gegenereer kan word.

Diensontdekking binne die netwerk word deur **DNS Service Discovery (DNS-SD)** vergemaklik. Deur die formaat van DNS SRV-rekords te benut, gebruik DNS-SD **DNS PTR-rekords** om die lys van verskeie dienste moontlik te maak. ’n Kliënt wat ’n spesifieke diens soek, sal ’n PTR-rekord vir `<Service>.<Domain>` aanvra en, indien die diens vanaf verskeie hosts beskikbaar is, ’n lys PTR-rekords in die formaat `<Instance>.<Service>.<Domain>` ontvang.

Die `dns-sd`-hulpmiddel kan gebruik word om **netwerkdienste te ontdek en te adverteer**. Hier is enkele voorbeelde van die gebruik daarvan:

### Soek na SSH-dienste

Om na SSH-dienste op die netwerk te soek, word die volgende opdrag gebruik:
```bash
dns-sd -B _ssh._tcp
```
Hierdie opdrag begin om na \_ssh.\_tcp-dienste te soek en voer besonderhede uit soos tydstempel, vlae, koppelvlak, domein, dienstipe en instansienaam.

### Advertering van ’n HTTP-diens

Om ’n HTTP-diens te adverteer, kan jy die volgende gebruik:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Hierdie opdrag registreer ’n HTTP-diens genaamd "Index" op poort 80 met ’n pad van `/index.html`.

Om vervolgens vir HTTP-dienste op die netwerk te soek:
```bash
dns-sd -B _http._tcp
```
Wanneer 'n diens begin, kondig dit sy beskikbaarheid aan alle toestelle op die subnet aan deur sy teenwoordigheid te multicast. Toestelle wat in hierdie dienste belangstel, hoef nie versoeke te stuur nie, maar kan eenvoudig na hierdie aankondigings luister.

Vir 'n meer gebruikersvriendelike koppelvlak kan die **Discovery - DNS-SD Browser**-app, wat in die Apple App Store beskikbaar is, die dienste wat op jou plaaslike netwerk aangebied word, visualiseer.

Alternatiewelik kan pasgemaakte scripts geskryf word om dienste te blaai en te ontdek met behulp van die `python-zeroconf`-biblioteek. Die [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)-script demonstreer hoe om 'n diensblaaier vir `_http._tcp.local.`-dienste te skep en dienste wat bygevoeg of verwyder is, te druk:
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
### macOS-spesifieke Bonjour hunting

Op macOS-netwerke is Bonjour dikwels die maklikste manier om **remote administration surfaces** te vind sonder om die target direk aan te raak. Apple Remote Desktop self kan clients deur Bonjour ontdek, dus is dieselfde discovery-data nuttig vir ’n attacker.
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
Vir breër **mDNS spoofing, impersonation, en cross-subnet discovery**-tegnieke, raadpleeg die toegewyde bladsy:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerating van Bonjour oor die network

* **Nmap NSE** – ontdek dienste wat deur ’n enkele host geadverteer word:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Die `dns-service-discovery`-script stuur ’n `_services._dns-sd._udp.local`-navraag en enumereer daarna elke geadverteerde dienstipe.

* **mdns_recon** – Python-tool wat volledige reekse skandeer op soek na *misconfigured* mDNS responders wat unicast-navrae beantwoord (nuttig om toestelle te vind wat oor subnets/WAN bereikbaar is):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Dit sal hosts terugstuur wat SSH via Bonjour buite die plaaslike skakel blootstel.

### Sekuriteitsoorwegings & onlangse vulnerabilities (2024-2025)

| Jaar | CVE | Erns | Probleem | Gepatch in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|’n Logikafout in *mDNSResponder* het toegelaat dat ’n vervaardigde packet ’n **denial-of-service** veroorsaak|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|’n Correctness-probleem in *mDNSResponder* kon vir **local privilege escalation** misbruik word|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Mei 2025) |

**Mitigation guidance**

1. Beperk UDP 5353 tot *link-local* scope – blokkeer dit of pas rate limiting toe op wireless controllers, routers en host-based firewalls.
2. Deaktiveer Bonjour heeltemal op stelsels wat nie service discovery benodig nie:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Vir omgewings waar Bonjour intern benodig word, maar nooit netwerkgrense mag kruis nie, gebruik *AirPlay Receiver*-profielbeperkings (MDM) of ’n mDNS proxy.
4. Aktiveer **System Integrity Protection (SIP)** en hou macOS op datum – albei vulnerabilities hier bo is vinnig gepatch, maar het vereis dat SIP geaktiveer is vir volledige beskerming.

### Deaktivering van Bonjour

Indien daar kommer oor sekuriteit of ander redes is om Bonjour te deaktiveer, kan dit met die volgende command afgeskakel word:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Verwysings

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Laterale beweging op macOS: Unieke en gewilde tegnieke en voorbeelde uit die praktyk](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple-ondersteuning - Meer oor die sekuriteitsinhoud van macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple-ondersteuning - Meer oor die sekuriteitsinhoud van macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Gebruik die Secure Remote Password (SRP)-protokol vir TLS-verifikasie](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
