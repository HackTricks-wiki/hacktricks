# macOS-netwerkdienste en -protokolle

{{#include ../../banners/hacktricks-training.md}}

## Afstandtoegangdienste

Dit is die algemene macOS-dienste om op afstand toegang daartoe te verkry.\
Jy kan hierdie dienste in `System Settings` --> `Sharing` aktiveer/deaktiveer

- **VNC**, bekend as “Screen Sharing” (tcp:5900)
- **SSH**, genoem “Remote Login” (tcp:22)
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
### Enumerasie van sharing-konfigurasie plaaslik

Wanneer jy reeds plaaslike kode-uitvoering op ’n Mac het, **kontroleer die gekonfigureerde toestand**, nie net die luisterende sokette nie. `systemsetup` en `launchctl` wys gewoonlik of die diens administratief geaktiveer is, terwyl `kickstart` en `system_profiler help om die effektiewe ARD/Sharing-konfigurasie te bevestig:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) is ’n uitgebreide weergawe van [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) wat vir macOS aangepas is en bykomende funksies bied. ’n Noemenswaardige kwesbaarheid in ARD is sy authentication-metode vir die beheerskermwagwoord, wat slegs die eerste 8 karakters van die wagwoord gebruik. Dit maak dit vatbaar vir [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) met tools soos Hydra of [GoRedShell](https://github.com/ahhh/GoRedShell/), aangesien daar geen standaard rate limits is nie.<sup>[3]</sup>

Kwesbare instansies kan met **nmap** se `vnc-info`-script geïdentifiseer word. Services wat `VNC Authentication (2)` ondersteun, is veral vatbaar vir brute force attacks weens die 8-karakter-wagwoordafkapping.

Om ARD vir verskeie administratiewe take soos privilege escalation, GUI-toegang of gebruikersmonitering te aktiveer, gebruik die volgende command:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bied veelsydige beheervlakke, insluitend waarneming, gedeelde beheer en volle beheer, met sessies wat voortduur selfs nadat gebruikerswagwoorde verander is. Dit laat toe dat Unix-opdragte direk gestuur word en dit as root vir administratiewe gebruikers uitgevoer word. Taakskedulering en Remote Spotlight-soektogte is noemenswaardige funksies wat afgeleë, lae-impak-soektogte na sensitiewe lêers oor verskeie masjiene moontlik maak.

Vanuit ’n operator-perspektief het **Monterey 12.1+ afgeleë-aktiveringswerkvloeie** in bestuurde vloote verander. As jy reeds beheer oor die slagoffer se MDM het, is Apple se `EnableRemoteDesktop`-opdrag dikwels die netjiesste manier om remote desktop-funksionaliteit op nuwer stelsels te aktiveer. As jy reeds ’n foothold op die gasheer het, is `kickstart` steeds nuttig om ARD-voorregte vanaf die command line te inspekteer of te herkonfigureer.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Onlangse `screensharingd`-navorsing het getoon dat Apple Screen Sharing nie altyd net klassieke VNC-auth is nie: nuwer builds praat **RFB `003.889`** en adverteer **security type `36`**, waar **SRP** eers authenticateer en **ChaCha20-Poly1305** slegs geïnstalleer word nadat `ccsrp_server_verify_session` suksesvol is. Die publieke write-up rapporteer dat die bug in **macOS Tahoe 26.6** (**27 Julie 2026**) reggestel is.<sup>[8][9]</sup>

’n Nuttige patroon om te onthou, is die **stale-status parser bypass**: ná ’n suksesvolle 4-grepe-lengte-lesing moet elke oversized/error-tak ’n nuwe error terugstuur. Op geaffekteerde builds laat ’n big-endian SRP-frame-lengte **`>= 32768`** die rejection path die vorige `NetBufferRead`-sukses (`0`) hergebruik, sodat die caller die sessie as authenticated stel, selfs al is geen password proof uitgevoer nie en geen transport crypto geïnstalleer nie. Omdat ongelese grepe in die gedeelde socket buffer bly, kan ’n aanvaller **malformed SRP-data en post-auth RFB-boodskappe in dieselfde TCP burst pipeline** en dit as **cleartext authenticated traffic** laat parse.<sup>[8]</sup>

Ná die bypass word Apple se eie **file-copy**-boodskap **`0x22`** ’n **root file read/write primitive** omdat `screensharingd` as root loop:<sup>[8]</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: arbitrêre lêerlees
- `kind=2` / `StartFileReceive`: arbitrêre lêerskryf
- Verskillende `sid`-waardes laat jou toe om verskeie transaksies in een verbinding te pipeline
- In `kind=101` (`NewItem`), stel byte `14` / `arg[0]` op `0x01` vir ’n gewone lêer, payload-offset `+42` op ’n **nie-nul** big-endian-lêergrootte, en payload-offset `+0x5a` op die verlangde Unix-modus (`0600` indien ’n crontab geteiken word)

Interessante post-write-pivots op skryfbare paaie sluit **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** en **`/var/root/.ssh/authorized_keys`** in. **SIP keer nie die auth bypass of root file read nie**, maar dit blokkeer sommige skryf-teikens soos **`/var/at`**, dus werk cron-gebaseerde uitvoering slegs met SIP gedeaktiveer. Op verstek SIP-geaktiveerde hosts, dink eerder in terme van **"root file write into privileged auto-consumed files"** as onmiddellike code execution.<sup>[8]</sup>

Nog ’n SRP-slagyster uit dieselfde navorsing: servers moet **`A mod N != 0`** (volgens RFC 5054) valideer, nie net `A > 0` nie. Deur **`A = N`** te aanvaar, kan die shared secret na nul gedwing word en password verification ondermyn word.<sup>[8][10]</sup>

**Opsporingsidees**

- Security type `36`-sessies waar die eerste SRP-frame-lengte **`>= 32768`** is
- Sessies wat begin om cleartext **`0x22`** file-copy-verkeer te verwerk voordat enige suksesvolle SRP-proof / cipher install plaasvind
- Herhaalde kortstondige retries teen **TCP/5900**, plus verskeie file-copy `sid`-waardes in een burst
- Onverwagte skepping van **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** of **`/var/root/.ssh/authorized_keys`** ná Screen Sharing-blootstelling

### Pentesting Remote Apple Events (RAE / EPPC)

Apple noem hierdie kenmerk **Remote Application Scripting** in moderne System Settings. Onder die enjinkap stel dit die **Apple Event Manager** op afstand bloot oor **EPPC** op **TCP/3031** via die `com.apple.AEServer`-diens. Palo Alto Unit 42 het dit weer uitgelig as ’n praktiese **macOS lateral movement**-primitive, omdat geldige credentials plus ’n geaktiveerde RAE-diens ’n operator toelaat om scriptable applications op ’n afgeleë Mac te beheer.<sup>[6]</sup>

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
In die praktyk is die misbruikgeval nie tot Finder beperk nie. Enige **scriptable application** wat die vereiste Apple events aanvaar, word ’n afgeleë aanvaloppervlak, wat RAE veral interessant maak ná credential theft op interne macOS-netwerke.

#### Onlangse Screen-Sharing- / ARD-kwesbaarhede (2023-2025)

| Jaar | CVE | Komponent | Impak | Reggestel in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Verkeerde sessieweergawe kon veroorsaak dat die *verkeerde* lessenaar of venster versend word, wat tot die uitlek van sensitiewe inligting kon lei|macOS Sonoma 14.2.1 (Des 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|’n Gebruiker met screen sharing-toegang kon moontlik **’n ander gebruiker se skerm** sien weens ’n toestandbestuursprobleem|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Okt-Des 2024) |

**Hardening-wenke**

* Deaktiveer *Screen Sharing*/*Remote Management* wanneer dit nie streng vereis word nie.
* Hou macOS volledig opgedateer (Apple lewer oor die algemeen security fixes vir die laaste drie major releases).
* Gebruik ’n **Strong Password** *en* dwing die *“VNC viewers may control screen with password”*-opsie **gedeaktiveer** af waar moontlik.
* Plaas die diens agter ’n VPN in plaas daarvan om TCP 5900/3283 aan die Internet bloot te stel.
* Voeg ’n Application Firewall-reël by om `ARDAgent` tot die plaaslike subnet te beperk:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour-protokol

Bonjour, ’n Apple-ontwerpte tegnologie, stel **toestelle op dieselfde netwerk in staat om mekaar se aangebode dienste op te spoor**. Dit staan ook as Rendezvous, **Zero Configuration** of Zeroconf bekend en stel ’n toestel in staat om by ’n TCP/IP-netwerk aan te sluit, **outomaties ’n IP-adres te kies** en sy dienste aan ander netwerktoestelle uit te saai.

Zero Configuration Networking, wat deur Bonjour verskaf word, verseker dat toestelle:

- **Outomaties ’n IP-adres verkry** selfs wanneer daar geen DHCP-bediener is nie.
- **Naam-na-adres-vertaling** uitvoer sonder dat ’n DNS-bediener vereis word.
- **Dienste ontdek** wat op die netwerk beskikbaar is.

Toestelle wat Bonjour gebruik, ken aan hulself ’n **IP-adres uit die 169.254/16-reeks toe** en verifieer dat dit uniek op die netwerk is. Macs handhaaf ’n roeteringtabelinskrywing vir hierdie subnet, wat met `netstat -rn | grep 169` geverifieer kan word.

Vir DNS gebruik Bonjour die **Multicast DNS (mDNS)-protokol**. mDNS werk oor **poort 5353/UDP** en gebruik **standaard DNS-navrae**, maar rig dit aan die **multicast-adres 224.0.0.251**. Hierdie benadering verseker dat alle toestelle op die netwerk wat luister, die navrae kan ontvang en daarop kan reageer, wat die opdatering van hul rekords vergemaklik.

Wanneer elke toestel by die netwerk aansluit, kies dit self ’n naam, wat gewoonlik op **.local** eindig en van die gasheernaam afgelei of willekeurig gegenereer kan word.

Diensontdekking binne die netwerk word deur **DNS Service Discovery (DNS-SD)** vergemaklik. Deur die formaat van DNS SRV-rekords te gebruik, gebruik DNS-SD **DNS PTR-rekords** om die lys van veelvuldige dienste moontlik te maak. ’n Kliënt wat ’n spesifieke diens soek, sal ’n PTR-rekord vir `<Service>.<Domain>` aanvra en in ruil ’n lys PTR-rekords in die formaat `<Instance>.<Service>.<Domain>` ontvang indien die diens vanaf veelvuldige gashere beskikbaar is.

Die `dns-sd`-nutsprogram kan gebruik word om netwerkdienste **te ontdek en te adverteer**. Hier is enkele voorbeelde van die gebruik daarvan:

### Soek na SSH-dienste

Om na SSH-dienste op die netwerk te soek, word die volgende opdrag gebruik:
```bash
dns-sd -B _ssh._tcp
```
Hierdie opdrag begin om vir \_ssh.\_tcp-dienste te blaai en lewer besonderhede soos tydstempel, vlae, koppelvlak, domein, dienstipe en instansienaam.

### Advertering van ’n HTTP-diens

Om ’n HTTP-diens te adverteer, kan jy gebruik:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Hierdie opdrag registreer ’n HTTP-diens genaamd "Index" op poort 80 met ’n pad van `/index.html`.

Om daarna vir HTTP-dienste op die netwerk te soek:
```bash
dns-sd -B _http._tcp
```
Wanneer 'n diens begin, kondig dit sy beskikbaarheid aan alle toestelle op die subnet aan deur sy teenwoordigheid te multicast. Toestelle wat in hierdie dienste belangstel, hoef nie versoeke te stuur nie, maar kan eenvoudig na hierdie aankondigings luister.

Vir 'n meer gebruikersvriendelike koppelvlak kan die **Discovery - DNS-SD Browser**-app, wat in die Apple App Store beskikbaar is, die dienste wat op jou plaaslike netwerk aangebied word, visualiseer.

Alternatiewelik kan pasgemaakte scripts geskryf word om deur dienste te blaai en dit te ontdek deur die `python-zeroconf`-library te gebruik. Die [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)-script demonstreer hoe om 'n diensblaaier vir `_http._tcp.local.`-dienste te skep en bygevoegde of verwyderde dienste te druk:
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
### macOS-spesifieke Bonjour-verkenning

Op macOS-netwerke is Bonjour dikwels die maklikste manier om **oppervlakke vir afgeleë administrasie** te vind sonder om die teiken direk aan te raak. Apple Remote Desktop kan self kliënte deur Bonjour ontdek, dus is dieselfde ontdekkingsdata ook nuttig vir ’n aanvaller.
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
Vir breër **mDNS spoofing, impersonation, en cross-subnet discovery**-tegnieke, kyk na die toegewyde bladsy:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerating Bonjour oor die netwerk

* **Nmap NSE** – ontdek dienste wat deur ’n enkele host geadverteer word:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Die `dns-service-discovery`-script stuur ’n `_services._dns-sd._udp.local`-navraag en enumereer dan elke geadverteerde dienstipe.

* **mdns_recon** – Python-tool wat volledige reekse skandeer op soek na *misconfigured* mDNS-responders wat unicast-navrae beantwoord (nuttig om toestelle te vind wat oor subnets/WAN bereikbaar is):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Dit sal hosts teruggee wat SSH via Bonjour buite die plaaslike skakel blootstel.

### Sekuriteitsoorwegings en onlangse kwesbaarhede (2024-2025)

| Jaar | CVE | Erns | Probleem | Gepleister in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|’n Logikafout in *mDNSResponder* het toegelaat dat ’n vervaardigde pakkie ’n **denial-of-service** veroorsaak|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|’n Korrektheidsprobleem in *mDNSResponder* kon vir **local privilege escalation** misbruik word|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Mei 2025) |

**Mitigation guidance**

1. Beperk UDP 5353 tot *link-local* scope – blokkeer dit of beperk die tempo daarvan op wireless controllers, routers en host-based firewalls.
2. Deaktiveer Bonjour volledig op stelsels wat nie service discovery benodig nie:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. In omgewings waar Bonjour intern vereis word, maar nooit netwerkgrense mag kruis nie, gebruik *AirPlay Receiver*-profielbeperkings (MDM) of ’n mDNS-proxy.
4. Aktiveer **System Integrity Protection (SIP)** en hou macOS op datum – albei bogenoemde kwesbaarhede is vinnig gepleister, maar het op SIP gesteun vir volledige beskerming.

### Bonjour deaktiveer

Indien daar kommer oor sekuriteit of ander redes is om Bonjour te deaktiveer, kan dit met die volgende opdrag afgeskakel word:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Verwysings

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [Die Kuns van Mac Malware, Volume I: Analise - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Laterale Beweging op macOS: Unieke en Gewilde Tegnieke en Voorbeelde uit die Werklike Wêreld](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Oor die sekuriteitsinhoud van macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Oor die sekuriteitsinhoud van macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Gebruik van die Secure Remote Password (SRP) Protocol vir TLS-verifikasie](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
