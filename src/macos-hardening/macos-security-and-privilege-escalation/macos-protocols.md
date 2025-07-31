# macOS Netwerkdienste & Protokolle

{{#include ../../banners/hacktricks-training.md}}

## Afgeleë Toegang Dienste

Dit is die algemene macOS dienste om hulle afgeleë te benader.\
Jy kan hierdie dienste in `Stelselsinstellings` --> `Deel` aktiveer/deaktiveer.

- **VNC**, bekend as “Skermdeling” (tcp:5900)
- **SSH**, genoem “Afgeleë Aanmelding” (tcp:22)
- **Apple Remote Desktop** (ARD), of “Afgeleë Bestuur” (tcp:3283, tcp:5900)
- **AppleEvent**, bekend as “Afgeleë Apple Gebeurtenis” (tcp:3031)

Kontroleer of enige geaktiveer is deur te loop:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) is 'n verbeterde weergawe van [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) wat vir macOS aangepas is, en bied addisionele kenmerke. 'n Opmerklike kwesbaarheid in ARD is sy outentikasie metode vir die kontroleer skerm wagwoord, wat slegs die eerste 8 karakters van die wagwoord gebruik, wat dit vatbaar maak vir [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) met gereedskap soos Hydra of [GoRedShell](https://github.com/ahhh/GoRedShell/), aangesien daar geen standaard koersbeperkings is nie.

Kwetsbare instansies kan geïdentifiseer word met **nmap**'s `vnc-info` skrip. Dienste wat `VNC Authentication (2)` ondersteun, is veral vatbaar vir brute force-aanvalle weens die 8-karakter wagwoord afkorting.

Om ARD vir verskeie administratiewe take soos privilige eskalasie, GUI-toegang, of gebruikersmonitering in te skakel, gebruik die volgende opdrag:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bied veelsydige kontrolevlakke, insluitend waaksaamheid, gedeelde beheer en volle beheer, met sessies wat voortduur selfs na gebruikerswagwoordveranderings. Dit laat toe om Unix-opdragte direk te stuur, en dit as root uit te voer vir administratiewe gebruikers. Taakbeplanning en Remote Spotlight-soektog is noemenswaardige kenmerke, wat afgeleë, lae-impak soektogte na sensitiewe lêers oor verskeie masjiene vergemaklik.

#### Onlangse Skermdeling / ARD kwesbaarhede (2023-2025)

| Jaar | CVE | Komponent | Impak | Geregverdig in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Skermdeling|Onkorrekte sessie-rendering kan veroorsaak dat die *verkeerde* lessenaar of venster oorgedra word, wat lei tot die lekkasie van sensitiewe inligting|macOS Sonoma 14.2.1 (Des 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Kernel geheue-beskerming omseiling wat geketting kan word na 'n suksesvolle afgeleë aanmelding (aktief in die natuur benut)|macOS Ventura 13.6.4 / Sonoma 14.4 (Mrt 2024) |

**Hardeerwenke**

* Deaktiveer *Skermdeling*/*Afgeleë Bestuur* wanneer dit nie streng vereis word nie.
* Hou macOS ten volle gepatch (Apple verskaf gewoonlik sekuriteitsoplossings vir die laaste drie groot weergawes).
* Gebruik 'n **Sterk Wagwoord** *en* handhaaf die *“VNC viewers may control screen with password”* opsie **deaktiveer** wanneer moontlik.
* Plaas die diens agter 'n VPN eerder as om TCP 5900/3283 aan die Internet bloot te stel.
* Voeg 'n Aansoek Vuurmuurreël by om `ARDAgent` tot die plaaslike subnet te beperk:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protokol

Bonjour, 'n Apple-ontwerpte tegnologie, laat **toestelle op dieselfde netwerk mekaar se aangebied dienste opspoor**. Ook bekend as Rendezvous, **Zero Configuration**, of Zeroconf, stel dit 'n toestel in staat om by 'n TCP/IP-netwerk aan te sluit, **automaties 'n IP-adres te kies**, en sy dienste aan ander netwerktoestelle te broadcast.

Zero Configuration Networking, wat deur Bonjour verskaf word, verseker dat toestelle kan:

- **Automaties 'n IP-adres verkry** selfs in die afwesigheid van 'n DHCP-bediener.
- **Naam-naar-adres vertaling** uitvoer sonder om 'n DNS-bediener te vereis.
- **Dienste** op die netwerk ontdek.

Toestelle wat Bonjour gebruik, sal vir hulleself 'n **IP-adres uit die 169.254/16 reeks** toewys en die uniekheid daarvan op die netwerk verifieer. Macs hou 'n routeringstabelinvoer vir hierdie subnet, wat verifieer kan word via `netstat -rn | grep 169`.

Vir DNS gebruik Bonjour die **Multicast DNS (mDNS) protokol**. mDNS werk oor **poort 5353/UDP**, wat **standaard DNS-vrae** gebruik maar teiken die **multicast adres 224.0.0.251**. Hierdie benadering verseker dat alle luisterende toestelle op die netwerk die vrae kan ontvang en daarop kan reageer, wat die opdatering van hul rekords vergemaklik.

By die aansluiting by die netwerk, kies elke toestel self 'n naam, wat gewoonlik eindig op **.local**, wat afgelei kan word van die gasheernaam of ewekansig gegenereer kan word.

Dienste ontdekking binne die netwerk word vergemaklik deur **DNS Service Discovery (DNS-SD)**. Deur die formaat van DNS SRV rekords te benut, gebruik DNS-SD **DNS PTR rekords** om die lys van verskeie dienste moontlik te maak. 'n Kliënt wat 'n spesifieke diens soek, sal 'n PTR rekord vir `<Service>.<Domain>` aan vra, en in ruil 'n lys van PTR rekords ontvang wat geformateer is as `<Instance>.<Service>.<Domain>` indien die diens beskikbaar is vanaf verskeie gasheer.

Die `dns-sd` nut kan gebruik word vir **ontdekking en advertering van netwerkdienste**. Hier is 'n paar voorbeelde van sy gebruik:

### Soek na SSH Dienste

Om na SSH dienste op die netwerk te soek, word die volgende opdrag gebruik:
```bash
dns-sd -B _ssh._tcp
```
Hierdie opdrag begin om \_ssh.\_tcp dienste te soek en gee besonderhede soos tydstempel, vlae, koppelvlak, domein, dienste tipe, en instansienaam uit.

### Adverteer 'n HTTP-diens

Om 'n HTTP-diens te adverteer, kan jy gebruik maak van:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Hierdie opdrag registreer 'n HTTP-diens genaamd "Index" op poort 80 met 'n pad van `/index.html`.

Om dan vir HTTP-dienste op die netwerk te soek:
```bash
dns-sd -B _http._tcp
```
Wanneer 'n diens begin, kondig dit sy beskikbaarheid aan alle toestelle op die subnet aan deur sy teenwoordigheid te multicast. Toestelle wat in hierdie dienste belangstel, hoef nie versoeke te stuur nie, maar luister eenvoudig na hierdie aankondigings.

Vir 'n meer gebruikersvriendelike koppelvlak kan die **Discovery - DNS-SD Browser** app beskikbaar op die Apple App Store die dienste wat op jou plaaslike netwerk aangebied word, visualiseer.

Alternatiewelik kan pasgemaakte skripte geskryf word om dienste te blaai en te ontdek met behulp van die `python-zeroconf` biblioteek. Die [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) skrip demonstreer die skep van 'n diensblaaier vir `_http._tcp.local.` dienste, wat bygevoegde of verwyderde dienste druk:
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
### Om Bonjour oor die netwerk te enumeer

* **Nmap NSE** – ontdek dienste wat deur 'n enkele gasheer geadverteer word:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Die `dns-service-discovery` skrip stuur 'n `_services._dns-sd._udp.local` navraag en enumeer dan elke geadverteerde dienste tipe.

* **mdns_recon** – Python-gereedskap wat hele reekse skandeer op soek na *verkeerd geconfigureerde* mDNS-responders wat unicast-navrae beantwoord (nuttig om toestelle te vind wat oor subnetwerke/WAN bereikbaar is):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Dit sal gashere teruggee wat SSH via Bonjour buite die plaaslike skakel blootstel.

### Sekuriteits oorwegings & onlangse kwesbaarhede (2024-2025)

| Jaar | CVE | Ernstigheid | Probleem | Gepatch in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|‘n Logika fout in *mDNSResponder* het 'n vervaardigde pakket toegelaat om 'n **diensonderbreking** te aktiveer|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|‘n Korrekheid probleem in *mDNSResponder* kan misbruik word vir **lokale privilige eskalasie**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Mei 2025) |

**Mitigering riglyne**

1. Beperk UDP 5353 tot *link-lokale* omvang – blokkeer of beperk dit op draadlose controllers, routers, en gasheer-gebaseerde vuurmure.
2. Deaktiveer Bonjour heeltemal op stelsels wat nie diensontdekking vereis nie:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Vir omgewings waar Bonjour intern vereis word maar nooit netwerkgrense mag oorskry nie, gebruik *AirPlay Receiver* profielbeperkings (MDM) of 'n mDNS-proxy.
4. Aktiveer **Stelselintegriteitbeskerming (SIP)** en hou macOS op datum – beide kwesbaarhede hierbo is vinnig gepatch, maar het op SIP se aktivering staatgemaak vir volle beskerming.

### Deaktivering van Bonjour

As daar bekommernisse oor sekuriteit of ander redes is om Bonjour te deaktiver, kan dit afgeskakel word met die volgende opdrag:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Verwysings

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
