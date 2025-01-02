# macOS Netwerkdienste & Protokolle

{{#include ../../banners/hacktricks-training.md}}

## Afgeleë Toegang Dienste

Dit is die algemene macOS dienste om hulle afgeleë te benader.\
Jy kan hierdie dienste in `Stelselsinstellings` --> `Deel`

- **VNC**, bekend as “Skermdeling” (tcp:5900)
- **SSH**, genoem “Afgeleë Aanmelding” (tcp:22)
- **Apple Remote Desktop** (ARD), of “Afgeleë Bestuur” (tcp:3283, tcp:5900)
- **AppleEvent**, bekend as “Afgeleë Apple Gebeurtenis” (tcp:3031)

Kontroleer of enige geaktiveer is deur te loop:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) is 'n verbeterde weergawe van [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) wat vir macOS aangepas is, en bied addisionele funksies. 'n Opmerkelijke kwesbaarheid in ARD is sy outentikasie metode vir die kontrole skerm wagwoord, wat slegs die eerste 8 karakters van die wagwoord gebruik, wat dit geneig maak tot [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) met gereedskap soos Hydra of [GoRedShell](https://github.com/ahhh/GoRedShell/), aangesien daar geen standaard koersbeperkings is nie.

Kwetsbare instansies kan geïdentifiseer word met **nmap**'s `vnc-info` skrip. Dienste wat `VNC Authentication (2)` ondersteun, is veral kwesbaar vir brute force-aanvalle weens die 8-karakter wagwoord afkorting.

Om ARD in te skakel vir verskeie administratiewe take soos privilige eskalasie, GUI-toegang, of gebruikersmonitering, gebruik die volgende opdrag:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bied veelsydige kontrole vlakke, insluitend waaksaamheid, gedeelde beheer, en volle beheer, met sessies wat voortduur selfs na gebruikerswagwoord veranderinge. Dit stel die stuur van Unix-opdragte direk moontlik, wat as root uitgevoer word vir administratiewe gebruikers. Taakbeplanning en Remote Spotlight soektog is noemenswaardige kenmerke, wat afgeleë, lae-impak soektogte na sensitiewe lêers oor verskeie masjiene fasiliteer.

## Bonjour Protokol

Bonjour, 'n Apple-ontwerpte tegnologie, stel **toestelle op dieselfde netwerk in staat om mekaar se aangebied dienste te ontdek**. Ook bekend as Rendezvous, **Zero Configuration**, of Zeroconf, stel dit 'n toestel in staat om by 'n TCP/IP-netwerk aan te sluit, **automaties 'n IP-adres te kies**, en sy dienste aan ander netwerktoestelle te broadcast.

Zero Configuration Networking, wat deur Bonjour verskaf word, verseker dat toestelle kan:

- **Automaties 'n IP-adres verkry** selfs in die afwesigheid van 'n DHCP-bediener.
- **Naam-naar-adres vertaling** uitvoer sonder om 'n DNS-bediener te vereis.
- **Dienste** beskikbaar op die netwerk ontdek.

Toestelle wat Bonjour gebruik, sal vir hulleself 'n **IP-adres uit die 169.254/16 reeks toewys** en die uniekheid daarvan op die netwerk verifieer. Macs hou 'n routeringstabelinvoer vir hierdie subnet, wat verifieer kan word via `netstat -rn | grep 169`.

Vir DNS gebruik Bonjour die **Multicast DNS (mDNS) protokol**. mDNS werk oor **poort 5353/UDP**, wat **standaard DNS-vrae** gebruik maar teiken die **multicast adres 224.0.0.251**. Hierdie benadering verseker dat alle luisterende toestelle op die netwerk die vrae kan ontvang en daarop kan reageer, wat die opdatering van hul rekords fasiliteer.

By die aansluiting by die netwerk, kies elke toestel self 'n naam, wat tipies eindig op **.local**, wat afgelei kan wees van die gasheernaam of ewekansig gegenereer kan word.

Dienste ontdekking binne die netwerk word gefasiliteer deur **DNS Service Discovery (DNS-SD)**. Deur die formaat van DNS SRV rekords te benut, gebruik DNS-SD **DNS PTR rekords** om die lys van verskeie dienste moontlik te maak. 'n Kliënt wat 'n spesifieke diens soek, sal 'n PTR rekord vir `<Service>.<Domain>` aan vra, en in ruil 'n lys van PTR rekords ontvang wat geformateer is as `<Instance>.<Service>.<Domain>` indien die diens beskikbaar is vanaf verskeie gasheers.

Die `dns-sd` nut kan gebruik word vir **die ontdekking en advertering van netwerkdienste**. Hier is 'n paar voorbeelde van sy gebruik:

### Soek na SSH Dienste

Om na SSH dienste op die netwerk te soek, word die volgende opdrag gebruik:
```bash
dns-sd -B _ssh._tcp
```
Hierdie opdrag begin om te soek na \_ssh.\_tcp dienste en gee besonderhede soos tydstempel, vlae, koppelvlak, domein, dienste tipe, en instansie naam.

### Advertering van 'n HTTP Diens

Om 'n HTTP diens te adverteer, kan jy gebruik maak van:
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
### Deaktiveer Bonjour

As daar bekommernisse oor sekuriteit is of ander redes om Bonjour te deaktiveer, kan dit met die volgende opdrag afgeskakel word:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Verwysings

- [**Die Mac Hacker se Handboek**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
