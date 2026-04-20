# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Udaljene usluge pristupa

Ovo su uobičajene macOS usluge za udaljeni pristup.\
Možete uključiti/isključiti ove usluge u `System Settings` --> `Sharing`

- **VNC**, poznat kao “Screen Sharing” (tcp:5900)
- **SSH**, nazvan “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), ili “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, poznat kao “Remote Apple Event” (tcp:3031)

Proverite da li je neka od njih uključena pokrenuto:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Enumerating sharing configuration locally

Kada već imate lokalno izvršavanje koda na Mac-u, **proverite konfigurisano stanje**, a ne samo listening sockets. `systemsetup` i `launchctl` obično pokazuju da li je servis administrativno omogućen, dok `kickstart` i `system_profiler` pomažu da potvrdite stvarnu ARD/Sharing konfiguraciju:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) je unapređena verzija [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) prilagođena za macOS, koja nudi dodatne funkcije. Značajna ranjivost u ARD-u je njegov metod autentikacije za lozinku kontrolnog ekrana, koji koristi samo prvih 8 karaktera lozinke, što ga čini podložnim [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) uz alate kao što su Hydra ili [GoRedShell](https://github.com/ahhh/GoRedShell/), pošto ne postoje podrazumevana ograničenja brzine.

Ranjive instance mogu da se identifikuju pomoću **nmap** skripte `vnc-info`. Servisi koji podržavaju `VNC Authentication (2)` posebno su podložni brute force attacks zbog skraćivanja lozinke na 8 karaktera.

Da biste omogućili ARD za različite administrativne zadatke kao što su privilege escalation, GUI access ili nadzor korisnika, koristite sledeću komandu:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD pruža različite nivoe kontrole, uključujući posmatranje, deljenu kontrolu i punu kontrolu, pri čemu sesije ostaju aktivne čak i nakon promene korisničke lozinke. Omogućava slanje Unix komandi direktno, izvršavajući ih kao root za administrativne korisnike. Zakazivanje zadataka i Remote Spotlight pretraga su značajne funkcije, jer omogućavaju udaljene pretrage sa niskim uticajem za osetljive fajlove na više mašina.

Iz perspektive operatera, **Monterey 12.1+ je promenio workflow za remote-enablement** u upravljanim flotama. Ako već kontrolišete MDM žrtve, Apple-ova `EnableRemoteDesktop` komanda je često najčistiji način da aktivirate remote desktop funkcionalnost na novijim sistemima. Ako već imate foothold na hostu, `kickstart` je i dalje koristan za proveru ili rekonfiguraciju ARD privilegija iz komandne linije.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple ovu funkciju naziva **Remote Application Scripting** u modernom System Settings. Ispod haube, ona izlaže **Apple Event Manager** udaljeno preko **EPPC** na **TCP/3031** putem servisa `com.apple.AEServer`. Palo Alto Unit 42 je ponovo istakao ovo kao praktičan **macOS lateral movement** mehanizam, jer važeći kredencijali plus omogućen RAE servis omogućavaju operateru da upravlja skriptabilnim aplikacijama na udaljenom Mac-u.

Korisne provere:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Ako već imate admin/root na meti i želite da ga omogućite:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Osnovni test povezivosti sa drugog Mac-a:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
U praksi, case abuse nije ograničen na Finder. Svaka **scriptable application** koja prihvata potrebne Apple events postaje remote attack surface, što čini RAE posebno interesantnim nakon krađe kredencijala na internim macOS mrežama.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Netačno renderovanje sesije moglo je da dovede do toga da se prenese *pogrešan* desktop ili prozor, što rezultira leak-om osetljivih informacija|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Korisnik sa screen sharing pristupom možda bi mogao da vidi **ekran drugog korisnika** zbog problema sa state-management|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

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

Bonjour, tehnologija koju je dizajnirao Apple, omogućava da **uređaji na istoj mreži otkriju usluge koje jedni drugima nude**. Poznat i kao Rendezvous, **Zero Configuration**, ili Zeroconf, omogućava uređaju da se poveže na TCP/IP mrežu, **automatski izabere IP adresu**, i emituje svoje usluge ka drugim mrežnim uređajima.

Zero Configuration Networking, koji obezbeđuje Bonjour, omogućava uređajima da:

- **Automatski dobiju IP Address** čak i kada nema DHCP servera.
- Izvrše **name-to-address translation** bez potrebe za DNS serverom.
- **Otkrivaju services** dostupne na mreži.

Uređaji koji koriste Bonjour dodeliće sebi **IP address iz opsega 169.254/16** i proveriti njenu jedinstvenost na mreži. Mac računari održavaju routing table unos za ovaj subnet, što se može proveriti pomoću `netstat -rn | grep 169`.

Za DNS, Bonjour koristi **Multicast DNS (mDNS) protocol**. mDNS radi preko **porta 5353/UDP**, koristeći **standard DNS queries** ali ciljajući **multicast address 224.0.0.251**. Ovaj pristup obezbeđuje da svi uređaji na mreži koji slušaju mogu da prime i odgovore na queries, olakšavajući update njihovih zapisa.

Nakon pridruživanja mreži, svaki uređaj sam bira naziv, tipično koji se završava sa **.local**, a koji može biti izveden iz hostname-a ili nasumično generisan.

Service discovery unutar mreže omogućava **DNS Service Discovery (DNS-SD)**. Koristeći format DNS SRV records, DNS-SD koristi **DNS PTR records** da omogući listing više services. Klijent koji traži određenu service zatražiće PTR record za `<Service>.<Domain>`, i kao odgovor dobiti listu PTR records u formatu `<Instance>.<Service>.<Domain>` ako je service dostupna sa više hostova.

`dns-sd` utility može se koristiti za **discovering and advertising network services**. Evo nekoliko primera njegove upotrebe:

### Searching for SSH Services

Da biste potražili SSH services na mreži, koristi se sledeća komanda:
```bash
dns-sd -B _ssh._tcp
```
Ova komanda pokreće pretragu za \_ssh.\_tcp servise i prikazuje detalje kao što su timestamp, flags, interface, domain, service type i instance name.

### Advertising an HTTP Service

Da biste reklamirali HTTP servis, možete koristiti:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ova komanda registruje HTTP servis pod nazivom "Index" na portu 80 sa putanjom `/index.html`.

Zatim, za pretragu HTTP servisa na mreži:
```bash
dns-sd -B _http._tcp
```
Kada se servis pokrene, on objavljuje svoju dostupnost svim uređajima na subnetu multicastovanjem svog prisustva. Uređajima koji su zainteresovani za ove servise nije potrebno da šalju zahteve, već samo da slušaju ove objave.

Za korisnički prijatniji interfejs, aplikacija **Discovery - DNS-SD Browser** dostupna na Apple App Store-u može da vizualizuje servise ponuđene na vašoj lokalnoj mreži.

Alternativno, mogu se napisati prilagođeni skriptovi za pregled i otkrivanje servisa koristeći `python-zeroconf` biblioteku. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) skript prikazuje kreiranje browsera za servise `_http._tcp.local.`, ispisujući dodate ili uklonjene servise:
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

Na macOS mrežama, Bonjour je često najlakši način da se pronađu **remote administration surfaces** bez direktnog dodirivanja mete. Apple Remote Desktop može da otkrije klijente kroz Bonjour, pa su isti podaci o otkrivanju korisni i napadaču.
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
Za šire tehnike **mDNS spoofing, impersonation, and cross-subnet discovery**, pogledajte namensku stranicu:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerating Bonjour over the network

* **Nmap NSE** – otkriva servise koje oglašava jedan host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script šalje `_services._dns-sd._udp.local` upit, a zatim enumerira svaki oglašeni tip servisa.

* **mdns_recon** – Python alat koji skenira cele opsege tražeći *misconfigured* mDNS responedere koji odgovaraju na unicast upite (korisno za pronalaženje uređaja dostupnih preko subnetova/WAN-a):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Ovo će vratiti hostove koji izlažu SSH putem Bonjour-a van lokalne veze.

### Security considerations & recent vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. Ograničite UDP 5353 na *link-local* opseg – blokirajte ga ili primenite rate-limit na bežičnim kontrolerima, ruterima i host-based firewall-ovima.
2. Potpuno onemogućite Bonjour na sistemima kojima service discovery nije potreban:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Za okruženja gde je Bonjour potreban interno, ali nikada ne sme da prelazi mrežne granice, koristite *AirPlay Receiver* profile restrictions (MDM) ili mDNS proxy.
4. Omogućite **System Integrity Protection (SIP)** i održavajte macOS ažurnim – obe ranjivosti iznad su brzo zakrpene, ali su za punu zaštitu zavisile od toga da SIP bude omogućen.

### Disabling Bonjour

Ako postoje bezbednosne brige ili drugi razlozi da se Bonjour isključi, može se ugasiti sledećom komandom:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
