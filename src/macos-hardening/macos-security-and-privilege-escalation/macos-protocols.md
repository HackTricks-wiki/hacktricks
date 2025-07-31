# macOS Mrežne Usluge i Protokoli

{{#include ../../banners/hacktricks-training.md}}

## Usluge Daljinskog Pristupa

Ovo su uobičajene macOS usluge za daljinski pristup.\
Možete omogućiti/onemogućiti ove usluge u `System Settings` --> `Sharing`

- **VNC**, poznat kao “Deljenje Ekrana” (tcp:5900)
- **SSH**, nazvan “Daljinska Prijava” (tcp:22)
- **Apple Remote Desktop** (ARD), ili “Daljinsko Upravljanje” (tcp:3283, tcp:5900)
- **AppleEvent**, poznat kao “Daljinski Apple Događaj” (tcp:3031)

Proverite da li je neka od njih omogućena pokretanjem:
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

Apple Remote Desktop (ARD) je unapređena verzija [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) prilagođena za macOS, koja nudi dodatne funkcije. Značajna ranjivost u ARD-u je njegova metoda autentifikacije za lozinku kontrolne ekrana, koja koristi samo prvih 8 karaktera lozinke, što je čini podložnom [brute force napadima](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) sa alatima kao što su Hydra ili [GoRedShell](https://github.com/ahhh/GoRedShell/), jer ne postoje podrazumevana ograničenja brzine.

Ranjive instance se mogu identifikovati korišćenjem **nmap**-ovog `vnc-info` skripta. Usluge koje podržavaju `VNC Authentication (2)` su posebno podložne brute force napadima zbog skraćivanja lozinke na 8 karaktera.

Da biste omogućili ARD za razne administrativne zadatke kao što su eskalacija privilegija, GUI pristup ili praćenje korisnika, koristite sledeću komandu:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD pruža svestrane nivoe kontrole, uključujući posmatranje, deljenu kontrolu i punu kontrolu, sa sesijama koje traju čak i nakon promene korisničke lozinke. Omogućava slanje Unix komandi direktno, izvršavajući ih kao root za administrativne korisnike. Planiranje zadataka i daljinsko Spotlight pretraživanje su značajne karakteristike, olakšavajući daljinsko, niskoprofilno pretraživanje osetljivih datoteka na više mašina.

#### Nedavne ranjivosti u deljenju ekrana / ARD (2023-2025)

| Godina | CVE | Komponenta | Uticaj | Ispravljeno u |
|--------|-----|------------|--------|----------------|
|2023|CVE-2023-42940|Deljenje ekrana|Netačno renderovanje sesije može uzrokovati da se prenese *pogrešan* desktop ili prozor, što rezultira curenjem osetljivih informacija|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Zaobilaženje zaštite memorije kernela koje se može povezati nakon uspešnog daljinskog prijavljivanja (aktivno iskorišćeno u prirodi)|macOS Ventura 13.6.4 / Sonoma 14.4 (Mar 2024) |

**Saveti za učvršćivanje**

* Onemogućite *Deljenje ekrana*/*Daljinsko upravljanje* kada nije strogo neophodno.
* Održavajte macOS potpuno ažuriranim (Apple obično isporučuje bezbednosne ispravke za poslednje tri glavne verzije).
* Koristite **Jaku lozinku** *i* primenite opciju *“VNC gledatelji mogu kontrolisati ekran sa lozinkom”* **onemogućeno** kada je to moguće.
* Stavite uslugu iza VPN-a umesto da izlažete TCP 5900/3283 internetu.
* Dodajte pravilo vatrozida aplikacije da ograničite `ARDAgent` na lokalnu podmrežu:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour protokol

Bonjour, tehnologija koju je dizajnirao Apple, omogućava **uređajima na istoj mreži da otkriju usluge koje nude jedni drugima**. Poznata i kao Rendezvous, **Zero Configuration**, ili Zeroconf, omogućava uređaju da se pridruži TCP/IP mreži, **automatski odabere IP adresu**, i emitira svoje usluge drugim mrežnim uređajima.

Zero Configuration Networking, koji pruža Bonjour, osigurava da uređaji mogu:

- **Automatski dobiti IP adresu** čak i u odsustvu DHCP servera.
- Izvršiti **prevod imena u adresu** bez potrebe za DNS serverom.
- **Otkrivati usluge** dostupne na mreži.

Uređaji koji koriste Bonjour dodeljuju sebi **IP adresu iz opsega 169.254/16** i proveravaju njenu jedinstvenost na mreži. Mac računari održavaju unos u tabeli rutiranja za ovu podmrežu, koji se može proveriti putem `netstat -rn | grep 169`.

Za DNS, Bonjour koristi **Multicast DNS (mDNS) protokol**. mDNS funkcioniše preko **porta 5353/UDP**, koristeći **standardne DNS upite** ali cilja **multicast adresu 224.0.0.251**. Ovaj pristup osigurava da svi uređaji koji slušaju na mreži mogu primati i odgovarati na upite, olakšavajući ažuriranje njihovih zapisa.

Prilikom pridruživanja mreži, svaki uređaj samostalno bira ime, obično završava u **.local**, koje može biti izvedeno iz imena hosta ili nasumično generisano.

Otkriće usluga unutar mreže olakšava **DNS Service Discovery (DNS-SD)**. Koristeći format DNS SRV zapisa, DNS-SD koristi **DNS PTR zapise** da omogući listanje više usluga. Klijent koji traži određenu uslugu će zatražiti PTR zapis za `<Service>.<Domain>`, primajući zauzvrat listu PTR zapisa formatiranih kao `<Instance>.<Service>.<Domain>` ako je usluga dostupna sa više hostova.

Alat `dns-sd` može se koristiti za **otkrivanje i oglašavanje mrežnih usluga**. Evo nekoliko primera njegove upotrebe:

### Pretraživanje SSH usluga

Da biste pretražili SSH usluge na mreži, koristi se sledeća komanda:
```bash
dns-sd -B _ssh._tcp
```
Ova komanda pokreće pretragu za \_ssh.\_tcp servisima i prikazuje detalje kao što su vremenska oznaka, zastavice, interfejs, domen, tip servisa i ime instance.

### Oglašavanje HTTP Servisa

Da biste oglasili HTTP servis, možete koristiti:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ova komanda registruje HTTP servis nazvan "Index" na portu 80 sa putanjom `/index.html`.

Da biste zatim pretražili HTTP servise na mreži:
```bash
dns-sd -B _http._tcp
```
Kada usluga počne, ona najavljuje svoju dostupnost svim uređajima na podmreži putem multicast-a. Uređaji zainteresovani za ove usluge ne moraju slati zahteve, već jednostavno slušaju ove najave.

Za korisnički prijatniji interfejs, aplikacija **Discovery - DNS-SD Browser** dostupna na Apple App Store-u može vizualizovati usluge koje se nude na vašoj lokalnoj mreži.

Alternativno, mogu se napisati prilagođeni skripti za pretraživanje i otkrivanje usluga koristeći biblioteku `python-zeroconf`. Skripta [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstrira kreiranje pretraživača usluga za `_http._tcp.local.` usluge, štampajući dodate ili uklonjene usluge:
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
### Enumerating Bonjour over the network

* **Nmap NSE** – otkrivanje usluga koje oglašava jedan host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` skripta šalje `_services._dns-sd._udp.local` upit i zatim enumeriše svaki oglašeni tip usluge.

* **mdns_recon** – Python alat koji skenira cele opsege u potrazi za *neispravno konfigurisanim* mDNS responderima koji odgovaraju na unicast upite (korisno za pronalaženje uređaja dostupnih preko podmreža/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Ovo će vratiti hostove koji izlažu SSH putem Bonjura van lokalne veze.

### Security considerations & recent vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Logička greška u *mDNSResponder* omogućila je da kreirani paket izazove **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|Problem tačnosti u *mDNSResponder* mogao bi biti zloupotrebljen za **lokalnu eskalaciju privilegija**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. Ograničite UDP 5353 na *link-local* opseg – blokirajte ili ograničite brzinu na bežičnim kontrolerima, ruterima i firewall-ima zasnovanim na hostu.
2. Potpuno onemogućite Bonjour na sistemima koji ne zahtevaju otkrivanje usluga:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Za okruženja gde je Bonjour potreban interno, ali nikada ne sme preći mrežne granice, koristite *AirPlay Receiver* profil ograničenja (MDM) ili mDNS proxy.
4. Omogućite **System Integrity Protection (SIP)** i redovno ažurirajte macOS – obe ranjivosti su brzo zakrpljene, ali su se oslanjale na to da je SIP omogućen za potpunu zaštitu.

### Disabling Bonjour

Ako postoje zabrinutosti u vezi sa bezbednošću ili drugi razlozi za onemogućavanje Bonjura, može se isključiti pomoću sledeće komande:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Reference

- [**Priručnik za hakere na Mac-u**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
