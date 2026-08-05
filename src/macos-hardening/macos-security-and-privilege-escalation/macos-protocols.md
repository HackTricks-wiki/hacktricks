# macOS mrežne usluge i protokoli

{{#include ../../banners/hacktricks-training.md}}

## Usluge za daljinski pristup

Ovo su uobičajene macOS usluge kojima se može pristupiti daljinski.\
Ove usluge možete omogućiti/onemogućiti u `System Settings` --> `Sharing`

- **VNC**, poznat kao “Screen Sharing” (tcp:5900)
- **SSH**, nazvan “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), ili “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, poznat kao “Remote Apple Event” (tcp:3031)

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
### Lokalno enumerisanje konfiguracije deljenja

Kada već imate lokalno izvršavanje koda na Mac računaru, **proverite konfigurisano stanje**, a ne samo listening sockets. `systemsetup` i `launchctl` obično pokazuju da li je servis administrativno omogućen, dok `kickstart` i `system_profiler` pomažu u potvrđivanju efektivne ARD/Sharing konfiguracije:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) je unapređena verzija [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) prilagođena za macOS, koja nudi dodatne funkcije. Značajna ranjivost u ARD-u jeste njegov metod autentifikacije za lozinku kontrolnog ekrana, koji koristi samo prvih 8 karaktera lozinke, zbog čega je podložan [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) napadima pomoću alata kao što su Hydra ili [GoRedShell](https://github.com/ahhh/GoRedShell/), pošto ne postoje podrazumevana ograničenja brzine.<sup>[[3]](#references)</sup>

Ranjive instance mogu se identifikovati pomoću **nmap** skripte `vnc-info`. Servisi koji podržavaju `VNC Authentication (2)` posebno su podložni brute force attacks napadima zbog skraćivanja lozinke na 8 karaktera.

Da biste omogućili ARD za različite administrativne zadatke, kao što su privilege escalation, GUI access ili monitoring korisnika, koristite sledeću komandu:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD pruža fleksibilne nivoe kontrole, uključujući nadgledanje, deljenu kontrolu i potpunu kontrolu, pri čemu sesije opstaju čak i nakon promene korisničkih lozinki. Omogućava direktno slanje Unix komandi i njihovo izvršavanje kao root za administrativne korisnike. Zakazivanje zadataka i Remote Spotlight pretraga predstavljaju značajne funkcije, omogućavajući udaljene pretrage osetljivih datoteka sa malim uticajem na više mašina.

Iz perspektive operatora, **Monterey 12.1+ je promenio tokove rada za remote-enablement** u upravljanim flotama. Ako već kontrolišete žrtvin MDM, Apple-ova komanda `EnableRemoteDesktop` često je najčistiji način za aktiviranje funkcionalnosti remote desktopa na novijim sistemima. Ako već imate foothold na hostu, `kickstart` je i dalje koristan za pregled ili ponovno podešavanje ARD privilegija iz komandne linije.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth zloupotreba kopiranja datoteka

Nedavna istraživanja `screensharingd` pokazala su da Apple Screen Sharing nije uvek samo klasični VNC auth: novije verzije koriste **RFB `003.889`** i oglašavaju **security type `36`**, gde **SRP** najpre obavlja autentifikaciju, a **ChaCha20-Poly1305** se instalira tek nakon uspešnog poziva `ccsrp_server_verify_session`. Javna analiza navodi da je bug ispravljen u **macOS Tahoe 26.6** (**27. jul 2026.**).<sup>[[8]](#references)[[9]](#references)</sup>

Koristan obrazac koji treba zapamtiti jeste **bypass parsera zastarelog statusa**: nakon uspešnog čitanja dužine od 4 bajta, svaka grana za prekoračenje veličine ili grešku mora vratiti novu grešku. Na pogođenim verzijama, SRP dužina frame-a u big-endian formatu **`>= 32768`** dovodi do toga da putanja odbijanja ponovo koristi prethodni uspeh funkcije `NetBufferRead` (`0`), pa caller postavlja sesiju kao autentifikovanu iako se dokaz lozinke nije izvršio i nije instalirana nikakva transportna kriptografija. Pošto nepročitani bajtovi ostaju u deljenom socket bufferu, napadač može **pipeline-ovati neispravne SRP podatke i post-auth RFB poruke u istom TCP burstu** i naterati ih da budu obrađeni kao **cleartext autentifikovani saobraćaj**.<sup>[[8]](#references)</sup>

Nakon bypass-a, Apple-ova vlasnička poruka za **file-copy** **`0x22`** postaje **root primitiv za čitanje/pisanje datoteka**, zato što `screensharingd` radi kao root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: čitanje proizvoljnog fajla
- `kind=2` / `StartFileReceive`: upis proizvoljnog fajla
- Različite vrednosti `sid` omogućavaju da se više transakcija izvršava kroz jednu konekciju
- U `kind=101` (`NewItem`), podesite bajt `14` / `arg[0]` na `0x01` za običan fajl, payload offset `+42` na **ne-nultu** veličinu fajla u big-endian formatu, a payload offset `+0x5a` na željeni Unix mode (`0600` ako je cilj crontab)

Zanimljivi post-write pivots na putanjama sa dozvolom upisa uključuju **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** i **`/var/root/.ssh/authorized_keys`**. **SIP ne sprečava auth bypass niti root čitanje fajlova**, ali blokira neke ciljeve upisa, kao što je **`/var/at`**, pa izvršavanje zasnovano na cron-u funkcioniše samo kada je SIP onemogućen. Na hostovima sa podrazumevano omogućenim SIP-om, razmišljajte u terminima **„root upisa fajla u privilegovane fajlove koji se automatski konzumiraju“**, a ne trenutnog izvršavanja koda.<sup>[[8]](#references)</sup>

Još jedna SRP zamka iz istog istraživanja: serveri moraju da provere **`A mod N != 0`** (prema RFC 5054), a ne samo `A > 0`. Prihvatanje **`A = N`** može da postavi shared secret na nulu i ugrozi proveru lozinke.<sup>[[8]](#references)[[10]](#references)</sup>

**Ideje za detekciju**

- Security type `36` sesije kod kojih je dužina prvog SRP frame-a **`>= 32768`**
- Sesije koje počnu da obrađuju cleartext **`0x22`** file-copy saobraćaj pre uspešnog SRP proof-a / instaliranja cipher-a
- Ponovljeni kratkotrajni pokušaji prema **TCP/5900**, uz više vrednosti file-copy `sid` u jednom burst-u
- Neočekivano kreiranje **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** ili **`/var/root/.ssh/authorized_keys`** nakon izlaganja Screen Sharing servisa

### Pentesting Remote Apple Events (RAE / EPPC)

Apple ovu funkciju u modernim System Settings nazivа **Remote Application Scripting**. Ispod haube ona izlaže **Apple Event Manager** udaljenim sistemima preko **EPPC** na **TCP/3031**, putem servisa `com.apple.AEServer`. Palo Alto Unit 42 ju je ponovo istakao kao praktičan **macOS lateral movement** primitive, jer validni credential-i i omogućen RAE servis omogućavaju operatoru da upravlja aplikacijama koje podržavaju scripting na udaljenom Mac-u.<sup>[[6]](#references)</sup>

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
Osnovni test povezivanja sa drugog Mac računara:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
U praksi, slučaj zloupotrebe nije ograničen samo na Finder. Svaka **scriptable application** koja prihvata potrebne Apple events predstavlja udaljenu površinu za napad, što RAE čini naročito zanimljivim nakon krađe akreditiva na internim macOS mrežama.

#### Nedavne ranjivosti Screen-Sharing / ARD-a (2023-2025)

| Godina | CVE | Komponenta | Uticaj | Ispravljeno u |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Neispravno prikazivanje sesije moglo je dovesti do toga da se prenese *pogrešna* radna površina ili prozor, što je rezultiralo curenjem osetljivih informacija|macOS Sonoma 14.2.1 (decembar 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Korisnik sa pristupom za screen sharing možda je mogao da vidi **ekran drugog korisnika** zbog problema sa upravljanjem stanjem|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (oktobar-decembar 2024) |

**Saveti za hardening**

* Onemogućite *Screen Sharing*/*Remote Management* kada nisu nužno potrebni.
* Održavajte macOS potpuno ažuriranim (Apple uglavnom isporučuje bezbednosne ispravke za poslednja tri glavna izdanja).
* Koristite **Strong Password** *i* po mogućnosti nametnite da opcija *“VNC viewers may control screen with password”* bude **onemogućena**.
* Postavite servis iza VPN-a umesto da TCP 5900/3283 bude izložen Internetu.
* Dodajte pravilo za Application Firewall koje ograničava `ARDAgent` na lokalnu podmrežu:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, tehnologija koju je dizajnirao Apple, omogućava **uređajima na istoj mreži da otkriju servise koje drugi uređaji nude**. Poznat i kao Rendezvous, **Zero Configuration** ili Zeroconf, omogućava uređaju da se pridruži TCP/IP mreži, **automatski izabere IP adresu** i emituje svoje servise drugim mrežnim uređajima.

Zero Configuration Networking, koji obezbeđuje Bonjour, omogućava uređajima da:

- **Automatski dobiju IP adresu** čak i kada nema DHCP servera.
- Obavljaju **prevođenje imena u adresu** bez potrebe za DNS serverom.
- **Otkrivaju servise** dostupne na mreži.

Uređaji koji koriste Bonjour dodeljuju sebi **IP adresu iz opsega 169.254/16** i proveravaju njenu jedinstvenost na mreži. Mac računari održavaju unos u routing tabeli za ovu podmrežu, što se može proveriti pomoću `netstat -rn | grep 169`.

Za DNS, Bonjour koristi **Multicast DNS (mDNS) protocol**. mDNS funkcioniše preko **porta 5353/UDP**, koristeći **standardne DNS upite**, ali usmerene na **multicast adresu 224.0.0.251**. Ovaj pristup omogućava svim uređajima na mreži koji osluškuju da prime i odgovore na upite, čime se olakšava ažuriranje njihovih zapisa.

Prilikom pridruživanja mreži, svaki uređaj sam bira ime, koje se obično završava nastavkom **.local** i može biti izvedeno iz hostname-a ili nasumično generisano.

Otkrivanje servisa unutar mreže omogućava **DNS Service Discovery (DNS-SD)**. Koristeći format DNS SRV zapisa, DNS-SD upotrebljava **DNS PTR zapise** za omogućavanje izlistavanja više servisa. Klijent koji traži određeni servis zatražiće PTR zapis za `<Service>.<Domain>` i, ako je servis dostupan sa više hostova, kao odgovor dobiti listu PTR zapisa u formatu `<Instance>.<Service>.<Domain>`.

Alat `dns-sd` može se koristiti za **otkrivanje i oglašavanje mrežnih servisa**. Evo nekoliko primera njegove upotrebe:

### Pretraga SSH servisa

Za pretragu SSH servisa na mreži koristi se sledeća komanda:
```bash
dns-sd -B _ssh._tcp
```
Ova komanda pokreće pretraživanje usluga \_ssh.\_tcp i prikazuje detalje kao što su vremenska oznaka, zastavice, interfejs, domen, tip usluge i naziv instance.

### Oglašavanje HTTP usluge

Da biste oglasili HTTP uslugu, možete koristiti:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ova komanda registruje HTTP servis pod nazivom „Index“ na portu 80 sa putanjom `/index.html`.

Zatim, da biste pretražili HTTP servise na mreži:
```bash
dns-sd -B _http._tcp
```
Kada se servis pokrene, on objavljuje svoju dostupnost svim uređajima na podmreži tako što multicast-uje svoje prisustvo. Uređaji zainteresovani za ove servise ne moraju da šalju zahteve, već samo slušaju ova obaveštenja.

Za korisnički prijatniji interfejs, aplikacija **Discovery - DNS-SD Browser**, dostupna u Apple App Store-u, može da vizualizuje servise ponuđene na vašoj lokalnoj mreži.

Alternativno, mogu se napisati prilagođene skripte za pregledanje i otkrivanje servisa pomoću biblioteke `python-zeroconf`. Skripta [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) prikazuje kreiranje service browser-a za servise `_http._tcp.local.`, uz ispisivanje dodatih ili uklonjenih servisa:
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
### Lov na macOS-specifični Bonjour

Na macOS mrežama, Bonjour je često najlakši način za pronalaženje **površina za udaljenu administraciju** bez direktnog kontakta sa metom. Apple Remote Desktop može da otkriva klijente putem Bonjour-a, pa su isti podaci o otkrivanju korisni i napadaču.
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
Za šire tehnike **mDNS spoofing, impersonation i cross-subnet discovery**, pogledajte posvećenu stranicu:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumeracija Bonjour-a preko mreže

* **Nmap NSE** – otkrivanje servisa koje oglašava jedan host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Skripta `dns-service-discovery` šalje upit `_services._dns-sd._udp.local`, a zatim enumeriše svaki oglašeni tip servisa.

* **mdns_recon** – Python alat koji skenira čitave opsege u potrazi za *misconfigured* mDNS responderima koji odgovaraju na unicast upite (korisno za pronalaženje uređaja dostupnih preko subnetova/WAN-a):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Ovo će vratiti hostove koji izlažu SSH putem Bonjour-a izvan lokalnog linka.

### Bezbednosne napomene i nedavne ranjivosti (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Srednja|Greška u logici u *mDNSResponder*-u omogućila je da posebno napravljen paket izazove **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|Visoka|Problem sa ispravnošću u *mDNSResponder*-u mogao je biti zloupotrebljen za **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Smernice za ublažavanje**

1. Ograničite UDP 5353 na *link-local* opseg – blokirajte ga ili ograničite njegovu brzinu na wireless kontrolerima, ruterima i host-based firewall-ima.
2. Potpuno onemogućite Bonjour na sistemima kojima nije potrebno otkrivanje servisa:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. U okruženjima u kojima je Bonjour interno potreban, ali nikada ne sme prelaziti granice mreže, koristite ograničenja *AirPlay Receiver* profila (MDM) ili mDNS proxy.
4. Omogućite **System Integrity Protection (SIP)** i redovno ažurirajte macOS – obe navedene ranjivosti brzo su zakrpljene, ali su se oslanjale na to da SIP bude omogućen radi potpune zaštite.

### Onemogućavanje Bonjour-a

Ako postoje bezbednosne ili drugi razlozi za onemogućavanje Bonjour-a, može se isključiti pomoću sledeće komande:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Reference

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - About the security content of macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - About the security content of macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
