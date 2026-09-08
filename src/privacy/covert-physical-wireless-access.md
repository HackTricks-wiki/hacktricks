# Prikriveni fizički i bežični pristup

Za detaljnu implementaciju odobrenu od strane vlasnika, koja obuhvata outbound rendezvous, oporavak napajanja/uplink-a, minimalan broj secrets koji se čuvaju na uređaju, testiranje capture-a i monitoring radi mogućeg otkrivanja, pogledajte [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Promena mrežne putanje može promeniti i prividno fizičko poreklo. Sofisticirani akter može koristiti obližnji kompromitovani sistem, skriveni uređaj, javni pristup, cellular backhaul ili satelitski receiver, tako da logovi cilja upućuju dalje od operatora. Ništa od toga ne uklanja fizičke, radio ili provider dokaze; attribution se premešta u različite skupove podataka.

## Matrica tehnika

| Tehnika | Prividno poreklo | Neophodan uslov | Dokazi visoke vrednosti |
|---|---|---|---|
| Nearby wireless pivot | poslovni ili stambeni objekat pored cilja | kompromitovani dual-homed host i pristup ciljnom Wi-Fi-ju | endpoint logovi susednog hosta, RF asocijacija i ciljni RADIUS/DHCP |
| Public/guest network | venue NAT ili tunnel exit | zakonit pristup ili zaobilaženje kontrole pristupa | captive portal, DHCP, AP asocijacija, CCTV i evidencija plaćanja/lokacije |
| Covert drop device | ciljna/obližnja wired, Wi-Fi ili cellular adresa | fizičko postavljanje ili dostava | switchport/USB, RF, inventar, napajanje i telemetrija outbound tunnel-a |
| Cellular router/eSIM | carrier NAT ili namenski APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier nalog i vremensko usklađivanje saobraćaja |
| Satellite-link abuse | subscriber adresa u footprint-u snopa | slabost specifična za protokol i servis | RF lokacija, uplink tok, nemoguć RTT/routing i evidencija provider-a |

## Nearest-neighbor attack

Volexity je dokumentovao APT28/GRU operaciju iz 2022. godine, u kojoj je akter bio udaljen od svog krajnjeg cilja. Izveo je password spraying nad javnim servisom cilja kako bi dobio važeće credentials, ali je MFA sprečio direktan Internet login. Enterprise Wi-Fi cilja prihvatao je te credentials bez MFA-a. Akter je kompromitovao organizacije koje su se fizički nalazile blizu cilja, pronašao dual-homed sistem sa bežičnim dometom i iskoristio taj sistem za autentifikaciju na ciljni Wi-Fi. Volexity je ovu tehniku nazvao **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Novina je u kompoziciji. Nijedan operator ne putuje do cilja, a MFA Internet-facing servisa i dalje funkcioniše. Kompromitovani sused obezbeđuje fizičku blizinu; ukradeni credential cilja obezbeđuje logički pristup; ciljni Wi-Fi postaje putanja za prelazak granice.

### Preconditions and visibility

- Sistem u blizini mora moći da se kontroliše remotely i da ima kompatibilan radio ili pristup drugom obližnjem pivotu.
- Ciljni SSID mora dosezati taj sistem, a Wi-Fi admission mora prihvatati credential/certificate/device state koji se može ponovo koristiti.
- Pivotu su često potrebne dve istovremene putanje: jedna nazad do operatora, a druga u ciljni WLAN.
- Cilj može videti novu station MAC adresu i legitiman username, ali ne i odgovarajući managed-device certificate, posture, istoriju ili očekivani ulazak u zgradu.
- Logovi susednog endpointa mogu pokazivati wireless scans, nove profile, promene interfejsa, tunneling i remote-control aktivnosti.

### Detection and prevention

1. Zahtevati certificate-backed EAP-TLS i managed-device posture za enterprise Wi-Fi; nemojte dozvoliti da password koji nije prošao MFA na Internetu bude dovoljan samo zato što stiže putem radio-veze.
2. Povezati RADIUS authentication sa MDM/NAC identitetom, istorijskim station/device bindingom, AP lokacijom, događajima fizičkog pristupa i istovremenim sesijama.
3. Generisati alert kada se account prvi put asocira, sa neuobičajene AP edge lokacije, bez managed certificate-a ili dok je isti identitet aktivan na drugom mestu.
4. Nadzirati endpointe sposobne za bridging interfejsa. Na Windows, Linux i network appliances sistemima istražiti neočekivane WLAN profile, forwarding/NAT konfiguraciju, virtual adapters i persistent tunnels.
5. Smanjiti nepotrebno širenje signala razumnim postavljanjem AP-ova i planiranjem snage. Ovo je pomoćna kontrola, a ne authentication.
6. Koordinisati incident response sa susednim zakupcima: konačni radio-izvor može i sam biti žrtva.

[Owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reprodukuje ove observables bez napada na suseda.

## Public venues and third-party Wi-Fi

Korišćenje Wi-Fi mreže u kafiću, hotelu, na aerodromu ili u opštinskom objektu menja IP adresu prikazanu odredištu. Ne stvara anonymity. Venue ili njegov provider mogu čuvati AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation i flow logs. Fizički ulazak, CCTV, kupovina, podaci o lokaciji mobilnog uređaja i evidencije putovanja mogu povezati digitalni događaj sa osobom.

Actor može pokušati da umanji značaj jednog identifikatora korišćenjem randomized MAC adresa, zasebnog uređaja, gotovine ili tunela. Korelacija na više slojeva i dalje je moguća putem vremena dolaska, ponavljanog obrasca posećivanja venue-a, radio fingerprints, ponašanja portala, vremenskog usklađivanja saobraćaja, snimaka kamera i tunnel provider-a. VPN takođe premešta odredište iz logova venue-a u VPN logove; ne uklanja saznanje venue-a da je uređaj bio prisutan.

Defenders of public access sistema treba da izoluju klijente, blokiraju lateral traffic, koriste WPA2/3-Enterprise ili ključeve po uređaju gde je to izvodljivo, zadržavaju proporcionalne DHCP/RADIUS/security logove, štite captive portale i objave abuse proces. Red teams treba da koriste takav venue samo kada njegovi uslovi i engagement to dozvoljavaju; zaobilaženje portala, krađa pristupa ili ciljanje drugih gostiju nije authorized testing prečica.

## Covert drop devices and warshipping

Drop je mali sistem postavljen u objektu ili dostavljen u njega, kojim se zatim upravlja putem outbound Ethernet-a, Wi-Fi-ja ili cellular veze. „Warshipping“ pakuje uređaj tako da ga uobičajena dostava unese unutar radio-perimetra. Mogući hardware se kreće od single-board computer-a do izmenjenog punjača, USB periferije, network appliance-a ili battery-powered modema.

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Uređaj može obezbediti udaljeni foothold, obavljati wireless merenja, emulirati authorized exercise peripheral ili prosleđivati saobraćaj. Njegov prividni izvor je lokalni, ali stvara fizičke tragove: serijske brojeve, ambalažu, otiske, kamere, evidencije pristupa, potrošnju energije, USB deskriptore, pregovaranje switchporta, DHCP fingerprinting, OUI/randomization ponašanje MAC adrese, RF emisije i ponavljajuće rendezvous konekcije.

### Defensive controls

- Održavajte procedure prijema i inventara opreme; pregledajte neočekivanu elektroniku i pakete adresirane na nepostojeće zaposlene.
- Koristite 802.1X/NAC na žičanom i wireless pristupu, onemogućite nekorišćene portove i nepoznate uređaje smeštajte u ograničeni remediation VLAN.
- Upozoravajte na nove DHCP fingerprinting obrasce, locally administered MAC adrese koje opstaju, nove USB network/HID uređaje, neautorizovani Wi-Fi Direct/Bluetooth i dugotrajne outbound tunnel konekcije.
- Napravite baseline switchporta, power-over-Ethernet, DNS i TLS ponašanja. Mali host bez zapisa u inventaru, koji periodično uspostavlja šifrovane konekcije, predstavlja jači signal od samog „Raspberry Pi OUI“.
- Tokom vežbe napravite inventar, označite uređaje, definišite scope, koristite enkripciju, obezbedite remote kill, postavite rok za preuzimanje i osigurajte da gubitak ne može otkriti credentials koje se mogu ponovo koristiti.

## Cellular and eSIM backhaul

Cellular modem zaobilazi Internet gateway cilja i može održavati drop dostupnim iza carrier NAT-a putem outbound rendezvous konekcije. Mobilne adrese mogu da se menjaju ili dele; cellular operator i dalje poseduje snažne podatke o subscriberu i mreži: identitet SIM/eSIM-a, IMSI, dodeljene adrese/portove, vreme komunikacije sa ćelijom/sektorom, kao i evidencije naloga/plaćanja i roaminga.

Iz perspektive enterprise-a, neočekivane modeme i personalne hotspotove otkrivajte wireless/RF surveys postupcima, USB/PCI inventarom endpointa, MDM ograničenjima, nadzorom rogue SSID-ja i fizičkim pregledom. Drop koji koristi cellular za kontrolu i dalje može biti otkriven na osnovu lokalnog Ethernet/Wi-Fi ponašanja i radio-emisija.

Za authorized exercise, organizacija treba da poseduje subscription i modem, evidentira identifikatore zajedno sa controllerom i proveri da li uslovi carrier/provider-a dozvoljavaju takav saobraćaj. Prepaid label ili kupovina cryptocurrency-em ne brišu evidencije baznih stanica, uređaja ili prodajnog mesta.

## MAC randomization and device fingerprinting

Moderni sistemi mogu koristiti locally administered random MAC adresu za svaku mrežu. Time se smanjuje pasivno dugoročno praćenje pomoću stabilne fabričke MAC adrese; to ne skriva:

- vreme probe/association događaja i skup zahtevanih mrežnih mogućnosti;
- 802.11 information elements, podržane rates i vendor-specific ponašanje;
- DHCP opcije/hostname, IPv6 identifikatore i captive-portal/browser fingerprint;
- authenticated 802.1X identity ili certificate;
- account, tunnel i traffic pattern na višem sloju; ili
- fizičko posmatranje.

Defenders ne bi trebalo da koriste MAC allowlists kao autentikaciju. Povežite radio identitet sa certificate/device posture podacima i promenljive MAC adrese smatrajte normalnim, osim ako je drugi kontekst anomalijski.

## Satellite-link hijacking

Kaspersky je dokumentovao da je Turla koristila slabosti starijeg jednosmernog DVB-S satellite Internet-a. Prema opisanom modelu, legitimni remote subscriber slao je outbound zahteve preko terrestrial linka, ali je downstream podatke primao putem nešifrovanog wide-area satellite broadcast-a. Actor unutar satellite footprint-a mogao je da posmatra downlink, izabere IP adresu aktivnog subscriber-a i organizuje da C2 odgovori budu adresirani na tu IP adresu. I legitimni subscriber i actor primali su broadcast; actor je izdvajao saobraćaj za izabrani port, dok je legitimni subscriber odbacivao unsolicited pakete. C2 operator je zatim izgledao kao da koristi adresu satellite provider-a iz druge geografije.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Ovo je bilo specifično za protokol/uslugu, ograničeno propusnim opsegom i nije bilo ekvivalentno kompromitovanju modernog dvosmernog šifrovanog satelitskog terminala. Takođe nije skrivao putanju odlaznog zahteva aktera od dovoljno sposobnog posmatrača. Mogućnosti za detekciju obuhvataju asimetrično/nemoguće rutiranje, saobraćaj ka pretplatniku koji nije inicirao tok, neuobičajene odredišne portove, telemetriju provajdera, ispitivanje lokacije prijemnika/RF-a i konfiguraciju malware-a. Iskoristite ovaj slučaj da preispitate pretpostavku da geolociranje C2 IP adrese geolocira njenog kontrolora — ne kao recept za izradu.

## Radni list za fizičko-digitalnu korelaciju

Kada je naizgled lokalni izvor sumnjiv, napravite jednu vremensku liniju:

1. normalizujte satove AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch i sistema za fizički pristup;
2. identifikujte prvo radio-povezivanje ili uspostavljanje veze, a ne samo prvi alert;
3. mapirajte stanicu na sertifikat, stanje uređaja, DHCP fingerprint i lokaciju switch-a/AP-a;
4. potražite istovremenu aktivnost remote-control/tunelovanja na obližnjim sistemima;
5. pregledajte isporuke, posetioce, inventarske izuzetke, kamere i RF nalaze u skladu sa važećim pravilima/zakonom;
6. sačuvajte sumnjivi uređaj i volatilno stanje mreže; nemojte naslepo izvršiti power-cycle;
7. utvrdite da li je naizgledni izvor infrastruktura pod kontrolom aktera ili druga žrtva.

## References

- [1] [Volexity — Napad najbližeg suseda: Kako je ruski APT naoružao obližnje Wi-Fi mreže](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control na nebu](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Dodaci hardvera (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Smernice za zaštitu bežičnih lokalnih mreža](https://csrc.nist.gov/pubs/sp/800/153/final)
