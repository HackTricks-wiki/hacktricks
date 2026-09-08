# Prikriveni fizički i bežični pristup

{{#include ../banners/hacktricks-training.md}}

Za detaljnu implementaciju odobrenu od vlasnika, koja obuhvata outbound rendezvous, oporavak napajanja/uplink-a, minimalne secrets koje uređaj poseduje, testiranje capture-a i monitoring radi moguće detekcije, pogledajte [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Promena mrežne putanje takođe može promeniti prividno fizičko poreklo. Sofisticirani actor može koristiti obližnji kompromitovani sistem, skriveni uređaj, javni pristup, cellular backhaul ili satelitski prijemnik tako da logovi cilja upućuju dalje od operatora. Nijedna od ovih metoda ne uklanja fizičke, radio ili evidence provajdera; ona prebacuje attribution u druge datasete.

## Matrica tehnika

| Tehnika | Prividno poreklo | Neophodan uslov | Dokazi visoke vrednosti |
|---|---|---|---|
| Nearby wireless pivot | poslovni ili stambeni objekat pored cilja | kompromitovani dual-homed host i Wi-Fi pristup cilja | endpoint logovi susednog hosta, RF asocijacija i RADIUS/DHCP cilja |
| Public/guest network | venue NAT ili tunnel exit | zakonit pristup ili zaobilaženje kontrole pristupa | captive portal, DHCP, AP asocijacija, CCTV i evidencija plaćanja/lokacije |
| Covert drop device | žična, Wi-Fi ili cellular adresa cilja/okolnog prostora | fizičko postavljanje ili dostava | switchport/USB, RF, inventory, napajanje i telemetry outbound tunnela |
| Cellular router/eSIM | carrier NAT ili namenski APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier nalog i timing saobraćaja |
| Satellite-link abuse | subscriber adresa u footprint-u snopa | slabost specifična za protokol i servis | RF lokacija, uplink flow, nemoguć RTT/routing i records provajdera |

## Nearest-neighbor attack

Volexity je dokumentovao APT28/GRU operaciju iz 2022. godine u kojoj je actor bio udaljen od krajnjeg cilja. Izveo je password spraying nad javnim servisom cilja kako bi dobio validne credentials, ali je MFA sprečio direktno Internet prijavljivanje. Enterprise Wi-Fi cilja prihvatao je te credentials bez MFA-a. Actor je kompromitovao organizacije koje su se fizički nalazile blizu cilja, pronašao dual-homed sistem sa wireless dometom i iskoristio taj sistem za autentifikaciju na Wi-Fi mreži cilja. Volexity je ovu tehniku nazvao **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Novina je u kombinaciji. Nijedan operator ne putuje do mete, a MFA Internet-facing service-a i dalje funkcioniše. Kompromitovani sused obezbeđuje fizičku blizinu; ukradeni credential mete obezbeđuje logički pristup; target Wi-Fi postaje putanja za prelazak granice.

### Preconditions and visibility

- Obližnji sistem mora moći da se kontroliše na daljinu i da ima kompatibilan radio ili pristup drugom obližnjem pivotu.
- Target SSID mora dopirati do tog sistema, a Wi-Fi admission mora prihvatati credential/certificate/device state koji može ponovo da se koristi.
- Pivotu su često potrebne dve istovremene putanje: jedna nazad do operatora, a druga ka target WLAN-u.
- Target može videti novu station MAC adresu i legitiman username, ali bez odgovarajućeg managed-device certificate-a, posture-a, istorije ili očekivanog ulaska u zgradu.
- Logovi neighbor endpoint-a mogu pokazati wireless scan-ove, nove profile, promene interfejsa, tunneling i remote-control aktivnost.

### Detection and prevention

1. Zahtevajte certificate-backed EAP-TLS i managed-device posture za enterprise Wi-Fi; nemojte smatrati password koji je pao na MFA proveri na Internetu dovoljnim samo zato što stiže putem radio-veze.
2. Povežite RADIUS authentication sa MDM/NAC identitetom, istorijskim povezivanjem station/device identiteta, lokacijom AP-a, događajima fizičkog pristupa i istovremenim session-ima.
3. Generišite alert kada se account prvi put asocira, sa neuobičajene ivice AP-a, bez managed certificate-a ili dok je isti identity aktivan na drugom mestu.
4. Nadgledajte endpoint-e sposobne za bridging interfejsa. Na Windows, Linux i network appliance sistemima istražite neočekivane WLAN profile, forwarding/NAT konfiguraciju, virtual adaptere i persistent tunnel-e.
5. Smanjite nepotrebno širenje signala razumnim postavljanjem AP-ova i planiranjem snage. Ovo je pomoćna kontrola, a ne authentication.
6. Koordinirajte incident response sa susednim zakupcima: konačni izvor radio-signala može i sam biti victim.

[Lab u vlasništvu dve organizacije](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reprodukuje ove observables bez napada na suseda.

## Public venues and third-party Wi-Fi

Korišćenje Wi-Fi mreže u kafiću, hotelu, na aerodromu ili u opštinskom objektu menja IP adresu prikazanu destinaciji. To ne stvara anonimnost. Objekat ili njegov provider mogu čuvati podatke o asocijaciji sa AP-om, MAC adresi uređaja, DHCP lease-u, account-u captive portal-a, SMS/email validaciji i flow logovima. Fizički ulazak, CCTV, kupovina, podaci o lokaciji mobilnog uređaja i putovanja mogu povezati digitalni događaj sa osobom.

Actor može pokušati da smanji jedan trag korišćenjem randomizovanih MAC adresa, posebnog uređaja, gotovine ili tunnel-a. Korelacija kroz više slojeva i dalje je moguća na osnovu vremena dolaska, ponavljanog obrasca posećivanja objekta, radio fingerprint-a, ponašanja portal-a, vremena odvijanja saobraćaja, snimaka kamera i tunnel provider-a. VPN takođe pomera destinaciju iz logova objekta u VPN logove; ne uklanja saznanje objekta da je uređaj bio prisutan.

Defenders javnog pristupa treba da izoluju klijente, blokiraju lateralni saobraćaj, koriste WPA2/3-Enterprise ili per-device ključeve gde je to izvodljivo, čuvaju proporcionalne DHCP/RADIUS/security logove, zaštite captive portal-e i objave proces za prijavu abuse-a. Red teams treba da koriste takav objekat samo kada njegovi uslovi i engagement to dozvoljavaju; zaobilaženje portal-a, krađa pristupa ili targeting drugih gostiju nije authorized testing prečica.

## Covert drop devices and warshipping

Drop je mali sistem postavljen u objekat ili dostavljen u njega, kojim se zatim upravlja preko outbound Ethernet-a, Wi-Fi-ja ili cellular veze. „Warshipping“ pakuje uređaj tako da ga obična dostava unese unutar radio-perimetra. Mogući hardware obuhvata single-board computer, modifikovani charger, USB peripheral, network appliance ili battery-powered modem.

Operativna arhitektura:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Uređaj može obezbediti udaljeni pristup, obavljati wireless merenja, emulirati autorizovanu peripheral opremu za vežbu ili prosleđivati saobraćaj. Njegov prividni izvor je lokalni, ali stvara fizičke tragove: serijske brojeve, ambalažu, fingerprints, kamere, evidencije pristupa, potrošnju energije, USB deskriptore, switchport pregovaranje, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions i ponavljajuće rendezvous connections.

### Defensive controls

- Održavajte procedure za prijemnu prostoriju i inventar imovine; pregledajte neočekivanu elektroniku i pakete adresirane na nepostojeće zaposlene.
- Koristite 802.1X/NAC za žični i wireless pristup, onemogućite nekorišćene portove i nepoznate uređaje smeštajte u ograničeni remediation VLAN.
- Upozoravajte na nove DHCP fingerprints, locally administered MAC adrese koje opstaju, nove USB network/HID uređaje, neautorizovani Wi-Fi Direct/Bluetooth i dugotrajne outbound tunnels.
- Uspostavite baseline za switchport, power-over-Ethernet, DNS i TLS ponašanje. Mali host bez inventarskog zapisa koji uspostavlja periodične encrypted connections predstavlja jači signal nego samo „Raspberry Pi OUI“.
- Tokom vežbe napravite inventar, označite uređaje, definišite scope, izvršite enkripciju, obezbedite remote kill, postavite rok za preuzimanje i osigurajte da gubitak ne može otkriti ponovo upotrebljive credentials.

## Cellular and eSIM backhaul

Cellular modem zaobilazi Internet gateway cilja i može održavati drop dostupnim iza carrier NAT-a putem outbound rendezvous veze. Mobilne adrese mogu da se menjaju ili dele; cellular operator i dalje ima snažne subscriber i network dokaze: identitet SIM/eSIM-a, IMSI, dodeljene adrese/portove, vreme ćelije/sektora, kao i account/payment i roaming zapise.

Iz perspektive preduzeća, neočekivane modeme i personal hotspots treba otkrivati wireless/RF survey-ima, inventarom endpoint USB/PCI uređaja, MDM ograničenjima, nadzorom rogue-SSID-ja i fizičkim pregledom. Drop koji koristi cellular za kontrolu i dalje može biti otkriven na osnovu svog lokalnog Ethernet/Wi-Fi ponašanja i radio emisija.

Za autorizovane vežbe, organizacija treba da poseduje subscription i modem, da identifikatore evidentira kod controller-a i proveri da li uslovi carrier/provider-a dozvoljavaju takav saobraćaj. Prepaid label ili kupovina cryptocurrency-jem ne brišu zapise o baznim stanicama, uređaju ili maloprodaji.

## MAC randomization and device fingerprinting

Moderni sistemi mogu koristiti locally administered random MAC po mreži. To smanjuje pasivno dugoročno praćenje pomoću stabilnog fabričkog MAC-a; ne skriva:

- probe/association timing i skup traženih network capabilities;
- 802.11 information elements, supported rates i vendor-specific behavior;
- DHCP options/hostname, IPv6 identifikatore i captive-portal/browser fingerprint;
- authenticated 802.1X identity ili certificate;
- nalog na višem sloju, tunnel i traffic pattern; ili
- fizičko posmatranje.

Defenders ne bi trebalo da koriste MAC allowlists kao authentication. Povežite radio identitet sa certificate/device posture podacima i tretirajte promenljive MAC adrese kao normalne, osim ako je drugi kontekst anomalijski.

## Satellite-link hijacking

Kaspersky je dokumentovao da je Turla koristila slabosti starijeg jednosmernog DVB-S satellite Internet-a. Prema opisanom modelu, legitimni remote subscriber je slao outbound requests putem terrestrial link-a, ali je downstream data primao preko nešifrovanog wide-area satellite broadcast-a. Actor unutar satellite footprint-a mogao je da posmatra downlink, izabere IP adresu aktivnog subscriber-a i obezbedi da C2 odgovori budu adresirani na tu IP adresu. I legitimni subscriber i actor primali su broadcast; actor je izdvajao saobraćaj za izabrani port, dok je legitimni subscriber odbacivao unsolicited packets. C2 operator je zatim izgledao kao da koristi adresu satellite provider-a u drugoj geografiji.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Ovo je bilo specifično za određeni protokol/servis, ograničeno propusnim opsegom i nije ekvivalent kompromitovanju modernog dvosmernog šifrovanog satelitskog terminala. Takođe nije skrivalo odlaznu putanju zahteva aktera od dovoljno sposobnog posmatrača. Mogućnosti za detekciju obuhvataju asimetrično/nemoguće rutiranje, saobraćaj ka pretplatniku koji nije inicirao tok, neuobičajene odredišne portove, telemetriju provajdera, istragu lokacije prijemnika/RF-a i konfiguraciju malware-a. Koristite ovaj slučaj da preispitate pretpostavku da geolociranje C2 IP adrese geolocira njenog kontrolora — a ne kao recept za izgradnju.

## Radni list za fizičko-digitalnu korelaciju

Kada je naizgled lokalni izvor sumnjiv, napravite jednu vremensku liniju:

1. normalizujte satove AP-a, RADIUS-a, DHCP-a, DNS-a, proxy-ja, VPN-a, EDR-a, switch-eva i sistema za fizičku kontrolu pristupa;
2. identifikujte prvo radio-povezivanje ili uspostavljanje veze, a ne samo prvo upozorenje;
3. povežite stanicu sa sertifikatom, stanjem uređaja, DHCP otiskom i lokacijom switch-a/AP-a;
4. potražite istovremenu aktivnost daljinske kontrole/tunela na obližnjim sistemima;
5. pregledajte isporuke, posetioce, inventarske izuzetke, kamere i RF nalaze u skladu sa važećim pravilima/zakonom;
6. sačuvajte sumnjivi uređaj i volatilno mrežno stanje; nemojte naslepo isključivati napajanje;
7. utvrdite da li je prividni izvor infrastruktura pod kontrolom aktera ili druga žrtva.

## References

- [1] [Volexity — Napad najbližeg suseda: Kako je ruski APT naoružao obližnje Wi-Fi mreže](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control in the sky](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Smernice za zaštitu bežičnih lokalnih mreža](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
