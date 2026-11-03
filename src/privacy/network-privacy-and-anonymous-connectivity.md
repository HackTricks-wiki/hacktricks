# Mrežna privatnost i anonimno povezivanje

{{#include ../banners/hacktricks-training.md}}

Mrežna privatnost je odluka o rutiranju, a ne potpuni identitet. Izaberite putanju tako što ćete se zapitati ko ne bi trebalo da može da poveže **izvor**, **odredište**, **sadržaj** i **vreme**.

Za normalizovani inventar — `Pros`, `Cons`, korak-po-korak `Procedure` i `Detection` za svaku porodicu pristupnih putanja — počnite od [Kataloga tehnika za anonimni pristup internetu](anonymous-internet-access-techniques.md). Ova stranica detaljnije obrađuje uobičajene opcije koje se mogu primeniti.

## Šta svaki posmatrač obično može da vidi

| Putanja | Lokalna mreža / ISP | Posrednik | Odredište | Glavno ograničenje | Relativna brzina |
|---|---|---|---|---|---|
| Direktan HTTPS | Izvor, metapodaci odredišta, vreme/obim | Hosting/CDN vidi vezu | Izvorna IP adresa, podaci pregledača/aplikacije | Ne pruža privatnost izvorne IP adrese | Najbrža |
| Komercijalni VPN | Izvor povezan sa VPN-om; obično ne vidi metapodatke odredišta | VPN vidi izvor i metapodatke odredišta | Izlazna IP adresa VPN-a | Jedan provajder postaje tačka za korelaciju | Obično brza |
| VPN/VPS u sopstvenom hostingu | Izvor povezan sa VPS-om | Host, nalog, plaćanje i kontrolni zapisi | Izlazna IP adresa VPS-a | Lako ga je povezati sa iznajmljenim serverom/nalogom | Obično brza |
| Tor Browser | Izvor povezan sa Tor-om/bridge-om; vreme/obim | Svaki relay vidi ograničeni deo | Tor izlaz, podaci pregledača | Sporiji; rizici povezani sa nalozima, krajnjom tačkom i korelacijom | Srednja/spora |
| Tails/Whonix | Slična Tor putanja, sa jačim granicama rutiranja | Ista ograničenja Tor-a | Tor izlaz/podaci aplikacije | Ostaju rizici operativnih grešaka, hosta i hardvera | Srednja/spora |
| Javni Wi-Fi za goste + HTTPS | Mesto vidi lokalni uređaj/vreme i odredišta | ISP lokacije vidi metapodatke | Javna IP adresa za goste | Korelacija sa fizičkom lokacijom, captive portalom i uređajem | Brza/promeljiva |
| Mobilni hotspot | Operater vidi pretplatnika, uređaj, lokaciju i odredišta | VPN/Tor ako se koristi | Izlazna IP adresa operatera, VPN-a ili Tor-a | Mobilna pretplata i lokacija dugotrajni su identifikatori | Brza/promeljiva |
| Mixnet | Pristupna mreža vidi korišćenje mixnet-a; vreme/obim | Više mixing čvorova | Gateway/izlaz | Ekosistem je u razvoju; cena su latencija i propusni opseg | Najsporija |

HTTPS štiti sadržaj tokom prenosa, ali ne i sve metapodatke. EFF napominje da domen, vreme i veličina saobraćaja mogu ostati vidljivi posrednicima čak i kada su putanje stranica, akreditivi i poruke šifrovani.<sup>[[1]](#references)</sup>

Šifrovani overlay nije automatski mreža za anonimnost: Yggdrasil direktni peers mogu da vide IP adrese jedni drugih.<sup>[[20]](#references)</sup> Njegov [userspace forwarding i SOCKS transport](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) predstavljaju opciju za tunneling, a ne sloj za anonimnost izvora.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN-ovi: brza privatnost uz koncentrisano poverenje

VPN je koristan za skrivanje metapodataka odredišta od pristupnog ISP-a, zaštitu prvog hop-a na nepouzdanoj mreži, korišćenje stabilne izlazne adrese za angažman ili pristup privatnoj mreži. Ne čini korisnika anonimnim. VPN vidi izvornu vezu i može da posmatra metapodatke odredišta; nalozi, kolačići, GPS, otisci prsta i podaci o plaćanju ostaju.<sup>[[1]](#references)</sup>

### Kontrolna lista za procenu provajdera

1. **Vlasništvo i jurisdikcija:** utvrdite pravno lice, matičnu kompaniju, zemlje poslovanja, podizvođače infrastrukture i važeće pravne postupke.
2. **Prikupljeni podaci:** razlikujte podatke o nalogu/naplati, izvornu IP adresu, vremenske oznake veze, propusni opseg, telemetriju o padovima, DNS upite i zapise odredišta. „Bez zapisa o pregledanju” ne znači „bez podataka”.
3. **Zadržavanje i brisanje:** pronađite tačne rokove i utvrdite da li se isti raspored primenjuje na rezervne kopije, sisteme za sprečavanje prevara i obrađivače.
4. **Dokazi:** prednost dajte javnim revizijama sa navedenim opsegom, datumom, nalazima i otklanjanjem problema; klijentima otvorenog koda koje je moguće reprodukovati; izveštajima o transparentnosti i dokumentovanim incidentima.
5. **Protokol i klijent:** održavani WireGuard, OpenVPN ili drugi provereni protokol; automatska ažuriranja; rukovanje DNS-om i IPv6; kill switch; i testovi leak-a za svaku platformu.
6. **Poslovni model:** saznajte kako se finansira besplatna ili subvencionisana usluga. Samo prisustvo u prodavnici aplikacija nije dokaz pouzdanog rada.
7. **Opcije plaćanja:** alternativni način plaćanja može da smanji količinu podataka o naplati koje VPN dobija, ali ne uklanja izvornu IP adresu koju vidi pri svakoj vezi.

### Konfigurisanje i provera VPN-a

1. Instalirajte potpisani klijent provajdera/organizacije iz zvaničnog izvora.
2. Izaberite **full tunnel**, osim ako dokumentovana ruta mora da ga zaobiđe. Split tunneling stvara mogućnosti za korelaciju i leak.
3. Uključite fail-closed/always-on ponašanje i blokirajte saobraćaj tokom ponovnog povezivanja.
4. Usmerite DNS kroz tunel i testirajte i IPv4 i IPv6. Onemogućite protokol samo ako ne može bezbedno da se tuneluje i prihvatate gubitak funkcionalnosti.
5. Testirajte stanje mirovanja/buđenja, promenu mreže, prijavu na captive portal, pad tunela i tethering preko hotspot-a. NCSC upozorava da klijenti povezani preko tethering-a na nekim platformama mogu zaobići VPN na telefonu.<sup>[[2]](#references)</sup>
6. Koristite testnu krajnju tačku pod kontrolom organizacije da zabeležite uočene IPv4, IPv6, DNS resolver i vreme povezivanja. Ne izlažite osetljiv angažman nasumičnim sajtovima za „testiranje leak-a”.
7. Ponovite testiranje nakon promena klijenta, OS-a, mreže ili pravila.

### Zaobilaženje rutiranja na zlonamernoj LAN mreži

VPN može i dalje da prikazuje status „povezan”, dok pojedini paketi zaobilaze tunel jer operativni sistem bira rutu **pre** nego što VPN šifruje paket. TunnelCrack je pokazao dva načina zloupotrebe uobičajenih izuzetaka u rutiranju: **LocalNet** čini da Internet odredište izgleda kao da se nalazi na direktno povezanoj podmreži, dok **ServerIP** lažira razrešavanje adrese VPN gateway-a, pa ciljna adresa dobija izuzetak za nešifrovanu mrežu koji zahteva VPN transport. To su propusti klijenta/rutiranja, a ne propusti u WireGuard-u, OpenVPN-u, IPsec-u ili TLS-u; HTTPS sadržaj ostaje šifrovan od kraja do kraja, ali lokalni posmatrač može da otkrije metapodatke odredišta/vremena i sve podatke protokola koji se prenose u otvorenom obliku.<sup>[[18]](#references)</sup>

TunnelVision koristi isti mehanizam pre šifrovanja preko DHCP opcije 121. Zlonameran ili kompromitovan DHCP server može da instalira classless rutu koja je specifičnija od opšte rute VPN-a, pa za proizvoljan host ili opseg bira fizički interfejs. Kontrolni kanal VPN-a može ostati aktivan, pa se kill switch koji se aktivira samo pri prekidu tunela možda neće uključiti, a jedna javna provera „IP leak-a” može da propusti selektivno zaobilaženje.<sup>[[19]](#references)</sup>

Packet-filter kill switch koji na fizičkom interfejsu dozvoljava samo DHCP i autentifikovani VPN transport trebalo bi da obezbedi fail-closed ponašanje, ali ciljano ubacivanje ruta i dalje može da stvori bočni kanal selektivnog uskraćivanja usluge. Za Linux radna opterećenja sa ozbiljnim posledicama, prednost dajte jačem [obrascu mrežnog prostora imena sa sprovođenjem ruta](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), gde prostor imena aplikacije nema fizički interfejs niti podrazumevanu rutu ka nešifrovanoj mreži.<sup>[[19]](#references)</sup>

#### Verifikacija u sopstvenoj laboratoriji

Testirajte tačnu kombinaciju klijenta/OS-a/verzije na sopstvenom AP-u, DHCP serveru, VPN krajnjoj tački i odredištu; tvrdnje o proizvodima brzo zastarevaju jer su implementacije rutiranja i packet filter-a specifične za platformu. Snimajte saobraćaj i na samoj krajnjoj tački i na testnom serveru — sajt koji prikazuje izlaznu IP adresu sam po sebi ne dokazuje da svako odredište koristi tunel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Povežite VPN, zabeležite adresu VPN servera i sačuvajte sve IPv4/IPv6 tabele rutiranja i pravila policy routing-a. U Windows-u koristite `route print`; u macOS-u `netstat -rn`; u Linux-u koristite komande navedene ispod.
2. Proverite izabranu rutu za nekoliko IP adresa odredišta koja posedujete. Sledeći hop/interfejs mora biti tunel, osim dokumentovane krajnje tačke VPN transporta.
3. Za TunnelVision obnovite zakup na kontrolisanoj DHCP mreži i instalirajte rutu opcije 121 **samo za testno odredište koje posedujete**. Test je uspešan ako se saobraćaj i dalje tuneluje ili blokira — nikada ne sme da se emituje kao saobraćaj namenjen odredištu preko fizičkog interfejsa.
4. Za LocalNet dodelite klijentu javnu testnu podmrežu namenjenu dokumentaciji, kao što je `203.0.113.0/24`, i smestite testno odredište koje posedujete u nju. Proverite da uključivanje pristupa LAN mreži ne dovodi do toga da odredišta dostupna preko Interneta zaobiđu tunel.
5. Za ServerIP, pre povezivanja na VPN podesite kontrolisani DNS da razreši ime hosta VPN-a u testno odredište koje posedujete, dok lab gateway prosleđuje VPN transport do stvarne VPN krajnje tačke koju posedujete. Klijent ne sme da izuzme nepovezan saobraćaj aplikacije ka lažiranoj adresi.
6. Ponovite test sa uključenom i isključenom opcijom „pristup lokalnoj mreži”, nakon ponovnog povezivanja, mirovanja/buđenja, promene mreže i pada VPN procesa. IPv4, IPv6 i DNS testirajte zasebno.
7. Pregledajte snimak saobraćaja na fizičkom interfejsu. Trebalo bi da sadrži DHCP i šifrovane pakete ka VPN serveru, a ne pakete upućene direktno testnom odredištu koje posedujete. Takođe proverite da odbijeno zaobilaženje ne može neprimetno da se prebaci na alternativnu rutu nakon korisničkih upita ili pokušaja popravljanja povezivosti.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: jača nepovezivost aktivnosti na vebu

Tor gradi circuit kroz više releja, tako da nijedan pojedinačni relej obično ne zna i izvor i odredište. Odredište vidi Tor izlazni čvor, a ne korisnikovu IP adresu; lokalna mreža obično vidi Tor vezu.<sup>[[3]](#references)</sup> Tor je osmišljen za TCP aplikacije sa malim kašnjenjem, pa je sporiji i ne može da garantuje zaštitu od napadača koji može da koreliše oba kraja veze.<sup>[[4]](#references)</sup>

### Bezbedno korišćenje Tor Browser-a

1. Preuzimajte Tor Browser samo sa sajta Tor Project-a ili zvaničnog ogledala i, kada je moguće, proverite potpis.
2. Koristite **Tor Browser**, a ne običan pregledač podešen na Tor SOCKS port. Obični pregledači mogu da otkriju DNS/WebRTC podatke i identifikacione informacije.<sup>[[5]](#references)</sup>
3. Zadržite podrazumevanu veličinu, fontove, ekstenzije i podešavanja privatnosti. Dodatni dodaci mogu učiniti pregledač prepoznatljivijim.<sup>[[6]](#references)</sup>
4. Izaberite nivo bezbednosti **Safer** ili **Safest** ako vam je prihvatljivo da neke funkcije neće raditi.
5. Koristite bridge ako je direktan pristup Tor-u blokiran ili bi obične IP adrese releja predstavljale neprihvatljiv rizik za privatnost na lokalnoj mreži. Bridge-ovi otežavaju jednostavno prepoznavanje, ali ne uklanjaju analizu saobraćaja.<sup>[[7]](#references)</sup>
6. Nemojte se prijavljivati na nalog koji otkriva vaš identitet, davati podatke koji vas identifikuju niti otvarati preuzete aktivne dokumente u spoljnoj aplikaciji povezanoj na mrežu.
7. Koristite zasebnu sesiju/kontekst za svaki identitet. „New circuit“ nije isto što i brisanje identiteta pregledača/aplikacije; po potrebi koristite **New Identity** ili ponovo pokrenite izolovano okruženje.
8. Dajte prednost autentifikovanom HTTPS-u ili autentifikovanoj onion usluzi. Tor izlazni čvor može da vidi nešifrovan HTTP saobraćaj.

### Tor uz VPN

Njihova kombinacija nije automatski bezbednija. VPN pre Tor-a može sakriti direktne veze sa Tor relejima od ISP-a, dok VPN vidi izvor; Tor pre VPN-a daje VPN-u stabilan uvid u aktivnost posle Tor-a i može smanjiti skup anonimnosti. Pogrešna konfiguracija može dovesti do leak-ova. Tor Project preporučuje takve kombinacije samo za napredne, izričito definisane modele pretnji.<sup>[[8]](#references)</sup>

## Javni i gostujući Wi-Fi

Zahvaljujući savremenom HTTPS-u, pasivni posmatrači u blizini obično ne mogu da čitaju pravilno šifrovan veb-sadržaj, ali gostujući Wi-Fi ne pruža anonimnost. Mesto može da beleži vreme povezivanja, identifikatore uređaja, podatke captive portal-a, odredišta i DHCP detalje; kamere, kupovine, prevoz i fizičko posmatranje mogu da otkriju identitet korisnika. Lažna pristupna tačka sa sličnim imenom može i da prikupi podatke za prijavu na portal ili manipuliše nešifrovanim saobraćajem.<sup>[[9]](#references)</sup>

### Zakonito korišćenje gostujuće mreže

1. Koristite samo mrežu namenjenu gostima ili mrežu za koju vam je vlasnik dao izričitu dozvolu. Zatražite od osoblja tačan SSID i uputstvo za portal.
2. Ažurirajte krajnji uređaj i putni ruter pre dolaska. Isključite deljenje datoteka/štampača, dolazno otkrivanje uređaja, automatsko povezivanje i proveravanje zapamćenih mreža.
3. Uključite privatnu/nasumično generisanu Wi-Fi adresu u operativnom sistemu. Savremeni Apple sistemi mogu da koriste rotirajuće adrese na otvorenim/slabo zaštićenim mrežama; nasumično generisanje adresa u savremenom Android-u obično je trajno za svaki SSID. Time se smanjuje izloženost samo jednog lokalnog identifikatora.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Dajte prednost putnom ruteru kojim upravlja organizacija ili bridge uređaju sa niskim nivoom poverenja između privilegovane radne stanice i gostujuće mreže. Time se centralizuju pravila firewall-a/VPN-a, ali se ruter ne skriva od mesta na kom se nalazite.<sup>[[12]](#references)</sup>
5. Pristupite captive portal-u samo preko predviđenog uređaja/pregledača sa niskim nivoom poverenja. Nikada ne unosite lične podatke za prijavu niti ponovo korišćene podatke u kontekstu koji navodno pruža anonimnost. Zatvorite pregledač portala nakon uspostavljanja veze.
6. Pokrenite VPN sa punim tunelom ili Tor pre osetljivih aktivnosti i potvrdite da se saobraćaj blokira u slučaju otkaza.
7. Zaboravite mrežu nakon korišćenja i pregledajte pravila naloga portala i zadržavanja podataka.

{% hint style="danger" %}
Probijanje Wi-Fi zaštite kod komšije, zaobilaženje portala, korišćenje procurelih podataka za prijavu gosta, kopiranje pristupa drugog gosta ili skrivanje Raspberry Pi-ja u kafiću predstavlja neovlašćenu aktivnost, a ne tehniku za zaštitu privatnosti. Bezbedne alternative su zakonita gostujuća mreža, lokacija koju je odobrio klijent ili dokumentovan drop node koji se postavlja i preuzima uz pisanu saglasnost vlasnika prostora.
{% endhint %}

## Putni ruteri

Putni ruter može da izoluje radnu stanicu od neprijateljskih lokalnih broadcast poruka, primenjuje firewall, obezbedi dosledan interni SSID i automatski ponovo uspostavi VPN vezu. On **ne** pruža anonimnost: mreža uzvodno vidi njegov radio-identitet i vreme saobraćaja, a VPN provajder vidi izvor tunela.

- Koristite podržani OpenWrt/firmware proizvođača i uklonite nekorišćene usluge.
- Administrirajte ga preko Ethernet-a ili namenski SSID za upravljanje sa jedinstvenom lozinkom.
- Isključite administraciju sa WAN strane, UPnP, WPS, deljenje datoteka i neželjeni dolazni saobraćaj.
- Koristite nasumično generisanu/privatnu WAN MAC adresu samo ako je podržana i dozvoljena.
- Primenite VPN pravila na ruteru, uključujući DNS i IPv6, i blokirajte odlazni saobraćaj ako tunel otkaže.
- Nemojte pretpostavljati da hotspot telefona usmerava povezane uređaje kroz VPN telefona; testirajte to.

## Mobilne mreže, SIM kartice i eSIM

Mobilna mreža je praktična, ali ne pruža anonimnost. Operatori čuvaju identifikatore pretplatnika/uređaja i lokaciju izvedenu iz povezivanja sa mrežom; eSIM je i dalje mobilna pretplata. Prepaid ne znači pouzdano da registracija nije potrebna — zahtevi se razlikuju među državama i menjaju se.<sup>[[13]](#references)</sup>

U praksi:

- Koristite zaseban, podržan uređaj da biste smanjili izloženost ličnih podataka, a ne da biste stvorili izmišljenog pretplatnika.
- Nemojte stalno nositi „zaseban“ uređaj uz lični telefon ako je istovremena fizička lokacija oba uređaja deo modela pretnji.
- Isključite nekorišćene mobilne veze, Wi-Fi, Bluetooth i pristup lokaciji; potpuno isključivanje uređaja predstavlja jaču radio-granicu od prekidača u interfejsu.
- Usmerite osetljiv saobraćaj kroz odobrenu VPN/Tor putanju, uz svest da operator i dalje zna lokaciju pretplate/uređaja i krajnju tačku tunela.
- Proverite važeća pravila registracije i zadržavanja podataka kod nacionalnog regulatora ili lokalnog pravnog savetnika; nemojte se oslanjati na spiskove „anonimnih SIM država“ na internetu.

## Metapodaci DNS-a i TLS-a

- **DoH/DoT/DoQ** šifruju DNS saobraćaj između klijenta i resolver-a, čime sprečavaju jednostavno lokalno čitanje ili izmenu, ali resolver i dalje vidi upite i identifikatore transporta. Oni premeštaju poverenje, ali ne pružaju anonimnost.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy tako da resolver ne mora da sazna IP adresu klijenta, pod pretpostavkom da proxy i odredišni server ne sarađuju. Analiza saobraćaja je izričito van opsega.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** može da zaštiti unutrašnje ime servera u TLS rukovanju kada ga podržavaju klijent, DNS i server. Odredišna IP adresa, vreme, obim saobraćaja i krajnja tačka ostaju vidljivi.<sup>[[16]](#references)</sup>
- U pravilno konfigurisanom VPN ili Tor okruženju, DNS treba da prati podržanu putanju tog okruženja. Dodavanje zasebnog resolver-a može uvesti novog posmatrača ili učiniti saobraćaj prepoznatljivijim.

### Provera šifrovanog DNS-a/ECH-a

1. Odlučite da li DNS kontroliše VPN/Tor okruženje, operativni sistem ili aplikacija. Podesite ga u **jednom** predviđenom sloju, umesto da kombinujete nepovezane resolver-e.
2. Izaberite resolver na osnovu objavljenih pravila privatnosti/zadržavanja podataka i uključite strogi šifrovani režim ako ga platforma podržava. Oportunistički prelazak na drugi režim može neprimetno vratiti DNS u otvoreni tekst.
3. Pošaljite upit za jedinstveni poddomen u autoritativnoj testnoj zoni koju kontrolišete; proverite da li autoritativni log beleži predviđeni rekurzivni resolver.
4. Uz odobrenje, snimite samo saobraćaj testnog uređaja. Proverite da li pristupna mreža može da pročita DNS u otvorenom tekstu, imajući u vidu da može da vidi krajnju tačku šifrovanog resolver-a/tunela.
5. Testirajte blokiran ili nedostupan šifrovani resolver. Uslov za prolaz je izabrano ponašanje fail-closed ili dokumentovani rezervni režim, a ne slučajno slanje DNS upita u otvorenom tekstu.
6. Za ECH koristite kontrolisani host sa uključenim ECH-om i pregledajte dijagnostiku klijenta/servera da biste potvrdili da je prihvaćen **unutrašnji** ClientHello. Samo oglašavanje HTTPS zapisa ne dokazuje da je ECH uspeo.
7. Ponovite test nakon promene mreže, captive portal-a, ažuriranja pregledača i ponovnog povezivanja VPN-a. Zabeležite koja komponenta upravlja DNS-om/ECH-om da administratori kasnije ne bi napravili zaobilaznu putanju.

## Mixnet-ovi

Mixnet-ovi kao što su Nym ili Katzenpost dodaju pakete fiksne veličine, kašnjenje, promenu redosleda i prikrivajući saobraćaj da bi se oduprli korelaciji po vremenu. Te osobine koštaju kašnjenja i propusnog opsega, a nezavisni dokazi o primeni u velikom obimu su ograničeni. Trenutne potrošačke mixnet-ove smatrajte **novim opcijama sa velikim kašnjenjem**, a ne bržom ili zagarantovanom zamenom za Tor/VPN-ove.<sup>[[17]](#references)</sup>

### Postupak procene

1. Utvrdite da li postoji održavan klijent i koja je tačno aplikacija podržana; nemojte usmeravati proizvoljan saobraćaj pregledača/sistema kroz nedokumentovani proxy.
2. Pročitajte aktuelni model pretnji za ulazne tačke, mix čvorove, gateway, odredište i pretpostavke o saradnji.
3. Instalirajte softver iz zvaničnog izvora sa potpisom u zasebno testno okruženje i koristite samo bezazlenu krajnju tačku koju posedujete.
4. Izmerite kašnjenje isporuke, ograničenja veličine poruke, pouzdanost, ponovne pokušaje slanja i ponašanje kada gateway nije dostupan.
5. Pregledajte lokalni saobraćaj i krajnju tačku koju posedujete da biste potvrdili predviđenu putanju i izvor. Proverite da li odgovori koriste isti dizajn zaštite privatnosti.
6. Testirajte gašenje/otkaz: aplikacija ne sme neprimetno da pređe na direktan pristup internetu.
7. Nemojte isključivati prikrivajući saobraćaj, smanjivati kašnjenja ili birati neuobičajene fiksne rute samo radi brzine; takve izmene mogu poništiti navedeni model anonimnosti.
8. Ostavite ga u eksperimentalnoj fazi dok konkretna primena, nezavisna analiza i operativna pouzdanost ne odgovaraju nivou posledica.

## Kontrolna lista pre povezivanja na mrežu

- [ ] Ovlašćenje obuhvata pristupnu mrežu, cilj, datume i izvornu infrastrukturu.
- [ ] Krajnji uređaj ne sadrži nepovezane identitete ili aktivne sesije sinhronizacije.
- [ ] IPv4, IPv6, DNS i ponašanje pri ponovnom povezivanju odgovaraju planu.
- [ ] Kontrolisano DHCP/ubrizgavanje ruta u lokalnu podmrežu ne može da preusmeri testni saobraćaj na fizički interfejs.
- [ ] Odredište vidi samo očekivani izlaz.
- [ ] Ponašanje captive portal-a i hotspot-a testirano je bez osetljivog saobraćaja.
- [ ] Lokalno deljenje/otkrivanje uređaja i automatsko povezivanje na mreže su isključeni.
- [ ] Tabela posmatrača i preostali rizik od korelacije saobraćaja su prihvaćeni.
- [ ] Pravila provajdera, zadržavanje podataka i kontakt za hitne slučajeve su aktuelni.

Za releje sa podeljenim znanjem, radna opterećenja sa rutiranjem nametnutim pravilima, pluggable transports, onion usluge, I2P i jednokratne udaljene pregledače, pogledajte [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Izbor VPN-a koji vam odgovara](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Smernice za bezbednost uređaja: virtuelne privatne mreže](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Zaštita privatnosti i anonimnosti koju Tor pruža](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Kratak uvod u Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Korišćenje Tor-a sa drugim pregledačima](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Dodaci i ekstenzije u Tor Browser-u](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Deblokiranje Tor-a](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Korišćenje Tor Browser-a uz VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Da li su javne Wi-Fi mreže bezbedne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Privatnost Wi-Fi mreže na Apple uređajima](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementacija nasumičnog generisanja MAC adresa](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principi za bezbedne radne stanice sa privilegovanim pristupom](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obavezna registracija SIM kartica: perspektive politika i propisa](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Preporuke za operatere usluga DNS privatnosti](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Model pretnji](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Zaobilaženje tunela: otkrivanje saobraćaja VPN klijenta zloupotrebom tabela rutiranja](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: kako napadači mogu da razotkriju VPN-ove zasnovane na rutiranju i u potpunosti izazovu leak VPN-a](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ: Da li je Yggdrasil anoniman?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
