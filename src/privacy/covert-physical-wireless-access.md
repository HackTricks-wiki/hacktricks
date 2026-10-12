# Prikriveni fizički i bežični pristup

{{#include ../banners/hacktricks-training.md}}

Za detaljnu implementaciju uz odobrenje vlasnika, koja obuhvata outbound rendezvous, oporavak napajanja/uzvodne veze, minimalan broj tajni koje uređaj čuva, testiranje hvatanja i praćenje mogućeg otkrivanja, pogledajte [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Promena mrežne putanje može da promeni i prividno fizičko poreklo. Sofisticirani akter može da koristi obližnji kompromitovani sistem, skriveni uređaj, javni pristup, mobilnu vezu ili satelitski prijemnik tako da evidencije mete ukazuju dalje od operatera. Ništa od toga ne uklanja fizičke, radio-frekvencijske ili dokaze kod provajdera; ono premešta atribuciju u druge skupove podataka.

## Matrica tehnika

| Tehnika | Prividno poreklo | Neophodan uslov | Dokazi visoke vrednosti |
|---|---|---|---|
| Bežični pivot preko obližnjeg sistema | poslovni/prostorni objekat pored mete | kompromitovani dual-homed host i Wi-Fi pristup mete | dnevnici krajnje tačke obližnjeg hosta, RF asocijacija i RADIUS/DHCP mete |
| Javna/mreža za goste | NAT lokala ili izlaz tunela | zakonit pristup ili zaobilaženje kontrole pristupa | captive portal, DHCP, AP asocijacija, CCTV i evidencije plaćanja/lokacije |
| Prikriveni uređaj za ubacivanje | žična, Wi-Fi ili mobilna adresa mete/obližnjeg sistema | fizičko postavljanje ili dostava | switchport/USB, RF, inventar, napajanje i telemetrija izlaznog tunela |
| Mobilni ruter/eSIM | NAT operatera ili namenski APN | modem/SIM/pretplata | IMEI/IMSI/eSIM, ćelijski sektor, nalog kod operatera i vremenska korelacija saobraćaja |
| Zloupotreba satelitske veze | adresa pretplatnika u području pokrivenom snopom | slabost specifična za protokol i uslugu | RF lokacija, tok uzvodne veze, nemogući RTT/rutiranje i evidencije provajdera |

## Napad preko najbližeg suseda

Volexity je dokumentovao operaciju APT28/GRU iz 2022. godine, u kojoj je akter bio udaljen od svoje krajnje mete. Izveo je password spraying nad javno dostupnom uslugom mete da bi došao do važećih akreditiva, ali je MFA sprečio direktno prijavljivanje preko Interneta. Wi-Fi mreža preduzeća koje je bilo meta prihvatala je te akreditive bez MFA. Akter je kompromitovao organizacije koje su se fizički nalazile blizu mete, pronašao dual-homed sistem sa bežičnim dometom i pomoću tog sistema se autentifikovao na Wi-Fi mreži mete. Volexity je ovu tehniku nazvao **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

Novina je u kombinaciji. Nijedan operater ne odlazi do cilja, a MFA usluge dostupne sa Interneta i dalje funkcioniše. Kompromitovani sused obezbeđuje fizičku blizinu; ukradeni kredencijali cilja obezbeđuju logički pristup; Wi-Fi mreža cilja postaje putanja za prelazak granice.

### Preduslovi i vidljivost

- Sistem u blizini mora moći da se kontroliše na daljinu i da ima kompatibilan radio ili pristup drugom obližnjem pivot-u.
- Ciljni SSID mora biti dostupan tom sistemu, a Wi-Fi kontrola pristupa mora prihvatati kredencijale, sertifikat ili stanje uređaja koji se mogu ponovo koristiti.
- Pivot-u su često potrebne dve istovremene putanje: jedna nazad do operatera, a druga u ciljni WLAN.
- Cilj može videti novu MAC adresu stanice i legitimno korisničko ime, ali ne i odgovarajući sertifikat upravljanog uređaja, njegov status usklađenosti, istoriju ili očekivani ulazak u zgradu.
- Evidencije susednog uređaja mogu pokazivati bežična skeniranja, nove profile, promene interfejsa, tuneliranje i aktivnost daljinskog upravljanja.

### Detekcija i prevencija

1. Za poslovni Wi-Fi zahtevajte EAP-TLS zasnovan na sertifikatima i proveru statusa upravljanog uređaja; nemojte dozvoliti da lozinka koja nije prošla MFA na Internetu bude dovoljna samo zato što je poslata putem radija.
2. Povežite RADIUS autentifikaciju sa MDM/NAC identitetom, istorijskim povezivanjem stanice sa uređajem, lokacijom AP-a, događajima fizičkog pristupa i istovremenim sesijama.
3. Generišite upozorenje kada se nalog prvi put poveže, sa neuobičajene ivice AP pokrivenosti, bez sertifikata upravljanog uređaja ili dok je isti identitet aktivan na drugom mestu.
4. Nadgledajte krajnje uređaje koji mogu da premošćavaju interfejse. Na Windowsu, Linuxu i mrežnim uređajima proveravajte neočekivane WLAN profile, konfiguracije prosleđivanja/NAT-a, virtuelne adaptere i trajne tunele.
5. Smanjite nepotrebno širenje signala pravilnim postavljanjem AP-ova i planiranjem snage. Ovo je dopunska kontrola, a ne autentifikacija.
6. Uskladite reagovanje na incidente sa susednim zakupcima: krajnji izvor radio-signala i sam može biti žrtva.

[Lab koji obuhvata dve organizacije i čiji su sistemi u vašem vlasništvu](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reprodukuje ove uočljive pojave bez napada na suseda.

### Provera putanje pivot-a na Windowsu

Windows host sa dve mrežne veze ne premošćava automatski svoje interfejse. Najpre popišite njegove adaptere, rute i WLAN stanje, a zatim se povežite samo pomoću odobrenog profila. Argument `name` komande `netsh wlan connect` označava instalirani profil, a ne proizvoljan SSID i lozinku. Uporedite tabelu rutiranja pre i posle povezivanja kako biste bili sigurni da nova podrazumevana ruta neće prekinuti putanju kontrole niti učiniti rezultat nevažećim. Nastavite sa [proverama nakon povezivanja](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) tek kada potvrdite da koristite predviđeni interfejs i rutu.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexity-jevi objavljeni artefakti incidenta pokazuju još jednu korisnu razliku. Ugrađeni C# otvara WLAN API, nabraja interfejse, čita EAP XML sa diska i poziva `WlanSetProfileEapXmlUserData` za imenovani profil na prvom bežičnom interfejsu. API postavlja EAP korisničke podatke za postojeći 802.1X profil, ali objavljena komponenta ne sadrži ni `WlanConnect` ni logiku otkrivanja opisanu u izveštaju. Posmatrajte je kao obezbeđivanje profila, a ne kao kompletan konektor, i pregledajte rezultujući profil u okviru [procene klijenta i supplicant-a](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Javna mesta i Wi-Fi trećih strana

Korišćenje Wi-Fi mreže u kafiću, hotelu, na aerodromu ili u opštini menja IP adresu koju odredište vidi. To ne pruža anonimnost. Mesto ili njegov provajder mogu da čuvaju evidenciju povezivanja sa AP-om, MAC adresu uređaja, DHCP zakup, nalog na captive portalu, SMS/email potvrdu i evidenciju protoka. Podaci o fizičkom ulasku, CCTV snimci, kupovine, lokacija mobilnog telefona i putovanja mogu da povežu digitalni događaj sa osobom.

Akter može pokušati da prikrije jedan identifikator korišćenjem nasumičnih MAC adresa, zasebnog uređaja, gotovine ili tunela. Korelacija između različitih slojeva i dalje je moguća na osnovu vremena dolaska, ponavljanja poseta istom mestu, radio otisaka, ponašanja na portalu, vremena saobraćaja, snimaka kamera i provajdera tunela. VPN takođe premešta odredište iz evidencije mesta u evidenciju VPN-a; ne uklanja saznanje mesta da je uređaj bio prisutan.

Oni koji obezbeđuju javni pristup treba da izoluju klijente, blokiraju bočni saobraćaj, koriste WPA2/3-Enterprise ili ključeve po uređaju gde je to izvodljivo, čuvaju srazmernu DHCP/RADIUS/bezbednosnu evidenciju, zaštite captive portale i objave postupak za prijavu zloupotreba. Red team-ovi treba da koriste takvo mesto samo ako to dozvoljavaju njegovi uslovi i angažman; zaobilaženje portala, krađa pristupa ili napad na druge goste nisu dozvoljena prečica za testiranje.

## Uređaji za tajno ostavljanje i warshipping

Drop je mali sistem postavljen ili dostavljen na lokaciju, kojim se zatim upravlja preko izlazne Ethernet, Wi-Fi ili mobilne veze. „Warshipping“ pakuje uređaj tako da ga uobičajena dostava unese unutar radio-perimetra. Mogući hardver obuhvata sve, od računara sa jednom pločom do modifikovanog punjača, USB periferije, mrežnog uređaja ili modema na baterije.

Operativna arhitektura:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Uređaj može da obezbedi udaljeni pristup, obavlja bežična merenja, oponaša periferni uređaj za ovlašćenu vežbu ili prosleđuje saobraćaj. Deluje kao da potiče sa lokalne mreže, ali ostavlja fizičke tragove: serijske brojeve, ambalažu, otiske prstiju, snimke kamera, evidenciju pristupa, potrošnju energije, USB deskriptore, pregovaranje na switchport-u, DHCP otiske, ponašanje MAC OUI-a/nasumičnog generisanja MAC adresa, RF emisije i ponavljajuće veze za povezivanje.

### Odbrambene mere

- Održavajte procedure za prijem robe i popis imovine; proveravajte neočekivanu elektroniku i pakete adresirane na nepostojeće zaposlene.
- Koristite 802.1X/NAC za žični i bežični pristup, isključite neiskorišćene portove i nepoznate uređaje smestite u ograničeni VLAN za sanaciju.
- Upozoravajte na nove DHCP otiske, lokalno dodeljene MAC adrese koje opstaju, nove USB mrežne/HID uređaje, neovlašćeni Wi-Fi Direct/Bluetooth i dugotrajne odlazne tunele.
- Utvrdite osnovne vrednosti za ponašanje switchport-a, napajanje preko Ethernet-a, DNS-a i TLS-a. Mali host bez evidencije u inventaru koji povremeno uspostavlja šifrovane veze predstavlja jači signal nego samo „Raspberry Pi OUI”.
- Tokom vežbe evidentirajte, označite i ograničite opseg uređaja, šifrujte ga, omogućite udaljeno isključivanje, postavite rok za preuzimanje i osigurajte da njegov gubitak ne može otkriti ponovo upotrebljive akreditive.

## Mobilna i eSIM veza za povratni saobraćaj

Ćelijski modem zaobilazi Internet mrežni prolaz ciljnog sistema i može da održi pristup uređaju iza NAT-a operatera putem odlazne veze za povezivanje. Mobilne adrese mogu da se menjaju ili dele; operater mobilne mreže i dalje raspolaže pouzdanim dokazima o pretplatniku i mreži: identitetom SIM/eSIM kartice, IMSI-jem, IMEI-jem uređaja, dodeljenim adresama/portovima, vremenom povezivanja sa ćelijom/sektorom, kao i evidencijom naloga/plaćanja i rominga.

U pogledu preduzeća, neočekivane modeme i lične pristupne tačke otkrivajte pregledima bežičnih/RF mreža, inventarizacijom USB/PCI uređaja na krajnjim uređajima, ograničenjima MDM-a, nadzorom neovlašćenih SSID-ova i fizičkim pregledom. Uређај за продор који користи ћелијску везу за контролу и даље може бити откривен на основу локалног Ethernet/Wi-Fi понашања и радио-емисија.

У овлашћеним вежбама, организација треба да поседује претплату и модем, евидентира идентификаторе код контролора и провери да ли услови оператера/провајдера дозвољавају такав саобраћај. Припејд етикета или куповина криптовалутом не бришу евиденцију базних станица, уређаја или продавца.

## Насумично генерисање MAC адреса и otисци уређаја

Савремени системи могу да користе локално додељену насумичну MAC адресу за сваку мрежу. Тиме се смањује пасивно дугорочно праћење помоћу стабилне фабричке MAC адресе; међутим, то не скрива:

- време слања probe захтева/успостављања везе и скуп тражених мрежних могућности;
- 802.11 информационе елементе, подржане брзине и понашање специфично за произвођача;
- DHCP опције/име хоста, IPv6 идентификаторе и отисак прегледача/портала за пријаву;
- потврђени 802.1X идентитет или сертификат;
- налоге, тунеле и обрасце саобраћаја на вишим слојевима; или
- физичко посматрање.

Браниоци не би требало да користе листе дозвољених MAC адреса за аутентификацију. Повежите радио-идентитет са сертификатом/безбедносним стањем уређаја и променљиве MAC адресе сматрајте нормалним, осим ако други контекст не указује на аномалију.

## Отмица сателитске везе

Kaspersky је документовао да Turla користи слабости старијег једносмерног DVB-S сателитског Интернета. У описаном моделу, легитимни удаљени претплатник слао је одлазне захтеве преко земаљске везе, али је долазне податке примао путем нешифрованог сателитског емитовања широког домета. Актер унутар подручја покривености сателита могао је да посматра силазни канал, изабере IP адресу активног претплатника и подеси да одговори C2 буду упућени на ту адресу. И легитимни претплатник и актер примали су емитовање; актер је издвајао саобраћај за изабрани порт, док је легитимни претплатник одбацивао нежељене пакете. Затим је деловало као да C2 оператор користи адресу сателитског провајдера у другом географском подручју.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Ovo je bilo specifično za protokol/uslugu, ograničeno propusnim opsegom i nije ekvivalentno kompromitovanju modernog dvosmernog šifrovanog satelitskog terminala. Takođe nije skrivalo izlaznu putanju zahteva aktera od dovoljno sposobnog posmatrača. Mogućnosti za otkrivanje uključuju asimetrično/nemoguće rutiranje, saobraćaj ka pretplatniku koji nije pokrenuo vezu, neuobičajene odredišne portove, telemetriju provajdera, istragu lokacije prijemnika/RF-a i konfiguraciju malvera. Iskoristite ovaj slučaj da preispitate pretpostavku da geolociranje C2 IP adrese otkriva lokaciju njenog kontrolora — ne kao uputstvo za izradu.

## Radni list za korelaciju fizičkih i digitalnih podataka

Kada je izvor koji deluje lokalno sumnjiv, napravite jednu vremensku liniju:

1. normalizujte vreme na AP-u, RADIUS-u, DHCP-u, DNS-u, proxy-ju, VPN-u, EDR-u, sviču i sistemima fizičke kontrole pristupa;
2. utvrdite prvo povezivanje radio-uređaja ili uspostavljanje veze, a ne samo prvo upozorenje;
3. povežite stanicu sa sertifikatom, stanjem uređaja, DHCP otiskom i lokacijom sviča/AP-a;
4. potražite istovremene aktivnosti daljinskog upravljanja/tunelovanja na obližnjim sistemima;
5. pregledajte isporuke, posetioce, odstupanja u inventaru, snimke kamera i RF nalaze u skladu sa važećim pravilima/zakonima;
6. sačuvajte sumnjivi uređaj i volatilno stanje mreže; nemojte ga naslepo isključivati i ponovo uključivati;
7. utvrdite da li je prividni izvor infrastruktura pod kontrolom aktera ili druga žrtva.

## References

- [1] [Volexity — Napad najbližeg suseda: kako je ruski APT naoružao obližnje Wi-Fi mreže za prikriveni pristup](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satelitski Turla: APT komandovanje i kontrola na nebu](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Dodavanje hardvera (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Smernice za zaštitu bežičnih lokalnih mreža](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Redigovani PowerShell/C# kod za WLAN profile](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — Funkcija WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
