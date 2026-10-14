# Ofanzivna infrastruktura i izbegavanje atribucije

{{#include ../banners/hacktricks-training.md}}

Operater retko stiče značajnu anonimnost pomoću jednog proxy-ja. Stvarne kampanje grade **graf razdvajanja**: operater pristupa pristupnom čvoru, prolazni čvorovi skrivaju taj čvor od izlaznog čvora, redirectori štite pravi C2, a jednokratna imena upućuju na javnu ivicu.

Koristite [Katalog tehnika za anonimni pristup internetu](anonymous-internet-access-techniques.md) za standardizovan pregled prednosti, nedostataka, primene i detekcije svake putanje. Ova stranica detaljnije obrađuje sastavljanje adversarijalne infrastrukture.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Poslednja adresa koju vidi cilj zato je dokaz o putanji, a ne dokaz o tome ko je upravljao tastaturom. MITRE mapira glavne komponente na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klase infrastrukture

| Klasa | Zašto je akter koristi | Dugotrajna izloženost | Najbolja tačka za pivotiranje za odbranu |
|---|---|---|---|
| Iznajmljeni VPS/cloud | Brz, predvidiv, rutabilan, lako ga je ponovo izgraditi | zakupac, naplata, konzola, istorija prijava sa izvora i image-a | događaji na nalogu/kontrolnoj ravni i ponavljajući otisak servera |
| Komercijalni VPN/Tor | Veliki skup zajedničkih izlaznih tačaka; nema administracije servera | vidljivost pružaoca/usluge i korelacija vremena od početka do kraja | ponašanje odredišta, dokazi sa krajnjih tačaka i korelacija tokova |
| Residential/mobile proxy | Potrošački ASN i geografska uverljivost | evidencija posrednika/korisnika; ponašanje proxyware-a ili zaraženog uređaja | nemoguće putovanje, proxy protokoli i promena adresa po sesiji |
| Kompromitovani server/ruter/IoT | Pozajmljuje reputaciju žrtve i njenu jurisdikciju | implant, upravljački tok i ponavljajući uzvodni kontroler | telemetrija uređaja i ORB topologija, a ne jedna izlazna IP adresa |
| CDN/redirector | Razdvaja javni edge od pozadinskog C2 | TLS/HTTP gramatika, sertifikat, rutiranje i artefakti cloud naloga | korelacija edge-a i origin-a i grupisanje po obliku zahteva |
| Legitimni web servis | Uklapa se u dozvoljeni GitHub/cloud/saobraćaj društvenih mreža | API token, identifikatori zakupca/objekta i neuobičajeno poreklo procesa | proces na krajnjoj tački i semantika servisa/API-ja |
| Fizička/mobilna/satelitska putanja | Menja prividno fizičko poreklo | RF, operater, pretplatnik, uređaj i podaci o lokaciji | kombinovani radio/fizički i mrežni dokazi |

## Mreže operativnih relay box uređaja

**ORB mreža** je upravljan proxy skup koji se koristi kao posredni servis. Mandiant ih deli na obezbeđene mreže iznajmljenih servera, mreže bez obezbeđivanja koje čine kompromitovani ruteri/IoT uređaji i hibridne mreže. Zrela topologija ima četiri logičke uloge:<sup>[[2]](#references)</sup>

1. **Administracioni server (ACOS):** održava inventar, akreditive, stanje i pravila rutiranja.
2. **Pristupni/relay čvor:** autentifikuje korisnike ili operatere; to je stabilna ulazna tačka u promenljivu mrežu.
3. **Traversal čvorovi:** jedan ili više iznajmljenih ili kompromitovanih sistema prosleđuju neprozirne veze.
4. **Izlazni/staging čvor:** predstavlja konačnu izvornu adresu sistemima za izviđanje, eksploataciju ili C2.

Mreža može da bira izlazne čvorove prema državi, ASN-u, latenciji или dostupnosti i da menja neispravne čvorove. Više pretnji može iznajmljivati istu mrežu. Mandiant je primetio da je IPv4 adresa u nekim ORB mrežama ostajala povezana sa njima svega 31 dan; zato preporučuje da se **mreža posmatra kao entitet nalik akteru koji se razvija**, umesto da se blokira zastarela lista IP adresa.<sup>[[2]](#references)</sup>

### Šta ovo omogućava — i šta leak-uje

- Cilj vidi izlaznu tačku koja može biti geografski blizu i naizgled rezidencijalna.
- Izlazna tačka vidi cilj i prethodni hop, ali ne nužno i operatera.
- Pristupni servis vidi korisnika i zahtev za rutom. Mreža kojom se nezavisno upravlja može da razdvoji korisnika od izlaznih tačaka, ali time nastaje moćan trag kod druge strane.
- Ponavljajući portovi, redosled rukovanja, baneri servera, sertifikati, vremenski intervali aktivnosti i veze među kontrolerima mogu da otkriju skup čvorova čak i dok se IP adrese menjaju.
- Kompromitovanom ruteru često nedostaje telemetrija krajnje tačke, ali njegov ISP i dalje ima podatke o pretplatniku i tokovima; zaplena otkriva artefakte implanta/konfiguracije.

{% hint style="info" %}
Za odobrenu vežbu, reprodukujte topologiju pomoću VM-ova ili rutera u vlasništvu organizacije i sačuvajte mapu atribucije kontrolera. Nemojte koristiti otvorene proxy-je niti uređaje trećih strana. [Vodič za laboratoriju](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) pravi istu strukturu hop-ova vidljivu braniocima, a da se pritom ne ugrožava posrednik.
{% endhint %}

## Rezidencijalne i mobilne proxy mreže

Rezidencijalni proxy servisi dodeljuju sesijama adrese potrošačkih širokopojasnih veza; mobilni proxy-ji izlaze preko NAT skupova operatera. Izvori mogu biti izričito uključeni uređaji, SDK/proxyware ugrađen u potrošačke aplikacije, preprodavci ili malware. Ovi izvori nisu istovetni: bez informisanog pristanka, servis za privatnost postaje kompromitovana infrastruktura.

Načini rotacije utiču na detekciju:

- **rotacija po zahtevu** dovodi do brzih diskontinuiteta IP adrese i ASN-a/geografije, dok identitet na višim slojevima ostaje stabilan;
- **lepljive sesije** zadržavaju izlaznu tačku nekoliko minuta ili sati, pa liče na uobičajenog pretplatnika;
- **backconnect pristupnici** korisniku izlažu jednu brokersku krajnju tačku, a interno biraju izlazne tačke;
- **mobilni skupovi** stavljaju mnogo stvarnih pretplatnika iza malog broja carrier NAT adresa, zbog čega je blokiranje IP adrese skupo.

Branioci treba da povezuju IP adresu sa autentifikovanom sesijom, TLS/klijentskim otiskom, redosledom HTTP zahteva, kolačićem uređaja i ponašanjem. Navodna lokalna rezidencijalna prijava praćena prijavom iz druge države, uz nepromenjene karakteristike na višim slojevima, predstavlja jači pokazatelj od same reputacije. Nasuprot tome, deljenje adresa i promena mobilne mreže dovode do legitimnih promena, zato klasifikaciju rezidencijalnog/proxy saobraćaja nikada ne tretirajte kao konačnu procenu.

### Kontrolne ravni proxyware-a i preklapanje preprodavaca

Nemojte modelovati rezidencijalni skup kao ravnu listu izlaznih tačaka. Analiza IPIDEA ekosistema otkrila je ponovo upotrebljivu **dvoslojnu kontrolnu ravan**: ugrađeni SDK najpre šalje metapodatke o uređaju/upisu domenu Tier One, a zatim prima parove IP:port za raspoređivanje i Tier Two `connect`/`proxy`. Čvor periodično proverava connect port Tier Two radi kodiranog zadatka, otvara drugu vezu ka uparenom proxy portu i prosleđuje zadate bajtove do traženog odredišta. SDK-ovi i proxy brendovi koji su nominalno bili različiti imali su zasebne domene za otkrivanje, ali su se spajali na zajedničku Tier Two infrastrukturu i preklapajuće izlazne skupove kroz zajedničko vlasništvo i odnose sa preprodavcima.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Ovo daje trajnije pivot tačke za threat hunting od bloka rezidencijalnih IP adresa:<sup>[[13]](#references)</sup>

- neočekivani proces neke pomoćne aplikacije, VPN-a, igre ili ugrađenog uređaja šalje stabilni ID uređaja/korisnički ključ i prima promenljivu listu servera;
- krajnja tačka proverava direktnu IP adresu na neuobičajenom portu, a zatim se neposredno pre otvaranja socket-a ka novom odredištu povezuje na drugi port iste adrese;
- nekoliko prividno različitih brendova deli Tier Two adrese, gramatiku protokola, SDK kod ili preklapanje izlaznih čvorova;
- različite aplikacije koje kontaktiraju različite Tier One domene dobijaju adrese iz istog Tier Two skupa.

Ovo preklapanje ujedno ograničava atribuciju: uočavanje IP adrese u oglašenom skupu nekog dobavljača ne utvrđuje koji ju je preprodavac, korisnik ili akter pretnje koristio u relevantnom trenutku. Sačuvajte vremenske oznake tokova, poreklo procesa, tela odgovora Tier One sistema i identifikatore zadataka Tier Two sistema.<sup>[[13]](#references)</sup> U ovlašćenoj vežbi, oponašajte ovu hijerarhiju samo pomoću krajnjih tačaka u vlasništvu organizacije; nikada ne registrujte uređaje potrošača ili proxyware trećih strana.

## Lanci višeskokovnih proxy-ja

MITRE pravi razliku između eksternih proxy-ja i **višeskokovnih proxy-ja (T1090.003)**. Ključno svojstvo nije broj skokova, već razdvajanje znanja i administracije.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Ako jedna strana upravlja A i B, zajednički logovi ili vremenski obrasci protoka mogu otkriti putanju veze. Dodavanje uzastopnih komercijalnih VPN-ova sa iste krajnje tačke/naloga može povećati kašnjenje, a da pritom ostavi tragove zajedničkog identiteta, plaćanja i vremenskih obrazaca. Tor umanjuje ovaj problem nezavisno odabranim relay čvorovima i zajedničkim dizajnom klijenta, ali mreža sa malim kašnjenjem za interaktivnu upotrebu ne može da garantuje otpornost na posmatrača koji meri oba kraja veze.

Česti propusti su zaobilaženje preko DNS-a ili IPv6, aplikacije koje otvaraju sopstvene sokete, upravljački saobraćaj koji direktno stiže do relay čvorova, sinhronizovana aktivnost, ponovo korišćeni SSH ključevi i prijavljivanje na naloge koji otkrivaju identitet. Ispravna provera je test otkaza: zaustavite svaki relay redom i pokažite da radno opterećenje ne može da pređe na nezaštićenu putanju.

### Otkazivanje tunela i curenje ka uzvodnoj infrastrukturi

Arhitektura relay čvorova često se najlakše pripisuje kada otkaže. Unit 42 je dokumentovao špijunsku putanju sa više nivoa koja je koristila VPS-ove okrenute ka žrtvama, relay VPS-ove, rezidencijalne proksije, Tor i druge proksi usluge; kada bi tunel izostao ili se prekinuo, skrivena uzvodna infrastruktura povezivala se direktno sa relay sistemima i sistemima okrenutim ka žrtvama. Ista istraga je koristila i X.509 sertifikat koji je nakratko bio izložen na uzvodnoj infrastrukturi kao pivot između nivoa.<sup>[[14]](#references)</sup>

Držite **data plane** (`victim <-> exit`) odvojenim od **control plane**-a (`operator/upstream -> relay administration`). Zadržite ulazne logove i logove autentifikacije na svakom nivou kojim upravljate, istoriju sertifikata i kratke neuspele veze — ne samo uspešne C2 sesije. Izvor koji se pojavljuje samo tokom prekida relay čvorova ili direktno administrira više čvorova okrenutih ka žrtvama jači je kandidat za uzvodni čvor od uobičajenog exit čvora, ali njegov ASN/geolokacija i dalje su hipoteza, a ne dokaz identiteta operatera.

Ovlašćeno laboratorijsko okruženje treba da zaustavi radno opterećenje u slučaju otkaza. Za radno opterećenje izolovano u Linux mrežnom imenskom prostoru, prva ruta mora da koristi tunel; nakon njegovog uklanjanja, i zahtev i provera rute moraju da otkažu, a ne da izaberu fizički uplink:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Ponovite test za DNS i IPv6, kao i na svakoj granici relay-a. Ako neka proba uspe, zabeležite stvarni interfejs/izvornu adresu pre nego što popravite policy routing ili firewall; to zapažanje predstavlja attribution leak koji bi istražitelj video.

## Slojevi redirector-a i oblikovanje saobraćaja

Javni **redirector** prihvata saobraćaj koji odgovara gramatici specifičnoj za operaciju i prosleđuje ga zaštićenom timskom serveru. Sve ostalo može da odbije ili da posluži bezazlen sadržaj.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Više nivoa ograničava izloženost: kompromitovanje javnog domena ne mora da otkrije timski server. CDN-ovi pružaju anycast kapacitet i reputabilan spoljašnji domen, ali CDN nalog i edge logovi postaju tačke atribucije. TLS otisci, istorija sertifikata, prepoznatljive putanje/redosled zaglavlja, veličine odgovora, ponašanje pri preusmeravanju i liste dozvoljenih origin servera mogu da povežu naizgled nepovezane frontove.

Za detekciju, zabeležite polja reverse proxy-ja pre normalizacije, uporedite SNI/Host/authority, pregledajte retke kombinacije zaglavlja, grupišite tela odgovora i TLS otiske i pretražite cloud/CDN audit logove radi preklapanja konfiguracija. Ovlašćeni red team-ovi treba da izbegavaju kopiranje stvarnog brenda ili postavljanje prikupljanja akreditiva iza nepovezane treće strane.

## Domain fronting i fronting bez domena

Kod klasičnog **domain fronting (T1090.004)**, TLS veza u SNI oglašava dozvoljeni front domen, dok šifrovani HTTP `Host` ili HTTP/2 `:authority` traži drugi back-end domen. Saradnički CDN usmerava saobraćaj prema unutrašnjoj vrednosti. Mrežni posmatrač bez TLS dekripcije vidi front; CDN vidi obe vrednosti i origin. Kod varijanti bez domena, SNI može biti prazan, dok drugo polje za usmeravanje bira odredište.<sup>[[4]](#references)</sup>

Ovo nije magično lažno predstavljanje: funkcioniše samo ako posrednik namerno ili slučajno dozvoljava nepoklapanje i zna kako da usmeri unutrašnje ime. Veliki provajderi su ograničili fronting između naloga. Encrypted ClientHello (ECH) menja ono što posmatrač na putanji može da vidi, ali ne briše CDN, krajnju tačku ni aplikacione zapise.

Tačke detekcije obuhvataju:

- poreklo procesa na krajnjoj tački i odredište koje se ne očekuje za tu aplikaciju;
- nepoklapanje između SNI i HTTP authority tamo gde je TLS inspekcija zakonita i dostupna;
- CDN logove koji pokazuju da jedan tenant/front usmerava saobraćaj ka drugom authority/origin;
- neuobičajene dugotrajne ili periodične sesije sa servisom koji se inače koristi interaktivno;
- stabilne veličine i ritam šifrovanih tokova uprkos promeni front domena.

Bezbedna laboratorijska vežba simulira nepoklapanje usmeravanja na reverse proxy-ju koji ste vlasništvom, a ne zloupotrebljava javni CDN.

## Dinamičko razrešavanje: DDNS, DGA i fast flux

Dinamičko razrešavanje odvaja logičku uslugu od fiksne infrastrukture:

- **DDNS:** autentifikovani klijent ažurira stabilno ime kada se njegova adresa promeni.
- **DGA:** krajnja tačka i kontroler izvode kandidate za imena domena iz semena vremena/ključa; operater registruje mali broj njih.
- **Fast flux:** ime vraća skup brzo promenljivih kompromitovanih/proxy adresa, često sa niskim TTL-ovima.
- **Double flux:** rotiraju se i adrese usluga i adrese autoritativnih name servera, čime se skriva i kontrolni sloj.

Fast flux je obrazac distribucije opterećenja koji se koristi u napadačke svrhe, a ne samo „mnogo DNS odgovora“. Jači dokazi kombinuju nizak TTL, veliki broj jedinstvenih adresa, široku disperziju ASN-ova/geografskih lokacija, kratak vek čvorova, ponavljano ponašanje aplikacije i sumnjivu istoriju registracije. CDN-ovi legitimno dele nekoliko ovih svojstava. MITRE preporučuje povezivanje DNS ponašanja sa procesom i kasnijim vezama.<sup>[[5]](#references)</sup>

DGA se može detektovati preko leksičke entropije, obrazaca suglasnika/cifara, naleta NXDOMAIN odgovora, sinhronizovanih domena viđenih prvi put i konteksta procesa. DGA-i zasnovani na listama reči i generativni modeli zaobilaze jednostavna pravila entropije, zbog čega su vremensko grupisanje na nivou celog sistema i poreklo krajnje tačke važniji.

## Kompromitovani domeni i domain shadowing

Napadač može da otme nalog registrara/DNS-a, preuzme viseći poddomen ili doda zapise ispod domena koji je inače reputabilan. **Domain shadowing** zadržava legitimni apex domen, dok veliki broj poddomena pod kontrolom napadača upućuje na promenljive hostove za isporuku ili C2. Tako se pozajmljuju starost i reputacija domena, a može se izbeći blokiranje celog domena.<sup>[[6]](#references)</sup>

Braniocima su potrebni audit logovi registrara i autoritativnog DNS-a, MFA, registry/registrar lock-ovi, upozorenja za nove delegacije/API tokene/name servere, nadzor Certificate Transparency-ja i inventar cloud resursa na koje upućuje DNS. Rezoluciju i istoriju sertifikata poddomena istražujte nezavisno od reputacije apex domena.

## Web usluge i dead-drop resolver-i

**Dead-drop resolver (T1102.001)** čuva kodirani pokazivač ka trenutnom C2-u unutar legitimne objave, profila, dokumenta, repozitorijuma, cloud objekta ili blockchain polja. Malware preuzima javni objekat, dekodira domen/IP adresu i povezuje se sa sledećom fazom. Dvosmerne varijante razmenjuju komande ili datoteke preko API-ja usluge.<sup>[[7]](#references)</sup>

Jedna GitHub-specifična varijanta resolver-a koristi Issues Search API samo kada autentifikovani kanal repozitorijuma ne uspe. Klijent traži issues koji odgovaraju trenutnom datumu, repozitorijumu i tipu issue-a, prati URL komentara svakog issue-a i izdvaja šifrat između oznaka `<!--` i `-->`. Nakon dekripcije po hostu, izvedene iz datuma, polja kao što su `Owner`, `LicRepo` i `LicToken` zamenjuju primarnog vlasnika repozitorijuma, putanju i token. To omogućava operateru da rotira akreditive i krajnje tačke bez zamene klijenta; komentar issue-a služi kao resolver, dok datoteke repozitorijuma ostaju kanal za zadatke.<sup>[[15]](#references)</sup>

Ovo pruža otpornost i skriva back-end C2 od statičke analize binarne datoteke. Takođe stvara stabilne identifikatore objekta, tenant-a, repozitorijuma, API-ja i obrazaca pristupa. Branioci treba da povežu:

1. proces koji je kontaktirao uslugu;
2. tačnu API putanju/objekat i hash odgovora;
3. aktivnost dekodiranja ili obrade stringova;
4. novu odlaznu vezu ubrzo nakon toga; i
5. isto ponašanje na drugim mestima u sistemu.

Blokiranje celog GitHub-a, cloud skladišta ili društvenih medija retko je izvodljivo. Politika izlaznog saobraćaja zasnovana na uslugama i korelacija na nivou procesa efikasnije su od blokiranja samo po domenu.

## Personae, nalozi i nabavka kroz odvojene segmente

Anonimnost infrastrukture ne uspeva kada persona, rezervni email, telefon, plaćanje, pregledač ili administratorska IP adresa povezuje odvojene segmente. Operacije povezane sa državama unapred su razvijale društvene profile, email identitete i cloud naloge; ATT&CK to beleži kao Establish Accounts (T1585), uključujući podtehnike za društvene mreže, email i cloud.<sup>[[8]](#references)</sup>

Branilac ili istražitelj gradi graf na osnovu:

- vremena kreiranja i prve prijave, lokaliteta, vremenske zone i radnog rasporeda;
- polja za oporavak naloga, MFA uređaja, identifikacionih dokumenata i načina plaćanja;
- otisaka pregledača/TLS-a i istorije izvornih mreža;
- ponovne upotrebe avatara, porekla slika, stila pisanja i rasta društvenog grafa;
- zajedničkog registranta domena, name servera, sertifikata, analytics ID-ja ili commita u repozitorijumu;
- radnji na kontrolnoj ravni koje zaobilaze arhitekturu javnog releja.

Za ovlašćeni red team, sintetičke persone treba dokumentovati kod kontrolora vežbe, koristiti recovery/payment kanale u vlasništvu organizacije, izbegavati lažno predstavljanje stvarnih, nepovezanih osoba i imati planirano povlačenje. SOC može ostati neobavešten, ali operacija ne sme postati neodgovorna.

## Obrasci u nastajanju koje treba modelovati kao pretnje

Sledeće su **kombinacije osmišljene iz perspektive odbrane**, a ne tvrdnje da je imenovani akter primenio svaki tačno ovakav dizajn. Kombinuju već uočene primitive i korisne su kao hipoteze za purple team vežbe.

### Asimetrično jednosmerno zadavanje zadataka

Komande stižu preko javnog, broadcast ili append-only izvora, dok rezultati odlaze drugim kanalom nakon odlaganja. Primeri primitiva obuhvataju jednosmernu komunikaciju preko web usluga i dead drop-ove. Razdvajanje sprečava da jedan tok deluje dvosmerno i otežava jednostavnu korelaciju zahtev/odgovor.<sup>[[9]](#references)</sup>

**Detekcija:** sačuvajte čitanja na nivou objekta, a zatim povežite promene stanja procesa sa kasnijim odlaznim prenosima u širem vremenskom prozoru. Tražite redak proces koji čita isti javni objekat, čak i kada nema neposrednog odgovora.

### Promovisanje kanala kroz više faza

Tiha prva faza obavlja inventarizaciju i promoviše samo odabrane sisteme na nepovezani kanal druge faze. Druga krajnja tačka, protokol i proces možda nemaju zajedničku infrastrukturu sa prvom fazom. Time se ograničava izloženost sposobnije infrastrukture, a obrazac je izričito modelovan kao ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detekcija:** povežite `prvi mrežni proces -> preuzeto/konfigurisano stanje -> novi proces ili ubacivanje koda -> nepovezano odredište`; ne zatvarajte incident nakon blokiranja prvog domena.

### Prevođenje releja između protokola

Različiti hop-ovi prevode HTTPS, QUIC, WebSocket, DNS, SSH ili API message-queue-a umesto da transparentno prosleđuju pakete. Prevođenje uklanja jedinstven end-to-end otisak protokola, ali stvara gateway-e sa prepoznatljivim vremenom, baferovanjem i semantičkom konverzijom. Tunneling protokola (T1572) može se kombinovati sa proxy-jima i lažnim predstavljanjem usluga.<sup>[[11]](#references)</sup>

**Detekcija:** tražite gateway hostove koji primaju jedan protokol, a uspostavljaju drugi, uz tesno povezano ponašanje u obimu podataka/vremenu; uporedite namenu krajnje tačke sa protokolom koji se zaista prenosi.

### Pasivno aktiviranje na edge uređajima

Umesto slanja beacon-a, implant prati saobraćaj koji već stiže do rutera/VPN-a i aktivira se samo na posebnu vrednost, obrazac izvornog porta ili autentifikovani token. Uobičajeni saobraćaj nastavlja ka stvarnoj usluzi. ATT&CK ovo naziva Traffic Signaling (T1205), uz dokumentovane primere mrežnih uređaja i APT-a.<sup>[[12]](#references)</sup>

**Detekcija:** integritet firmware-a/datoteka, snimanje sirovih paketa tokom ovlašćene istrage, neočekivani socket filteri i razlike u ponašanju usluge. Odsustvo periodičnog beacon-a ne dokazuje da je edge uređaj čist.

### Rotacija serverless i ephemeral origin-a

Front zadržava stabilan logički identitet, dok kratkotrajne funkcije/kontejneri obrađuju pojedinačne faze u nekoliko regiona/naloga. Time se skraćuje životni vek podataka na disku i izbegavaju fiksne origin IP adrese, ali kreiranje na kontrolnoj ravni, image/layer, uloga, tajna, request ID i telemetrija naplate postaju trajni elementi grafa.

**Detekcija:** čuvajte cloud audit i invocation logove izvan workload-a; grupišite deployment šablone, uloge, ključeve okruženja i odnose front-origin.

### Raznolikost slojeva privatnosti

Operacija može namerno da izbegne jedan ujednačen lanac: na primer, jedan kanal koristi iznajmljeni relej, zadaci koriste javni objekat, izlaz koristi vlasničku mobilnu vezu iz laboratorije, a administracija zasebnu mrežu organizacije. Ovo smanjuje vrednost kompromitovanja jednog provajdera, ali povećava rizik korelacije vremena između slojeva i operativnih grešaka.

**Detekcija:** pravite vremenske linije kampanje preko senzora identiteta, DNS-a, SaaS-a, mreže i cloud-a. Tražite sinhronizovane promene stanja umesto istih indikatora.

### Decentralizovani dead drop-ovi ili dead drop-ovi u transparency log-u

Napadač može da postavi mali šifrovani pokazivač u bilo koji trajan, javni append-only sistem, content-addressed skladište ili feed nalik transparency log-u. Javni objekat je otporan, ali njegov tačan indeks/hash sadržaja i ponašanje klijenta pri polling-u postaju stabilni identifikatori.

**Detekcija:** beležite pune API/objekt identifikatore i hash-eve odgovora; postavljajte upozorenja za nestandardne procese koji proveravaju nepromenljive objekte, a zatim ih dekodiraju ili uspostavljaju nove veze.

### Odložene operacije store-and-forward

Interaktivni C2 stvara snažnu vremensku korelaciju. Dizajn store-and-forward grupiše šifrovane zadatke i vraća rezultate minutima ili satima kasnije preko drugog reda ili fizičkog prenosa. Time se žrtvuje odzivnost radi slabije end-to-end vremenske korelacije.

**Detekcija:** produžite vremenske prozore korelacije, modelujte periodični pristup redovima i pregledajte staging na krajnjim tačkama. Grupisanje premešta signal sa vremena prenosa paketa na zakazano ponašanje procesa/datoteka; ne uklanja ga.

## Pregled dizajna: razmišljajte iz perspektive posmatrača

Za svaku putanju popunite ovu tabelu pre raspoređivanja i nakon prikupljanja podataka:

| Sloj | Vidi izvor? | Vidi odredište? | Vidi sadržaj? | Stabilni identifikatori | Vlasnik zadržavanja podataka/pravnih obaveza |
|---|---:|---:|---:|---|---|
| lokalna mreža/operater | | | | | |
| ulazna/pristupna usluga | | | | | |
| operater(i) za prosleđivanje | | | | | |
| izlazni relej/redirector/CDN | | | | | |
| autoritativni DNS/registrar | | | | | |
| cilj | | | | | |
| provajder naloga/plaćanja | | | | | |

Ako jedan uobičajeni provajder može da popuni svaku kolonu, arhitektura pruža prikrivanje od cilja, ali ne i pouzdano razdvajanje. Ako nijedan interni kontrolor ne može da poveže aktivnost sa angažmanom, arhitektura nije pogodna za profesionalni red teaming.

## References

- [1] [MITRE ATT&CK — Nabavka infrastrukture (T1583), kompromitovanje infrastrukture (T1584) i proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Špijunski akteri povezani s Kinom koriste ORB mreže](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Višehopni proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kompromitovanje infrastrukture: domeni (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web usluga: dead-drop resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Kreiranje naloga (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web usluga: jednosmerna komunikacija (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Višefazni kanali (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunneling protokola (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Signalizacija saobraćajem (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Prekid rada najveće svetske mreže rezidencijalnih proxy-ja](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampanje senki: otkrivanje globalne špijunaže](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel kampanja cilja iračku infrastrukturu](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
