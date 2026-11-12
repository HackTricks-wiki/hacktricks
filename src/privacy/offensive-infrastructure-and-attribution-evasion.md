# Ofanzivna infrastruktura i izbegavanje atribucije

{{#include ../banners/hacktricks-training.md}}

Operater retko postiže značajnu anonimnost pomoću jednog proxy-ja. Prave kampanje grade **graf razdvajanja**: operater pristupa pristupnom čvoru, posrednički čvorovi skrivaju taj čvor od izlaznog čvora, redirectori štite pravi C2, a jednokratna imena upućuju na javnu ivicu.

Za standardizovan pregled prednosti i mana, primene i detekcije svih putanja koristite [Katalog tehnika za anonimni pristup internetu](anonymous-internet-access-techniques.md). Ova stranica detaljnije obrađuje sastavljanje adversarijalne infrastrukture.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Poslednja adresa koju meta vidi zato je dokaz o putanji, a ne dokaz o tome ko je upravljao tastaturom. MITRE mapira glavne komponente na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klase infrastrukture

| Klasa | Zašto je akter koristi | Trajna izloženost | Najbolja tačka pivotiranja za branioca |
|---|---|---|---|
| Iznajmljeni VPS/cloud | Brz, predvidljiv, dostupan za rutiranje i jednostavan za ponovnu izgradnju | Podaci o zakupcu, naplati, konzoli, prijavama sa izvornih lokacija i istoriji slika | Događaji na nivou naloga/kontrolne ravni i ponavljajući otisak servera |
| Komercijalni VPN/Tor | Veliki skup zajedničkih izlaznih adresa; nema administracije servera | Vidljivost pružaoca/nadzora i korelacija vremena od početka do kraja | Ponašanje odredišta, dokazi sa krajnjih tačaka i korelacija tokova |
| Rezidencijalni/mobilni proxy | Potrošački ASN i uverljiva geografska lokacija | Podaci brokera/korisnika; ponašanje proxyware-a ili zaraženog hosta | Nemoguće putovanje, proxy protokoli i promena adrese po sesiji |
| Kompromitovani server/ruter/IoT | Pozajmljuje reputaciju i jurisdikciju žrtve | Implant, upravljački tok i ponavljajući uzvodni kontroler | Telemetrija uređaja i ORB topologija, a ne jedna izlazna IP adresa |
| CDN/redirector | Razdvaja javni edge od pozadinskog C2 | TLS/HTTP gramatika, sertifikat, rutiranje i artefakti cloud naloga | Korelacija edge-a sa originom i grupisanje po obliku zahteva |
| Legitimni web servis | Stapa se sa dozvoljenim GitHub/cloud/društvenim saobraćajem | API token, identifikatori zakupca/objekta i neuobičajeno poreklo procesa | Proces na krajnjoj tački i semantika servisa/API-ja |
| Fizička/mobilna/satelitska putanja | Menja prividno fizičko poreklo | RF, operater, pretplatnik, uređaj i podaci o lokaciji | Kombinovani radiofizički i mrežni dokazi |

## Mreže operativnih relay box-ova

**ORB mreža** je upravljana proxy flota koja se koristi kao posredni servis. Mandiant ih deli na obezbeđene mreže iznajmljenih servera, mreže koje nisu obezbeđene i sastoje se od kompromitovanih rutera/IoT uređaja, i hibridne mreže. Zrela topologija ima četiri logičke uloge:<sup>[[2]](#references)</sup>

1. **Administracioni server (ACOS):** održava inventar, akreditive, stanje i politiku rutiranja.
2. **Pristupni/relay čvor:** autentifikuje korisnike ili operatere; to je stabilna ulazna tačka u promenljivu mrežu.
3. **Čvorovi za prosleđivanje:** jedan ili više iznajmljenih ili kompromitovanih sistema prosleđuju neprozirne veze.
4. **Izlazni/pripremni čvor:** predstavlja konačnu izvornu adresu ciljevima za izviđanje, eksploataciju ili C2.

Mreža može da bira izlazne čvorove prema zemlji, ASN-u, latenciji ili dostupnosti i da menja neispravne čvorove. Više grupa pretnji može da iznajmljuje istu mrežu. Mandiant je primetio da je jedna IPv4 adresa u nekim ORB-ovima ostajala povezana sa njima svega 31 dan; zato preporučuje da se **mreža posmatra kao promenljiv entitet nalik akteru**, umesto da se blokira zastarela lista IP adresa.<sup>[[2]](#references)</sup>

### Šta ovo omogućava — i šta otkriva

- Meta vidi izlazni čvor koji može biti geografski blizu i naizgled rezidencijalan.
- Izlazni čvor vidi metu i prethodni skok, ali ne nužno i operatera.
- Pristupni servis vidi korisnika i zahtev za rutom. Nezavisno upravljana mreža može da razdvoji korisnika od izlaznih čvorova, ali time nastaje moćan zapis kod druge strane.
- Ponavljajući portovi, redosled rukovanja, baneri servera, sertifikati, periodi dostupnosti i odnosi između kontrolera mogu da otkriju flotu čak i dok se IP adrese menjaju.
- Kompromitovanom ruteru često nedostaje telemetrija krajnje tačke, ali njegov ISP i dalje ima podatke o pretplatniku i tokovima; zaplena otkriva artefakte implanta/konfiguracije.

{% hint style="info" %}
Za ovlašćenu vežbu, reprodukujte topologiju pomoću virtuelnih mašina ili rutera u vlasništvu organizacije i sačuvajte mapu atribucije kontrolera. Nemojte koristiti otvorene proxy-je niti uređaje trećih strana. [Vodič za laboratoriju](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) pravi istu strukturu skokova vidljivu braniocu, a da pritom ne koristi posrednika kao žrtvu.
{% endhint %}

## Rezidencijalne i mobilne proxy mreže

Rezidencijalni proxy servisi dodeljuju sesije adresama potrošačkih širokopojasnih veza; mobilni proxy-ji izlaze preko NAT skupova operatera. Izvori mogu biti izričito prijavljeni uređaji, SDK/proxyware ugrađen u potrošačke aplikacije, preprodavci ili malver. Ovi izvori nisu istovetni: nedostatak informisanog pristanka pretvara servis za privatnost u kompromitovanu infrastrukturu.

Načini rotacije utiču na detekciju:

- **rotacija po zahtevu** stvara brze diskontinuitete IP adresa i ASN-a/geografske lokacije, dok identitet na višim slojevima ostaje stabilan;
- **lepljive sesije** zadržavaju izlazni čvor nekoliko minuta ili sati, nalik uobičajenom pretplatniku;
- **backconnect gateway-i** korisniku izlažu jednu brokersku krajnju tačku, a interno biraju izlazne čvorove;
- **mobilni skupovi** smeštaju mnogo stvarnih pretplatnika iza malog broja NAT adresa operatera, pa je blokiranje IP adrese skupo.

Branioci treba da korelišu IP adresu sa autentifikovanom sesijom, TLS/klijentskim otiskom, redosledom HTTP zahteva, kolačićem uređaja i ponašanjem. Prijava navodno sa lokalne rezidencijalne adrese, kojoj zatim sledi prijava iz druge zemlje dok sve karakteristike viših slojeva ostaju iste, ubedljiviji je signal od same reputacije. S druge strane, deljenje adresa i promena mobilne veze uzrokuju legitimne promene, zato klasifikaciju kao rezidencijalnog/proxy saobraćaja nikada ne smatrajte konačnim zaključkom.

### Kontrolne ravni proxyware-a i preklapanje preprodavaca

Nemojte modelovati rezidencijalni skup kao prostu listu izlaznih čvorova. Analiza IPIDEA ekosistema otkrila je kontrolnu ravan sa ponovnom upotrebom u **dva nivoa**: ugrađeni SDK najpre šalje metapodatke o uređaju/registraciji domenu prvog nivoa, a zatim dobija raspoređivanje i IP:port parove `connect`/`proxy` drugog nivoa. Čvor periodično proverava port `connect` drugog nivoa u potrazi za kodiranim zadatkom, otvara drugu vezu ka uparenom portu `proxy` i prosleđuje zadate bajtove traženom odredištu. SDK-ovi i proxy brendovi koji su se nominalno razlikovali imali su zasebne domene za pronalaženje, ali su se preklapali u zajedničkoj infrastrukturi drugog nivoa i skupovima izlaznih čvorova, usled zajedničkog vlasništva i odnosa sa preprodavcima.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Ovo daje trajnije pivot tačke za lov od bloka rezidencijalnih IP adresa:<sup>[[13]](#references)</sup>

- neočekivani proces iz oblasti komunalnih usluga, VPN-a, igara ili ugrađenih uređaja šalje stabilan ID uređaja/ključ korisnika i prima promenljivu listu servera;
- endpoint šalje upite direktnoj IP adresi na neuobičajenom portu, a zatim se povezuje na drugi port iste adrese neposredno pre otvaranja socket-a ka novom odredištu;
- nekoliko prividnih brendova deli Tier Two adrese, gramatiku protokola, SDK kod ili preklapanje exit-node čvorova;
- različite aplikacije koje kontaktiraju različite Tier One domene dobijaju adrese iz istog Tier Two skupa.

Preklapanje takođe ograničava atribuciju: to što se IP adresa nalazi u oglašenom skupu nekog dobavljača ne utvrđuje koji ju je preprodavac, korisnik ili akter pretnje koristio u relevantnom trenutku. Sačuvajte vremenske oznake tokova, poreklo procesa, tela odgovora Tier One i identifikatore zadataka Tier Two.<sup>[[13]](#references)</sup> U okviru odobrene vežbe, oponašajte ovu hijerarhiju isključivo pomoću endpointa u vlasništvu organizacije; nikada nemojte uključivati uređaje potrošača ili proxyware trećih strana.

## Višeskokovni proxy lanci

MITRE razlikuje eksterne proxy servere od **višeskokovnih proxy servera (T1090.003)**. Ključno svojstvo nije broj skokova, već razdvajanje znanja i administracije.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Ako jedna strana upravlja A i B, zajednički logovi ili vremenski obrasci protoka mogu da otkriju circuit. Dodavanje uzastopnih komercijalnih VPN-ova sa iste krajnje tačke/naloga može povećati latenciju, a da pritom ostanu zajednički identitet, podaci o plaćanju i vremenski obrasci. Tor umanjuje ovaj problem nezavisno odabranim relay-ima i zajedničkim dizajnom klijenta, ali mreža sa malom latencijom za interaktivni saobraćaj ne može da garantuje otpornost na posmatrača koji meri obe krajnje tačke.

Česti propusti su zaobilaženje preko DNS-a ili IPv6, aplikacije koje otvaraju sopstvene sokete, upravljački saobraćaj koji direktno stiže do relay-a, sinhronizovana aktivnost, ponovo korišćeni SSH ključevi i prijavljivanje na naloge koji otkrivaju identitet. Ispravna provera je test otkaza: zaustavite svaki relay redom i pokažite da radno opterećenje ne može da pređe na nešifrovanu putanju.

### Kolaps tunela i upstream leak

Relay arhitektura je često najlakše poveziva sa akterom kada zakaže. Unit 42 je dokumentovao višeslojnu špijunsku putanju koja je koristila VPS-ove okrenute ka žrtvama, relay VPS-ove, rezidencijalne proxy-je, Tor i druge proxy servise; kada bi tunel bio izostavljen ili bi se urušio, skrivena upstream infrastruktura povezivala se direktno sa relay sistemima i sistemima okrenutim ka žrtvama. Ista istraga je koristila i X.509 sertifikat nakratko izložen na upstream infrastrukturi kao osnovu za povezivanje između slojeva.<sup>[[14]](#references)</sup>

Držite **data plane** (`victim <-> exit`) odvojenim od **control plane**-a (`operator/upstream -> relay administration`). Zadržavajte ingress i authentication logove na svakom sloju kojim upravljate, istoriju sertifikata i kratkotrajne neuspele konekcije — ne samo uspešne C2 sesije. Izvor koji se pojavljuje samo tokom prekida relay-a ili direktno administrira više čvorova okrenutih ka žrtvama snažniji je kandidat za upstream nego običan exit, ali njegov ASN/geolokacija i dalje su hipoteza, a ne dokaz identiteta operatera.

U ovlašćenom labu treba podesiti radno opterećenje da pri otkazu ne uspostavlja vezu. Kod radnog opterećenja izolovanog u Linux network namespace-u, prva ruta mora da koristi tunel; nakon njegovog uklanjanja, i zahtev i provera rute moraju da ne uspeju, umesto da izaberu fizički uplink:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Ponovite test za DNS i IPv6, kao i na granici svakog relay-a. Ako bilo koja proba uspe, zabeležite stvarni interfejs/izvornu adresu pre nego što popravite policy routing ili firewall; to zapažanje predstavlja attribution leak koji bi istražitelj uočio.

## Slojevi redirector-a i oblikovanje saobraćaja

Javni **redirector** prihvata saobraćaj koji odgovara gramatici specifičnoj za operaciju i prosleđuje ga zaštićenom team server-u. Sve ostalo može da bude odbijeno ili da dobije bezazlen sadržaj.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Više slojeva ograničava izloženost: odbacivanje javnog domena ne mora da otkrije timski server. CDN-ovi dodaju anycast kapacitet i reputabilan spoljašnji domen, ali CDN nalog i edge logovi postaju tačke za atribuciju. TLS otisci, istorija sertifikata, prepoznatljive putanje/redosled zaglavlja, veličine odgovora, ponašanje pri preusmeravanju i liste dozvoljenih origin servera mogu povezati navodno nepovezane frontove.

Za detekciju beležite polja reverse proxy-ja pre normalizacije, upoređujte SNI/Host/authority, pregledajte retke kombinacije zaglavlja, grupišite tela odgovora i TLS otiske i pretražujte cloud/CDN audit logove radi preklapanja konfiguracija. Ovlašćeni red teams ne treba da kopiraju stvarni brend niti da prikupljanje pristupnih podataka postavljaju iza nepovezane treće strane.

## Domain fronting and domainless fronting

Kod klasičnog **domain fronting (T1090.004)**, TLS veza u SNI navodi dozvoljeni front domen, dok šifrovani HTTP `Host` ili HTTP/2 `:authority` zahteva drugi back-end domen. CDN koji učestvuje u tome usmerava saobraćaj na osnovu unutrašnje vrednosti. Mrežni posmatrač bez TLS dešifrovanja vidi front; CDN vidi obe vrednosti i origin. Kod varijanti bez domena, SNI može biti prazan, dok drugo polje za usmeravanje bira odredište.<sup>[[4]](#references)</sup>

Ovo nije magično lažno predstavljanje: funkcioniše samo kada posrednik namerno ili slučajno dozvoljava nepodudaranje i zna kako da usmeri saobraćaj na osnovu unutrašnjeg imena. Veliki provajderi su ograničili fronting između različitih naloga. Encrypted ClientHello (ECH) menja ono što posmatrač na putanji može da vidi, ali ne briše zapise CDN-a, krajnje tačke ni aplikacije.

Tačke za detekciju obuhvataju:

- poreklo procesa na krajnjoj tački i odredište koje nije očekivano za tu aplikaciju;
- nepodudaranje SNI-ja i HTTP authority-ja kada je TLS inspekcija zakonita i dostupna;
- CDN logove koji pokazuju da jedan tenant/front usmerava saobraćaj ka drugom authority/origin-u;
- neuobičajene dugotrajne ili periodične sesije ka servisu koji se obično koristi interaktivno;
- stabilne veličine i učесталост šifrovanog saobraćaja kroz front domene koji se menjaju.

Bezbedna laboratorija simulira nepodudaranje usmeravanja na reverse proxy-ju koji je u vašem vlasništvu; ne zloupotrebljava javni CDN.

## Dynamic resolution: DDNS, DGA and fast flux

Dinamičko razrešavanje odvaja logički servis od fiksne infrastrukture:

- **DDNS:** autentifikovani klijent ažurira stabilno ime nakon promene svoje adrese.
- **DGA:** krajnja tačka izvodi imena domena iz početne vrednosti, često na osnovu vremena ili ključa, ali ponekad i promenljivog javnog sadržaja; operater podešava DNS za aktivno ime.<sup>[[17]](#references)</sup>
- **Fast flux:** ime vraća skup brzo promenljivih kompromitovanih/proxy adresa, često sa kratkim TTL-ovima.
- **Double flux:** menjaju se i adrese servisa i adrese autoritativnih name servera, čime se skriva i kontrolni sloj.

Fast flux je obrazac raspodele opterećenja koji se koristi u zlonamerne svrhe, a ne samo „mnogo DNS odgovora“. Jači dokaz kombinuje kratak TTL, veliki broj jedinstvenih adresa, široku rasprostranjenost po ASN-u i geografskom području, kratak vek čvorova, ponavljano ponašanje aplikacije i sumnjivu istoriju registracije. CDN-ovi legitimno dele nekoliko tih osobina. MITRE preporučuje povezivanje DNS ponašanja sa procesom i naknadnim vezama.<sup>[[5]](#references)</sup>

DGA se može otkriti na osnovu leksičke entropije, obrazaca suglasnika/cifara, naleta NXDOMAIN odgovora, sinhronizovanih domena prvi put viđenih i konteksta procesa. DGA-ovi zasnovani na listama reči i generativni modeli zaobilaze jednostavna pravila entropije, pa su grupisanje po vremenu u celom okruženju i poreklo procesa na krajnjim tačkama važniji.

### Mutable image seed for a wordlist DGA

DGA ne mora da zavisi od vremena. Jedan loader preuzima stranicu javnog Telegram kanala, čita `src` elementa `tgme_page_photo_image`, preuzima tu profilnu sliku i izračunava hash njenih **poslednjih 50 bajtova datoteke**, a ne dekodiranih piksela. Četiri hash početne vrednosti biraju pridev, imenicu, glagol i broj. Promena slike menja izvedeno DNS ime, bez potrebe da se isporuči novi klijent. Zadržite iste tačne bajtove preuzete slike i isti redosled liste reči na obe strane; ponovno kodiranje slike ili promena redosleda stavki na listi daje drugačija imena.<sup>[[17]](#references)</sup>

Kada se liste reči preuzmu iz klijenta, ovim se ponavlja korak izbora imena. Hash koji izvor izračunava bajt po bajt koristi 64-bitni akumulator, množilac `0x1000193` i odvojene početne vrednosti za svaku komponentu:<sup>[[17]](#references)</sup>

<details>
<summary>Ponovite izbor imena sa liste reči, uz početnu vrednost izvedenu iz slike</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

За разлику од [dead-drop resolver-а](#web-services-and-dead-drop-resolvers), који објављује саму крајњу тачку, јавни објекат овде пружа само променљиво почетно семе; клијент локално изводи крајњу тачку.

Затим се за генерисано име тражи DNS TXT запис преко `https://dns.google/resolve?name=<domain>&type=TXT`. Клијент Base64-декодира поље `data` у JSON одговору, проверава Ed25519 потпис помоћу уграђеног јавног кључа и тек потом AES-ECB-дешифрује команду. Уочени отворени текст почиње селектором метода и URL-ом за шифровани садржај. Провера потписа значи да само разрешив TXT запис не може да обезбеди прихваћено задавање задатака.<sup>[[17]](#references)</sup>

## Компромитовани домени и domain shadowing

Актер може да отме налог регистрара/DNS-а, преузме напуштени поддомен или дода записе испод иначе угледног домена. **Domain shadowing** задржава легитимни apex, док велики број поддомена под контролом нападача упућује на променљиве хостове за испоруку или C2. Овим се користе старост и репутација домена, а може се заобићи и блокирање целог домена.<sup>[[6]](#references)</sup>

Браниоцима су потребни евиденциони записи регистрара и ауторитативног DNS-а, MFA, браве регистра/регистрара, упозорења за нове делегације/API токене/сервере имена, праћење Certificate Transparency и попис cloud ресурса на које DNS упућује. Истражујте резолуцију и историју сертификата поддомена независно од репутације apex-а.

## Web услуге и dead-drop resolver-и

**Dead-drop resolver (T1102.001)** чува кодирани показивач на тренутни C2 у легитимној објави, профилу, документу, репозиторијуму, cloud објекту или blockchain пољу. Malware преузима јавни објекат, декодира домен/IP и повезује се са следећом фазом. Двосмерне варијанте размењују команде или датотеке преко API-ја услуге.<sup>[[7]](#references)</sup>

Једна варијанта resolver-а специфична за GitHub користи Issues Search API само када аутентификовани канал репозиторијума откаже. Клијент тражи issues који одговарају тренутном датуму, репозиторијуму и типу issue-а, прати URL коментара сваког issue-а и издваја шифровани текст између ознака `<!--` и `-->`. Након дешифровања изведеног по хосту и датуму, поља као што су `Owner`, `LicRepo` и `LicToken` замењују примарног власника репозиторијума, путању и токен. Ово омогућава оператору да ротира акредитиве и крајње тачке без замене клијента; коментар у issue-у је resolver, док датотеке репозиторијума остају канал за задавање задатака.<sup>[[15]](#references)</sup>

Android варијанта при покретању бира једну од две јавне Telegram странице и издваја шифровани текст између два појављивања маркера уграђеног у APK. Она Base64URL-декодира вредност и дешифрује је помоћу AES-128-CBC: првих 16 бајтова од `SHA-256(marker)` су кључ, а преосталих 16 бајтова су IV. Отворени текст је стварни C2 основни URL, а не URL Telegram странице. При репродукцији резолуције сачувајте садржај странице и тачан маркер; изменом јавне странице ротира се крајња тачка без поновне изградње APK-а.<sup>[[16]](#references)</sup>

Ово обезбеђује отпорност и скрива позадински C2 од статичке анализе бинарног фајла. Такође ствара стабилне идентификаторе објеката, tenant-а, репозиторијума, API-ја и образаца приступа. Браниоци треба да повежу:

1. процес који је контактирао услугу;
2. тачну API путању/објекат и hash одговора;
3. активност декодирања или обраде стрингова;
4. нову одлазну везу убрзо након тога; и
5. идентично понашање на другим местима у окружењу.

Блокирање целог GitHub-а, cloud storage-а или друштвених мрежа ретко је изводљиво. Контрола излазног саобраћаја свесна услуге и корелација на нивоу процеса ефикасније су од блокирања само на основу домена.

## Персоне, налози и набавни сегменти

Анонимност инфраструктуре пада када persona, адреса е-поште за опоравак, телефон, плаћање, прегледач или администраторска IP адреса повезују сегменте. Операције повезане са државама стварале су друштвене профиле, идентитете е-поште и cloud налоге много пре њихове употребе; ATT&CK то бележи као Establish Accounts (T1585), укључујући друштвене, е-поштанске и cloud под-технике.<sup>[[8]](#references)</sup>

Бранилац или истражитељ гради граф на основу:

- времена креирања и прве пријаве, локалитета, временске зоне и распореда рада;
- поља за опоравак налога, MFA уређаја, докумената за идентификацију и средстава плаћања;
- отисака прегледача/TLS-а и историје изворне мреже;
- поновне употребе аватара, порекла слика, стила писања и раста друштвеног графа;
- заједничког регистратора домена, сервера имена, сертификата, аналитичког ID-а или комита у репозиторијуму;
- радњи у управљачкој равни које заобилазе јавну relay архитектуру.

За овлашћени red team, синтетичке персоне треба документовати код контролора вежбе, користити канале за опоравак/плаћање у власништву организације, избегавати лажно представљање стварних особа које нису укључене и имати планирано повлачење. SOC може остати необавештен; операција не сме постати неодговорна.

## Нови сложени обрасци за моделирање претњи

Следеће су **композиције усмерене на одбрану**, а не тврдње да је неки именовани актер применио сваки тачно описани дизајн. Оне комбинују већ уочене примитиве и корисне су као purple-team хипотезе.

### Асиметрично једносмерно задавање задатака

Команде стижу преко јавног, емитованог или append-only извора, док резултати одлазе другим каналом након одлагања. Примери ових примитива укључују једносмерну комуникацију преко web услуга и dead drop-ове. Раздвајање спречава да један ток делује двосмерно и отежава једноставну корелацију захтева и одговора.<sup>[[9]](#references)</sup>

**Детекција:** сачувајте читања на нивоу објекта, а затим повежите промене стања процеса са каснијим преносима података кроз дужи временски прозор. Потражите редак процес који чита исти јавни објекат чак и када одмах не уследи одговор.

### Промоција канала у више фаза

Тихи први ступањ врши попис и промовише само одабране системе на неповезани канал другог ступња. Друга крајња тачка, протокол и процес можда немају заједничку инфраструктуру са првим ступњем. Ово ограничава изложеност инфраструктуре за сложеније операције и експлицитно је моделовано као ATT&CK T1104.<sup>[[10]](#references)</sup>

**Детекција:** повежите `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; не закључујте инцидент након блокирања првог домена.

### Превођење relay-а између протокола

Различите карике преводе HTTPS, QUIC, WebSocket, DNS, SSH или API реда порука, уместо да транспарентно прослеђују пакете. Превођење уклања један јединствени отисак end-to-end протокола, али ствара gateway-је са препознатљивим временским обрасцима, баферовањем и семантичком конверзијом. Protocol tunneling (T1572) може се комбиновати са proxy-јима и имитацијом услуга.<sup>[[11]](#references)</sup>

**Детекција:** потражите gateway хостове који примају један протокол и покрећу други, уз тесно повезано понашање у погледу бајтова/времена; упоредите намену крајње тачке са протоколом који се заправо преноси.

### Пасивна активација на edge уређајима

Уместо beaconing-а, implant надгледа саобраћај који већ стиже до рутера/VPN-а и активира се само на магичну вредност, образац изворног порта или аутентификовани токен. Нормалан саобраћај наставља ка стварној услузи. ATT&CK ово назива Traffic Signaling (T1205), уз документоване примере мрежних уређаја и APT-а.<sup>[[12]](#references)</sup>

**Детекција:** интегритет firmware-а/датотека, снимање сирових пакета током овлашћене истраге, неочекивани socket филтери и разлике у понашању услуга. Одсуство периодичног beacon-а не доказује да је edge уређај чист.

### Ротација serverless и краткотрајног порекла

Front задржава стабилан логички идентитет, док краткотрајне функције/контейнери обрађују појединачне ступњеве у више региона/налога. Ово скраћује време постојања података на диску и уклања фиксне IP адресе порекла, али телеметрија управљачке равни о креирању, слици/слоју, улози, тајни, ID-у захтева и обрачуну постаје трајни граф.

**Детекција:** чувајте cloud евиденционе записе и евиденцију позива ван радног оптерећења; групишите шаблоне распоређивања, улоге, кључеве окружења и односе између front-а и порекла.

### Разноврсност слојева приватности

Операција може намерно да избегава један хомоген ланац: на пример, један канал користи изнајмљени relay, задавање задатака користи јавни објекат, излаз користи мобилну везу лабораторије у власништву организације, а администрација засебну мрежу организације. Ово умањује вредност компромитовања једног провајдера, али повећава ризик од корелације времена између слојева и оперативних грешака.

**Детекција:** правите временске линије кампање кроз сензоре идентитета, DNS-а, SaaS-а, мреже и cloud-а. Тражите синхронизоване промене стања, а не идентичне индикаторе.

### Dead drop-ови у децентрализованим системима или евиденцијама транспарентности

Актер може поставити мали шифровани показивач у било који трајни јавни append-only систем, content-addressed складиште или feed налик евиденцији транспарентности. Јавни објекат је отпоран, али његов тачан индекс/hash садржаја и образац polling-а клијента постају стабилни идентификатори.

**Детекција:** бележите пуне API/објектне идентификаторе и hash-еве одговора; упозоравајте на неуобичајене процесе који испитују непроменљиве објекте, а затим их декодирају или успостављају нове везе.

### Одложене операције са складиштењем и прослеђивањем

Интерактивни C2 ствара јаку временску корелацију. Дизајн са складиштењем и прослеђивањем групише шифроване задатке и враћа резултате минутима или сатима касније преко другог реда или физичког преноса. Он жртвује брзину одзива ради слабије end-to-end временске корелације.

**Детекција:** продужите временске прозоре корелације, моделирајте периодични приступ реду и испитајте припрему на крајњој тачки. Груписање помера сигнал са временских образаца пакета на заказано понашање процеса/датотека; не уклања га.

## Преглед дизајна: размишљајте као посматрач

За сваку путању попуните ову табелу пре распоређивања и након прикупљања:

| Слој | Види извор? | Види одредиште? | Види садржај? | Стабилни идентификатори | Рок чувања/правни власник |
|---|---:|---:|---:|---|---|
| локална мрежа/оператер | | | | | |
| улазна/приступна услуга | | | | | |
| оператор(и) traversal-а | | | | | |
| излаз/redirector/CDN | | | | | |
| ауторитативни DNS/регистратор | | | | | |
| циљ | | | | | |
| провајдер налога/плаћања | | | | | |

Ако један уобичајени провајдер може да попуни сваку колону, архитектура прикрива активности од циља, али не обезбеђује робусно раздвајање. Ако ниједан интерни контролор не може да повеже активности са ангажовањем, архитектура није погодна за професионални red teaming.

## References

- [1] [MITRE ATT&CK — Прибављање инфраструктуре (T1583), компромитовање инфраструктуре (T1584) и Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Шпијунски актери повезани са Кином користе ORB мреже](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Вишеструки Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Компромитовање инфраструктуре: домени (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web услуга: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Успостављање налога (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web услуга: једносмерна комуникација (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Вишестепени канали (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Ометање највеће светске мреже резиденцијалних Proxy сервера](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Кампање из сенке: откривање глобалне шпијунаже](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Кампања Blinder Tunnel циља инфраструктуру Ирака](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI је направио преклапајуће слојеве. Жртве губе PIN-ове](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Трикови из прошлости примењени преко потписаних ChatGPT и Claude бинарних фајлова](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
