# Ofanzivna infrastruktura i izbegavanje atribucije

{{#include ../banners/hacktricks-training.md}}

Operator retko postiže značajnu anonimnost koristeći samo jedan proxy. Prave kampanje grade **graf razdvajanja**: operator se povezuje sa pristupnim čvorom, čvorovi za prosleđivanje skrivaju taj čvor od izlaznog čvora, redirectori štite pravi C2, a jednokratna imena upućuju na javnu ivicu.

Koristite [Katalog tehnika za anoniman pristup internetu](anonymous-internet-access-techniques.md) za standardizovani pregled prednosti i nedostataka, primene i detekcije za svaki put. Ova stranica detaljnije obrađuje sastavljanje protivničke infrastrukture.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Poslednja adresa koju vidi meta zato je dokaz putanje, a ne dokaz ko je upravljao tastaturom. MITRE mapira glavne komponente na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klase infrastrukture

| Klasa | Zašto je akter koristi | Trajna izloženost | Najbolja polazna tačka za branioca |
|---|---|---|---|
| Iznajmljeni VPS/cloud | Brz, predvidljiv, dostupan preko mreže, lako ga je ponovo izgraditi | zakupac, naplata, konzola, istorija izvornih prijava i image-a | događaji na nalogu/control plane-u i ponavljajući otisak servera |
| Komercijalni VPN/Tor | Velik skup zajedničkih izlaznih adresa; ne zahteva administraciju servera | uvid provajdera/nadzornika i end-to-end vremensko usklađivanje | ponašanje prema odredištu, dokazi sa endpointa i korelacija saobraćajnih tokova |
| Rezidencijalni/mobilni proxy | Potrošački ASN i geografska uverljivost | evidencija brokera/korisnika; proxyware ili ponašanje zaraženog hosta | nemoguće putovanje, proxy protokoli i promena adresa po sesiji |
| Kompromitovani server/ruter/IoT | Pozajmljuje reputaciju i jurisdikciju žrtve | implant, tok upravljanja i ponavljajući upstream kontroler | telemetrija uređaja i ORB topologija, a ne jedna izlazna IP adresa |
| CDN/redirector | Razdvaja javni edge od back-end C2 | TLS/HTTP gramatika, sertifikat, rutiranje i artefakti cloud naloga | korelacija edge-to-origin i grupisanje po obliku zahteva |
| Legitimna web usluga | Uklapa se u dozvoljeni saobraćaj ka GitHub/cloud/društvenim mrežama | API token, identifikatori zakupca/objekta i neuobičajeno poreklo procesa | proces na endpointu i semantika usluge/API-ja |
| Fizička/mobilna/satelitska putanja | Menja prividno fizičko poreklo | RF, evidencija operatera, pretplatnika, uređaja i lokacije | kombinacija radio/fizičkih i mrežnih dokaza |

## Mreže operativnih relay box-ova

**ORB mreža** je upravljana proxy flota koja se koristi kao posrednička usluga. Mandiant ih deli na unapred obezbeđene mreže iznajmljenih servera, mreže bez unapred obezbeđenih resursa koje čine kompromitovani ruteri/IoT uređaji i hibridne mreže. Zrela topologija ima četiri logičke uloge:<sup>[[2]](#references)</sup>

1. **Administracioni server (ACOS):** održava inventar, kredencijale, ispravnost i pravila rutiranja.
2. **Pristupni/relay čvor:** autentifikuje klijente ili operatere; to je stabilna ulazna tačka u promenljivu mrežu.
3. **Traversal čvorovi:** jedan ili više iznajmljenih ili kompromitovanih sistema prosleđuju neprozirne veze.
4. **Izlazni/staging čvor:** predstavlja konačnu izvornu adresu tokom izviđanja, eksploatacije ili C2 komunikacije sa metama.

Mreža može da bira izlazne čvorove prema državi, ASN-u, latenciji ili dostupnosti i da menja neispravne čvorove. Više pretnji može da iznajmljuje istu mrežu. Mandiant je zabeležio da je neka IPv4 adresa bila povezana sa pojedinim ORB-ovima svega 31 dan; zato preporučuje da se **mreža tretira kao promenljiv entitet nalik akteru**, umesto da se blokira zastarela lista IP adresa.<sup>[[2]](#references)</sup>

### Šta ovo omogućava — i šta odaje

- Meta vidi izlazni čvor koji može biti geografski blizu i naizgled rezidencijalan.
- Izlazni čvor vidi metu i prethodni hop, ali ne nužno i operatora.
- Pristupna usluga vidi klijenta i zahtev za rutom. Mreža kojom se nezavisno upravlja može da razdvoji klijenta od izlaznih čvorova, ali pritom stvara vrednu evidenciju kod druge ugovorne strane.
- Ponavljajući portovi, redosled handshake-a, baneri servera, sertifikati, periodi dostupnosti i veze sa kontrolerima mogu da otkriju flotu čak i kada se IP adrese rotiraju.
- Kompromitovanom ruteru često nedostaje telemetrija endpointa, ali njegov ISP i dalje ima podatke o pretplatniku i saobraćajnim tokovima; zaplena otkriva artefakte implanta/konfiguracije.

{% hint style="info" %}
Za odobrenu vežbu, reprodukujte topologiju pomoću VM-ova ili rutera u vlasništvu organizacije i sačuvajte mapu atribucije kontrolera. Ne regrutujte otvorene proxy-je niti uređaje trećih strana. [Vodič za laboratoriju](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) pravi istu strukturu hop-ova vidljivu braniocima, bez ugrožavanja posrednika.
{% endhint %}

## Rezidencijalne i mobilne proxy mreže

Rezidencijalne proxy usluge dodeljuju sesije adresama potrošačkih broadband veza; mobilni proxy-ji izlaze preko NAT skupova operatera. Resursi mogu dolaziti od uređaja čiji su vlasnici izričito pristali na uključivanje, SDK/proxyware-a ugrađenog u potrošačke aplikacije, preprodavaca ili malware-a. Ovi izvori nisu istovetni: bez informisanog pristanka, usluga privatnosti postaje kompromitovana infrastruktura.

Načini rotacije utiču na detekciju:

- **rotacija po zahtevu** izaziva brze diskontinuitete IP adrese i ASN-a/geografije, dok identitet na višim slojevima ostaje stabilan;
- **lepljive sesije** zadržavaju izlazni чvor на nekoliko minuta ili sati i liče na običnog pretplatnika;
- **backconnect gateways** klijentu prikazuju jednu brokersku krajnju tačku, a interno biraju izlazne čvorove;
- **mobilni skupovi** smeštaju mnogo stvarnih pretplatnika iza malog broja mobilnih NAT adresa, zbog čega je blokiranje IP adrese skupo.

Branioci treba da korelišu IP adresu sa autentifikovanom sesijom, TLS/klijentskim otiskom, redosledom HTTP zahteva, kolačićem uređaja i ponašanjem. Navodno lokalna rezidencijalna prijava praćena prijavom iz druge države, uz nepromenjene karakteristike viših slojeva, jači je signal od same reputacije. Nasuprot tome, deljenje adresa i promena mobilne mreže stvaraju legitimnu fluktuaciju, zato klasifikaciju kao rezidencijalni/proxy nikada ne tretirajte kao konačan zaključak.

### Control plane-ovi proxyware-a i preklapanje preprodavaca

Ne modelujte rezidencijalni skup kao ravnu listu izlaznih čvorova. Analiza IPIDEA ekosistema otkrila je ponovo upotrebljiv **dvoslojni control plane**: ugrađeni SDK najpre šalje metapodatke o uređaju/registraciji domenu Tier One, a zatim dobija parove IP:port za zakazivanje i Tier Two `connect`/`proxy`. Čvor povremeno proverava Tier Two connect port radi kodiranog zadatka, otvara drugu vezu ka uparenom proxy portu i prosleđuje dostavljene bajtove do traženog odredišta. SDK-ovi i proxy brendovi koji su nominalno bili različiti imali su odvojene discovery domene, ali su se spajali na zajedničku Tier Two infrastrukturu i preklapajuće izlazne skupove zbog zajedničkog vlasništva i odnosa sa preprodavcima.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Ovo daje trajnije hunting pivote od bloka rezidencijalnih IP adresa:<sup>[[13]](#references)</sup>

- neočekivani proces uslužnog programa, VPN-a, igre ili ugrađenog uređaja šalje stabilni ID uređaja/korisnički ključ i prima promenljivu listu servera;
- endpoint proverava direktnu IP adresu na neuobičajenom portu, zatim se povezuje na drugi port na istoj adresi neposredno pre otvaranja socket-a ka novom odredištu;
- više prividnih brendova deli Tier Two adrese, gramatiku protokola, SDK kod ili preklapanje izlaznih čvorova;
- različite aplikacije koje kontaktiraju različite Tier One domene dobijaju adrese iz istog Tier Two skupa.

Ovo preklapanje takođe ograničava atribuciju: to što se IP adresa pojavljuje u oglašenom skupu nekog vendora ne dokazuje koji ju je reseller, korisnik ili akter pretnje koristio u relevantnom trenutku. Sačuvajte vremenske oznake tokova, poreklo procesa, tela odgovora Tier One i identifikatore zadataka Tier Two.<sup>[[13]](#references)</sup> U ovlašćenoj vežbi emulirajte ovu hijerarhiju isključivo pomoću endpointa u vlasništvu organizacije; nikada ne uključujte uređaje potrošača ili proxyware trećih strana.

## Lanci proxy servera sa više skokova

MITRE razlikuje spoljne proxy servere od **multi-hop proxies (T1090.003)**. Važno svojstvo nije broj skokova, već razdvojenost znanja i administracije.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Ako ista strana upravlja i A i B, zajednički logovi ili vremenski obrasci protoka mogu otkriti putanju. Dodavanje uzastopnih komercijalnih VPN-ova sa iste krajnje tačke/naloga može povećati kašnjenje, a da pritom ostanu zajednički identitet, podaci o plaćanju i vremenski obrasci. Tor umanjuje ovaj problem nezavisno odabranim relejima i zajedničkim dizajnom klijenta, ali mreža sa malim kašnjenjem za interaktivnu komunikaciju ne može da garantuje otpornost na posmatrača koji meri oba kraja.

Česti propusti su zaobilaženje preko DNS-a ili IPv6, aplikacije koje otvaraju sopstvene sokete, upravljački saobraćaj koji direktno stiže do releja, sinhronizovana aktivnost, ponovo korišćeni SSH ključevi i prijavljivanje na naloge koji otkrivaju identitet. Ispravna provera je test otkaza: zaustavite svaki relej redom i pokažite da radno opterećenje ne može da pređe na nezaštićenu putanju.

### Kolaps tunela i upstream leakage

Arhitektura releja često se najlakše pripisuje kada zakaže. Unit 42 je dokumentovao špijunsku putanju sa više nivoa koja je koristila VPS-ove okrenute ka žrtvama, relejne VPS-ove, rezidencijalne proksije, Tor i druge proksi servise; kada bi tunel izostao ili se urušio, skrivena upstream infrastruktura povezivala se direktno sa relejnim sistemima i sistemima okrenutim ka žrtvama. Ista istraga je koristila i X.509 sertifikat koji je nakratko bio izložen na upstream infrastrukturi kao osnovu za povezivanje nivoa.<sup>[[14]](#references)</sup>

Držite **data plane** (`victim <-> exit`) odvojenim od **control plane**-a (`operator/upstream -> relay administration`). Čuvajte ulazne i autentifikacione logove na svakom nivou koji posedujete, istoriju sertifikata i kratke neuspele konekcije — ne samo uspešne C2 sesije. Izvor koji se pojavljuje samo tokom ispada releja ili direktno upravlja većim brojem sistema okrenutih ka žrtvama snažniji je kandidat za upstream infrastrukturu nego običan izlazni čvor, ali njegov ASN/geolokacija i dalje predstavljaju pretpostavku, a ne dokaz identiteta operatera.

U ovlašćenom labu radno opterećenje treba da bude podešeno tako da pri otkazu prekine rad. Ako je radno opterećenje izolovano u Linux network namespace-u, prva ruta mora da koristi tunel; nakon njegovog uklanjanja, i zahtev i pretraga rute moraju da zakažu, umesto da izaberu fizički uplink:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Ponovite test za DNS i IPv6, kao i na svakoj granici relay-a. Ako bilo koja proba uspe, zabeležite stvarni interfejs/izvornu adresu pre nego što popravite policy routing ili firewall; to je attribution leak koji bi istražitelj uočio.

## Slojevi redirector-a i oblikovanje saobraćaja

Javni **redirector** prihvata saobraćaj koji odgovara gramatici specifičnoj za operaciju i prosleđuje ga zaštićenom team server-u. Sve ostalo može da odbije ili da posluži bezazlen sadržaj.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Više slojeva ograničava izloženost: kompromitovanje javnog domena ne mora da otkrije team server. CDN-ovi dodaju anycast kapacitet i ugledan spoljašnji domen, ali CDN nalog i edge logovi postaju tačke za atribuciju. TLS otisci, istorija sertifikata, karakteristične putanje/redosled zaglavlja, veličine odgovora, ponašanje pri preusmeravanju i liste dozvoljenih origin-a mogu da povežu frontove koji naizgled nisu povezani.

Za detekciju, sačuvajte polja reverse proxy-ja pre normalizacije, uporedite SNI/Host/authority, proveravajte retke kombinacije zaglavlja, grupišite tela odgovora i TLS otiske, a zatim pretražite cloud/CDN audit logove da biste pronašli preklapanja u konfiguraciji. Ovlašćeni red team-ovi ne treba da kopiraju stvarne brendove niti da prikupljaju akreditive preko nepovezane treće strane.

## Domain fronting i fronting bez domena

Kod klasičnog **domain fronting (T1090.004)**, TLS veza u SNI navodi dozvoljeni front domen, dok šifrovani HTTP `Host` ili HTTP/2 `:authority` traži drugi back-end domen. CDN koji sarađuje usmerava saobraćaj na osnovu unutrašnje vrednosti. Mrežni posmatrač bez TLS dešifrovanja vidi front; CDN vidi obe vrednosti i origin. Kod varijanti bez domena, SNI može biti prazan, dok drugo polje za rutiranje bira odredište.<sup>[[4]](#references)</sup>

Ovo nije magično lažno predstavljanje: funkcioniše samo ako posrednik namerno ili slučajno dozvoljava nepoklapanje i zna kako da rutira unutrašnje ime. Veliki provajderi su ograničili fronting između naloga. Encrypted ClientHello (ECH) menja ono što posmatrač na putanji može da vidi, ali ne briše zapise CDN-a, krajnje tačke ni aplikacije.

Tačke za detekciju uključuju:

- poreklo procesa na krajnjoj tački i одredište које та апликација не би требало да користи;
- непоклапање SNI-ja и HTTP authority-ја тамо где је TLS инспекција законита и доступна;
- CDN логове који показују да један tenant/front рутира ка другом authority/origin-у;
- необично дуготрајне или периодичне сесије ка сервису који се обично користи интерактивно;
- стабилне величине и ритам шифрованог тока кроз различите front домене.

Безбедна лабораторијска вежба симулира непоклапање рутирања на reverse proxy-ју који је у вашем власништву; не злоупотребљава јавни CDN.

## Динамичко разрешавање: DDNS, DGA и fast flux

Динамичко разрешавање одваја логички сервис од фиксне инфраструктуре:

- **DDNS:** аутентификовани клијент ажурира стабилно име након промене адресе.
- **DGA:** и крајња тачка и контролер изводе могућа имена домена на основу временског/кључног seed-а; оператор региструје мањи подскуп.
- **Fast flux:** име враћа скуп компромитованих/proxy адреса који се брзо мења, често са ниским TTL-овима.
- **Double flux:** ротирају и адресе сервиса и адресе ауторитативних name server-а, чиме се скрива и контролни слој.

Fast flux је образац расподеле оптерећења који се користи у злонамерне сврхе, а не само „много DNS одговора“. Јачи докази комбинују низак TTL, велики број јединствених адреса, широку географску и ASN распршеност, кратак животни век чворова, понављајуће понашање апликације и сумњиву историју регистрације. CDN-ови легитимно деле неколико ових особина. MITRE препоручује повезивање DNS понашања са процесом и накнадним везама.<sup>[[5]](#references)</sup>

DGA се може открити помоћу лексичке ентропије, образаца сугласника/цифара, навала NXDOMAIN одговора, синхронизованих домена који су први пут виђени и контекста процеса. DGA-ови засновани на листама речи и генеративни модели заобилазе једноставна правила ентропије, па су временско груписање на нивоу целокупне флоте и порекло на крајњој тачки важнији.

## Компромитовани домени и domain shadowing

Актер може да отме налог регистратора/DNS-а, преузме заборављени поддомен или дода записе испод домена који иначе ужива углед. **Domain shadowing** задржава легитиман apex домен, док велики број поддомена под контролом нападача упућује на променљиве хостове за испоруку садржаја или C2. Тако позајмљује старост и углед домена и може да избегне блокирање целог домена.<sup>[[6]](#references)</sup>

Браниоцима су потребни audit логови регистратора и ауторитативног DNS-а, MFA, браве регистра/регистратора, упозорења за нове делегације/API токене/name server-е, праћење certificate transparency-ја и инвентар cloud ресурса на које DNS упућује. Резолуцију и историју сертификата поддомена истражујте независно од угледа apex домена.

## Веб-сервиси и dead-drop резолвери

**Dead-drop resolver (T1102.001)** чува кодирану референцу ка тренутном C2 у легитимној објави, профилу, документу, репозиторијуму, cloud објекту или blockchain пољу. Malware преузима јавни објекат, декодира домен/IP адресу и повезује се са следећом фазом. Двосмерне варијанте размењују команде или датотеке преко API-ја сервиса.<sup>[[7]](#references)</sup>

Једна варијанта резолвера специфична за GitHub користи Issues Search API само ако аутентификовани канал репозиторијума откаже. Клијент претражује issues који одговарају тренутном датуму, репозиторијуму и типу issue-а, прати URL коментара за сваки issue и издваја шифровани текст између ознака `<!--` и `-->`. Након дешифровања изведеног по хосту и датуму, поља као што су `Owner`, `LicRepo` и `LicToken` замењују примарног власника репозиторијума, путању и токен. Тако оператор може да ротира акредитиве и крајње тачке без замене клијента; коментар issue-а служи као резолвер, док датотеке репозиторијума остају канал за задатке.<sup>[[15]](#references)</sup>

Android варијанта при покретању бира једну од две јавне Telegram странице и издваја шифровани текст између два појављивања ознаке уграђене у APK. Декодира вредност помоћу Base64URL-а и дешифрује је помоћу AES-128-CBC: првих 16 бајтова од `SHA-256(marker)` чине кључ, а преосталих 16 бајтова IV. Отворени текст је стварни C2 основни URL, а не URL Telegram странице. Приликом репродукције резолуције сачувајте садржај странице и тачну ознаку; промена јавне странице ротира крајњу тачку без поновне изградње APK-а.<sup>[[16]](#references)</sup>

Ово обезбеђује отпорност и скрива back-end C2 од статичке анализе бинарне датотеке. Такође ствара стабилне идентификаторе објеката, tenant-а, репозиторијума, API-ја и образаца приступа. Браниоци треба да повежу:

1. процес који је контактирао сервис;
2. тачну API путању/објекат и hash одговора;
3. активности декодирања или обраде стрингова;
4. нову одлазну везу убрзо након тога; и
5. истоветно понашање другде у флоти.

Блокирање целог GitHub-а, cloud складишта или друштвених мрежа ретко је изводљиво. Политика излазног саобраћаја која узима у обзир сервис и корелација на нивоу процеса ефикасније су од блокирања само на основу домена.

## Персоне, налози и набавне преграде

Анонимност инфраструктуре нестаје када персона, адреса за опоравак, телефон, плаћање, browser или admin IP адреса повежу раздвојене целине. Операције повезане са државама много пре употребе негују профиле на друштвеним мрежама, идентитете е-поште и cloud налоге; ATT&CK ово бележи као Establish Accounts (T1585), укључујући под-технике за друштвене мреже, е-пошту и cloud.<sup>[[8]](#references)</sup>

Бранилац или истражитељ прави граф на основу:

- времена креирања и прве пријаве, локализације, временске зоне и распореда активности;
- поља за опоравак, MFA уређаја, личних докумената и платних средстава;
- browser/TLS отисака и историје изворне мреже;
- поновне употребе аватара, порекла слика, стила писања и раста друштвеног графа;
- заједничког регистратора домена, name server-а, сертификата, analytics ID-ја или repository commit-а;
- радњи на management plane-у које заобилазе архитектуру јавног релеја.

Овлашћени red team треба да документују синтетичке персоне код контролора вежбе, користе канале за опоравак/плаћање у власништву организације, избегавају лажно представљање стварних особа које нису укључене и планирају повлачење персона. SOC можда неће знати за операцију, али она не сме постати неодговорна.

## Нови сложени обрасци за моделовање претњи

Следећи примери су **композиције усмерене на одбрану**, а не тврдње да је неки именовани актер употребио сваки тачан дизајн. Они комбинују већ уочене примитиве и корисне су претпоставке за purple-team вежбе.

### Асиметрично једносмерно задавање

Команде стижу преко јавног, broadcast или append-only извора, док резултати одлазе другим каналом са закашњењем. Примери примитива укључују једносмерну комуникацију преко веб-сервиса и dead drop-ове. Раздвајање спречава да један ток делује двосмерно и отежава једноставну корелацију захтева/одговора.<sup>[[9]](#references)</sup>

**Детекција:** сачувајте приступе на нивоу објеката, а затим повежите промене стања процеса и касније одлазне преносе у ширем временском прозору. Потражите редак процес који чита исти јавни објекат чак и када не следи непосредан одговор.

### Промоција на вишестепени канал

Тиха прва фаза врши инвентарисање и само изабране системе пребацује на неповезани канал друге фазе. Друга крајња тачка, протокол и процес можда не деле никакву инфраструктуру са првом. Тиме се ограничава излагање инфраструктуре за напредније операције; ово је изричито моделовано као ATT&CK T1104.<sup>[[10]](#references)</sup>

**Детекција:** повежите `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; не завршавајте инцидент након блокирања првог домена.

### Превођење релеја између протокола

Различити скокови преводе HTTPS, QUIC, WebSocket, DNS, SSH или API реда порука уместо да транспарентно прослеђују пакете. Превођење уклања један отисак протокола од почетка до краја, али ствара gateway-је са карактеристичним временским обрасцима, баферовањем и семантичком конверзијом. Protocol tunneling (T1572) може се комбиновати са proxy-јима и имитацијом сервиса.<sup>[[11]](#references)</sup>

**Детекција:** потражите gateway хостове који примају један протокол, а покрећу други уз тесно повезано понашање по количини бајтова/времену; упоредите очекивану намену крајње тачке са протоколом који се заиста преноси.

### Пасивна активација на edge уређајима

Уместо beacon-овања, implant надгледа саобраћај који већ стиже до рутера/VPN-а и активира се само на магичну вредност, образац изворног порта или аутентификовани токен. Уобичајени саобраћај наставља ка стварном сервису. ATT&CK ово назива Traffic Signaling (T1205), уз документоване примере за мрежне уређаје и APT.<sup>[[12]](#references)</sup>

**Детекција:** интегритет firmware-а/датотека, снимање необрађених пакета током овлашћене истраге, неочекивани socket филтери и разлике у понашању сервиса. Одсуство периодичног beacon-а не доказује да је edge уређај чист.

### Serverless и ротација ephemeral origin-а

Front задржава стабилан логички идентитет, док краткотрајне функције/контејнери обрађују појединачне фазе у неколико региона/налога. Ово смањује трајање складиштења на диску и број фиксних origin IP адреса, али телеметрија control plane-а о креирању, image/layer-у, улози, тајни, request ID-ју и обрачуну постаје трајни граф.

**Детекција:** чувајте cloud audit и invocation логове изван workload-а; групишите шаблоне за распоређивање, улоге, environment кључеве и односе front-а и origin-а.

### Разноликост слојева приватности

Операција може намерно да избегне један хомоген ланац: на пример, један канал користи закупљени релеј, задаци се преносе преко јавног објекта, излаз долази преко сопствене лабораторијске мобилне везе, а администрација користи засебну мрежу организације. Ово умањује вредност компромитовања једног провајдера, али повећава ризик од корелације временских образаца између слојева и оперативних грешака.

**Детекција:** направите временске линије кампање на основу сензора за идентитет, DNS, SaaS, мрежу и cloud. Потражите синхронизоване промене стања уместо истоветних индикатора.

### Dead drop-ови на децентрализованим системима или transparency логовима

Актер може да постави малу шифровану референцу у било који трајан јавни append-only систем, content-addressed складиште или feed сличан transparency feed-у. Јавни објекат је отпоран, али његов тачан индекс/hash садржаја и понашање клијента при polling-у постају стабилни идентификатори.

**Детекција:** бележите пуне API/објектне идентификаторе и hash-еве одговора; постављајте упозорења за процесе који на необичан начин приступају непроменљивим објектима, а затим их декодирају или успостављају нове везе.

### Одложене операције са складиштењем и прослеђивањем

Интерактивни C2 ствара јаку временску корелацију. Дизајн са складиштењем и прослеђивањем групише шифроване задатке и враћа резултате после неколико минута или сати преко другог реда или физичког преноса. Он жртвује брзину одзива ради слабије временске корелације од почетка до краја.

**Детекција:** продужите временске прозоре за корелацију, моделујте периодични приступ редовима и анализирајте staging на крајњој тачки. Груписање премешта сигнал са временског обрасца пакета на заказане активности процеса/датотека; не уклања га.

## Преглед дизајна: размишљајте из перспективе посматрача

За сваку путању попуните ову табелу пре распоређивања и после прикупљања података:

| Слој | Види извор? | Види одредиште? | Види садржај? | Стабилни идентификатори | Рок чувања/правни власник |
|---|---:|---:|---:|---|---|
| локална мрежа/оператер | | | | | |
| улазни/приступни сервис | | | | | |
| оператор(и) за прелазак | | | | | |
| излазни релеј/преусмеривач/CDN | | | | | |
| ауторитативни DNS/регистратор | | | | | |
| циљ | | | | | |
| провајдер налога/плаћања | | | | | |

Ако један уобичајени провајдер може да попуни сваку колону, архитектура прикрива активности од циља, али не обезбеђује робусно раздвајање. Ако ниједан интерни контролор не може да повеже активности са конкретним ангажовањем, архитектура није погодна за професионални red teaming.

## References

- [1] [MITRE ATT&CK — Прибављање инфраструктуре (T1583), компромитовање инфраструктуре (T1584) и Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Шпијунски актери повезани са Кином користе ORB мреже](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Вишескоковни Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Компромитовање инфраструктуре: домени (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Веб-сервис: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Отварање налога (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Веб-сервис: једносмерна комуникација (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Вишестепени канали (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Тунеловање протокола (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Сигнализирање саобраћајем (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Ометање највеће светске мреже residential proxy сервера](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Кампање Shadow: откривање глобалне шпијунаже](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Кампања Blinder Tunnel циља инфраструктуру у Ираку](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI је направио преклапајуће слојеве. Жртве губе PIN-ове](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
