# Aanstootlike Infrastruktuur en Toeskrywingsontduiking

{{#include ../banners/hacktricks-training.md}}

’n Operateur verkry selde betekenisvolle anonimiteit deur ’n enkele proxy te gebruik. Werklike veldtogte bou ’n **skeidingsgrafiek**: die operateur bereik ’n toegangsknoop, deurvoerknope verberg daardie knoop vir die uitgang, redirectors beskerm die werklike C2, en weggooibare name wys na die openbare randpunt.

Gebruik die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) vir ’n gestandaardiseerde oorsig van die voor- en nadele, ontplooiing en opsporing van elke roete. Hierdie bladsy gaan dieper in op die samestelling van infrastruktuur vir adversariële doeleindes.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Die laaste adres wat ’n teiken sien, is dus bewys van ’n roete, nie bewys van wie die sleutelbord beheer het nie. MITRE karteer die hoofkomponente na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) en Web Service (T1102).<sup>[[1]](#references)</sup>

## Infrastruktuurklasse

| Klas | Waarom ’n akteur dit gebruik | Volgehoue blootstelling | Verdediger se beste aanknopingspunt |
|---|---|---|---|
| Gehuurde VPS/cloud | Vinnig, voorspelbaar, bereikbaar en maklik om te herbou | huurder, fakturering, konsole, bron-aanmeldings en beeldgeskiedenis | rekening-/beheerlaaggebeurtenisse en herhalende bediener-fingerafdruk |
| Kommersiële VPN/Tor | Groot gedeelde uitgaande adresstel; geen bedieneradministrasie nie | verskaffer-/sigbaarheidsbeheer en end-tot-end-tydsberekening | bestemminggedrag, eindpuntbewyse en verkeersvloei-korrelasie |
| Residential/mobile proxy | Verbruikers-ASN en geografiese geloofwaardigheid | makelaar-/kliënterekords; proxyware- of besmette-gasheer-gedrag | onmoontlike reis, proxyprotokolle en adresverandering per sessie |
| Compromised server/router/IoT | Leen slagofferreputasie en jurisdiksie | implantaat, bestuursverkeer en herhalende stroomop-beheerder | toesteltelemetrie en ORB-topologie, nie een enkele uitgang-IP nie |
| CDN/redirector | Skei die publieke rand van die back-end C2 | TLS/HTTP-grammatika, sertifikaat, roetering en cloud-rekeningartefakte | korrelasie tussen rand en oorsprong, en groepering volgens versoekvorm |
| Wettige webdiens | Meng in met toegelate GitHub/cloud/sosiale verkeer | API-token, huurder-/objekidentifiseerders en ongewone proseslyn | eindpuntproses plus diens-/API-semantiek |
| Fisiese/selulêre/satellietroete | Verander die skynbare fisiese oorsprong | RF-, diensverskaffer-, intekenaar-, toestel- en liggingrekords | gekombineerde radio-/fisiese en netwerkbewyse |

## Operasionele aflosboksnetwerke

’n **ORB-netwerk** is ’n bestuurde proxy-vloot wat as ’n tussengangerdiens gebruik word. Mandiant verdeel hulle in voorsiene netwerke van gehuurde bedieners, nie-voorsiene netwerke van compromised routers/IoT, en hibriede netwerke. ’n Volwasse topologie het vier logiese rolle:<sup>[[2]](#references)</sup>

1. **Administrasiebediener (ACOS):** hou voorraad, geloofsbriewe, gesondheid en roeteringsbeleid by.
2. **Toegangs-/aflosnode:** verifieer kliënte of operateurs; dit is die stabiele toegangspunt tot ’n veranderende mesh.
3. **Deurkruisingsnodes:** een of meer gehuurde of compromised stelsels stuur ondeursigtige verbindings aan.
4. **Uitgangs-/staging-node:** bied die finale bronadres aan verkennings-, uitbuitings- of C2-teikens.

Die mesh kan uitgange kies volgens land, ASN, latensie of beskikbaarheid, en ongesonde nodes roteer. Verskeie bedreigingsgroepe kan dieselfde netwerk huur. Mandiant het waargeneem dat ’n IPv4-adres vir sommige ORB’s so min as 31 dae daarmee geassosieer gebly het; daarom beveel dit aan dat die **netwerk as ’n ontwikkelende entiteit soortgelyk aan ’n akteur** behandel word, eerder as om ’n verouderde lys IP’s te blokkeer.<sup>[[2]](#references)</sup>

### Wat dit oplewer—and wat dit uitlek

- Die teiken sien ’n uitgang wat geografies naby en skynbaar residensieel kan wees.
- Die uitgang sien die teiken en die voorafgaande hop, maar nie noodwendig die operateur nie.
- Die toegangsdiens sien die kliënt en die roeteversoek. ’n Onafhanklik bestuurde mesh kan die kliënt van die uitgange geskei hou, maar dit skep ’n kragtige rekord by ’n teenparty.
- Herhaalde poorte, handskudvolgorde, bedienerbaniere, sertifikate, beskikbaarheidstye en beheerderverwantskappe kan die vloot blootlê, selfs terwyl IP’s roteer.
- ’n Compromised router het dikwels nie eindpunttelemetrie nie, maar sy ISP het steeds intekenaar- en verkeersvloeidata; beslaglegging ontbloot implantaat-/konfigurasieartefakte.

{% hint style="info" %}
Vir ’n gemagtigde oefening, boots die topologie na met VM’s of routers wat deur die organisasie besit word en hou die beheerder se toeskrywingskaart by. Moenie oop proxies of derdepartytoestelle werf nie. Die [labgids](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) skep dieselfde hop-struktuur wat vir verdedigers sigbaar is, sonder om ’n tussenganger te viktimiseer.
{% endhint %}

## Residential- en mobile-proxynetwerke

Residential proxy-dienste ken sessies aan verbruikersbreëbandadresse toe; mobile proxies stuur uitgaande verkeer deur diensverskaffer-NAT-poele. Die aanbod kan afkomstig wees van toestelle wat uitdruklik ingeskryf is, SDK’s/proxyware wat by verbruikerstoepassings ingesluit is, herverkopers of malware. Hierdie oorspronge is nie gelykwaardig nie: sonder ingeligte toestemming word ’n privaatheidsdiens compromised infrastruktuur.

Rotasiemodusse beïnvloed opsporing:

- **rotasie per versoek** veroorsaak vinnige diskontinuïteite in IP en ASN/geografie terwyl die identiteit op hoër lae stabiel bly;
- **kleefsessies** hou ’n uitgang vir minute of ure, wat soos ’n gewone intekenaar lyk;
- **backconnect-gateways** wys die kliënt een makelaar-eindpunt en kies uitgange intern;
- **mobile-poele** plaas baie egte intekenare agter ’n klein aantal diensverskaffer-NAT-adresse, wat ’n IP-blokkering duur maak.

Verdedigers moet die IP korreleer met die geverifieerde sessie, TLS-/kliënt-fingerafdruk, HTTP-volgorde, toestelnaspoor en gedrag. ’n Aanmelding vanaf ’n sogenaamd plaaslike residential-adres, gevolg deur een uit ’n ander land terwyl alle kenmerke op hoër lae identies bly, is sterker bewys as reputasie alleen. Omgekeerd veroorsaak adresdeling en mobile-oorskakeling wettige wisseling, dus moet residential-/proxy-klassifikasie nooit as ’n uitspraak behandel word nie.

### Proxyware-beheervlakke en oorvleueling tussen herverkopers

Moenie ’n residential-poel as ’n plat lys uitgange modelleer nie. Ontleding van die IPIDEA-ekosisteem het ’n herbruikbare **tweevlak-beheervlak** blootgelê: ’n ingebedde SDK rapporteer eers toestel-/inskrywingsmetadata aan ’n Tier One-domein en ontvang skedulering plus Tier Two `connect`/`proxy` IP:port-pare. Die node doen periodiek navraag by die Tier Two connect-poort vir ’n geënkodeerde taak, maak ’n tweede verbinding met die gepaarde proxy-poort oop en stuur die verskafte grepe aan na die aangevraagde bestemming. SDK’s en proxy-handelsmerke wat oënskynlik verskil, het afsonderlike ontdekkingsdomeine gehad, maar het deur gemeenskaplike eienaarskap en herverkoperverhoudings op gedeelde Tier Two-infrastruktuur en oorvleuelende uitgangspoele saamgekom.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Dit lewer meer duursame hunting-pivots as ’n residensiële IP-blok:<sup>[[13]](#references)</sup>

- ’n onverwagte nutsprogram-, VPN-, speletjie- of ingebedde-toestelproses stuur ’n stabiele toestel-ID/kliëntsleutel en ontvang ’n veranderende bedienerlys;
- die eindpunt peil ’n direkte IP op ’n ongewone poort, en koppel dan aan ’n ander poort op dieselfde adres net voordat dit ’n nuwe bestemmingsokkel oopmaak;
- verskeie oënskynlike handelsmerke deel Tier Two-adresse, protokolgrammatika, SDK-kode of oorvleueling tussen uitgangsnodusse;
- afsonderlike toepassings wat verskillende Tier One-domeine kontak, ontvang adresse uit dieselfde Tier Two-poel.

Die oorvleueling beperk ook attribusie: om ’n IP in een verskaffer se geadverteerde poel te sien, bewys nie watter herverkoper, kliënt of bedreigingsakteur dit op die betrokke tydstip gebruik het nie. Bewaar vloeitydmerke, prosesafstamming, Tier One-antwoordliggame en Tier Two-taakidentifiseerders.<sup>[[13]](#references)</sup> Emuleer hierdie hiërargie in ’n gemagtigde oefening slegs met eindpunte wat die organisasie besit; moet nooit verbruikerstoestelle of derdeparty-proxyware inskryf nie.

## Multi-hop proxy chains

MITRE onderskei eksterne proxy’s van **multi-hop proxies (T1090.003)**. Die belangrike eienskap is nie die aantal hops nie, maar die skeiding van kennis en administrasie.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

As een party A en B bedryf, kan gedeelde logs of vloeitiming die circuit rekonstrueer. Deur opeenvolgende kommersiële VPN’s vanaf dieselfde eindpunt/rekening te gebruik, kan latensie toeneem terwyl gemeenskaplike identiteits-, betalings- en tydsbewyse behoue bly. Tor verminder hierdie probleem met relays wat onafhanklik gekies word en ’n gedeelde kliëntontwerp, maar ’n interaktiewe netwerk met lae latensie kan nie weerstand waarborg teen ’n waarnemer wat albei kante meet nie.

Algemene foute is DNS- of IPv6-omseiling, toepassings wat hul eie sockets open, bestuursverkeer wat relays direk bereik, gesinchroniseerde aktiwiteit, hergebruikte SSH-sleutels en aanmeldings by identifiseerbare rekeninge. Die korrekte verifikasie is ’n faaltoets: stop elke relay om die beurt en wys dat die workload nie na ’n ongeënkripteerde roete kan oorskakel nie.

### Tonnel-ineenstorting en upstream-lekkasie

’n Relay-argitektuur is dikwels die maklikste om toe te skryf wanneer dit faal. Unit 42 het ’n spioenasieroete met verskeie lae gedokumenteer wat VPS’e aan die slagofferkant, relay-VPS’e, residensiële proxies, Tor en ander proxy-dienste gebruik het; wanneer ’n tonnel weggelaat of ineengestort het, het versteekte upstream-infrastruktuur direk met relay- en slagofferkantstelsels verbind. Dieselfde ondersoek het ook ’n X.509-sertifikaat gebruik wat kortliks op upstream-infrastruktuur blootgelê is as ’n skakel tussen lae.<sup>[[14]](#references)</sup>

Hou die **data plane** (`victim <-> exit`) apart van die **control plane** (`operator/upstream -> relay administration`). Behou ingress- en verifikasielogs by elke beheerde laag, sertifikaatgeskiedenis en kort mislukte verbindings—nie net suksesvolle C2-sessies nie. ’n Bron wat net tydens relay-onderbrekings verskyn of verskeie stelsels aan die slagofferkant direk administreer, is ’n sterker upstream-kandidaat as ’n gewone exit, maar sy ASN/geoligging is steeds ’n hipotese, nie bewys van ’n operateur se identiteit nie.

’n Gemagtigde lab behoort die workload veilig te laat faal. Vir ’n workload wat in ’n Linux-network namespace geïsoleer is, moet die eerste roete die tonnel gebruik; nadat dit verwyder is, moet beide die versoek en roete-opsoek misluk, eerder as om die fisiese uplink te kies:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Herhaal die toets vir DNS en IPv6, en by elke relay-grens. As enige probe slaag, teken die werklike koppelvlak-/bronadres aan voordat jy die policy routing of firewall herstel; daardie waarneming is die attribution-lek wat ’n ondersoeker sou sien.

## Redirector-lae en traffic shaping

’n Openbare **redirector** aanvaar verkeer wat by ’n operasie-spesifieke grammar pas en stuur dit aan na ’n beskermde team server. Alles anders kan verwerp word of onskadelike inhoud bedien.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Veelvuldige lae beperk blootstelling: as ’n publieke domein opgebruik word, hoef dit nie die spanbediener bloot te stel nie. CDN’s voeg anycast-kapasiteit en ’n geloofwaardige buitenste domein by, maar die CDN-rekening en edge-logs word punte vir toeskrywing. TLS-fingerafdrukke, sertifikaatgeskiedenis, kenmerkende paaie/volgorde van headers, antwoordgroottes, redirect-gedrag en oorsprong-toelatingslyste kan fronte wat glo onverwant is, saamgroepeer.

Teken vir opsporing reverse-proxy-velde aan voordat dit genormaliseer word, vergelyk SNI/Host/authority, ondersoek seldsame header-kombinasies, groepeer antwoordliggame en TLS-fingerafdrukke, en deursoek cloud/CDN-ouditlogs vir oorvleueling in konfigurasie. Vermy dit vir gemagtigde rooi spanne om ’n regte handelsmerk na te boots of geloofsbriefversameling agter ’n onverwante derde party te plaas.

## Domain fronting en domeinlose fronting

Met klassieke **domain fronting (T1090.004)** kondig die TLS-verbinding ’n toegelate frontdomein in SNI aan, terwyl die geënkripteerde HTTP `Host` of HTTP/2 `:authority` ’n ander back-end-domein versoek. ’n Samewerkende CDN roeteer op grond van die binneste waarde. ’n Netwerkwaarnemer sonder TLS-dekripsie sien die front; die CDN sien albei waardes en die oorsprong. In domeinlose variante kan SNI leeg wees terwyl ’n ander roeteerveld die bestemming kies.<sup>[[4]](#references)</sup>

Dit is nie magiese nabootsing nie: dit werk net wanneer die tussenganger die wanpassing doelbewus of per ongeluk toelaat en weet hoe om die binneste naam te roeteer. Groot verskaffers het fronting oor verskillende rekeninge heen beperk. Encrypted ClientHello (ECH) verander wat ’n waarnemer op die netwerkpad kan sien, maar wis nie CDN-, eindpunt- of toepassingsrekords uit nie.

Opsporingspunte sluit in:

- eindpunt-prosesafkoms en ’n bestemming wat nie vir daardie toepassing verwag word nie;
- wanpassing tussen SNI en HTTP-authority waar TLS-inspeksie wettig en beskikbaar is;
- CDN-logs wat wys dat een huurder/front na ’n ander authority/oorsprong roeteer;
- buitengewoon lang sessies of periodieke sessies na ’n diens wat normaalweg interaktief is;
- stabiele geënkripteerde vloeigroottes en -kadens oor veranderende frontdomeine.

Die veilige lab simuleer die roeteerwanpassing op ’n eie reverse proxy; dit misbruik nie ’n publieke CDN nie.

## Dinamiese resolusie: DDNS, DGA en fast flux

Dinamiese resolusie ontkoppel ’n logiese diens van vaste infrastruktuur:

- **DDNS:** ’n geverifieerde kliënt dateer ’n stabiele naam op nadat sy adres verander.
- **DGA:** beide eindpunt en beheerder lei kandidaat-domeinname af van ’n tyd-/sleutelsaad; die operateur registreer ’n klein subset.
- **Fast flux:** ’n naam gee ’n vinnig veranderende stel gekompromitteerde/proxy-adresse terug, dikwels met lae TTL’s.
- **Double flux:** beide diensadresse en gesaghebbende naambedieneradresse roteer, wat die beheerlaag ook verberg.

Fast flux is ’n lasverspreidingspatroon wat teenstanders gebruik, nie bloot “baie DNS-antwoorde” nie. Sterker bewyse kombineer lae TTL, ’n hoë aantal unieke adresse, wye verspreiding oor ASN’s/geografie, kort lewensduur van nodusse, herhaalde toepassingsgedrag en verdagte registrasiegeskiedenis. CDN’s deel verskeie van hierdie eienskappe op wettige wyse. MITRE beveel aan dat DNS-gedrag met die proses en daaropvolgende verbindings gekorreleer word.<sup>[[5]](#references)</sup>

’n DGA kan opgespoor word deur leksikale entropie, patrone van konsonante/syfers, NXDOMAIN-uitbarstings, gesinchroniseerde domeine wat die eerste keer gesien word en proses-konteks. Woordelys-DGA’s en generatiewe modelle omseil eenvoudige entropiereëls, wat vlootwye temporele groepering en eindpunt-afkoms belangriker maak.

## Gekompromitteerde domeine en domain shadowing

’n Akteur kan ’n registrar-/DNS-rekening kaap, ’n verlate subdomein oorneem, of rekords onder ’n andersins geloofwaardige domein byvoeg. **Domain shadowing** behou die wettige apex terwyl groot getalle aanvallerbeheerde subdomeine na veranderende aflewerings- of C2-gashere wys. Dit leen die domein se ouderdom en reputasie en kan domeinwye blokkering ontduik.<sup>[[6]](#references)</sup>

Verdedigers benodig ouditlogs vir registrar en gesaghebbende DNS, MFA, registry-/registrar-slotte, waarskuwings oor nuwe delegerings/API-tokens/naambedieners, sertifikaat-deursigtigheidsmonitering en ’n inventaris van cloud-hulpbronne waarna DNS verwys. Ondersoek ’n subdomein se resolusie- en sertifikaatgeskiedenis onafhanklik van die apex se reputasie.

## Webdienste en dead-drop-resolvers

’n **dead-drop resolver (T1102.001)** stoor ’n geënkodeerde wyser na huidige C2 binne ’n wettige plasing, profiel, dokument, repository, cloud-objek of blockchain-veld. Malware haal die publieke objek op, dekodeer ’n domein/IP en kontak die volgende stadium. Tweerigtingvariante ruil opdragte of lêers uit deur diens-API’s.<sup>[[7]](#references)</sup>

Een GitHub-spesifieke resolver-variasie gebruik die Issues Search API slegs wanneer ’n geverifieerde repository-kanaal misluk. Die kliënt soek na issues wat by die huidige datum, repository en issuetipe pas, volg elke issue se kommentaar-URL en haal ciphertext tussen `<!--` en `-->`-merkers uit. Ná dekripsie per gasheer, afgelei van die datum, vervang velde soos `Owner`, `LicRepo` en `LicToken` die primêre repository-eienaar, -pad en -token. Dit laat die operateur toe om geloofsbriewe en eindpunte te roteer sonder om die kliënt te vervang; die issue-kommentaar dien as resolver, terwyl die repository-lêers die tasking-kanaal bly.<sup>[[15]](#references)</sup>

’n Android-variasie kies met opstart een van twee publieke Telegram-bladsye en haal ciphertext tussen twee voorkomste van ’n merker uit wat in die APK ingebed is. Dit Base64URL-dekodeer die waarde en dekripteer dit met AES-128-CBC: die eerste 16 grepe van `SHA-256(marker)` is die sleutel en die oorblywende 16 grepe is die IV. Die plaintext is die werklike C2-basis-URL, nie die Telegram-bladsy-URL nie. Behou die bladsy-inhoud en presiese merker wanneer resolusie gereproduseer word; deur die publieke bladsy te verander, roteer die eindpunt sonder dat die APK herbou hoef te word.<sup>[[16]](#references)</sup>

Dit bied veerkragtigheid en verberg back-end C2 vir statiese binêre analise. Dit skep ook stabiele identifiseerders vir objekte, huurders, repositories, API’s en toegangspatrone. Verdedigers behoort die volgende te verbind:

1. die proses wat die diens gekontak het;
2. die presiese API-pad/objek en antwoord-hash;
3. dekoderings- of stringverwerkingsaktiwiteit;
4. die nuwe uitgaande verbinding kort daarna; en
5. identiese gedrag elders in die vloot.

Om alle GitHub, cloud-berging of sosiale media te blokkeer, is selde haalbaar. Uitgaande beleid wat diensbewus is en korrelasie op prosesvlak werk beter as blokkering wat net op domeine berus.

## Personas, rekeninge en verkrygingskompartemente

Infrastruktuur-anonimiteit faal wanneer ’n persona, herstel-e-posadres, telefoonnommer, betaling, blaaier of admin-IP kompartemente met mekaar verbind. Operasies wat aan state gekoppel is, het sosiale profiele, e-posidentiteite en cloud-rekeninge lank voor gebruik opgebou; ATT&CK teken dit aan as Establish Accounts (T1585), insluitend sosiale, e-pos- en cloud-subtegnieke.<sup>[[8]](#references)</sup>

’n Verdediger of ondersoeker bou ’n grafiek op grond van:

- skeppingstyd en eerste aanmelding, locale, tydsone en werkskedule;
- herstelvelde, MFA-toestelle, identiteitsdokumente en betaalinstrumente;
- blaaier-/TLS-fingerafdrukke en geskiedenis van bronnetwerke;
- hergebruik van avatars, beeldherkoms, skryfstyl en groei van die sosiale grafiek;
- gedeelde domeinregistrant, naambediener, sertifikaat, analytics-ID of repository-commit;
- bestuursvlak-aksies wat die publieke relay-argitektuur omseil.

Vir ’n gemagtigde rooi span behoort sintetiese personas aan die oefenbeheerder gedokumenteer te word, organisasiebeheerde herstel-/betaalkanale te gebruik, nabootsing van regte mense wat nie betrokke is nie te vermy, en ’n beplande aftrede te hê. Die SOC mag steeds onbewus wees; die operasie mag nie onbeheerbaar word nie.

## Ontluikende saamgestelde patrone om as bedreigings te modelleer

Die volgende is **verdedigergedrewe samestellings**, nie bewerings dat ’n genoemde akteur elke presiese ontwerp ontplooi het nie. Hulle kombineer reeds waargenome primitiewe en is nuttige hipoteses vir purple-team-oefeninge.

### Asimmetriese eenrigting-tasking

Opdragte kom deur ’n publieke, uitsaai- of slegs-byvoegbare bron aan, terwyl resultate ná ’n vertraging deur ’n onverwante kanaal uitgaan. Voorbeelde van die primitief sluit eenrigtingkommunikasie deur webdienste en dead drops in. Skeiding verhoed dat ’n enkele vloei tweerigting lyk en bemoeilik eenvoudige korrelasie van versoek/antwoord.<sup>[[9]](#references)</sup>

**Opsporing:** bewaar lesings op objekvlak en korreleer daarna prosesstatusveranderinge en latere uitgaande oordragte oor ’n wyer tydvenster. Soek na ’n seldsame proses wat dieselfde publieke objek lees, selfs wanneer geen onmiddellike antwoord volg nie.

### Bevordering van multi-stadium-kanale

’n Stil eerste stadium doen inventarisering en bevorder net geselekteerde stelsels na ’n onverwante tweedestadium-kanaal. Die tweede eindpunt, protokol en proses deel moontlik geen infrastruktuur met die eerste nie. Dit beperk blootstelling van bekwame infrastruktuur en word uitdruklik as ATT&CK T1104 gemodelleer.<sup>[[10]](#references)</sup>

**Opsporing:** verbind `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; moenie die voorval afsluit nadat die eerste domein geblokkeer is nie.

### Relay-vertaling tussen protokolle

Verskillende skakels vertaal HTTPS, QUIC, WebSocket, DNS, SSH of ’n message-queue-API eerder as om pakkies deursigtig aan te stuur. Vertaling verwyder ’n enkele end-to-end-protokolvingerafdruk, maar skep gateways met kenmerkende tydsberekening, buffering en semantiese omskakeling. Protocol tunneling (T1572) kan met proxies en diensnabootsing gekombineer word.<sup>[[11]](#references)</sup>

**Opsporing:** soek na gateway-gashere wat een protokol ontvang en ’n ander begin, met nou gekoppelde greep-/tydgedrag; vergelyk die eindpunt se bedoeling met die protokol wat werklik gedra word.

### Passiewe aktivering op edge-toestelle

In plaas daarvan om beacons te stuur, monitor ’n implantaat verkeer wat reeds ’n router/VPN bereik en aktiveer slegs op ’n magic value, bronpoortpatroon of geverifieerde token. Normale verkeer gaan steeds na die regte diens. ATT&CK noem dit Traffic Signaling (T1205), met gedokumenteerde voorbeelde van netwerktoestelle en APT’s.<sup>[[12]](#references)</sup>

**Opsporing:** firmware-/lêerintegriteit, rou pakkie-opname tydens ’n gemagtigde ondersoek, onverwagte socket-filters en verskille in diensgedrag. Die afwesigheid van ’n periodieke beacon bewys nie dat ’n edge-toestel skoon is nie.

### Serverless- en kortstondige oorsprongrotasie

’n Front behou ’n stabiele logiese identiteit terwyl kortstondige funksies/containers individuele stadiums in verskeie streke/rekeninge hanteer. Dit verminder die lewensduur van data op skyf en vaste oorsprong-IP’s, maar telemetrie oor skepping in die beheerlaag, image/layer, rol, secret, versoek-ID en fakturering word die blywende grafiek.

**Opsporing:** behou cloud-oudit- en invocation-logs buite die workload; groepeer ontplooiingsjablone, rolle, omgewingsleutels en verhoudings tussen front en oorsprong.

### Diversiteit van privaatheidslae

’n Operasie kan doelbewus eenvormige kettings vermy: byvoorbeeld, een kanaal gebruik ’n gehuurde relay, tasking gebruik ’n publieke objek, ’n uitgang kom van ’n eie laboratorium-selfoonverbinding, en administrasie gebruik ’n aparte organisasienetwerk. Dit verminder die waarde daarvan om een verskaffer te kompromitteer, maar verhoog die risiko van korrelasie oor lae heen en operasionele foute.

**Opsporing:** bou veldtogtydlyne oor identiteit-, DNS-, SaaS-, netwerk- en cloud-sensors heen. Soek na gesinchroniseerde statusoorgange eerder as identiese aanwysers.

### Gedesentraliseerde of transparency-log-dead drops

’n Akteur kan ’n klein geënkripteerde wyser in enige duursame publieke slegs-byvoegbare stelsel, content-addressed store of transparency-agtige feed plaas. Die publieke objek is veerkragtig, maar die presiese indeks/content-hash en die kliënt se polling-gedrag word stabiele identifiseerders.

**Opsporing:** teken volledige API-/objek-identifiseerders en antwoord-hashes aan; waarsku oor nie-standaard prosesse wat onveranderlike objekte poll, gevolg deur dekodering of nuwe verbindings.

### Vertraagde store-and-forward-operasies

Interaktiewe C2 skep sterk tydskorrelasie. ’n Store-and-forward-ontwerp bondel geënkripteerde take en stuur resultate minute of ure later deur ’n ander tou of fisiese oordrag terug. Dit offer reaksiespoed op vir swakker end-to-end-tydskorrelasie.

**Opsporing:** verleng korrelasievensters, modelleer periodieke toegang tot toue en ondersoek eindpunt-staging. Bondeling verskuif die sein van pakkietydsberekening na geskeduleerde proses-/lêergedrag; dit wis dit nie uit nie.

## Ontwerphersiening: dink vanuit waarnemers se perspektief

Vul vir elke pad hierdie tabel in voor ontplooiing en ná dataversameling:

| Laag | Sien bron? | Sien bestemming? | Sien inhoud? | Stabiele identifiseerders | Bewaring/wetlike eienaar |
|---|---:|---:|---:|---|---|
| plaaslike netwerk/diensverskaffer | | | | | |
| intree-/toegangsdiens | | | | | |
| tussenganger(s) | | | | | |
| uitgang/redirector/CDN | | | | | |
| gesaghebbende DNS/registrar | | | | | |
| teiken | | | | | |
| rekening-/betalingsverskaffer | | | | | |

As een gewone verskaffer elke kolom kan invul, bied die argitektuur verberging teenoor die teiken, maar nie robuuste skeiding nie. As geen interne beheerder aktiwiteit aan ’n betrokkenheid kan koppel nie, is dit ongeskik vir professionele rooi-spanwerk.

## References

- [1] [MITRE ATT&CK — Verkry infrastruktuur (T1583), kompromitteer infrastruktuur (T1584) en Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Spioenasie-akteurs met bande met China gebruik ORB-netwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kompromitteer infrastruktuur: domeine (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Webdiens: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Stel rekeninge op (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Webdiens: eenrigtingkommunikasie (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Ontwrigting van die wêreld se grootste residensiële proxy-netwerk](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Die Shadow-veldtogte: onthulling van wêreldwye spioenasie](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel-veldtog teiken Irakse infrastruktuur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: KI het die oorlegsels gebou. Slagoffers verloor hul PIN’s](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
