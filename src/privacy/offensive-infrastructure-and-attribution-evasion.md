# Aanstootlike infrastruktuur en ontduiking van toeskrywing

{{#include ../banners/hacktricks-training.md}}

’n Operateur verkry selde betekenisvolle anonimiteit met net een proxy. Werklike veldtogte bou ’n **skeidingsgrafiek**: die operateur bereik ’n toegangsnodus, deurgangsnodusse verberg daardie nodus vir die uitgang, redirectors beskerm die werklike C2, en weggooibare name wys na die publieke rand.

Gebruik die [Tegniekkatalogus vir anonieme internettoegang](anonymous-internet-access-techniques.md) vir ’n gestandaardiseerde oorsig van die voordele, nadele, ontplooiing en opsporing van elke roete. Hierdie bladsy delf dieper in die samestelling van infrastruktuur vir teenstanders.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Die laaste adres wat ’n teiken sien, is dus bewys van ’n roete, nie bewys van wie die sleutelbord beheer het nie. MITRE karteer die hoofkomponente as Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) en Web Service (T1102).<sup>[[1]](#references)</sup>

## Infrastruktuurklasse

| Klas | Waarom ’n akteur dit gebruik | Volgehoue blootstelling | Verdediger se beste ondersoekingspunt |
|---|---|---|---|
| Gehuurde VPS/cloud | Vinnig, voorspelbaar, roeteerbaar, maklik om te herbou | huurder, fakturering, konsole, bronaanmelding en beeldgeskiedenis | rekening-/beheerlaaggebeure en herhaalde bedienervingerafdrukke |
| Kommersiële VPN/Tor | Groot gedeelde egress-stel; geen bedieneradministrasie nie | verskaffer-/sigbaarheidsbeheer en end-tot-end-tydsberekening | bestemminggedrag, eindpuntbewyse en verkeersvloeikorrelasie |
| Residensiële/mobiele proxy | Verbruikers-ASN en geografiese geloofwaardigheid | makelaar-/kliëntrekords; proxyware- of besmettegasheergedrag | onmoontlike reise, prox protokolle en adresverandering per sessie |
| Gekompromitteerde bediener/roeteerder/IoT | Leen slagofferreputasie en jurisdiksie | implantaat, bestuursverkeer en herhaalde stroomop-beheerder | toesteltelemetrie en ORB-topologie, nie ’n enkele exit-IP nie |
| CDN/redirector | Skei die openbare edge van die back-end C2 | TLS/HTTP-grammatika, sertifikaat-, roeterings- en cloud-rekeningartefakte | edge-na-origin-korrelasie en groepering volgens versoekvorm |
| Legitieme webdiens | Meng in met toegelate GitHub/cloud/sosiale verkeer | API-token, huurder-/objekidentifiseerders en ongewone prosesafstamming | eindpuntproses plus diens-/API-semantiek |
| Fisiese-/sellulêre-/satellietroete | Verander die skynbare fisiese oorsprong | RF-, diensverskaffer-, intekenaar-, toestel- en liggingrekords | radio-/fisiese en netwerkbewyse saam |

## Operasionele aflosnodusnetwerke

’n **ORB-netwerk** is ’n bestuurde proxy-vloot wat as ’n tussengangerdiens gebruik word. Mandiant verdeel hulle in voorsiene netwerke van gehuurde bedieners, nie-voorsiene netwerke van gekompromitteerde roeteerders/IoT, en hibriede netwerke. ’n Volwasse topologie het vier logiese rolle:<sup>[[2]](#references)</sup>

1. **Administrasiebediener (ACOS):** hou die inventaris, aanmeldbesonderhede, gesondheid en roeteringsbeleid by.
2. **Toegangs-/aflosnodus:** staaf kliënte of operateurs; dit is die stabiele ingang na ’n veranderende mesh.
3. **Deurvoernodusse:** een of meer gehuurde of gekompromitteerde stelsels stuur ondeursigtige verbindings aan.
4. **Exit-/staging-nodus:** bied die finale bronadres aan teikens vir verkenning, uitbuiting of C2.

Die mesh kan exits volgens land, ASN, latensie of beskikbaarheid kies en ongesonde nodusse roteer. Verskeie bedreigingsgroepe kan dieselfde netwerk huur. Mandiant het waargeneem dat ’n IPv4-adres vir sommige ORB’s vir so min as 31 dae geassosieer gebly het; daarom beveel dit aan dat die **netwerk as ’n ontwikkelende entiteit soortgelyk aan ’n akteur** beskou word, eerder as om ’n verouderde lys IP’s te blokkeer.<sup>[[2]](#references)</sup>

### Wat dit oplewer—and wat dit uitlek

- Die teiken sien ’n exit wat geografies naby en oënskynlik residensieel kan wees.
- Die exit sien die teiken en die voorafgaande hop, maar nie noodwendig die operateur nie.
- Die toegangsdiens sien die kliënt en die roeteversoek. ’n Onafhanklik bestuurde mesh kan die kliënt van die exits geskei hou, maar dit skep ’n kragtige teenpartyrekord.
- Herhaalde poorte, handdrukvolgorde, bedienerbaniere, sertifikate, beskikbaarheidstydperke en beheerderverhoudings kan die vloot blootlê selfs terwyl IP’s roteer.
- ’n Gekompromitteerde roeteerder het dikwels nie eindpunttelemetrie nie, maar sy ISP het steeds intekenaar- en verkeersvloeidata; ’n beslaglegging stel implantaat-/konfigurasieartefakte bloot.

{% hint style="info" %}
Vir ’n gemagtigde oefening, boots die topologie na met VM’s of roeteerders wat deur die organisasie besit word, en hou die beheerder se toeskrywingskaart by. Moenie oop proxys of derdepartytoestelle werf nie. Die [labgids](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) skep dieselfde hop-struktuur wat vir verdedigers sigbaar is, sonder om ’n tussenganger te viktimiseer.
{% endhint %}

## Residensiële en mobiele proxynetwerke

Residensiële proxy-dienste wys sessies aan verbruikersbreëbandadresse toe; mobiele proxys stuur egress deur draer-NAT-poele. Die aanbod kan kom van toestelle wat uitdruklik ingeskryf is, SDK’s/proxyware wat in verbruikerstoepassings gebundel is, herverkopers of malware. Hierdie oorspronge is nie gelykwaardig nie: sonder ingeligte toestemming verander ’n privaatheidsdiens in gekompromitteerde infrastruktuur.

Rotasiemetodes beïnvloed opsporing:

- **rotasie per versoek** veroorsaak vinnige IP- en ASN-/geografiese diskontinuïteite terwyl die identiteit op hoër lae stabiel bly;
- **taai sessies** behou ’n exit vir minute of ure, wat soos ’n gewone intekenaar lyk;
- **backconnect-gateways** wys een makelaarseindpunt aan die kliënt en kies exits intern;
- **mobiele poele** plaas baie werklike intekenare agter ’n klein stel draer-NAT-adresse, wat ’n IP-blokkering duur maak.

Verdedigers behoort die IP met die geverifieerde sessie, TLS-/kliëntvingerafdruk, HTTP-volgorde, toestelkoekie en gedrag te korreleer. ’n Aanmelding wat na bewering plaaslik en residensieel is, gevolg deur een uit ’n ander land terwyl al die hoërlaagkenmerke identies bly, is sterker bewys as reputasie alleen. Omgekeerd veroorsaak adresdeling en mobiele oorskakeling legitieme veranderinge, moet dus nooit residensiële-/proxyklassifikasie as ’n uitspraak beskou nie.

### Proxyware-beheerlae en oorvleueling tussen herverkopers

Moenie ’n residensiële poel as ’n plat lys exits modelleer nie. Ontleding van die IPIDEA-ekosisteem het ’n herbruikbare **tweevlak-beheerlaag** blootgelê: ’n ingebedde SDK rapporteer eers toestel-/inskrywingsmetadata aan ’n Tier One-domein en ontvang skedulering plus Tier Two `connect`/`proxy` IP:poort-pare. Die nodus peil gereeld die Tier Two connect-poort vir ’n geënkodeerde taak, open ’n tweede verbinding met die gepaarde proxy-poort en stuur die verskafde grepe aan na die aangevraagde bestemming. SDK’s en proxyhandelsmerke wat nominaal verskillend was, het afsonderlike ontdekkingsdomeine gehad, maar het deur gemeenskaplike eienaarskap en herverkoperverhoudings op gedeelde Tier Two-infrastruktuur en oorvleuelende exit-poele saamgekom.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Dit lewer duursamer hunting-pivots as ’n residential IP block:<sup>[[13]](#references)</sup>

- ’n Onverwagte nutsprogram-, VPN-, speletjie- of ingebedde toestelproses stuur ’n stabiele toestel-ID/kliëntsleutel en ontvang ’n veranderende bedienerlys;
- die endpoint poll ’n direkte IP op ’n ongewone poort en koppel dan aan ’n ander poort op dieselfde adres, net voordat dit ’n nuwe bestemmingsocket oopmaak;
- verskeie oënskynlike handelsmerke deel Tier Two-adresse, protokolgrammatika, SDK-kode of oorvleuelende exit nodes;
- afsonderlike toepassings wat verskillende Tier One-domeine kontak, ontvang adresse uit dieselfde Tier Two-poel.

Die oorvleueling beperk ook attribusie: om ’n IP in een verskaffer se geadverteerde poel te sien, bewys nie watter herverkoper, kliënt of bedreigingsakteur dit op die betrokke tydstip gebruik het nie. Bewaar vloei-tydstempels, prosesafkoms, Tier One-antwoordliggame en Tier Two-taakidentifiseerders.<sup>[[13]](#references)</sup> Emuleer hierdie hiërargie in ’n gemagtigde oefening slegs met endpoints wat die organisasie besit; moet nooit verbruikerstoestelle of proxyware van derde partye inskryf nie.

## Multi-hop proxy-kettings

MITRE onderskei eksterne proxies van **multi-hop proxies (T1090.003)**. Die belangrike eienskap is nie die aantal hops nie, maar die skeiding van kennis en administrasie.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

As een party A en B bedryf, kan gedeelde logs of vloeitydsberekening die circuit rekonstrueer. Deur opeenvolgende kommersiële VPN’s vanaf dieselfde endpoint/rekening by te voeg, kan latensie toeneem terwyl gemeenskaplike identiteits-, betalings- en tydsberekeningsbewyse steeds bestaan. Tor verminder hierdie probleem met onafhanklik gekose relays en ’n gedeelde kliëntontwerp, maar ’n interaktiewe netwerk met lae latensie kan nie weerstand waarborg teen ’n waarnemer wat albei kante meet nie.

Algemene foute sluit in DNS- of IPv6-omseiling, toepassings wat hul eie sockets oopmaak, bestuursverkeer wat relays direk bereik, gesinchroniseerde aktiwiteit, hergebruikte SSH-sleutels en aanmelding by identifiserende rekeninge. Die korrekte verifikasie is ’n faaltoets: stop elke relay om die beurt en toon aan dat die werklading nie na ’n ongeënkripteerde roete kan terugval nie.

### Tunnel-ineenstorting en upstream leakage

’n Relay-argitektuur is dikwels die maklikste om toe te skryf wanneer dit faal. Unit 42 het ’n spioenasieroete met verskeie lae gedokumenteer, wat VPS’e aan die slagofferkant, relay-VPS’e, residensiële proxys, Tor en ander proxy-dienste gebruik het; toe ’n tunnel weggelaat of ineengestort het, het verborge upstream-infrastruktuur direk met relay- en slagofferkantstelsels verbind. Dieselfde ondersoek het ook ’n X.509-sertifikaat wat kortliks op upstream-infrastruktuur blootgelê is, as ’n cross-tier-pivot gebruik.<sup>[[14]](#references)</sup>

Hou die **data plane** (`victim <-> exit`) apart van die **control plane** (`operator/upstream -> relay administration`). Bewaar inkomende verbindings- en verifikasielogs by elke besitte laag, sertifikaatgeskiedenis en kort mislukte verbindings—nie net suksesvolle C2-sessies nie. ’n Bron wat slegs tydens relay-onderbrekings verskyn of verskeie slagofferkantnodusse direk administreer, is ’n sterker upstream-kandidaat as ’n gewone exit, maar sy ASN/geoligging bly ’n hipotese, nie bewys nie.

’n Gemagtigde laboratorium behoort die werklading te laat misluk indien dit nie veilig kan voortgaan nie. Vir ’n werklading wat in ’n Linux-netwerknaamruimte geïsoleer is, moet die eerste roete die tunnel gebruik; nadat dit verwyder is, moet beide die versoek en roete-opsoek misluk eerder as om die fisiese uplink te kies:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Herhaal die toets vir DNS en IPv6, en by elke relay-grens. As enige probe slaag, teken die werklike koppelvlak-/bronadres aan voordat jy policy routing of die firewall herstel; daardie waarneming is die attribution leak wat ’n ondersoeker sou sien.

## Redirector-lae en verkeersvorming

’n Openbare **redirector** aanvaar verkeer wat by ’n operasie-spesifieke grammatika pas en stuur dit aan na ’n beskermde team server. Alles anders kan geweier word of onskuldige inhoud bedien word.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Veelvuldige lae beperk blootstelling: om ’n publieke domein te verbrand, hoef nie die spanbediener bloot te stel nie. CDN’s voeg anycast-kapasiteit en ’n gerespekteerde buitenste domein by, maar die CDN-rekening en randlogboeke word attribusiepunte. TLS-fingerafdrukke, sertifikaatgeskiedenisse, kenmerkende paaie/volgorde van opskrifte, reaksiegroottes, herleidingsgedrag en oorsprong-toegelatelyste kan sogenaamd onverwante voorkante saamgroepeer.

Vir opsporing, teken omgekeerde-instaanbedienervelde aan voordat dit genormaliseer word, vergelyk SNI/Host/authority, ondersoek seldsame kombinasies van opskrifte, groepeer reaksieliggame en TLS-fingerafdrukke, en soek in wolk-/CDN-ouditlogboeke na konfigurasie-oorvleueling. Vir gemagtigde rooi spanne, moenie ’n regte handelsmerk naboots of geloofsbriewersameling agter ’n onverwante derde party plaas nie.

## Domain fronting and domainless fronting

Met klassieke **domain fronting (T1090.004)** kondig die TLS-verbinding ’n toegelate voordomein in SNI aan, terwyl die geënkripteerde HTTP `Host` of HTTP/2 `:authority` ’n ander agterkantdomein versoek. ’n Samewerkende CDN roeteer op grond van die innerlike waarde. ’n Netwerkwaarnemer sonder TLS-dekripsie sien die voorkant; die CDN sien albei waardes en die oorsprong. In domainless-variante kan SNI leeg wees, terwyl ’n ander roeteererveld die bestemming kies.<sup>[[4]](#references)</sup>

Dit is nie magiese nabootsing nie: dit werk slegs wanneer die tussenganger doelbewus of per ongeluk die verskil toelaat en weet hoe om die innerlike naam te roeteer. Groot verskaffers het kruisrekening-fronting beperk. Encrypted ClientHello (ECH) verander wat ’n waarnemer op die netwerkpad kan sien, maar verwyder nie CDN-, eindpunt- of toepassingsrekords nie.

Opsporingspunte sluit in:

- eindpunt-prosesafstamming en ’n bestemming wat nie vir daardie toepassing verwag word nie;
- SNI teenoor HTTP authority-wanpassing waar TLS-inspeksie wettig en beskikbaar is;
- CDN-logboeke wat wys dat een huurder/voorkant na ’n ander authority/oorsprong roeteer;
- buitengewoon langlewende of periodieke sessies na ’n diens wat gewoonlik interaktief is;
- stabiele groottes en ritme van geënkripteerde vloei oor veranderende voordomeine.

Die veilige laboratorium simuleer die roeteerwanpassing op ’n eie omgekeerde instaanbediener; dit misbruik nie ’n publieke CDN nie.

## Dynamic resolution: DDNS, DGA and fast flux

Dinamiese resolusie ontkoppel ’n logiese diens van vaste infrastruktuur:

- **DDNS:** ’n geverifieerde kliënt werk ’n stabiele naam by nadat sy adres verander.
- **DGA:** beide die eindpunt en kontroleerder lei kandidaatdomeinname van ’n tyd-/sleutelsaad af; die operateur registreer ’n klein deel daarvan.
- **Fast flux:** ’n naam lewer ’n vinnig veranderende stel gekompromitteerde/instaanbedieneradresse op, dikwels met lae TTL’s.
- **Double flux:** beide diensadresse en gesaghebbende naambedieneradresse roteer, wat ook die beheerlaag versteek.

Fast flux is ’n lasverspreidingspatroon wat teenstanders gebruik, nie bloot “baie DNS-antwoorde” nie. Sterker bewyse kombineer lae TTL, ’n hoë aantal unieke adresse, wye verspreiding oor ASN’e/geografieë, kort nodusleeftyd, herhaalde toepassingsgedrag en verdagte registrasiegeskiedenis. CDN’s deel wettiglik verskeie van hierdie eienskappe. MITRE beveel aan dat DNS-gedrag met die proses en daaropvolgende verbindings gekorreleer word.<sup>[[5]](#references)</sup>

’n DGA kan opgespoor word deur leksikale entropie, konsonant-/syferpatrone, NXDOMAIN-uitbarstings, gesinchroniseerde domeine wat die eerste keer gesien word, en proses-konteks. Woordlys-DGA’s en generatiewe modelle omseil eenvoudige entropiereëls, wat vlootwye tydelike groepering en eindpunt-afstamming belangriker maak.

## Compromised domains and domain shadowing

’n Akteur kan ’n registrateur-/DNS-rekening kaap, ’n verlate subdomein oorneem, of rekords onder ’n andersins gerespekteerde domein byvoeg. **Domain shadowing** behou die wettige apex terwyl groot getalle aanvaller-beheerde subdomeine na veranderende aflewerings- of C2-gashere wys. Dit leen ouderdom en reputasie en kan domeinwye blokkering ontduik.<sup>[[6]](#references)</sup>

Verdedigers benodig ouditlogboeke van registrateurs en gesaghebbende DNS, MFA, slotte by registers/registrateurs, waarskuwings vir nuwe delegerings/API-tokens/naambedieners, monitering van sertifikaatdeursigtigheid, en ’n inventaris van wolkbronne waarna DNS verwys. Ondersoek ’n subdomein se resolusie- en sertifikaatgeskiedenis onafhanklik van die apex se reputasie.

## Web services and dead-drop resolvers

’n **dead-drop resolver (T1102.001)** stoor ’n geënkodeerde wyser na huidige C2 in ’n wettige plasing, profiel, dokument, bewaarplek, wolkobjek of blokkettingveld. Wanware haal die publieke objek op, dekodeer ’n domein/IP en kontak die volgende stadium. Tweerigtingvariante ruil opdragte of lêers deur diens-API’s uit.<sup>[[7]](#references)</sup>

Een GitHub-spesifieke resolver-variasie gebruik die Issues Search API slegs wanneer ’n geverifieerde bewaarplekkanaal faal. Die kliënt soek na issues wat by die huidige datum, bewaarplek en issuetipe pas, volg elke issue se kommentaar-URL, en onttrek syferteks tussen `<!--` en `-->`-merkers. Ná dekripsie per gasheer, afgelei van die datum, vervang velde soos `Owner`, `LicRepo` en `LicToken` die primêre bewaarplekeienaar, pad en token. Só kan die operateur geloofsbriewe en eindpunte roteer sonder om die kliënt te vervang; die issue-kommentaar is ’n resolver, terwyl die bewaarpleklêers die taakskeduleringskanaal bly.<sup>[[15]](#references)</sup>

Dit bied veerkragtigheid en versteek C2 aan die agterkant vir statiese binêre ontleding. Dit skep ook stabiele identifiseerders vir objekte, huurders, bewaarplekke, API’s en toegangspatrone. Verdedigers behoort die volgende te koppel:

1. die proses wat die diens gekontak het;
2. die presiese API-pad/objek en reaksiehash;
3. dekoderings- of stringverwerkingsaktiwiteit;
4. die nuwe uitgaande verbinding kort daarna; en
5. identiese gedrag elders in die vloot.

Om alle GitHub, wolkberging of sosiale media te blokkeer, is selde haalbaar. Uitgaande beleid wat diensbewus is en korrelasie op prosesvlak vaar beter as blokkering op grond van domeine alleen.

## Personas, accounts and procurement compartments

Infrastruktuuranonimiteit faal wanneer ’n persona, herstel-e-posadres, telefoonnommer, betaling, blaaier of admin-IP kompartemente oorbrug. Staatsgekoppelde operasies het sosiale profiele, e-posidentiteite en wolkrekeninge lank voor gebruik opgebou; ATT&CK teken dit aan as Establish Accounts (T1585), insluitend sosiale, e-pos- en wolk-subtegnieke.<sup>[[8]](#references)</sup>

’n Verdediger of ondersoeker bou ’n grafiek op grond van:

- skeppingstyd en eerste aanmelding, streek, tydsone en werkskedule;
- herstelvelde, MFA-toestelle, identiteitsdokumente en betaalmiddele;
- blaaier-/TLS-fingerafdrukke en geskiedenis van bronnetwerke;
- hergebruik van avatars, beeldherkoms, skryfstyl en groei van die sosiale grafiek;
- gedeelde domeinregistrant, naambediener, sertifikaat, analise-ID of bewaarplekbystand;
- bestuursvlak-aksies wat die publieke aflosargitektuur omseil.

Vir ’n gemagtigde rooi span behoort sintetiese personas aan die oefeningbeheerder gedokumenteer te word, organisasie-besitte herstel-/betaalkanale te gebruik, nabootsing van regte en onverwante mense te vermy, en ’n beplande aftrede te hê. Die SOC mag steeds onbewus wees; die operasie mag nie onopspoorbaar raak nie.

## Emerging compound patterns to threat-model

Die volgende is **verdedigergedrewe samestellings**, nie bewerings dat ’n genoemde akteur elke presiese ontwerp ontplooi het nie. Hulle kombineer reeds waargenome boustene en is nuttige hipoteses vir perspan-oefeninge.

### Asymmetric one-way tasking

Opdragte kom deur ’n publieke, uitsaai- of slegs-byvoegbare bron aan, terwyl resultate ná ’n vertraging deur ’n onverwante kanaal vertrek. Voorbeelde van die bousteen sluit in eenrigtingkommunikasie deur webdienste en dead drops. Skeiding keer dat ’n enkele vloei tweerigting lyk en bemoeilik eenvoudige versoek-/reaksiekorrelasie.<sup>[[9]](#references)</sup>

**Opsporing:** bewaar lesings op objekvlak, en korreleer dan prosesstatusveranderinge en latere uitgaande oordragte oor ’n langer tydvenster. Soek na ’n seldsame proses wat dieselfde publieke objek lees, selfs wanneer geen onmiddellike antwoord volg nie.

### Multi-stage channel promotion

’n Stil eerste stadium doen inventarisopname en bevorder slegs geselekteerde stelsels na ’n onverwante tweede-stadiumkanaal. Die tweede eindpunt, protokol en proses deel dalk geen infrastruktuur met die eerste nie. Dit beperk blootstelling van bekwame infrastruktuur en word uitdruklik as ATT&CK T1104 gemodelleer.<sup>[[10]](#references)</sup>

**Opsporing:** koppel `eerste netwerkproses -> afgelaaide/gekonfigureerde status -> nuwe proses of inspuiting -> onverwante bestemming`; moenie die voorval afsluit nadat die eerste domein geblokkeer is nie.

### Cross-protocol relay translation

Verskillende spronge vertaal HTTPS, QUIC, WebSocket, DNS, SSH of ’n boodskapry-API, eerder as om pakkies deursigtig aan te stuur. Vertaling verwyder ’n enkele end-tot-end-protokolfingerafdruk, maar skep poorte met kenmerkende tydsberekening, buffering en semantiese omskakeling. Protokoltrekking (T1572) kan met instaanbedieners en diensnabootsing gekombineer word.<sup>[[11]](#references)</sup>

**Opsporing:** soek na poortgashere wat een protokol ontvang en ’n ander begin met nou gekoppelde greep-/tydgedrag; vergelyk eindpuntbedoeling met die protokol wat werklik vervoer word.

### Passive activation on edge devices

In plaas van beaconing monitor ’n implantaat verkeer wat reeds ’n roeteerder/VPN bereik en aktiveer dit slegs op ’n magiese waarde, bronpoortpatroon of geverifieerde token. Normale verkeer gaan voort na die werklike diens. ATT&CK noem dit Traffic Signaling (T1205), met gedokumenteerde voorbeelde van netwerktoestelle en APT’s.<sup>[[12]](#references)</sup>

**Opsporing:** fermware-/lêerintegriteit, rou pakkievaslegging tydens ’n gemagtigde ondersoek, onverwagte sokfilters en verskille in diensgedrag. Die afwesigheid van ’n periodieke beacon bewys nie dat ’n randtoestel skoon is nie.

### Serverless and ephemeral origin rotation

’n Voorkant behou ’n stabiele logiese identiteit terwyl kortstondige funksies/houers individuele stadiums in verskeie streke/rekeninge hanteer. Dit verminder skyfleeftyd en vaste oorsprong-IP’s, maar beheervlak-skepping, beeld/lae, rol, geheim, versoek-ID en faktureringsdata word die blywende grafiek.

**Opsporing:** behou wolkoudit- en aanroeplogboeke buite die werklas; groepeer ontplooiingsjablone, rolle, omgewingsleutels en voorkant-tot-oorsprong-verhoudings.

### Privacy-layer diversity

’n Operasie kan doelbewus eenvormige ketting vermy: byvoorbeeld, een kanaal gebruik ’n gehuurde aflos, taakskedulering gebruik ’n publieke objek, ’n uitgang kom van ’n besitte laboratoriumsellulêre skakel, en administrasie gebruik ’n afsonderlike organisasienetwerk. Dit verminder die waarde daarvan om een verskaffer te kompromitteer, maar verhoog die risiko van tydsberekening- en operasionele foute oor lae heen.

**Opsporing:** bou veldtogtydlyne oor identiteits-, DNS-, SaaS-, netwerk- en wolksensors heen. Soek na gesinchroniseerde statusoorgange eerder as identiese aanwysers.

### Decentralized or transparency-log dead drops

’n Akteur kan ’n klein geënkripteerde wyser in enige duursame publieke stelsel wat slegs byvoeg, inhoudadresseerbare berging of deursigtigheidsagtige voer plaas. Die publieke objek is veerkragtig, maar sy presiese indeks/inhoudhash en die kliënt se peilgedrag word stabiele identifiseerders.

**Opsporing:** teken volledige API-/objekidentifiseerders en reaksiehashes aan; waarsku oor nie-standaardprosesse wat onveranderlike objekte peil, gevolg deur dekodering of nuwe verbindings.

### Delayed store-and-forward operations

Interaktiewe C2 skep sterk tydskorrelasie. ’n Store-and-forward-ontwerp bondel geënkripteerde take en stuur resultate minute of ure later deur ’n ander ry of fisiese oordrag terug. Dit verruil responsiwiteit vir swakker end-tot-end-tydskorrelasie.

**Opsporing:** verleng korrelasievensters, modelleer periodieke rytoegang en ondersoek eindpunt-stasering. Bondeling verskuif die sein van pakkietydsberekening na geskeduleerde proses-/lêergedrag; dit wis dit nie uit nie.

## Design review: think in observers

Vul hierdie tabel vir elke roete in, voor ontplooiing en ná versameling:

| Laag | Sien bron? | Sien bestemming? | Sien inhoud? | Stabiele identifiseerders | Bewaring/wetlike eienaar |
|---|---:|---:|---:|---|---|
| plaaslike netwerk/draer | | | | | |
| toegangsdiens | | | | | |
| deurvoeroperateur(s) | | | | | |
| uitgang/herleier/CDN | | | | | |
| gesaghebbende DNS/registrateur | | | | | |
| teiken | | | | | |
| rekening-/betalingsverskaffer | | | | | |

As een gewone verskaffer elke kolom kan invul, bied die argitektuur verberging teenoor die teiken, maar nie robuuste skeiding nie. As geen interne beheerder aktiwiteit aan ’n opdrag kan koppel nie, is dit ongeskik vir professionele rooi spanne.

## References

- [1] [MITRE ATT&CK — Verkryging van infrastruktuur (T1583), kompromittering van infrastruktuur (T1584), en instaanbediener (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-gekoppelde spioenasie-akteurs gebruik ORB-netwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kompromittering van infrastruktuur: domeine (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Rekeninge opstel (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protokoltrekking (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Ontwrigting van die wêreld se grootste residensiële instaanbedienernetwerk](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Die Shadow-veldtogte: Blootlegging van wêreldwye spioenasie](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel-veldtog teiken Irakse infrastruktuur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
