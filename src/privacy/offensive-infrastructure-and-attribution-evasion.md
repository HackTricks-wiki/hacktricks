# Aanvallende infrastruktuur en ontduiking van toeskrywing

{{#include ../banners/hacktricks-training.md}}

’n Operateur verkry selde betekenisvolle anonimiteit deur net een proxy te gebruik. Werklike veldtogte bou ’n **skeidingsgrafiek**: die operateur bereik ’n toegangsnodus, deurkruisingsnodusse verberg daardie nodus vir die uitgang, redirectors beskerm die werklike C2, en weggooibare name wys na die publieke rand.

Gebruik die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) vir ’n gestandaardiseerde oorsig van die voordele, nadele, ontplooiing en opsporing van elke roete. Hierdie bladsy gaan dieper in op die samestelling van teenstanders se infrastruktuur.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Die laaste adres wat ’n teiken sien, is dus bewys van ’n roete, nie bewys van wie die sleutelbord beheer het nie. MITRE karteer die belangrikste komponente as Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) en Web Service (T1102).<sup>[[1]](#references)</sup>

## Infrastructure classes

| Klas | Waarom ’n akteur dit gebruik | Duursame blootstelling | Verdediger se beste aanknopingspunt |
|---|---|---|---|
| Gehuurde VPS/cloud | Vinnig, voorspelbaar, roeteerbaar, maklik om te herbou | huurder-, fakturering-, konsole-, bronaanmelding- en beeldgeskiedenis | rekening-/beheerlaaggebeurtenisse en herhaalde bediener-fingerprint |
| Kommersiële VPN/Tor | Groot gedeelde egress-stel; geen bedieneradministrasie nie | verskaffer-/sigbaarheidsbeheer en end-tot-end-tydsberekening | bestemmingsgedrag, eindpuntbewyse en verkeersvloeikorrelasie |
| Residensiële/mobiele proxy | Verbruikers-ASN en geografiese geloofwaardigheid | makelaar-/kliëntrekords; proxyware- of besmettegasheergedrag | onmoontlike reis, proxy-protokolle en adreswisseling per sessie |
| Gekompromitteerde bediener/roeteerder/IoT | Leen die slagoffer se reputasie en jurisdiksie | implantaat, bestuursverkeer en herhaalde stroomop-beheerder | toesteltelematrie en ORB-topologie, nie een uitgang-IP nie |
| CDN/redirector | Skei die openbare rand van die back-end-C2 | TLS/HTTP-grammatika, sertifikaat-, roeterings- en cloud-rekeningartefakte | korrelasie tussen rand en oorsprong, en groepering volgens versoekvorm |
| Wettige webdiens | Meng in met toegelate GitHub/cloud/sosiale verkeer | API-token, huurder-/objekidentifiseerders en ongewone prosesafstamming | eindpuntproses plus diens-/API-semantiek |
| Fisiese/selfoon-/satellietroete | Verander die skynbare fisiese oorsprong | RF-, diensverskaffer-, intekenaar-, toestel- en liggingrekords | gekombineerde radio-/fisiese en netwerkbewyse |

## Operasionele relay box-netwerke

’n **ORB-netwerk** is ’n bestuurde proxyvloot wat as ’n tussengangerdiens gebruik word. Mandiant verdeel hulle in voorsiene netwerke van gehuurde bedieners, nie-voorsiene netwerke van gekompromitteerde roeteerders/IoT, en hibriede netwerke. ’n Volwasse topologie het vier logiese rolle:<sup>[[2]](#references)</sup>

1. **Administrasiebediener (ACOS):** hou inventaris, geloofsbriewe, gesondheid en roeteringsbeleid by.
2. **Toegangs-/relay-node:** staaf kliënte of operateurs; dit is die stabiele ingang na ’n veranderende mesh.
3. **Deurgangsnodes:** een of meer gehuurde of gekompromitteerde stelsels relay ondeursigtige verbindings.
4. **Uitgang-/staging-node:** bied die finale bronadres aan verkennings-, uitbuitings- of C2-teikens.

Die mesh kan uitgange volgens land, ASN, latensie of beskikbaarheid kies en ongesonde nodes roteer. Verskeie bedreigingsgroepe kan dieselfde netwerk huur. Mandiant het waargeneem dat ’n IPv4-adres met sommige ORB’s vir so min as 31 dae geassosieer gebly het; daarom beveel dit aan om die **netwerk as ’n ontwikkelende entiteit soortgelyk aan ’n akteur** te behandel, eerder as om ’n verouderde lys IP’s te blokkeer.<sup>[[2]](#references)</sup>

### Wat dit oplewer — en wat dit uitlek

- Die teiken sien ’n uitgang wat geografies naby en oënskynlik residensieel kan wees.
- Die uitgang sien die teiken en die voorafgaande hop, maar nie noodwendig die operateur nie.
- Die toegangsdiens sien die kliënt en die roeteversoek. ’n Onafhanklik bestuurde mesh kan die kliënt van die uitgange geskei hou, maar skep ’n kragtige teenpartyrekord.
- Herhaalde poorte, handdrukvolgorde, bedienerbaniere, sertifikate, uptymvensters en beheerderverhoudings kan die vloot blootlê selfs terwyl IP’s roteer.
- ’n Gekompromitteerde roeteerder het dikwels nie eindpunttelemetrie nie, maar sy ISP het steeds intekenaar- en verkeersvloeidata; ’n beslaglegging stel implantaat-/konfigurasieartefakte bloot.

{% hint style="info" %}
Reproduseer die topologie vir ’n gemagtigde oefening met virtuele masjiene of roeteerders wat deur die organisasie besit word, en hou die beheerder se toeskrywingskaart by. Moenie oop proxy’s of toestelle van derde partye werf nie. Die [labgids](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) skep dieselfde hopstruktuur wat vir verdedigers sigbaar is, sonder om ’n tussenganger te viktimiseer.
{% endhint %}

## Residensiële en mobiele proxynetwerke

Residensiële proxy-dienste ken sessies aan verbruikersbreëbandadresse toe; mobiele proxy’s se egress loop deur diensverskaffer-NAT-poele. Die aanbod kan kom van toestelle waarvoor uitdruklik ingeskryf is, SDK’s/proxyware wat by verbruikerstoepassings ingesluit is, herverkopers of malware. Hierdie oorspronge is nie gelykwaardig nie: gebrek aan ingeligte toestemming verander ’n privaatheidsdiens in gekompromitteerde infrastruktuur.

Rotasiemodusse beïnvloed opsporing:

- **rotasie per versoek** veroorsaak vinnige IP- en ASN-/geografiese diskontinuïteite terwyl die identiteit op hoër lae stabiel bly;
- **kleefsessies** hou ’n uitgang vir minute of ure, wat soos ’n gewone intekenaar lyk;
- **backconnect-gateways** wys een makelaar-eindpunt aan die kliënt en kies intern uitgange;
- **mobiele poele** plaas baie egte intekenare agter ’n klein stel diensverskaffer-NAT-adresse, wat ’n IP-blokkering duur maak.

Verdedigers moet die IP korreleer met die geverifieerde sessie, TLS-/kliënt-fingerprint, HTTP-volgorde, toestelkoekie en gedrag. ’n Aanmelding wat na bewering plaaslik residensieel is en daarna uit ’n ander land plaasvind terwyl alle hoërlaagkenmerke identies bly, is sterker bewys as reputasie alleen. Omgekeerd veroorsaak adresdeling en mobiele oorskakeling wettige wisseling, dus moet residensiële/proxyklassifikasie nooit as ’n uitspraak beskou word nie.

### Proxyware-beheerlae en oorvleueling tussen herverkopers

Moenie ’n residensiële poel modelleer as ’n plat lys uitgange nie. Ontleding van die IPIDEA-ekosisteem het ’n herbruikbare **tweevlak-control plane** blootgelê: ’n ingebedde SDK rapporteer eers toestel-/inskrywingsmetadata aan ’n Tier One-domein en ontvang skedulering plus Tier Two `connect`/`proxy`-IP:poortpare. Die node vra die Tier Two-connect-poort periodiek vir ’n geënkodeerde taak, open ’n tweede verbinding met die gepaarde proxy-poort en relay die verskafde grepe na die versoekte bestemming. SDK’s en proxyhandelsmerke wat formeel verskil het, het afsonderlike ontdekkingsdomeine gehad, maar het deur gemeenskaplike eienaarskap en herverkoperverhoudings by gedeelde Tier Two-infrastruktuur en oorvleuelende uitgangspoele uitgekom.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Dit lewer duursamer hunting pivots as ’n residential IP-blok:<sup>[[13]](#references)</sup>

- ’n Onverwagte nutsprogram-, VPN-, speletjie- of ingebedde-toestelproses stuur ’n stabiele toestel-ID/kliëntsleutel en ontvang ’n veranderende bedienerlys;
- die eindpunt pols ’n direkte IP op ’n ongewone poort en koppel dan aan ’n ander poort op dieselfde adres, net voordat ’n nuwe bestemmingsokkel oopgemaak word;
- verskeie oënskynlike handelsmerke deel Tier Two-adresse, protokolgrammatika, SDK-kode of oorvleueling van uitgangnodusse;
- afsonderlike toepassings wat verskillende Tier One-domeine kontak, ontvang adresse uit dieselfde Tier Two-poel.

Die oorvleueling beperk ook attribusie: om ’n IP in een verskaffer se geadverteerde poel te sien, bewys nie watter herverkoper, kliënt of bedreigingsakteur dit op die betrokke tydstip gebruik het nie. Bewaar vloeitydstempels, prosesafstamming, Tier One-antwoordliggame en Tier Two-taakidentifiseerders.<sup>[[13]](#references)</sup> Emuleer hierdie hiërargie in ’n gemagtigde oefening slegs met eindpunte wat deur die organisasie besit word; skryf nooit verbruikerstoestelle of derdeparty-proxyware in nie.

## Multi-hop proxy-kettings

MITRE onderskei tussen eksterne proxies en **multi-hop proxies (T1090.003)**. Die belangrike eienskap is nie die aantal hops nie, maar die skeiding van kennis en administrasie.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

As een party A en B bedryf, kan gedeelde logs of die tydsberekening van verkeersvloei die circuit rekonstrueer. As opeenvolgende kommersiële VPNs vanaf dieselfde endpoint/account bygevoeg word, kan dit latency verhoog terwyl gemeenskaplike identiteits-, betalings- en tydsbewyse behoue bly. Tor verminder hierdie probleem met relays wat onafhanklik gekies word en ’n gedeelde kliëntontwerp, maar ’n interaktiewe netwerk met lae latency kan nie weerstand waarborg teen ’n waarnemer wat albei kante meet nie.

Algemene foute sluit in DNS- of IPv6-omseiling, toepassings wat hul eie sockets oopmaak, management traffic wat relays direk bereik, gesinchroniseerde aktiwiteit, hergebruikte SSH keys en aanmelding by rekeninge wat jou identiteit bekend maak. Die korrekte verifikasie is ’n faaltoets: stop elke relay om die beurt en wys dat die workload nie na ’n onbeveiligde pad kan terugval nie.

### Tunnel-ineenstorting en lekkasie na die stroomop-infrastruktuur

’n Relay-argitektuur is dikwels die maklikste om aan iemand toe te skryf wanneer dit faal. Unit 42 het ’n spioenasiepad met veelvuldige lae gedokumenteer wat VPSs aan die slagofferkant, relay-VPSs, residensiële proxies, Tor en ander proxy-dienste gebruik het; toe ’n tunnel weggelaat is of ineengestort het, het versteekte stroomop-infrastruktuur direk met relay- en slagofferkantstelsels verbind. Dieselfde ondersoek het ook ’n X.509-sertifikaat gebruik wat kortstondig op stroomop-infrastruktuur blootgelê is as ’n skakel om tussen lae te beweeg.<sup>[[14]](#references)</sup>

Hou die **data plane** (`victim <-> exit`) apart van die **control plane** (`operator/upstream -> relay administration`). Bewaar ingress- en verifikasiëlogs by elke beheerde laag, sertifikaatgeskiedenis en kort mislukte verbindings—nie net suksesvolle C2-sessies nie. ’n Bron wat slegs tydens relay-onderbrekings verskyn of verskeie slagofferkantnodes direk administreer, is ’n sterker kandidaat vir stroomop-infrastruktuur as ’n gewone exit, maar sy ASN/geoligging bly ’n hipotese, nie bewys van ’n operateur se identiteit nie.

’n Gemagtigde lab behoort die workload veilig te laat faal. Vir ’n workload wat in ’n Linux-netwerknaamruimte geïsoleer is, moet die eerste roete die tunnel gebruik; nadat dit verwyder is, moet beide die versoek en roete-opsoek faal, eerder as om die fisiese uplink te kies:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Herhaal die toets vir DNS en IPv6, en by elke relay-grens. As enige probe slaag, teken die werklike koppelvlak-/bronadres aan voordat jy policy routing of die firewall herstel; daardie waarneming is die attribution leak wat ’n ondersoeker sou sien.

## Redirector-vlakke en verkeersvorming

’n Openbare **redirector** aanvaar verkeer wat by ’n operasie-spesifieke grammar pas en stuur dit aan na ’n beskermde team server. Alles anders kan geweier word of van onskadelike inhoud voorsien word.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Veelvuldige lae beperk blootstelling: om ’n publieke domein te brand, hoef nie die spanbediener bloot te stel nie. CDN’s voeg anycast-kapasiteit en ’n geloofwaardige buitenste domein by, maar die CDN-rekening en randlogs word punte vir toeskrywing. TLS-vingerafdrukke, sertifikaatgeskiedenisse, kenmerkende paaie/kopvolgorde, antwoordgroottes, herleidingsgedrag en oorsprongstoelaatlyste kan sogenaamd onverwante fronte groepeer.

Vir opsporing, teken omgekeerde-instaanbedienervelde aan voordat dit genormaliseer word, vergelyk SNI/Host/authority, inspekteer seldsame kombinasies van koppe, groepeer antwoordliggame en TLS-vingerafdrukke, en soek in wolk-/CDN-ouditlogs na oorvleueling in konfigurasies. Vir gemagtigde red teams, vermy dit om ’n regte handelsmerk na te boots of geloofsbrameinsameling agter ’n onverwante derde party te plaas.

## Domain fronting and domainless fronting

Met klassieke **domain fronting (T1090.004)** kondig die TLS-verbinding ’n toegelate voordomein in SNI aan, terwyl die geënkripteerde HTTP `Host` of HTTP/2 `:authority` ’n ander agterkantdomein aanvra. ’n Samewerkende CDN roeteer op grond van die binneste waarde. ’n Netwerkwaarnemer sonder TLS-dekripsie sien die front; die CDN sien albei waardes en die oorsprong. In domainless fronting-variante kan SNI leeg wees terwyl ’n ander roeteringsveld die bestemming kies.<sup>[[4]](#references)</sup>

Dit is nie magiese nabootsing nie: dit werk slegs wanneer die tussenganger die wanpassing doelbewus of per ongeluk toelaat en weet hoe om die binneste naam te roeteer. Groot verskaffers het fronting tussen verskillende rekeninge beperk. Encrypted ClientHello (ECH) verander wat ’n waarnemer op die netwerkpad kan sien, maar wis nie CDN-, eindpunt- of toepassingsrekords uit nie.

Opsporingspunte sluit in:

- prosesherkoms op die eindpunt en ’n bestemming wat nie vir daardie toepassing verwag word nie;
- ’n wanpassing tussen SNI en HTTP authority waar TLS-inspeksie wettig en beskikbaar is;
- CDN-logs wat wys dat een tenant/front na ’n ander authority/oorsprong roeteer;
- buitengewoon lang sessies of sessies met ’n vaste periodisiteit na ’n diens wat normaalweg interaktief gebruik word;
- stabiele groottes en frekwensie van geënkripteerde vloei oor veranderende frontdomeine.

Die veilige laboratorium simuleer die roeteringswanpassing op ’n omgekeerde instaanbediener wat jy besit; dit misbruik nie ’n publieke CDN nie.

## Dynamic resolution: DDNS, DGA and fast flux

Dinamiese resolusie ontkoppel ’n logiese diens van vaste infrastruktuur:

- **DDNS:** ’n geverifieerde kliënt werk ’n stabiele naam by nadat sy adres verander.
- **DGA:** die eindpunt lei domeinname af van ’n saadjie, dikwels tyd of ’n sleutel maar soms veranderlike publieke inhoud; die operateur stel DNS vir die aktiewe naam op.<sup>[[17]](#references)</sup>
- **Fast flux:** ’n naam gee ’n vinnig veranderende stel gekompromitteerde/instaanbedieneradresse terug, dikwels met lae TTL’s.
- **Double flux:** beide diensadresse en gesaghebbende naamserveradresse roteer, wat ook die beheerlaag verberg.

Fast flux is ’n lasverspreidingspatroon wat aanvallend gebruik word, nie bloot “baie DNS-antwoorde” nie. Sterker bewyse kombineer ’n lae TTL, ’n groot aantal unieke adresse, wye verspreiding oor ASN’s/geografieë, kort lewensduur van nodusse, herhaalde toepassinggedrag en verdagte registrasiegeskiedenis. CDN’s deel wettiglik verskeie van hierdie eienskappe. MITRE beveel aan dat DNS-gedrag met die proses en daaropvolgende verbindings gekorreleer word.<sup>[[5]](#references)</sup>

’n DGA kan opgespoor word deur leksikale entropie, konsonant-/syferpatrone, NXDOMAIN-storms, domeine wat gelyktydig die eerste keer gesien word en proses-konteks. Woordlys-DGA’s en generatiewe modelle omseil eenvoudige entropiereëls, wat tydelike groepering oor die hele vloot en eindpuntafstamming belangriker maak.

### Mutable image seed for a wordlist DGA

’n DGA hoef nie van tyd afhanklik te wees nie. Een loader haal ’n publieke Telegram-kanaalbladsy op, lees die `src` van sy `tgme_page_photo_image`-element af, laai daardie profielprent af en bereken ’n hash van die **laaste 50 grepe van die lêer** eerder as van die gedekodeerde pixels. Vier hash-saadwaardes kies ’n byvoeglike naamwoord, selfstandige naamwoord, werkwoord en getal. As die prent verander, verander die afgeleide DNS-naam sonder dat ’n nuwe kliënt versprei hoef te word. Hou die presiese afgelaaide prentgrepe en dieselfde volgorde van die woordlyste aan albei kante; as die prent herkodeer word of ’n lys se volgorde verander, lewer dit verskillende name op.<sup>[[17]](#references)</sup>

Met die woordlyste wat van die kliënt herwin is, reproduseer dit die naamkeusestap. Die bron se greep-vir-greep-hash gebruik ’n 64-bis-akkumulator, vermenigvuldiger `0x1000193` en aparte saadwaardes vir elke komponent:<sup>[[17]](#references)</sup>

<details>
<summary>Reproduce the image-seeded wordlist name selection</summary>

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

Anders as ’n [dead-drop resolver](#web-services-and-dead-drop-resolvers) wat die endpoint self publiseer, verskaf die openbare objek hier slegs ’n veranderlike saad; die kliënt lei die endpoint plaaslik af.

Die gegenereerde naam word dan vir ’n DNS TXT-rekord navraag gedoen deur `https://dns.google/resolve?name=<domain>&type=TXT`. Die kliënt Base64-dekodeer die JSON-antwoord se `data`-veld, verifieer ’n Ed25519-handtekening met die ingebedde publieke sleutel, en AES-ECB-dekripteer eers daarna die opdrag. Die waargenome gewone teks begin met ’n metodekeurder en ’n URL vir ’n geënkripteerde payload. Die handtekeningkontrole beteken dat ’n TXT-rekord wat bloot oplosbaar is, nie op sigself aanvaarde taakdata kan verskaf nie.<sup>[[17]](#references)</sup>

## Gekompromitteerde domeine en domeinskaduwering

’n Akteur kan ’n registrateur-/DNS-rekening kaap, ’n verlate subdomein oorneem, of rekords onder ’n andersins gerekende domein byvoeg. **Domain shadowing** behou die wettige apex, terwyl groot getalle aanvallerbeheerde subdomeine na veranderende aflewerings- of C2-gashere wys. Dit benut ouderdom en reputasie en kan domeinwye blokkering ontduik.<sup>[[6]](#references)</sup>

Verdedigers het registrateur- en gesaghebbende DNS-ouditlogboeke, MFA, register-/registrateur-slotte, waarskuwings vir nuwe delegerings/API-tokens/naamservers, sertifikaatdeursigtigheidmonitering en ’n inventaris van wolkhulpbronne waarna DNS verwys, nodig. Ondersoek ’n subdomein se resolusie- en sertifikaatgeskiedenis onafhanklik van die apex se reputasie.

## Webdienste en dead-drop resolvers

’n **dead-drop resolver (T1102.001)** stoor ’n geënkodeerde aanwyser na die huidige C2 in ’n wettige plasing, profiel, dokument, repository, wolkobjek of blockchain-veld. Malware haal die openbare objek op, dekodeer ’n domein/IP en kontak die volgende stadium. Tweerigtingvariante ruil opdragte of lêers deur diens-API’s uit.<sup>[[7]](#references)</sup>

Een GitHub-spesifieke resolver-variant gebruik die Issues Search API slegs wanneer ’n geverifieerde repository-kanaal misluk. Die kliënt soek na issues wat by die huidige datum, repository en issuetipe pas, volg elke issue se kommentaar-URL en haal syferteks tussen `<!--` en `-->`-merkers uit. Ná dekripsie per gasheer, afgelei van die datum, vervang velde soos `Owner`, `LicRepo` en `LicToken` die primêre repository-eienaar, pad en token. Dit laat die operateur toe om geloofsbriewe en endpoints te roteer sonder om die kliënt te vervang; die issue-kommentaar dien as ’n resolver, terwyl die repository-lêers die taakdatakanaal bly.<sup>[[15]](#references)</sup>

’n Android-variant kies met opstart een van twee openbare Telegram-bladsye en haal syferteks uit tussen twee voorkomste van ’n merker wat in die APK ingebed is. Dit Base64URL-dekodeer die waarde en dekripteer dit met AES-128-CBC: die eerste 16 grepe van `SHA-256(marker)` is die sleutel en die oorblywende 16 grepe is die IV. Die gewone teks is die werklike C2-basis-URL, nie die Telegram-bladsy se URL nie. Behou die bladsy-inhoud en presiese merker wanneer jy die resolusie reproduseer; deur die openbare bladsy te verander, kan die endpoint geroteer word sonder om die APK te herbou.<sup>[[16]](#references)</sup>

Dit bied veerkragtigheid en verberg back-end C2 vir statiese binêre analise. Dit skep ook stabiele identifiseerders vir objekte, huurders, repositories, API’s en toegangspatrone. Verdedigers behoort die volgende te koppel:

1. die proses wat die diens gekontak het;
2. die presiese API-pad/objek en antwoord-hash;
3. dekoderings- of stringverwerkingsaktiwiteit;
4. die nuwe uitgaande verbinding kort daarna; en
5. identiese gedrag elders in die vloot.

Dit is selde haalbaar om alle GitHub, wolkberging of sosiale media te blokkeer. Uitgaande beleid wat diensbewus is en korrelasie op prosesvlak vaar beter as blokkering wat net op domeine berus.

## Personas, rekeninge en verkrygingskompartemente

Infrastruktuuranonimiteit misluk wanneer ’n persona, herstel-e-posadres, foon, betaling, blaaier of admin-IP kompartemente verbind. Operasies wat aan state gekoppel is, het sosiale profiele, e-posidentiteite en wolkrekeninge lank voor gebruik opgebou; ATT&CK teken dit aan as Establish Accounts (T1585), met sosiale-, e-pos- en wolksubtegnieke.<sup>[[8]](#references)</sup>

’n Verdediger of ondersoeker bou ’n grafiek op grond van:

- tyd van skepping en eerste aanmelding, locale, tydsone en werkskedule;
- herstelvelde, MFA-toestelle, identiteitsdokumente en betaalmiddels;
- blaaier-/TLS-vingerafdrukke en geskiedenis van bronnetwerke;
- hergebruik van avatars, beeldherkoms, skryfstyl en groei van die sosiale grafiek;
- gedeelde domeinregistrant, naamserver, sertifikaat, analytics-ID of repository-commit;
- aksies op die bestuursvlak wat die openbare-aflosargitektuur omseil.

Vir ’n gemagtigde red team behoort sintetiese personas aan die oefeningbeheerder gedokumenteer te word, organisasiebeheerde herstel-/betaalkanale te gebruik, nabootsing van werklike, onverwante mense te vermy, en ’n beplande aftrede te hê. Die SOC mag onbewus bly; die operasie moet nie sonder aanspreeklikheid wees nie.

## Ontluikende saamgestelde patrone om as bedreigings te modelleer

Die volgende is **verdedigergedrewe samestellings**, nie bewerings dat ’n genoemde akteur elke presiese ontwerp ontplooi het nie. Dit kombineer reeds waargenome basiese tegnieke en is nuttig as hipoteses vir purple-team-oefeninge.

### Asimmetriese eenrigting-taakdata

Opdragte kom deur ’n openbare, uitsaaigebaseerde of slegs-byvoegbare bron aan, terwyl resultate ná ’n vertraging deur ’n onverwante kanaal uitgaan. Voorbeelde van die basiese tegniek sluit in eenrigtingkommunikasie via webdienste en dead drops. Die skeiding keer dat ’n enkele vloei tweerigting lyk en bemoeilik eenvoudige korrelasie van versoek en antwoord.<sup>[[9]](#references)</sup>

**Opsporing:** behou rekords van objeklesings en korreleer dan prosesstatusveranderings en latere uitgaande oordragte oor ’n langer tydvenster. Soek na ’n seldsame proses wat dieselfde openbare objek lees, selfs wanneer geen onmiddellike antwoord volg nie.

### Bevordering van kanale oor verskeie stadiums

’n Stil eerste stadium doen inventarisering en bevorder slegs geselekteerde stelsels na ’n onverwante tweedestadiumkanaal. Die tweede endpoint, protokol en proses deel moontlik geen infrastruktuur met die eerste nie. Dit beperk blootstelling van gevorderde infrastruktuur en word uitdruklik as ATT&CK T1104 gemodelleer.<sup>[[10]](#references)</sup>

**Opsporing:** koppel `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; moenie die voorval afsluit nadat jy die eerste domein geblokkeer het nie.

### Vertaling tussen protokolaflosse

Verskillende skakels vertaal HTTPS, QUIC, WebSocket, DNS, SSH of ’n message-queue-API, eerder as om pakkies deursigtig aan te stuur. Vertaling verwyder ’n enkele end-tot-end-protokolvingerafdruk, maar skep poorte met kenmerkende tydsberekening, buffering en semantiese omskakeling. Protokoltonneling (T1572) kan met proxies en diensnabootsing gekombineer word.<sup>[[11]](#references)</sup>

**Opsporing:** soek na poortgashere wat een protokol ontvang en ’n ander begin gebruik, met nou gekoppelde grepe-/tydgedrag; vergelyk die endpoint se bedoeling met die protokol wat werklik gedra word.

### Passiewe aktivering op randtoestelle

In plaas daarvan om te beacon, monitor ’n implantaat verkeer wat reeds ’n router/VPN bereik en aktiveer dit slegs op ’n magic value, bronpoortpatroon of geverifieerde token. Normale verkeer gaan voort na die werklike diens. ATT&CK noem dit Traffic Signaling (T1205), met gedokumenteerde voorbeelde van netwerktoestelle en APT’s.<sup>[[12]](#references)</sup>

**Opsporing:** firmware-/lêerintegriteit, rou pakkievaslegging tydens ’n gemagtigde ondersoek, onverwagte sokfilters en verskille in diensgedrag. Die afwesigheid van ’n periodieke beacon bewys nie dat ’n randtoestel skoon is nie.

### Serverless- en kortstondige oorsprongrotasie

’n Front behou ’n stabiele logiese identiteit terwyl kortstondige funksies/houers individuele stadiums in verskeie streke/rekeninge hanteer. Dit verminder skyfleeftyd en vaste oorsprong-IP’s, maar telemetry oor die skepping op die bestuursvlak, image/layer, rol, geheim, versoek-ID en fakturering vorm die blywende grafiek.

**Opsporing:** behou wolkoudit- en aanroepingslogboeke buite die workload; groepeer ontplooiingsjablone, rolle, omgewingsleutels en front-tot-oorsprong-verhoudings.

### Diversiteit van privaatheidslae

’n Operasie kan doelbewus ’n enkele homogene ketting vermy: byvoorbeeld, een kanaal gebruik ’n gehuurde aflos, taakdata gebruik ’n openbare objek, ’n uitgang kom van ’n besitde laboratoriumsellulêre skakel, en administrasie gebruik ’n aparte organisasienetwerk. Dit verminder die waarde daarvan om een verskaffer te kompromitteer, maar verhoog die risiko van tydsberekening wat lae oorbrug en operasionele foute.

**Opsporing:** bou veldtogtydlyne oor identiteits-, DNS-, SaaS-, netwerk- en wolksensors. Soek na gesinchroniseerde statusoorgange eerder as identiese aanwysers.

### Gedesentraliseerde dead drops of dead drops in deursigtigheidslogboeke

’n Akteur kan ’n klein geënkripteerde aanwyser in enige blywende openbare stelsel wat slegs byvoeg, inhoudsadresseerbare berging of deursigtigheidsagtige toevoer plaas. Die openbare objek is veerkragtig, maar sy presiese indeks/inhoud-hash en die kliënt se pollinggedrag word stabiele identifiseerders.

**Opsporing:** teken volledige API-/objekidentifiseerders en antwoord-hashes aan; waarsku oor nie-standaardprosesse wat onveranderlike objekte poll, gevolg deur dekodering of nuwe verbindings.

### Vertraagde store-and-forward-operasies

Interaktiewe C2 skep sterk tydskorrelasie. ’n Store-and-forward-ontwerp bondel geënkripteerde take en stuur resultate minute of ure later terug deur ’n ander tou of fisiese oordrag. Dit offer reaksiespoed op vir swakker end-tot-end-tydskorrelasie.

**Opsporing:** verleng korrelasievensters, modelleer periodieke tou-toegang en ondersoek endpoint-staging. Groepering verskuif die sein van pakkietydsberekening na geskeduleerde proses-/lêergedrag; dit wis dit nie uit nie.

## Ontwerphersiening: dink in waarnemers

Vul hierdie tabel vir elke roete in voor ontplooiing en ná data-insameling:

| Laag | Sien bron? | Sien bestemming? | Sien inhoud? | Stabiele identifiseerders | Bewaring/wetlike eienaar |
|---|---:|---:|---:|---|---|
| plaaslike netwerk/diensverskaffer | | | | | |
| toegangsdiens | | | | | |
| roeteerder(s) | | | | | |
| uitgang/redirector/CDN | | | | | |
| gesaghebbende DNS/registrateur | | | | | |
| teiken | | | | | |
| rekening-/betaalverskaffer | | | | | |

As een gewone verskaffer elke kolom kan invul, bied die argitektuur verberging teenoor die teiken, maar nie robuuste skeiding nie. As geen interne beheerder aktiwiteit aan ’n opdrag kan koppel nie, is dit ongeskik vir professionele red teaming.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), and Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Disrupting the World's Largest Residential Proxy Network](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign Targets Iraqi Infrastructure](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI Built the Overlays. Victims Lose their PINs](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Tricks from the Past Deployed via Signed ChatGPT and Claude Binaries](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
