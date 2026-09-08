# Gevorderde netwerkprivaatheidsargitekture

{{#include ../banners/hacktricks-training.md}}

Kompleksiteit is slegs nuttig wanneer dit 'n spesifieke waarnemer of foutmodus verwyder. 'n Unieke tunnel stack, pasgemaakte pakkietipe, seldsame user agent of infrastruktuur wat gereeld roteer, kan 'n sterker fingerprint word as 'n standaardkonfigurasie wat deur duisende mense gebruik word.

Die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) verskaf die algemene `Pros`/`Cons`/`Procedure`/`Detection`-skema. Hierdie bladsy brei die meer komplekse argitekture en trust boundaries uit.

Die gevorderde doel is dus **skeiding van kennis**: geen gewone komponent behoort terselfdertyd die gebruikeridentiteit, bestemming, plaintext en langtermynaktiwiteitsgeskiedenis te besit nie. Dit is nie onsigbaarheid nie, en collusion, legal process, endpoint compromise of end-to-end traffic correlation kan steeds die pad rekonstrueer.

## Argitektuurkeuse

| Patroon | Eienskap verkry | Nuwe trust/foutmodus | Geskikte gebruik |
|---|---|---|---|
| Standard Tor Browser | Gedeelde browser fingerprint en multi-relay-pad | Lae latency laat traffic correlation toe | Algemene anonieme webblaai |
| Tor bridge + pluggable transport | Maak direkte Tor-blokkering/klassifikasie moeiliker | Bridge/transport kan steeds opgespoor word; bridge leer die bron | Gecensureerde netwerke |
| Onion service | Verberg service IP; vermy exit; verifieer onion-identiteit | Onion key en server endpoint word kritieke bates | Private publikasie, intake of administrasie |
| Independent ingress + egress relays | Geen enkele relay sien normaalweg die bron en bestemming nie | Operators kan collude; timing kruis albei | Hoëprestasie-toepassings met ondersteuning |
| Oblivious HTTP | Skei source IP van encrypted stateless HTTP request | Vereis application-, relay- en gateway-ondersteuning | Telemetry, queries en submissions sonder session state |
| VPN-only workload namespace | Kernel-afgedwonge afwesigheid van 'n clear-network-roete | VPN sien steeds albei kante; host/root bly trusted | Gemagtigde engagement tools en vaste egress |
| Disposable remote browser | Bestemming word van die plaaslike browser/endpoint geïsoleer | Workspace-provider sien aktiwiteit en login-identiteit | Untrusted sites/files en beheerde navorsing |
| I2P internal service | Afsonderlike inbound/outbound overlay tunnels; geen amptelike exits nie | Kleiner/andersoortige ekosisteem; langdurige peer-gedrag | Dienste wat native aan I2P is, nie gewone webvervanging nie |
| Mixnet/asynchronous delivery | Vertraging, batching en cover traffic weerstaan timing analysis | Hoë latency, beperkte toepassings en volwassenheid | Boodskappe/take wat nie interaksie benodig nie |

## Split-knowledge relays

'n Two-operator relay-patroon kan 'n enkele VPN vir 'n beperkte toepassing oortref:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay is 'n ontplooide voorbeeld: Apple bedryf die ingress, terwyl 'n ander inhoudverskaffer die egress bedryf, sodat geen van hulle normaalweg beide die kliënt-IP en blaaibestemming sien nie.<sup>[[1]](#references)</sup> Dit is 'n produkspesifieke Safari/DNS-privaatheidsdiens, nie 'n anonimiteitsnetwerk vir alle toestelle nie, en dit behou doelbewus 'n growwe streek.

Oblivious HTTP (OHTTP) standardiseer 'n enger toepassingspatroon. Die relay sien die kliënt en geënkripteerde gateway-verkeer; die gateway dekripteer die HTTP-boodskap, maar sien die relay, nie die kliënt nie. RFC 9458 waarsku dat dit gewillige relay/gateway-ondersteuning vereis, die beste geskik is vir versoeke sonder koekies/verifikasie/sessietoestand, en verkeersanalise van sy waarborge uitsluit.<sup>[[2]](#references)</sup>

### Ontwerp-kontrolelys

1. Definieer die presiese toepassingsboodskappe wat beskerm moet word; moenie arbitrêre geverifieerde websessies stilweg proxy nie.
2. Gebruik onafhanklik bedryfde ingress- en egress-organisasies met afsonderlike administrasie, geloofsbriewe, logging en regsbeheer waar moontlik.
3. Enkripteer die toepassingsversoek na die gateway sodat die ingress dit nie kan lees nie.
4. Verwyder kliënt-afgeleide forwarding headers, TLS-identifiseerders en stabiele per-gebruiker-tokens by die toepaslike laag.
5. Vermy unieke sleutels, koekies of loonvragvelde wat die gateway in staat stel om versoeke weer te koppel ondanks vervoerskeiding.
6. Aggregateer, minimaliseer en laat logs aan beide kante verval; dokumenteer samespannings- en gedwonge-openbaarmakingsrisiko.
7. Pad of bondel slegs volgens 'n hersiene protokol. Tuisgemaakte verkeersvorming kan 'n unieke handtekening skep sonder om korrelasie te stop.
8. Toets met beheerde kanarieversoeke en vergelyk wat die kliënt, ingress, gateway en teiken elk aanteken.

Vir gewone interaktiewe blaai, gebruik Tor Browser eerder as om 'n private OHTTP-proxy uit te dink. OHTTP beskerm 'n ondersteunde toepassingstransaksie, nie 'n volledige blaaieridentiteit nie.

## Dwing die roete per werklading af

'n Kill switch wat slegs op veranderlike gasheerroetes gebaseer is, kan misluk tydens DHCP-hernuwing, slaap/ontwaking, IPv6-veranderinge of 'n tonnelongeluk. 'n Sterker Linux-patroon gee 'n container of network namespace slegs 'n loopback-koppelvlak en 'n tonnelkoppelvlak. WireGuard dokumenteer dat 'n koppelvlak in 'n fisiese namespace geskep, na 'n werklading-namespace verskuif, en sy geënkripteerde UDP-sok in die oorspronklike namespace behou kan word.<sup>[[3]](#references)</sup>

### Ontplooiingspatroon

1. Bou dit eers op 'n weggooibare/lokale-konsole-gasheer; namespace-foute kan afstandstoegang verwyder.
2. Plaas die fisiese Ethernet/Wi-Fi-koppelvlak en DHCP/supplicant in 'n **fisiese** namespace.
3. Skep die WireGuard-koppelvlak daar sodat sy geënkripteerde vervoersok toegang tot die fisiese netwerk het.
4. Verskuif slegs die WireGuard-koppelvlak na die **werklading**-namespace en maak dit die enigste verstekroete.
5. Gee die werklading 'n namespace-spesifieke resolver wat slegs deur die tonnel bereikbaar is. Hanteer IPv6 uitdruklik.
6. Begin die blaaier/tool-container in daardie namespace sonder gasheernetwerk, bevoorregte vermoë, gedeelde blaaiergids of persoonlike geloofsbriefagent.
7. Stop die tonnel en verifieer dat die werklading nie 'n beheerde IPv4- of IPv6-eindpunt kan resolve of bereik nie.
8. Toets eindpunt-roaming, DHCP-hernuwing, suspend/resume en captive-portal-hantering buite die werklading-namespace.
9. Teken die namespace/tonnel-konfigurasiehash en goedgekeurde egress-adres aan vir engagement-aanspreeklikheid.

Dit bied **roeteafdwinging**, nie anonimiteit teenoor die VPN of engagement-bastion nie. 'n Gekompromitteerde gasheer/root kan namespaces inspekteer of verander.

## Tor bridges en pluggable transports

Bridges is nie-openbare Tor-ingangsrelays. Pluggable transports verander die eerstesprong-verkeer sodat eenvoudige blokkering of protokolklassifikasie moeiliker is. Hulle voeg nie anonieme relay-lae ná toegang by nie en verydel nie 'n waarnemer wat tot breër tydsberekeningskorrelasie in staat is nie.

| Transport | Eerstesprong-benadering | Praktiese afweging |
|---|---|---|
| **obfs4** | Laat verkeer ewekansig lyk en weerstaan aktiewe probing | 'n Bekende bridge-adres kan steeds geblokkeer word |
| **Snowflake** | Gebruik kortlewende vrywilliger-WebRTC-proxies om 'n bridge te bereik | Werkverrigting wissel; broker/STUN/WebRTC-patrone bestaan |
| **WebTunnel** | Dra bridge-verkeer in 'n HTTPS-agtige WebSocket-tonnel | Hang van 'n bereikbare web-front af en kan steeds geklassifiseer word |

The Tor Project beskryf Snowflake en WebTunnel as sensuur-omseilingstransporte, nie perfekte ononderskeibaarheid nie.<sup>[[4]](#references)</sup>

### Veilige werksvloei

1. Begin met Tor Browser se direkte verbinding. Voeg slegs 'n bridge by wanneer blokkering of sigbaarheid in die plaaslike waarnemermodel dit regverdig.
2. Gebruik ingeboude transporte of bridge-lyne wat deur Tor Project-kanale verkry is. Moenie ewekansige transportbinaries of openbare bronlyste van forums aflaai nie.
3. Probeer die mins komplekse ondersteunde opsie wat betroubaar verbind; teken aan waarom dit gekies is.
4. Hou Tor Browser andersins standaard. 'n Bridge maak pasgemaakte uitbreidings, rekeningaanmeldings of ongewone blaaierinstellings nie veilig nie.
5. Toets herverbinding en klokkorrektheid. Moenie transporte herhaaldelik roteer op 'n manier wat 'n kenmerkende volgorde aan dieselfde plaaslike waarnemer stuur nie.
6. Herassesseer indien die sensuur- of netwerkbeleid verander; gebruik kan self sensitief of op sommige plekke beperk wees.

## Onion services as 'n private ontmoetingspunt

'n Onion service maak uitgaande Tor-kringe na bekendstellingspunte en rendezvous-relays, dus benodig dit geen openbare inkomende poort nie en stel dit nie sy bediener-IP deur die onion-protokol bloot nie. Kliënt-na-diens-verkeer bly binne Tor en die onion-adres verifieer die dienssleutel.<sup>[[5]](#references)</sup>

Vir 'n wettige intake-portaal, private repository, administratiewe koppelvlak of engagement-bewysaflaaipunt:

1. Begin die toepassing op 'n toegewyde gasheer/VM en bind dit aan loopback of 'n geïsoleerde Unix-sok.
2. Installeer Tor vanaf sy amptelike repository en volg die amptelike v3 onion-service-opstelling; gebruik nooit verouderde v2-instruksies nie.
3. Beskerm die onion service se private sleutel soos 'n TLS/signing key. Rugsteun dit slegs indien stabiele identiteit vereis word.
4. Voeg onion-service-kliëntmagtiging vir 'n geslote groep by en lewer geloofsbriewe oor 'n onafhanklik geverifieerde kanaal.<sup>[[6]](#references)</sup>
5. Verhoed dat die oorsprong derdeparty-lettertipes, analytics, opdaterings of webhooks gaan haal wat sy openbare IP of operateurrekening openbaar.
6. Plaas verifikasie en magtiging ook in die toepassing; besit van die onion-adres is nie toegangsbeheer nie.
7. Bring pleisters aan, beperk tempo en monitor die diens sonder om derdeparty-telemetrie in te bed.
8. Bevestig vanuit 'n aparte toetskonteks dat DNS, e-pos, foutbladsye, lêermetadata en response headers nie die oorsprong openbaar nie.
9. Vir red-team-gebruik, lys die diens, eienaar, doel en afskakelingstyd in die ROE. Moenie dit gebruik om buite-omvang C2 te verberg nie.

## Remote browser en weggooibare werksruimte

'n Remote browser verskuif rendering en riskante inhoud weg van die plaaslike eindpunt en kan 'n engagement-spesifieke cloud-egress aanbied. Dit beskerm die plaaslike toestel teen sommige inhoud en volharding; dit maak die operateur nie anoniem teenoor die werksruimteverskaffer nie. AWS dokumenteer byvoorbeeld die insameling van portaal-, identiteit-, beleid-, voorkeur- en sessielogdata, selfs al word die weggooibare blaaierinstansie aan die einde van die sessie weggegooi.<sup>[[7]](#references)</sup>

Gebruik een organisasiebeheerde werksruimte per engagement, beperk aflaaie/oplaaie/knipbord, deaktiveer persoonlike identiteitsverskaffers, stuur sy vaste egress deur die goedgekeurde bastion, en laat die werksruimte verval nadat bewyse uitgevoer is. Behandel die verskafferkonsole, IdP en administrateur as waarnemers.

## I2P en interne overlays

I2P bou afsonderlike eenrigting-in- en uitgaand-tonnels en het geen amptelike netwerklaag-egresse nie; dit is hoofsaaklik vir dienste binne I2P.<sup>[[8]](#references)</sup> Dit is nie 'n direkte, vinniger manier om die openbare Internet te blaai nie. Outproxies voeg 'n vertrouenspunt by, en die amptelike bedreigingsmodel vra uitdruklik vir meer navorsing en beweer nie perfekte anonimiteit nie.

Gebruik I2P slegs wanneer beide kante dit doelbewus ondersteun, isoleer sy langdurige router van persoonlike toepassings, en verstaan dat peers/plaaslike netwerke I2P-deelname kan waarneem. Moenie hop-tellings verhoog of peer-seleksie instel sonder bewyse nie: ongewone instellings kan werkverrigting verminder en die anonimiteitsstel verklein.

## Korrelasiebestande bedrywighede

- Verkies 'n algemene, ondersteunde kliëntkonfigurasie bo 'n unieke bou.
- Skei identiteite by die eindpunt; geen roeteringstopologie herstel rekening-, betaling-, herstel- of inhoudhergebruik nie.
- Vir nie-interaktiewe take, verkies 'n hersiene asynchrone protokol/mixnet bo die handmatige byvoeging van sleeps of vals verkeer.
- Vermy die bedryf van sogenaamd geskeide identiteite in 'n gesinchroniseerde patroon vanuit dieselfde fisiese konteks.
- Gebruik 'n eenrigting-uitvoerpunt: onbetroubare inhoud gaan 'n weggooibare renderer binne; slegs 'n hersiene, gesuiwerde resultaat gaan uit.
- Hou horlosies korrek vir protokolsekuriteit, maar verwyder onnodige presiese tydstempels uit gepubliseerde artefakte.
- Minimaliseer sessieduur en verouderde infrastruktuur sonder vinnige “fast-flux”-rotasie, wat opvallend is en aanspreeklikheid benadeel.

## Tegnieke wat nie-onbetrokke derde partye kan gebruik

Hierdie is egte adversary-tegnieke, nie denkbeeldige of onbelangrike tegnieke nie. Die meganika en opsporing daarvan word gedek in [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md), en die [APT case studies](government-and-apt-case-studies.md). Reproduseer tydens 'n gemagtigde oefening hul waarneembare gedrag met besitlike plaasvervangers:

- modelleer residential/mobile exit churn met beheerde relay-poele, nooit markte met onduidelike toestemming nie;
- modelleer open proxies, gekompromitteerde routers en botnets met besitlike VM's/routers;
- modelleer gesteelde cloud-rekeninge met 'n aangewese oefentenant en sintetiese slagofferidentiteit;
- modelleer domain fronting op 'n besitlike reverse proxy eerder as 'n onwillige CDN;
- modelleer derdeparty-Wi-Fi met twee geïsoleerde AP's wat deur die laboratorium besit word;
- behandel custom encryption, multi-VPN chains en identifier rotation as toetshipoteses waarvan die vloei-, rekening- en eindpuntartefakte steeds opspoorbaar bly.

Vir 'n gemagtigde red team moet enige poging om verkeer minder herkenbaar te maak 'n eksplisiete opsporingsdoelwit in die ROE wees, 'n attributiekaart hê wat deur die beheerder gehou word, en 'n stop/deconfliction-meganisme insluit.

## Verifikasiematriks

| Toets | Verwagte resultaat | Mislukking beteken |
|---|---|---|
| Tonnel/bridge gestop | Werklading het geen direkte IPv4/IPv6/DNS-pad nie | Roeteafdwinging is onvolledig |
| Teikenlog geïnspekteer | Slegs beplande egress/toepassingsidentiteit verskyn | Header-, roete- of rekening-leak |
| Ingress-log geïnspekteer | Bron teenwoordig; duidelike teiken/versoek afwesig | Vertrouenskeiding het by ingress misluk |
| Egress-log geïnspekteer | Relay/versoek teenwoordig; bronidentiteit afwesig | Vertrouenskeiding het by egress misluk |
| Onion-oorsprong ekstern geskandeer | Geen openbare oorsprongdiens is bereikbaar/gekoppel nie | Oorsprong het geleak of is dual-homed |
| Weggooibare sessie beëindig | Instanstoestand weg; goedgekeurde bewyse afsonderlik behou | Volhardingsgrens het misluk |
| Beheerder-opsoek uitgevoer | Aktiwiteit karteer onmiddellik na engagement/operateur | Red-team-aanspreeklikheid het misluk |

## References

- [1] [Apple Platform Security — iCloud Private Relay-sekuriteit](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Roetering en Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake en pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Hoe Onion Services werk](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Gevorderde Onion Service-instellings en kliëntmagtiging](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data-enkripsie in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Bedreigingsmodel](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
