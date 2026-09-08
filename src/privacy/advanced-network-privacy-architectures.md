# Gevorderde netwerkprivaatheidsargitekture

Kompleksiteit is slegs nuttig wanneer dit 'n spesifieke waarnemer of faalmodus verwyder. 'n Unieke tunnel stack, pasgemaakte pakkievorm, seldsame user agent of infrastruktuur wat gereeld roteer, kan 'n sterker fingerprint word as 'n standaardkonfigurasie wat deur duisende mense gebruik word.

Die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) verskaf die algemene `Pros`/`Cons`/`Procedure`/`Detection`-skema. Hierdie bladsy brei die meer komplekse argitekture en vertrouensgrense uit.

Die gevorderde doel is dus **skeiding van kennis**: geen gewone komponent behoort gelyktydig die gebruiker se identiteit, bestemming, plaintext en langtermynaktiwiteitsgeskiedenis te besit nie. Dit is nie onsigbaarheid nie, en samespanning, regsprosesse, endpoint-kompromittering of end-to-end-verkeerskorrelasie kan steeds die pad rekonstrueer.

## Argitektuurkeuse

| Patroon | Verkrygde eienskap | Nuwe vertroue/faling | Geskikte gebruik |
|---|---|---|---|
| Standard Tor Browser | Gedeelde browser-fingerprint en multi-relay-pad | Lae latency maak verkeerskorrelasie moontlik | Algemene anonieme webblaai |
| Tor bridge + pluggable transport | Maak direkte Tor-blokkering/klassifikasie moeiliker | Bridge/transport kan steeds opgespoor word; bridge leer die bron | Gesensureerde netwerke |
| Onion service | Verberg service-IP; vermy exit; autentiseer onion-identiteit | Onion-sleutel en server-endpoint word kritieke bates | Private publisering, ontvangs of administrasie |
| Independent ingress + egress relays | Geen enkele relay sien normaalweg die bron en bestemming nie | Operators kan saamsweer; tydsberekening kruis albei | Hoëprestasie-ondersteunde toepassings |
| Oblivious HTTP | Skei bron-IP van geënkripteerde stateless HTTP-request | Vereis ondersteuning van die toepassing, relay en gateway | Telemetrie, navrae en voorleggings sonder session state |
| VPN-only workload namespace | Kernel-afgedwonge afwesigheid van 'n clear-network-roete | VPN sien steeds albei kante; host/root bly vertrou | Gemagtigde engagement-tools en vaste egress |
| Disposable remote browser | Bestemming word van die plaaslike browser/endpoint geïsoleer | Workspace-provider sien aktiwiteit en login-identiteit | Onvertroude sites/lêers en beheerde navorsing |
| I2P internal service | Afsonderlike inkomende/uitgaande overlay-tunnels; geen amptelike exits nie | Kleiner/andersoortige ekosisteem; langlopende peer-gedrag | Dienste wat oorspronklik vir I2P is, nie as gewone webvervanging nie |
| Mixnet/asynchronous delivery | Vertraging, batching en cover traffic bied weerstand teen tydsberekeningsanalise | Hoë latency, beperkte toepassings en volwassenheid | Boodskappe/take wat nie interaksie benodig nie |

## Relays met gesplete kennis

'n Relay-patroon met twee operators kan 'n enkele VPN vir 'n eng toepassing oortref:
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
Apple Private Relay is 'n ontplooide voorbeeld: Apple bedryf die ingress terwyl 'n ander inhoudverskaffer die egress bedryf, sodat geen van die twee normaalweg beide die kliënt-IP en blaaibestemming sien nie.<sup>[[1]](#references)</sup> Dit is 'n produkspesifieke Safari/DNS-privaatheidsdiens, nie 'n anonymity network vir alle toestelle nie, en dit behou doelbewus 'n growwe streek.

Oblivious HTTP (OHTTP) standaardiseer 'n nouer toepassingspatroon. Die relay sien die kliënt en geënkripteerde gateway-verkeer; die gateway dekripteer die HTTP-boodskap, maar sien die relay, nie die kliënt nie. RFC 9458 waarsku dat dit gewillige relay/gateway-ondersteuning vereis, die beste geskik is vir versoeke sonder cookies/authentication/session state, en verkeersanalise van sy waarborge uitsluit.<sup>[[2]](#references)</sup>

### Ontwerp-kontrolelys

1. Definieer die presiese toepassingsboodskappe wat beskerm moet word; moenie outomaties arbitrêre geauthentiseerde websessies proxy nie.
2. Gebruik onafhanklik bedryfde ingress- en egress-organisasies met afsonderlike administrasie, credentials, logging en wetlike beheer waar moontlik.
3. Enkripteer die toepassingsversoek na die gateway sodat die ingress dit nie kan lees nie.
4. Verwyder kliënt-afgeleide forwarding headers, TLS-identifiseerders en stabiele per-gebruiker-tokens by die toepaslike laag.
5. Vermy unieke keys, cookies of payload-velde wat die gateway in staat stel om versoeke weer te koppel ondanks vervoerskeiding.
6. Aggregeer, minimaliseer en laat logs aan beide kante verval; dokumenteer die risiko van samespanning en gedwonge openbaarmaking.
7. Pad of batch slegs volgens 'n hersiene protokol. Selfgemaakte traffic shaping kan 'n unieke signature skep sonder om korrelasie te stop.
8. Toets met beheerde canary-versoeke en vergelyk wat die kliënt, ingress, gateway en teiken elk aanteken.

Vir gewone interaktiewe blaai, gebruik Tor Browser eerder as om 'n private OHTTP-proxy uit te dink. OHTTP beskerm 'n ondersteunde toepassingstransaksie, nie 'n volledige blaaieridentiteit nie.

## Dwing die roete per workload af

'n Kill switch wat slegs op veranderlike host-roetes gebaseer is, kan tydens DHCP-vernuwing, slaap/wek, IPv6-veranderings of 'n tunnel-crash misluk. 'n Sterker Linux-patroon gee aan 'n container of network namespace slegs 'n loopback-interface en 'n tunnel-interface. WireGuard dokumenteer dat 'n interface in 'n fisiese namespace geskep, na 'n workload-namespace verskuif en sy geënkripteerde UDP-socket in die oorspronklike namespace behou kan word.<sup>[[3]](#references)</sup>

### Ontplooiingspatroon

1. Bou dit eers op 'n weggooibare/lokale-console-host; namespace-foute kan afstandtoegang verwyder.
2. Plaas die fisiese Ethernet/Wi-Fi-interface en DHCP/supplicant in 'n **physical** namespace.
3. Skep die WireGuard-interface daar sodat sy geënkripteerde transportsocket toegang tot die fisiese netwerk het.
4. Verskuif slegs die WireGuard-interface na die **workload** namespace en maak dit die enigste verstekroete.
5. Gee die workload 'n namespace-spesifieke resolver wat slegs deur die tunnel bereikbaar is. Rekening moet uitdruklik met IPv6 gehou word.
6. Begin die blaaier/tool-container in daardie namespace sonder host networking, privileged capability, gedeelde blaaiergids of persoonlike credential-agent.
7. Stop die tunnel en verifieer dat die workload nie 'n beheerde IPv4- of IPv6-endpoint kan resolve of verbind nie.
8. Toets endpoint-roaming, DHCP-vernuwing, suspend/resume en captive-portal-hantering buite die workload-namespace.
9. Log die namespace/tunnel-konfigurasie-hash en goedgekeurde egress-adres vir engagement-aanspreeklikheid.

Dit bied **route enforcement**, nie anonymity teenoor die VPN of engagement-bastion nie. 'n Gekompromitteerde host/root kan namespaces inspekteer of verander.

## Tor bridges en pluggable transports

Bridges is nie-openbare Tor-entry-relays. Pluggable transports verander die eerstesprong-verkeer sodat eenvoudige blokkering of protokolklassifikasie moeiliker is. Hulle voeg nie anonieme relay-lae ná entry by nie en verydel nie 'n observator wat breër tydsberekeningskorrelasie kan uitvoer nie.

| Transport | Eerstesprong-benadering | Praktiese afweging |
|---|---|---|
| **obfs4** | Laat verkeer ewekansig lyk en weerstaan aktiewe probing | 'n Bekende bridge-adres kan steeds geblokkeer word |
| **Snowflake** | Gebruik kortlewende vrywilliger-WebRTC-proxies om 'n bridge te bereik | Werkverrigting wissel; broker/STUN/WebRTC-patrone bestaan |
| **WebTunnel** | Dra bridge-verkeer in 'n HTTPS-agtige WebSocket-tunnel | Hang af van 'n bereikbare web-front en kan steeds geklassifiseer word |

Die Tor Project beskryf Snowflake en WebTunnel as transports vir sensuur-omseiling, nie perfekte ononderskeibaarheid nie.<sup>[[4]](#references)</sup>

### Veilige werkvloei

1. Begin met Tor Browser se direkte verbinding. Voeg slegs 'n bridge by wanneer blokkering of sigbaarheid in die plaaslike observatormodel dit regverdig.
2. Gebruik ingeboude transports of bridge-lyne wat deur Tor Project-kanale verkry is. Moenie ewekansige transport-binaries of openbare bridge-lyste van forums aflaai nie.
3. Probeer die minste komplekse ondersteunde opsie wat betroubaar verbind; teken aan waarom dit gekies is.
4. Hou Tor Browser andersins standaard. 'n Bridge maak pasgemaakte extensions, account-logins of ongewone blaaierinstellings nie veilig nie.
5. Toets reconnect en klokkorrektheid. Moenie transports herhaaldelik siklus op 'n manier wat 'n kenmerkende reeks na dieselfde plaaslike observator stuur nie.
6. Herassesseer indien die censor of netwerkbeleid verander; gebruik kan self sensitief of beperk wees in sommige liggings.

## Onion services as 'n private rendezvous

'n Onion service maak uitgaande Tor-circuits na introduction points en rendezvous-relays, sodat dit geen openbare inbound port nodig het nie en nie sy server-IP deur die onion-protokol blootstel nie. Kliënt-na-diens-verkeer bly binne Tor en die onion-adres authentiseer die dienskey.<sup>[[5]](#references)</sup>

Vir 'n wettige intake portal, private repository, administratiewe interface of engagement evidence drop:

1. Begin die toepassing op 'n toegewyde host/VM en bind dit aan loopback of 'n geïsoleerde Unix-socket.
2. Installeer Tor vanaf sy amptelike repository en volg die amptelike v3 onion-service-opstelling; gebruik nooit verouderde v2-instruksies nie.
3. Beskerm die onion service private key soos 'n TLS/signing key. Rugsteun dit slegs indien stabiele identiteit vereis word.
4. Voeg onion-service client authorization vir 'n geslote groep by en lewer credentials oor 'n onafhanklik geauthentiseerde kanaal.<sup>[[6]](#references)</sup>
5. Verhoed dat die origin derdeparty-fonts, analytics, updates of webhooks ophaal wat sy openbare IP of operator-account openbaar.
6. Plaas authentication en authorization ook in die toepassing; besit van die onion-adres is nie toegangsbeheer nie.
7. Patch, rate-limit en monitor die diens sonder om derdeparty-telemetry in te bed.
8. Bevestig vanuit 'n afsonderlike toetskonteks dat DNS, e-pos, foutbladsye, lêermetadata en response headers nie die origin openbaar nie.
9. Lys vir red-team-gebruik die diens, eienaar, doel en afskakelingstyd in die ROE. Moenie dit gebruik om C2 buite die omvang te verberg nie.

## Remote browser en disposable workspace

'n Remote browser verskuif rendering en riskante inhoud weg van die plaaslike endpoint en kan 'n engagement-spesifieke cloud-egress aanbied. Dit beskerm die plaaslike toestel teen sommige inhoud en persistence; dit maak die operator nie anoniem teenoor die workspace-verskaffer nie. AWS dokumenteer byvoorbeeld die insameling van portal-, identity-, policy-, preference- en session-log-data, selfs al word die disposable browser-instance aan die einde van die sessie weggegooi.<sup>[[7]](#references)</sup>

Gebruik een organisasie-beheerde workspace per engagement, beperk downloads/uploads/clipboard, deaktiveer persoonlike identity providers, stuur sy vaste egress deur die goedgekeurde bastion, en laat die workspace verval ná evidence-export. Behandel die verskaffer se console, IdP en administrator as observators.

## I2P en interne overlays

I2P bou afsonderlike eenrigting-inbound- en outbound-tunnels en het geen amptelike network-layer exits nie; dit is hoofsaaklik vir dienste binne I2P.<sup>[[8]](#references)</sup> Dit is nie 'n direkte, vinniger manier om die openbare Internet te browse nie. Outproxies stel 'n trust point bekend, en die amptelike threat model vra uitdruklik vir meer navorsing en beweer nie perfekte anonymity nie.

Gebruik I2P slegs wanneer beide kante dit doelbewus ondersteun, isoleer sy langdurige router van persoonlike toepassings, en verstaan dat peers/lokale netwerke I2P-deelname kan waarneem. Moenie hop counts verhoog of peer selection instel sonder bewyse nie: ongewone instellings kan werkverrigting verlaag en die anonymity set verklein.

## Korrelasie-bestande bedrywighede

- Verkies 'n algemene, ondersteunde kliëntkonfigurasie bo 'n unieke build.
- Skeí identiteite by die endpoint; geen routing topology herstel account-, payment-, recovery- of content-reuse nie.
- Vir nie-interaktiewe take, verkies 'n hersiene asynchronous protocol/mixnet bo die handmatige byvoeging van sleeps of fake traffic.
- Vermy die bedryf van veronderstelde afsonderlike identiteite in 'n gesinchroniseerde patroon vanuit dieselfde fisiese konteks.
- Gebruik 'n eenrigting-export gate: onbetroubare inhoud gaan 'n disposable renderer binne; slegs 'n hersiene, gesaniteerde resultaat verlaat dit.
- Hou clocks korrek vir protokol-sekuriteit, maar verwyder onnodige presiese timestamps uit gepubliseerde artefakte.
- Minimaliseer sessieduur en verouderde infrastruktuur sonder vinnige “fast-flux”-rotasie, wat opvallend is en aanspreeklikheid skaad.

## Tegnieke wat nie-onbetrokke derde partye kan gebruik nie

Hierdie is egte adversary-tegnieke, nie denkbeeldige of onbelangrike tegnieke nie. Die meganika en opsporing daarvan word gedek in [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md), en die [APT case studies](government-and-apt-case-studies.md). Reproduseer tydens 'n gemagtigde oefening hul waarneembare gedrag met besitlike plaasvervangers:

- model residential/mobile exit churn met beheerde relay pools, nooit markte met onduidelike toestemming nie;
- model open proxies, compromised routers en botnets met besitlike VMs/routers;
- model stolen cloud accounts met 'n aangewese exercise tenant en sintetiese victim identity;
- model domain fronting op 'n besitlike reverse proxy eerder as 'n onwillige CDN;
- model third-party Wi-Fi met twee geïsoleerde APs wat deur die lab besit word;
- behandel custom encryption, multi-VPN chains en identifier rotation as toetshipoteses waarvan die flow-, account- en endpoint-artefakte steeds detecteerbaar bly.

Vir 'n gemagtigde red team moet enige poging om verkeer minder herkenbaar te maak 'n uitdruklike detection objective in die ROE wees, 'n attribution map hê wat deur die controller gehou word, en 'n stop/deconfliction-meganisme insluit.

## Verifikasiematriks

| Toets | Verwagte resultaat | Mislukking beteken |
|---|---|---|
| Tunnel/bridge gestop | Workload het geen direkte IPv4/IPv6/DNS-pad nie | Route enforcement is onvolledig |
| Teikenlog geïnspekteer | Slegs beplande egress/application identity verskyn | Header-, roete- of account leak |
| Ingress-log geïnspekteer | Bron teenwoordig; duidelike teiken/versoek afwesig | Trust split het by ingress misluk |
| Egress-log geïnspekteer | Relay/versoek teenwoordig; bronidentiteit afwesig | Trust split het by egress misluk |
| Onion-origin ekstern geskandeer | Geen openbare origin-diens is bereikbaar/gekoppel nie | Origin het geleak of is dual-homed |
| Disposable session beëindig | Instance state weg; goedgekeurde evidence afsonderlik behou | Persistence boundary het misluk |
| Controller lookup uitgevoer | Aktiwiteit word vinnig aan engagement/operator gekoppel | Red-team-aanspreeklikheid het misluk |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
