# Reproduseerbare privaatheidstoetsing

'n Privaatheidsopstelling is nie afgehandel wanneer dit verbind nie. Dit is afgehandel wanneer die beweerde grens daarvan tydens normale gebruik, faling, herstel en afbreek getoets is. Toets teen infrastruktuur wat jy besit of waarvoor jy gemagtig is om dit te inspekteer; openbare “leak test”-werwe word nog 'n waarnemer.

## Bou 'n klein gemagtigde toetsomgewing

Gebruik drie rolle, ideaal gesproke op afsonderlike verskaffers/netwerke:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Teken vóór elke toets aan:

- toets-ID, UTC-begin/eind, operateur en magtiging;
- endpoint-/OS-/client-weergawes en konfigurasie-hash;
- verwagte IPv4-, IPv6-, DNS-, TLS-, account-, betalings- en fisiese waarnemings;
- watter logs geïnspekteer sal word en hul horlosies/tydsones;
- slaag/misluk-reël en opruimingstyd.

Moet nooit eerste met ’n sensitiewe identiteit toets nie. Gebruik ’n sintetiese account en onskadelike, unieke canary-waardes wat deur die tester besit word.

## Netwerkpad-toets

### 1. Teken die basislyn aan

Teken plaaslike roetes en resolvers aan voordat die privaatheidspad geaktiveer word:
```bash
ip route
ip -6 route
resolvectl status
```
Gebruik op macOS `route -n get default`, `netstat -rn -f inet6` en `scutil --dns`. Stoor die uitvoer slegs in die beheerste bewysbewaarplek; dit kan plaaslike identifiseerders bevat.

### 2. Koppel en inspekteer roetering

Aktiveer die VPN/Tor/werkladingsnaamruimte en kontroleer dan die roete wat vir beheerde publieke adresse gekies is:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Vervang dokumentasieadresse met die toetsbedieneradresse. Bevestig dat die geselekteerde koppelvlak/tabel met die ontwerp ooreenstem.

### 3. Neem vanaf albei kante waar

Stel die URL van die endpoint wat jy besit, en versoek dan ’n unieke onskadelike pad:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Gebruik ’n domein wat deur die tester beheer word, geauthentiseerde TLS en ’n nie-sensitiewe padtoken. Inspekteer die bedienerlog vir:

- bronadres/ASN en verwagte egress;
- IPv4 teenoor IPv6;
- Host/SNI-gedrag wat by die endpoint sigbaar is;
- user agent en application headers;
- presiese tyd en hergebruik van die request.

Moenie `X-Forwarded-For`, unieke debug headers of identity-bearing cookies by ’n sogenaamd geskeide request voeg nie.

### 4. Toets DNS met ’n canary wat jy besit

Konfigureer ’n authoritative test zone waarvan jy die query logs beheer. Doen ’n navraag na ’n unieke ewekansige label deur die compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Inspekteer die gesaghebbende logboek. Dit sien normaalweg die rekursiewe resolver, nie noodwendig die client nie. Vergelyk daardie resolver met die beoogde VPN/Tor/application DNS-ontwerp. ’n Ewekansige publieke DNS-leak-webwerf word nie vereis nie.

### 5. Toets fail-closed-gedrag

Hou ’n goedaardige aanvraaglus wat op die besit endpoint gemik is, en stop dan die privaatheidspad. Die workload moet faal eerder as om na ’n fisiese koppelvlak oor te skakel. Kontroleer beide adresfamilies en DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Herhaal tydens:

- tunnel-proses-omval;
- Wi-Fi-na-Ethernet- of hotspot-wisseling;
- slaap/wek;
- DHCP-hernuwing;
- captive-portal-toestand;
- provider-herkoppeling/sleutelverval.

Vir ’n Linux namespace/container, stop sy tunnel en verifieer dat dit geen ander standaardroete of resolver het nie:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Name en commands verskil per ontplooiing. Moenie dit na 'n afgeleë production host plak sonder console recovery nie.

### 6. Inspekteer plaaslike sockets en packets

Met magtiging, kontroleer watter process/interface werklik kommunikeer:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Vervang `TEST_SERVER_IP` met die eksplisiete beheerde adres; vermy breë opvangs van onverwante gebruikers. Die fisiese koppelvlak behoort die tunnel/bridge-peer te sien, terwyl duidelike bestemmingsverkeer slegs op die beoogde laag behoort te bestaan.

## Tor- en onion-service-toets

1. Besoek in Tor Browser die Tor Project se verbindingskontrole en bevestig Tor-gebruik. Moenie dit as bewys van identiteit beskou nie.<sup>[[1]](#references)</sup>
2. Besoek die beheerde HTTPS-endpoint met ’n unieke canary en bevestig dat dit ’n Tor-exit sien, geen identifiserende cookies het nie, en die standaard browser-konteks gebruik.
3. Kies **New Identity**, besoek dit weer met ’n ander canary, en verifieer dat plaaslike toestand soos verwag uitgevee is. ’n Verandering van exit-IP word nie gewaarborg nie en is nie die doel van New Identity nie.
4. Vir ’n onion service, verkry slegs toegang daartoe deur Tor Browser. Bevestig met ’n gemagtigde eksterne scan dat die service-host geen publieke listener het nie, en dat application responses geen publieke hostname/IP bevat nie.
5. Inspekteer origin se uitgaande DNS/HTTP, templates, error pages, e-pos/webhooks en third-party assets. Enige direkte fetch kan die origin of operator-account openbaar.
6. Indien client authorization geaktiveer is, bevestig dat ’n ongeauthentiseerde skoon Tor Browser nie kan verbind nie en dat ’n geauthentiseerde een wel kan.
7. Roteer ’n toets-authorization key en bevestig dat die herroepe client toegang verloor sonder om die onion identity te verander.

## Browser-kompartementtoets

Skep ’n beheerde bladsy wat slegs die velde aanteken wat vir die toets benodig word, met ’n kort retention-periode. Vergelyk persoonlike en privacy-kompartemente vir:

- cookies/local storage/service workers en cache;
- browser sync/login state;
- taal, tydsone, skerm-/vensterafmetings en fonts;
- WebRTC/network candidates;
- permissions en extension-visible modifications;
- TLS/HTTP user-agent-data by die server.

Moenie probeer om Tor Browser “meer random” te maak nie. Die slaagvoorwaarde is ooreenkoms met sy standaard anonymity set en die afwesigheid van persoonlike toestand, nie maksimum verskil van die persoonlike browser nie.

Toets copy/paste, drag/drop, die opening van afgelaaide lêers, password-manager-suggestions en identity-provider-buttons. Dit is gereelde brûe tussen kompartemente.

## Bedryfstelsel-isolasietoets

### Tails

1. Begin met ’n onskadelike lêer/canary in ’n session sonder Persistent Storage.
2. Skakel volledig af, herlaai, en bevestig dat dit weg is.
3. Aktiveer slegs een vereiste persistence category, herhaal, en bevestig dat onverwante browser/application state nie behou word nie.
4. Verifieer dat die Unsafe Browser nie ná portal login vir sensitiewe aktiwiteit gebruik kan word nie, en dat Tor applications normaalweg herkoppel.

### Whonix/Qubes

1. Stop die Gateway/net qube en bewys dat die Workstation/app qube nie IPv4, IPv6 of DNS kan bereik nie.
2. Probeer slegs die eksplisiet gekonfigureerde inter-qube clipboard/file path en bevestig dat ander shared-folder/device paths afwesig is.
3. Maak ’n onskadelike toetsdokument in ’n disposable qube oop, maak dit toe, en bevestig dat sy toestand verdwyn.
4. Kontroleer dat die vault qube geen NetVM het nie en nie een deur ’n template/default change kan verkry nie.
5. Neem ’n snapshot van ’n toets-VM, herstel dit, en inspekteer of identity-bearing state onverwags terugkeer.

## Kommunikasiemetadata-toets

Vir elke geselekteerde messenger:

1. Skep slegs vir toetse bedoelde participants op beheerde devices.
2. Teken aan wat registration vereis: phone, app-store account, IP, push service, username of invitation.
3. Stuur een onskadelike boodskap terwyl notification previews, linked desktops, wearables en backups geïnspekteer word.
4. Verifieer safety/security codes oor ’n onafhanklike pad.
5. Deaktiveer receipts/push of aktiveer Tor/local transports een op ’n slag, en neem veranderinge in reliability/metadata waar.
6. Eksporteer of herstel ’n toetsbackup en dokumenteer presies watter profile, contacts en history dit bevat.
7. Verloor/herroep ’n toetsdevice en bevestig dat die oorblywende participants die verwagte key/device change sien.

Moenie toets deur onverwante mense te kontak of abusive traffic te genereer nie.

## Lêer-sanitization-toets

1. Hash en bewaar die oorspronklike in encrypted evidence storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Skep 'n skoongemaakte kopie deur die formaatformaatspesifieke proses in [Privaatheidsbewuste kommunikasie en deling](privacy-preserving-communications-and-sharing.md) te gebruik.
3. Vergelyk metadata-inventarisse:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Gee die kopie weer in ’n weggooibare konteks. Kontroleer verborge inhoud, aanhegsels, skakels, vorms, lae, duimnaels en visuele identifiseerders.
5. Soek slegs in die voorbereide kopie na bekende canary-outeur/e-pos/pad-stringe.
6. Hash die finale uitvoer en laat ’n tweede persoon die presiese lêer wat gepubliseer word, verifieer.

Afwesigheid uit ExifTool-uitvoer is nie bewys van anonimiteit nie; formaatinterne besonderhede, pixels, prosa en verspreidingsrekords bly bestaan.

## Betalingsprivaatheidstoets

Gebruik die kleinste toegelate bedrag of ’n amptelike test network/sandbox:

1. Skryf die verwagte aansig vir die betaler, begunstigde/handelaar, uitreiker/beurs, network/node, publieke grootboek en rekenmeester/beheerder.
2. Skep ’n unieke toetsfaktuur/handelaar-konteks sonder ’n vals identiteit.
3. Betaal een keer, en versamel dan jou **eie** kwitansie, staat, handelaar-dashboard, wallet/node-log en publieke-ketting-aansig waar van toepassing.
4. Kontroleer of die bedrag, tydstempel, adres/token, rekening, IP/toestel, aflewering en terugbetalingsroete met die waarnemerstabel ooreenstem.
5. Vir Bitcoin, ondersoek adreshergebruik, geselekteerde insette, kleingeld en latere konsolidasie in die wallet se coin-control-aansig.
6. Vir shielded protocols, verifieer die werklike pool/path en wat ’n viewing key openbaar; moenie privaatheid uit wallet-branding aflei nie.
7. Vir e-cash/Taler, toets rugsteun/herstel, terugbetaling en aflossing met ’n klein waarde; dokumenteer mint/exchange/federation-grensrekords.
8. Herroep ’n virtuele kaart/toetscredential en bevestig dat latere magtiging misluk terwyl wettige terugbetalingshantering steeds verstaan word.
9. Rekonsilieer en behou vereiste belasting-/magtigingsbewyse geïnkripteer.

Moet nooit sirkeltransfers, drempelverdeling, vals aankope of verdagte terugbetalings as ’n “privaatheidstoets” skep nie.

## Gemagtigde red-team-aanspreeklikheidsoefening

Voor die oefening, voer ’n tabletop- en tegniese oefening uit:

1. ’n Operator loods ’n goedaardige canary vanaf elke goedgekeurde bronpad.
2. Die teiken-SOC teken aan wat dit bespeur sonder om die operator se identiteit te ontvang indien blind testing bedoel word.
3. Die oefeningbeheerder koppel bron → engagement → operator vanuit die escrowed map en getekende werkopdrag.
4. Die beheerder stuur die emergency stop; die operator en infrastruktuureienaar demonstreer afskakeling binne die ROE-tyd.
5. Provider abuse ontvang die korrekte 24/7-kontak en magtigingsverwysing.
6. Bewyse toon die teiken, tyd, tool/job en operator sonder om onnodige payload-inhoud te behou.
7. ’n Tweede operator verifieer credential-herroeping en hulpbronteardown.

Misluk die gereedheidsoorsig indien die SOC persoonlike/tuisinfrastruktuur triviaal kan sien **OF** indien die beheerder nie die bron vinnig kan toeskryf en stop nie.

## Toetsrekordsjabloon
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Verbindingkontrole](https://check.torproject.org/)
- [2] [WireGuard — Roetering en netwerknaamruimtes](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ en metadatariglyne](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Tegniese gids tot inligtingsekuriteitstoetsing en -assessering](https://csrc.nist.gov/pubs/sp/800/115/final)
