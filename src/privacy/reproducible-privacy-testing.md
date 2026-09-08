# Reproduseerbare privaatheidstoetsing

{{#include ../banners/hacktricks-training.md}}

’n Privaatheidsopstelling is nie klaar wanneer dit verbind nie. Dit is klaar wanneer die beweerde grens daarvan tydens normale gebruik, faling, herstel en afbreek getoets is. Toets teen infrastruktuur wat jy besit of gemagtig is om te inspekteer; openbare “leak test”-webwerwe word nog ’n waarnemer.

## Bou ’n klein gemagtigde toetsomgewing

Gebruik drie rolle, ideaal gesproke op aparte providers/netwerke:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Teken voor elke toets aan:

- toets-ID, UTC-begin/eind, operateur en magtiging;
- eindpunt/OS/kliëntweergawes en konfigurasiehash;
- verwagte IPv4-, IPv6-, DNS-, TLS-, rekening-, betalings- en fisiese waarnemings;
- watter logs geïnspekteer sal word en hul horlosies/tydsones;
- slaag/misluk-reël en aftakelingstyd.

Moet nooit eerste ’n sensitiewe identiteit toets nie. Gebruik ’n sintetiese rekening en onskadelike, unieke kanariewaardes wat deur die toetser besit word.

## Netwerkpad-toets

### 1. Teken die basislyn aan

Teken plaaslike roetes en resolvers aan voordat die privaatheidspad geaktiveer word:
```bash
ip route
ip -6 route
resolvectl status
```
Op macOS gebruik `route -n get default`, `netstat -rn -f inet6`, en `scutil --dns`. Stoor die uitvoer slegs in die beheerde bewyse-bergplek; dit kan plaaslike identifiseerders bevat.

### 2. Koppel en inspekteer roetering

Aktiveer die VPN/Tor/workload namespace, en kontroleer dan die roete wat vir beheerde publieke adresse gekies is:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Vervang dokumentasieadresse met die toetsbedieneradresse. Bevestig dat die geselekteerde koppelvlak/tabel met die ontwerp ooreenstem.

### 3. Neem vanaf albei kante waar

Stel die URL van die beheerde endpoint in en versoek dan ’n unieke onskadelike path:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Gebruik ’n domein wat deur die werklike tester beheer word, geverifieerde TLS en ’n nie-sensitiewe pad-token. Inspekteer die bedienerlog vir:

- bronadres/ASN en verwagte egress;
- IPv4 teenoor IPv6;
- Host/SNI-gedrag wat by die endpoint sigbaar is;
- user agent en toepassingsheaders;
- presiese tyd en hergebruik van die versoek.

Moenie `X-Forwarded-For`, unieke debug-headers of identiteit-draende koekies by ’n sogenaamd geskeide versoek voeg nie.

### 4. Toets DNS met ’n canary wat jy besit

Konfigureer ’n gesaghebbende toets-sone waarvan jy die query-logboeke beheer. Doen ’n navraag vir ’n unieke ewekansige label deur die kompartement:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Inspekteer die authoritative log. Dit sien normaalweg die recursive resolver, nie noodwendig die client nie. Vergelyk daardie resolver met die beoogde VPN/Tor/application DNS-ontwerp. ’n Ewekansige publieke DNS-leak-webwerf word nie vereis nie.

### 5. Toets fail-closed-gedrag

Hou ’n onskadelike versoeklus gerig op die besitte endpoint aan, en stop dan die privacy-pad. Die workload moet misluk eerder as om na ’n fisiese interface oor te skakel. Kontroleer beide address families en DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Herhaal tydens:

- tunnel-prosesineenstorting;
- Wi-Fi-na-Ethernet- of hotspot-oorskakeling;
- slaap/wakker word;
- DHCP-hernuwing;
- captive-portal-status;
- verskafferherverbinding/sleutelverval.

Vir ’n Linux-namespace/container, stop sy tunnel en verifieer dat dit geen ander verstekroete of resolver het nie:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Name en opdragte verskil per ontplooiing. Moenie dit sonder konsoleherstel op ’n afgeleë produksiegasheer plak nie.

### 6. Inspekteer plaaslike sokkette en pakkette

Met magtiging, kontroleer watter proses/koppelvlak werklik kommunikeer:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Vervang `TEST_SERVER_IP` met die eksplisiete beheerde adres; vermy breë vaslegging van onverwante gebruikers. Die fisiese koppelvlak behoort die tunnel/bridge-peer te sien, terwyl duidelike bestemmingsverkeer slegs op die beoogde laag behoort te bestaan.

## Tor- en onion-service-toets

1. Besoek die Tor Project-verbindingkontrole in Tor Browser en bevestig Tor-gebruik. Moenie dit as bewys van identiteit beskou nie.<sup>[[1]](#references)</sup>
2. Besoek die beheerde HTTPS-endpoint met ’n unieke canary en bevestig dat dit ’n Tor-exit sien, geen identifiserende cookies ontvang nie, en die standaardblaaierkonteks gebruik.
3. Kies **New Identity**, besoek dit weer met ’n ander canary, en verifieer dat die plaaslike toestand soos verwag skoongemaak is. ’n Verandering van exit-IP word nie gewaarborg nie en is nie die doel van New Identity nie.
4. Vir ’n onion service, verkry dit slegs deur Tor Browser. Bevestig met ’n gemagtigde eksterne scan dat die service-host geen publieke listener het nie, en dat application responses geen publieke hostname/IP bevat nie.
5. Inspekteer origin se uitgaande DNS/HTTP, templates, error pages, email/webhooks en third-party assets. Enige direkte fetch kan die origin of operator account bekend maak.
6. Indien client authorization geaktiveer is, bevestig dat ’n ongeauthentiseerde, skoon Tor Browser nie kan verbind nie en dat ’n geauthentiseerde een wel kan.
7. Roteer ’n toets-authorization key en bevestig dat die herroepe client toegang verloor sonder om die onion-identiteit te verander.

## Browser-compartment-toets

Skep ’n beheerde bladsy wat slegs die velde opteken wat vir die toets nodig is, met ’n kort retensietydperk. Vergelyk persoonlike en privaatheidscompartments vir:

- cookies/local storage/service workers en cache;
- browser sync/login state;
- taal, tydsone, skerm-/venstergroottes en fonts;
- WebRTC/network candidates;
- permissions en wysigings wat deur extensions sigbaar is;
- TLS/HTTP user-agent-data op die server.

Moenie probeer om Tor Browser “meer random” te maak nie. Die slaagvoorwaarde is ooreenkoms met sy standaard anonymity set en die afwesigheid van persoonlike toestand, nie die maksimum verskil van die persoonlike browser nie.

Toets copy/paste, drag/drop, die oopmaak van afgelaaide files, password-manager-suggestions en identity-provider-knoppies. Dit is gereelde brûe tussen compartments.

## Operating-system-isolasietoets

### Tails

1. Begin met ’n onskadelike file/canary in ’n sessie sonder Persistent Storage.
2. Skakel volledig af, reboot, en bevestig dat dit weg is.
3. Aktiveer slegs een vereiste persistence-category, herhaal, en bevestig dat onverwante browser/application-state nie behou word nie.
4. Verifieer dat die Unsafe Browser nie ná portal-login vir sensitiewe aktiwiteit gebruik kan word nie en dat Tor applications normaal reconnect.

### Whonix/Qubes

1. Stop die Gateway/net qube en bewys dat die Workstation/app qube nie IPv4, IPv6 of DNS kan bereik nie.
2. Probeer slegs die eksplisiet gekonfigureerde inter-qube clipboard/file-path en bevestig dat ander shared-folder/device-paths afwesig is.
3. Maak ’n onskadelike toetsdokument in ’n disposable qube oop, maak dit toe, en bevestig dat die toestand daarvan verdwyn.
4. Kontroleer dat die vault qube geen NetVM het nie en dit nie deur ’n template/default-verandering kan verkry nie.
5. Neem ’n snapshot van ’n toets-VM, herstel dit, en inspekteer of identity-bearing-state onverwags terugkeer.

## Communications-metadata-toets

Vir elke geselekteerde messenger:

1. Skep toets-slegs-deelnemers op beheerde devices.
2. Teken aan wat registration vereis: phone, app-store-account, IP, push-service, username of invitation.
3. Stuur een onskadelike message terwyl notification-previews, linked desktops, wearables en backups geïnspekteer word.
4. Verifieer safety/security-codes oor ’n onafhanklike pad.
5. Skakel receipts/push af of aktiveer Tor/local transports een op ’n slag, en neem veranderinge in reliability/metadata waar.
6. Export of restore ’n toetsbackup en dokumenteer presies watter profile, contacts en history dit bevat.
7. Verloor/herroep ’n toetsdevice en bevestig dat die oorblywende deelnemers die verwagte key/device-verandering sien.

Moenie toets deur onverwante mense te kontak of abusive traffic te genereer nie.

## File-sanitization-toets

1. Hash en bewaar die oorspronklike in geënkripteerde evidence-storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Skep ’n skoongemaakte kopie deur die formaatspesifieke proses in [Privaatheidsbehoudende kommunikasie en deling](privacy-preserving-communications-and-sharing.md) te gebruik.
3. Vergelyk metadata-inventarisse:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Render/open die kopie in ’n weggooibare konteks. Kontroleer verborge inhoud, aanhegsels, links, vorms, lae, duimnaels en visuele identifiseerders.
5. Soek slegs in die opgevoerde kopie na bekende canary-skrywer/e-pos-/padstringe.
6. Hash die finale uitvoer en laat ’n tweede persoon die presiese lêer wat gepubliseer word, verifieer.

Afwesigheid uit ExifTool-uitvoer is nie bewys van anonimiteit nie; formaat-interne data, pixels, prosa en verspreidingsrekords bly bestaan.

## Betalingsprivaatheidstoets

Gebruik die kleinste toegelate bedrag of ’n amptelike test network/sandbox:

1. Skryf die verwagte sigbaarheid vir die betaler, begunstigde/handelaar, uitreiker/exchange, netwerk/node, openbare ledger en rekenmeester/beheerder.
2. Skep ’n unieke toetsfaktuur/handelaarkonteks sonder ’n vals identiteit.
3. Betaal een keer, en versamel daarna jou eie kwitansie, staat, handelaarsdashboard, wallet/node-log en openbare-chain-aansig waar van toepassing.
4. Kontroleer of die bedrag, tydstempel, adres/token, rekening, IP/toestel, aflewering en terugbetalingsroete met die waarnemerstabel ooreenstem.
5. Vir Bitcoin, inspekteer adreshergebruik, geselekteerde inputs, change en latere konsolidasie in die wallet se coin-control-aansig.
6. Vir shielded protocols, verifieer die werklike pool/path en wat ’n viewing key openbaar; moenie privaatheid uit wallet-branding aflei nie.
7. Vir e-cash/Taler, toets backup/recovery, terugbetaling en redemption met ’n klein waarde; dokumenteer mint/exchange/federation-grensrekords.
8. Herroep ’n virtuele kaart/toetscredential en bevestig dat latere authorization misluk terwyl wettige terugbetalingshantering verstaanbaar bly.
9. Rekonsilieer en behou vereiste belasting-/authorization-bewyse geënkripteer.

Moet nooit sirkeltransfers, drempelverdeling, vals aankope of verdagte terugbetalings as ’n “privaatheidstoets” skep nie.

## Gemagtigde red-team-aanspreeklikheidsdril

Voor die oefening, voer ’n tabletop- en tegniese dril uit:

1. ’n Operator lanseer ’n onskadelike canary vanaf elke goedgekeurde bronpad.
2. Die teiken-SOC teken aan wat dit bespeur sonder om die operator se identiteit te ontvang indien blind testing bedoel word.
3. Die oefeningbeheerder koppel bron → engagement → operator vanuit die escrowed map en signed job record.
4. Die beheerder stuur die noodstop; die operator en infrastruktuureienaar demonstreer shutdown binne die ROE-tyd.
5. Provider abuse ontvang die korrekte 24/7-kontak en authorization reference.
6. Bewyse toon die teiken, tyd, tool/job en operator sonder om onnodige payload-inhoud te behou.
7. ’n Tweede operator verifieer credential revocation en resource teardown.

Laat die gereedheidsoorsig misluk indien die SOC persoonlike/tuisinfrastruktuur triviaal kan sien **of** indien die beheerder nie die bron vinnig kan attribueer en stop nie.

## Toetsrekord-sjabloon
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

- [1] [Tor Project — Verbindingskontrole](https://check.torproject.org/)
- [2] [WireGuard — Roetering en netwerknaamruimtes](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ en metadata-riglyne](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Tegniese gids vir inligtingsekuriteitstoetsing en -assessering](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
