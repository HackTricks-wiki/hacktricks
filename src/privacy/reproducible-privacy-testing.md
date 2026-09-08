# Upimaji wa Faragha Unaoweza Kurudiwa

Mpangilio wa faragha haujakamilika unapounganisha tu. Unakamilika wakati mpaka wake unaodaiwa umejaribiwa wakati wa matumizi ya kawaida, hitilafu, urejeshaji na kuondoa usanidi. Fanya majaribio dhidi ya miundombinu unayomiliki au umeidhinishwa kukagua; tovuti za umma za “leak test” huwa mwangalizi mwingine.

## Unda mazingira madogo ya majaribio yaliyoidhinishwa

Tumia majukumu matatu, ikiwezekana kwenye watoa huduma/mitandao tofauti:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Rekodi kabla ya kila test:

- ID ya test, muda wa kuanza/kumaliza wa UTC, operator na authorization;
- matoleo na configuration ya endpoint/OS/client, pamoja na configuration hash;
- uchunguzi unaotarajiwa wa IPv4, IPv6, DNS, TLS, account, malipo na mazingira halisi;
- ni logs zipi zitakazokaguliwa na clocks/time zones zake;
- kanuni ya pass/fail na muda wa teardown.

Usiwahi kuanza kwa test identity nyeti. Tumia synthetic account na benign unique canary values zinazomilikiwa na tester.

## Test ya network-path

### 1. Nasa baseline

Kabla ya kuwezesha privacy path, rekodi local routes na resolvers:
```bash
ip route
ip -6 route
resolvectl status
```
Kwenye macOS tumia `route -n get default`, `netstat -rn -f inet6`, na `scutil --dns`. Hifadhi matokeo pekee kwenye evidence store inayodhibitiwa; yanaweza kuwa na vitambulisho vya ndani.

### 2. Unganisha na kagua routing

Washa VPN/Tor/workload namespace, kisha kagua route iliyochaguliwa kwa anwani za umma zinazodhibitiwa:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Badilisha anwani za documentation ziwe anwani za test server. Thibitisha kuwa interface/table iliyochaguliwa inalingana na muundo.

### 3. Chunguza kutoka pande zote mbili

Weka URL ya endpoint unayomiliki, kisha omba path ya kipekee isiyo na madhara:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Tumia domain inayodhibitiwa na tester, TLS yenye authentication na token isiyo nyeti katika path. Kagua log ya server kwa:

- anwani ya chanzo/ASN na egress inayotarajiwa;
- IPv4 dhidi ya IPv6;
- tabia ya Host/SNI inayoonekana kwenye endpoint;
- user agent na application headers;
- muda kamili na matumizi tena kwa request.

Usiongeze `X-Forwarded-For`, debug headers za kipekee au cookies zenye utambulisho kwenye request inayodaiwa kuwa imetenganishwa.

### 4. Test DNS with an owned canary

Sanidi test zone ya authoritative ambayo query logs zake unazidhibiti. Fanya query ya unique random label kupitia compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Kagua log ya authoritative. Kwa kawaida huona recursive resolver, si lazima client. Linganisha resolver hiyo na muundo uliokusudiwa wa VPN/Tor/application DNS. Tovuti ya random ya public DNS leak si lazima.

### 5. Test fail-closed behavior

Endeleza loop ya benign request inayolenga endpoint inayomilikiwa, kisha simamisha privacy path. Workload lazima ishindwe badala ya kubadilisha kwenda physical interface. Kagua address families zote mbili na DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Rudia wakati wa:

- ku-crash kwa mchakato wa tunnel;
- kubadili kutoka Wi-Fi kwenda Ethernet au hotspot;
- kulala/kuamka;
- kufanywa upya kwa DHCP;
- hali ya captive portal;
- kuunganishwa tena na provider/ku-expire kwa key.

Kwa Linux namespace/container, simamisha tunnel yake na uthibitishe kuwa haina default route nyingine au resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Majina na commands hutofautiana kulingana na deployment. Usiyabandike kwenye remote production host bila console recovery.

### 6. Kagua local sockets na packets

Ukiwa na authorization, kagua ni process/interface gani hasa huwasiliana:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Badilisha `TEST_SERVER_IP` kwa anwani halisi iliyo chini ya umiliki wako; epuka kukusanya kwa upana data ya users wasiohusika. Interface ya kimwili inapaswa kuona peer wa tunnel/bridge, huku traffic ya destination iliyo wazi ikipaswa kuwepo tu kwenye layer iliyokusudiwa.

## Tor and onion-service test

1. Katika Tor Browser, tembelea ukaguzi wa connection wa Tor Project na uthibitishe matumizi ya Tor. Usichukulie hili kama uthibitisho wa identity.<sup>[[1]](#references)</sup>
2. Tembelea HTTPS endpoint iliyo chini ya umiliki wako ukiwa na canary ya kipekee na uthibitishe kwamba inaona Tor exit, haina cookies zinazotambulisha, na iko katika browser context ya kawaida.
3. Chagua **New Identity**, tembelea tena ukiwa na canary tofauti, na uthibitishe kwamba local state ilifutwa kama ilivyotarajiwa. Mabadiliko ya Exit IP hayahakikishwi wala si madhumuni ya New Identity.
4. Kwa onion service, ifikie kupitia Tor Browser pekee. Thibitisha kwamba service host haina public listener kwa external scan iliyoidhinishwa na kwamba application responses hazina public hostname/IP.
5. Kagua origin outbound DNS/HTTP, templates, error pages, email/webhooks na third-party assets. Fetch yoyote ya moja kwa moja inaweza kufichua origin au operator account.
6. Ikiwa client authorization imewashwa, thibitisha kwamba Tor Browser safi isiyo na credentials haiwezi kuunganishwa na yenye credentials inaweza.
7. Rotate test authorization key na uthibitishe kwamba client iliyorevokiwa inapoteza access bila kubadilisha onion identity.

## Browser-compartment test

Unda controlled page inayorekodi fields zinazohitajika kwa test pekee, ikiwa na retention period fupi. Linganisha personal na privacy compartments kwa:

- cookies/local storage/service workers na cache;
- browser sync/login state;
- language, time zone, screen/window dimensions na fonts;
- WebRTC/network candidates;
- permissions na modifications zinazoonekana kwa extension;
- TLS/HTTP user-agent data kwenye server.

Usijaribu kuifanya Tor Browser iwe “random zaidi.” Pass condition ni kufanana na standard anonymity set yake na kutokuwepo kwa personal state, si tofauti ya juu zaidi kutoka kwa personal browser.

Test copy/paste, drag/drop, ufunguaji wa downloaded files, mapendekezo ya password manager na identity-provider buttons. Hizi ni bridges za kawaida kati ya compartments.

## Operating-system isolation test

### Tails

1. Anza na file/canary isiyo na madhara katika session isiyo na Persistent Storage.
2. Zima mfumo kikamilifu, reboot, na uthibitishe kwamba file hiyo haipo tena.
3. Washa persistence category moja tu inayohitajika, rudia test, na uthibitishe kwamba browser/application state isiyohusiana haikuhifadhiwa.
4. Thibitisha kwamba Unsafe Browser haiwezi kutumiwa baada ya portal login kwa shughuli nyeti na kwamba Tor applications zinaunganishwa tena kwa kawaida.

### Whonix/Qubes

1. Simamisha Gateway/net qube na uthibitishe kwamba Workstation/app qube haiwezi kufikia IPv4, IPv6 au DNS.
2. Jaribu inter-qube clipboard/file path iliyosanidiwa wazi pekee na uthibitishe kwamba shared-folder/device paths nyingine hazipo.
3. Fungua benign test document katika disposable qube, ifunge, na uthibitishe kwamba state yake inapotea.
4. Kagua kwamba vault qube haina NetVM na haiwezi kuipata kupitia template/default change.
5. Snapshot/restore test VM na ukague ikiwa identity-bearing state inarudi bila kutarajiwa.

## Communications metadata test

Kwa kila messenger iliyochaguliwa:

1. Unda test-only participants kwenye controlled devices.
2. Rekodi kinachohitajika kwa registration: phone, app-store account, IP, push service, username au invitation.
3. Tuma ujumbe mmoja usio na madhara huku ukikagua notification previews, linked desktops, wearables na backups.
4. Thibitisha safety/security codes kupitia independent path.
5. Zima receipts/push au washa Tor/local transports moja kwa wakati na uangalie mabadiliko ya reliability/metadata.
6. Export au restore test backup na uandike kwa usahihi profile, contacts na history iliyo ndani yake.
7. Poteza/revoke test device na uthibitishe kwamba participants waliosalia wanaona key/device change iliyotarajiwa.

Usifanye test kwa kuwasiliana na watu wasiohusika au kuzalisha abusive traffic.

## File-sanitization test

1. Hash na uhifadhi original katika encrypted evidence storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Unda nakala iliyosafishwa kwa kutumia mchakato mahususi wa umbizo katika [Mawasiliano na Kushiriki kwa Kulinda Faragha](privacy-preserving-communications-and-sharing.md).
3. Linganisha orodha za metadata:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Render/fungua nakala hiyo katika context inayoweza kutupwa. Kagua maudhui yaliyofichika, attachments, links, forms, layers, thumbnails na visual identifiers.
5. Tafuta katika nakala iliyowekwa kwa staging pekee strings zinazojulikana za canary za author/email/path.
6. Tengeneza hash ya output ya mwisho na mtu wa pili athibitishe file halisi inayochapishwa.

Kutokuwepo kwenye output ya ExifTool si uthibitisho wa anonymity; internals za format, pixels, prose na records za usambazaji bado zinabaki.

## Payment privacy test

Tumia kiasi kidogo zaidi kinachoruhusiwa au official test network/sandbox:

1. Andika view inayotarajiwa kwa payer, payee/merchant, issuer/exchange, network/node, public ledger na accountant/controller.
2. Unda invoice/merchant context ya kipekee ya test bila identity ya uongo.
3. Lipa mara moja, kisha kusanya receipt, statement, merchant dashboard, wallet/node log na public-chain view yako mwenyewe inapohitajika.
4. Kagua kama amount, timestamp, address/token, account, IP/device, delivery na refund route zinalingana na jedwali la observers.
5. Kwa Bitcoin, kagua address reuse, inputs zilizochaguliwa, change na consolidation ya baadaye katika coin-control view ya wallet.
6. Kwa protocols zenye shielding, thibitisha pool/path halisi na kile viewing key inachofichua; usidhanie privacy kutokana na branding ya wallet.
7. Kwa e-cash/Taler, test backup/recovery, refund na redemption kwa thamani ndogo; andika records za mipaka ya mint/exchange/federation.
8. Revoke virtual card/test credential na uthibitishe kuwa authorization ya baadaye inakataliwa huku handling halali ya refund ikiendelea kueleweka.
9. Reconcile na uhifadhi ushahidi unaohitajika wa tax/authorization ukiwa encrypted.

Usiwahi kuunda circular transfers, threshold-splitting, fake purchases au suspicious refunds kama “privacy test.”

## Authorized red-team accountability drill

Kabla ya zoezi, endesha tabletop na technical drill:

1. Operator anazindua canary isiyo na madhara kutoka kila approved source path.
2. SOC ya target inarekodi inachogundua bila kupokea identity ya operator ikiwa blind testing imekusudiwa.
3. Exercise controller anatambua source → engagement → operator kutoka kwenye escrowed map na signed job record.
4. Controller anatuma emergency stop; operator na infrastructure owner wanaonyesha shutdown ndani ya muda wa ROE.
5. Provider abuse inapokea 24/7 contact na authorization reference sahihi.
6. Evidence inaonyesha target, time, tool/job na operator bila kuhifadhi payload content isiyohitajika.
7. Operator wa pili anathibitisha credential revocation na resource teardown.

Kataa readiness review ikiwa SOC inaweza kuona kwa urahisi personal/home infrastructure **OR** ikiwa controller hawezi kuhusisha na kusimamisha source kwa haraka.

## Test record template
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

- [1] [Tor Project — Ukaguzi wa muunganisho](https://check.torproject.org/)
- [2] [WireGuard — Uelekezaji na Nafasi za Majina za Mtandao](https://www.wireguard.com/netns/)
- [3] [ExifTool — Maswali yanayoulizwa mara kwa mara na mwongozo wa metadata](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Mwongozo wa Kiufundi wa Upimaji na Tathmini ya Usalama wa Taarifa](https://csrc.nist.gov/pubs/sp/800/115/final)
