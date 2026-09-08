# Upimaji wa Faragha Unaoweza Kurudiwa

{{#include ../banners/hacktricks-training.md}}

Usanidi wa faragha haujakamilika unapounganisha tu. Hukamilika wakati mpaka unaodaiwa umefanyiwa majaribio wakati wa matumizi ya kawaida, hitilafu, urejeshaji na uondoaji. Fanya majaribio dhidi ya infrastructure unayomiliki au umeidhinishwa kukagua; tovuti za umma za “leak test” huwa mwangalizi mwingine.

## Jenga mazingira madogo ya majaribio yaliyoidhinishwa

Tumia majukumu matatu, ikiwezekana kwenye providers/networks tofauti:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Rekodi kabla ya kila test:

- kitambulisho cha test, muda wa kuanza/kumaliza wa UTC, mwendeshaji na idhini;
- matoleo na usanidi wa endpoint/OS/client pamoja na hash ya usanidi;
- uchunguzi unaotarajiwa wa IPv4, IPv6, DNS, TLS, akaunti, malipo na mazingira halisi;
- ni logi zipi zitakazokaguliwa pamoja na saa na time zone zake;
- kanuni ya pass/fail na muda wa teardown.

Usiwahi kuanza kwa ku-test utambulisho nyeti. Tumia akaunti ya synthetic na thamani za kipekee za canary zisizo na madhara, zinazomilikiwa na tester.

## Test ya njia ya mtandao

### 1. Capture baseline

Kabla ya kuwezesha njia ya faragha, rekodi routes za ndani na resolvers:
```bash
ip route
ip -6 route
resolvectl status
```
Kwenye macOS tumia `route -n get default`, `netstat -rn -f inet6`, na `scutil --dns`. Hifadhi matokeo pekee katika hifadhi ya ushahidi inayodhibitiwa; yanaweza kuwa na vitambulishi vya ndani.

### 2. Unganisha na kagua routing

Washa VPN/Tor/workload namespace, kisha angalia route iliyochaguliwa kwa anwani za umma zinazodhibitiwa:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Badilisha anwani za documentation ziwe anwani za test server. Thibitisha kuwa interface/table iliyochaguliwa inalingana na muundo.

### 3. Angalia kutoka ncha zote mbili

Weka URL ya endpoint unayoimiliki, kisha omba path salama ya kipekee:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Tumia domain halisi inayodhibitiwa na tester, TLS iliyo-authenticate na token isiyo nyeti kwenye path. Kagua server log kwa:

- anwani ya chanzo/ASN na egress inayotarajiwa;
- IPv4 dhidi ya IPv6;
- tabia ya Host/SNI inayoonekana kwenye endpoint;
- user agent na application headers;
- muda kamili na matumizi tena kwa request.

Usiongeze `X-Forwarded-For`, debug headers za kipekee au identity-bearing cookies kwenye request inayodhaniwa kuwa imetenganishwa.

### 4. Test DNS kwa canary inayomilikiwa

Sanidi authoritative test zone ambayo query logs zake unadhibiti. Fanya query ya unique random label kupitia compartment:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Kagua log yenye mamlaka. Kwa kawaida huona recursive resolver, si lazima client. Linganisha resolver huyo na muundo uliokusudiwa wa VPN/Tor/application DNS. Tovuti ya nasibu ya public DNS leak haihitajiki.

### 5. Test fail-closed behavior

Weka loop isiyo na madhara inayolenga endpoint inayomilikiwa, kisha simamisha privacy path. Workload lazima ishindwe badala ya kubadili kwenda kwenye physical interface. Kagua address families zote mbili pamoja na DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Rudia wakati wa:

- kuanguka kwa mchakato wa tunnel;
- kubadilisha kutoka Wi-Fi hadi Ethernet au hotspot;
- kulala/kuamka;
- kusasisha DHCP;
- hali ya captive-portal;
- provider kuunganishwa tena/kuisha kwa key.

Kwa Linux namespace/container, simamisha tunnel yake na uthibitishe kuwa haina default route au resolver nyingine:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Majina na commands hutofautiana kulingana na deployment. Usiyabandike kwenye remote production host bila console recovery.

### 6. Kagua soketi na pakiti za ndani

Kwa idhini, kagua ni process/interface gani hasa huwasiliana:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Replace `TEST_SERVER_IP` with the explicit owned address; epuka broad capture ya users wasiohusika. Physical interface inapaswa kuona tunnel/bridge peer, huku traffic ya clear destination ikiwapo tu kwenye layer iliyokusudiwa.

## Tor and onion-service test

1. Katika Tor Browser, tembelea ukaguzi wa connection wa Tor Project na uthibitishe matumizi ya Tor. Usichukulie hili kama uthibitisho wa identity.<sup>[[1]](#references)</sup>
2. Tembelea HTTPS endpoint yako inayomilikiwa ikiwa na canary ya kipekee na uthibitishe kuwa inaona Tor exit, haina cookies zinazoweza kutambulisha, na iko katika browser context ya kawaida.
3. Chagua **New Identity**, tembelea tena ukiwa na canary tofauti, na uthibitishe kuwa local state ilisafishwa kama ilivyotarajiwa. Mabadiliko ya Exit IP hayahakikishwi wala siyo lengo la New Identity.
4. Kwa onion service, ifikie kupitia Tor Browser pekee. Thibitisha kuwa service host haina public listener kwa authorized external scan na kwamba application responses hazina public hostname/IP.
5. Kagua origin outbound DNS/HTTP, templates, error pages, email/webhooks na third-party assets. Fetch yoyote ya moja kwa moja inaweza kufichua origin au operator account.
6. Ikiwa client authorization imewashwa, thibitisha kuwa Tor Browser isiyo na credentials na iliyo safi haiwezi kuunganishwa, na iliyo na credentials inaweza.
7. Rotate test authorization key na uthibitishe kuwa client iliyorevokewa inapoteza access bila kubadilisha onion identity.

## Browser-compartment test

Unda controlled page inayorekodi fields zinazohitajika kwa test pekee, ikiwa na muda mfupi wa retention. Linganisha personal na privacy compartments kwa:

- cookies/local storage/service workers na cache;
- browser sync/login state;
- language, time zone, screen/window dimensions na fonts;
- WebRTC/network candidates;
- permissions na modifications zinazoonekana kwa extension;
- TLS/HTTP user-agent data kwenye server.

Usijaribu kuifanya Tor Browser iwe “more random.” Pass condition ni kufanana na standard anonymity set yake na kutokuwepo kwa personal state, siyo tofauti ya juu kabisa kutoka kwa personal browser.

Test copy/paste, drag/drop, kufungua downloaded-file, password-manager suggestions na identity-provider buttons. Hizi ni bridges za mara kwa mara kati ya compartments.

## Operating-system isolation test

### Tails

1. Anza na file/canary isiyo na madhara katika session isiyo na Persistent Storage.
2. Zima mfumo kikamilifu, reboot, na uthibitishe kuwa file hiyo imetoweka.
3. Washa persistence category moja tu inayohitajika, rudia test, na uthibitishe kuwa browser/application state isiyohusiana haijahifadhiwa.
4. Thibitisha kuwa Unsafe Browser haiwezi kutumiwa baada ya portal login kwa shughuli nyeti na kwamba Tor applications zinaunganika tena kwa kawaida.

### Whonix/Qubes

1. Simamisha Gateway/net qube na uthibitishe kuwa Workstation/app qube haiwezi kufikia IPv4, IPv6 au DNS.
2. Jaribu inter-qube clipboard/file path iliyosanidiwa wazi pekee na uthibitishe kuwa shared-folder/device paths nyingine hazipo.
3. Fungua benign test document katika disposable qube, ifunge, na uthibitishe kuwa state yake imetoweka.
4. Kagua kuwa vault qube haina NetVM na haiwezi kupata moja kupitia template/default change.
5. Fanya snapshot/restore ya test VM na kagua ikiwa identity-bearing state inarudi bila kutarajiwa.

## Communications metadata test

Kwa kila messenger iliyochaguliwa:

1. Unda test-only participants kwenye controlled devices.
2. Rekodi registration inachohitaji: phone, app-store account, IP, push service, username au invitation.
3. Tuma benign message moja huku ukikagua notification previews, linked desktops, wearables na backups.
4. Thibitisha safety/security codes kupitia independent path.
5. Zima receipts/push au washa Tor/local transports moja kwa wakati na uangalie mabadiliko ya reliability/metadata.
6. Export au restore test backup na uandike kwa usahihi profile, contacts na history iliyomo.
7. Poteza/revoke test device na uthibitishe kuwa participants waliosalia wanaona key/device change iliyotarajiwa.

Usifanye test kwa kuwasiliana na watu wasiohusika au kuzalisha abusive traffic.

## File-sanitization test

1. Hash na hifadhi original katika encrypted evidence storage:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Unda nakala iliyosafishwa kwa kutumia mchakato mahususi wa muundo katika [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md).
3. Linganisha orodha za metadata:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Render/fungua nakala katika muktadha unaoweza kutupwa. Kagua maudhui yaliyofichwa, viambatisho, links, fomu, layers, vijipicha na vitambulishi vya kuona.
5. Tafuta kwenye nakala iliyowekwa tayari pekee strings za canary zinazojulikana za mwandishi/barua pepe/njia.
6. Tengeneza hash ya matokeo ya mwisho na mtu wa pili athibitishe faili halisi itakayochapishwa.

Kutokuwepo kwenye matokeo ya ExifTool si uthibitisho wa kutokujulikana; mambo ya ndani ya format, pixels, maandishi na rekodi za usambazaji bado zinaweza kubaki.

## Jaribio la faragha ya malipo

Tumia kiasi kidogo zaidi kinachoruhusiwa au test network/sandbox rasmi:

1. Andika mwonekano unaotarajiwa kwa mlipaji, mpokeaji/mfanyabiashara, issuer/exchange, network/node, public ledger na accountant/controller.
2. Tengeneza invoice/merchant context ya kipekee ya majaribio bila kutumia utambulisho wa uwongo.
3. Lipa mara moja, kisha kusanya receipt yako mwenyewe, statement, merchant dashboard, wallet/node log na public-chain view inapohusika.
4. Kagua ikiwa kiasi, timestamp, address/token, account, IP/device, uwasilishaji na njia ya refund zinalingana na jedwali la watazamaji.
5. Kwa Bitcoin, kagua address reuse, selected inputs, change na later consolidation katika coin-control view ya wallet.
6. Kwa shielded protocols, thibitisha pool/path halisi na kile ambacho viewing key hufichua; usikadirie faragha kutokana na branding ya wallet.
7. Kwa e-cash/Taler, jaribu backup/recovery, refund na redemption kwa thamani ndogo; andika rekodi za mipaka ya mint/exchange/federation.
8. Revoke virtual card/test credential na uthibitishe kuwa authorization za baadaye zinashindikana huku handling halali ya refund ikiendelea kueleweka.
9. Linganisha na uhifadhi ushahidi unaohitajika wa kodi/authorization ukiwa ume-encryptiwa.

Usiwahi kuunda circular transfers, threshold-splitting, fake purchases au suspicious refunds kama “privacy test.”

## Drill ya uwajibikaji ya Authorized red-team

Kabla ya zoezi, endesha tabletop na technical drill:

1. Operator azindue canary isiyo na madhara kutoka kila source path iliyoidhinishwa.
2. SOC ya target irekodi inachogundua bila kupokea utambulisho wa operator ikiwa blind testing imekusudiwa.
3. Exercise controller atatue source → engagement → operator kutoka kwenye ramani iliyowekwa escrow na job record iliyotiwa saini.
4. Controller atume emergency stop; operator na infrastructure owner waonyeshe shutdown ndani ya muda wa ROE.
5. Provider abuse ipokee contact sahihi ya 24/7 na authorization reference.
6. Ushahidi uonyeshe target, muda, tool/job na operator bila kuhifadhi payload content isiyohitajika.
7. Operator wa pili athibitishe credential revocation na resource teardown.

Kataa ukaguzi wa readiness ikiwa SOC inaweza kuona kwa urahisi infrastructure ya kibinafsi/nyumbani **AU** ikiwa controller hawezi kutambua haraka na kusimamisha source.

## Kiolezo cha rekodi ya jaribio
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
- [2] [WireGuard — Uelekezaji na nafasi za majina za mtandao](https://www.wireguard.com/netns/)
- [3] [ExifTool — Maswali yanayoulizwa mara kwa mara na mwongozo wa metadata](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Mwongozo wa kiufundi wa upimaji na tathmini ya usalama wa taarifa](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
