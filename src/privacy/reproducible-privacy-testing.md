# Reproducible Privacy Testing

कोई privacy setup तब finished नहीं होता जब वह connect हो जाता है। वह तब finished होता है जब उसकी claimed boundary को normal use, failure, recovery और teardown के दौरान test किया गया हो। ऐसी infrastructure के विरुद्ध test करें जिसकी ownership आपके पास हो या जिसका निरीक्षण करने की आपको authorization हो; public “leak test” sites एक और observer बन जाती हैं।

## एक छोटा authorized test environment बनाएं

तीन roles का उपयोग करें, आदर्श रूप से अलग-अलग providers/networks पर:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
प्रत्येक test से पहले रिकॉर्ड करें:

- test ID, UTC प्रारंभ/समाप्ति, operator और authorization;
- endpoint/OS/client versions और configuration hash;
- अपेक्षित IPv4, IPv6, DNS, TLS, account, payment और physical observations;
- किन logs का निरीक्षण किया जाएगा और उनकी clocks/time zones;
- pass/fail rule और teardown time।

किसी sensitive identity का पहली बार test कभी न करें। Synthetic account और tester के स्वामित्व वाले benign unique canary values का उपयोग करें।

## Network-path test

### 1. Baseline capture करें

Privacy path को enable करने से पहले, local routes और resolvers रिकॉर्ड करें:
```bash
ip route
ip -6 route
resolvectl status
```
macOS पर `route -n get default`, `netstat -rn -f inet6`, और `scutil --dns` का उपयोग करें। आउटपुट को केवल नियंत्रित evidence store में सहेजें; इसमें local identifiers हो सकते हैं।

### 2. कनेक्ट करें और routing का निरीक्षण करें

VPN/Tor/workload namespace सक्षम करें, फिर controlled public addresses के लिए चयनित route जाँचें:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Documentation addresses को test server addresses से बदलें। पुष्टि करें कि चयनित interface/table design से मेल खाता है।

### 3. दोनों सिरों से निरीक्षण करें

Owned endpoint का URL सेट करें, फिर एक unique benign path का अनुरोध करें:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
एक वास्तविक tester-controlled domain, authenticated TLS और एक non-sensitive path token का उपयोग करें। निम्नलिखित के लिए server log का निरीक्षण करें:

- source address/ASN और expected egress;
- IPv4 बनाम IPv6;
- endpoint पर दिखाई देने वाला Host/SNI behavior;
- user agent और application headers;
- exact time और request reuse।

अलग किए गए request में `X-Forwarded-For`, unique debug headers या identity-bearing cookies न जोड़ें।

### 4. अपने canary के साथ DNS का परीक्षण करें

एक authoritative test zone configure करें, जिसके query logs पर आपका नियंत्रण हो। compartment के माध्यम से एक unique random label query करें:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
प्राधिकृत लॉग का निरीक्षण करें। यह सामान्यतः client को नहीं, बल्कि recursive resolver को देखता है। उस resolver की तुलना इच्छित VPN/Tor/application DNS design से करें। किसी random public DNS leak site की आवश्यकता नहीं है।

### 5. fail-closed behavior का परीक्षण करें

owned endpoint को लक्षित करते हुए एक benign request loop चालू रखें, फिर privacy path को रोक दें। Workload को physical interface पर switch करने के बजाय fail होना चाहिए। दोनों address families और DNS की जाँच करें:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
इन स्थितियों के दौरान दोहराएँ:

- tunnel process crash;
- Wi-Fi-to-Ethernet या hotspot switch;
- sleep/wake;
- DHCP renewal;
- captive-portal state;
- provider reconnect/key expiry।

Linux namespace/container के लिए, उसका tunnel रोकें और सत्यापित करें कि उसके पास कोई अन्य default route या resolver नहीं है:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Names और commands deployment के अनुसार अलग-अलग होते हैं। Console recovery के बिना उन्हें remote production host पर paste न करें।

### 6. Local sockets और packets का निरीक्षण करें

Authorization के साथ जाँचें कि वास्तव में कौन-सा process/interface communicate करता है:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
`TEST_SERVER_IP` को स्पष्ट रूप से अपने स्वामित्व वाले address से बदलें; असंबंधित users का व्यापक capture करने से बचें। Physical interface को tunnel/bridge peer दिखना चाहिए, जबकि clear destination traffic केवल intended layer पर मौजूद होना चाहिए।

## Tor और onion-service test

1. Tor Browser में Tor Project connection check खोलें और Tor के उपयोग की पुष्टि करें। इसे identity proof न मानें।<sup>[[1]](#references)</sup>
2. एक unique canary के साथ owned HTTPS endpoint खोलें और पुष्टि करें कि उसे Tor exit दिखाई दे रहा है, कोई identifying cookies नहीं हैं, और standard browser context है।
3. **New Identity** चुनें, अलग canary के साथ फिर से खोलें और सत्यापित करें कि local state अपेक्षा के अनुसार clear हो गई है। Exit IP का बदलना guaranteed नहीं है और न ही यह New Identity का उद्देश्य है।
4. Onion service के लिए access केवल Tor Browser के माध्यम से करें। Authorized external scan से पुष्टि करें कि service host पर कोई public listener नहीं है और application responses में कोई public hostname/IP नहीं है।
5. Origin outbound DNS/HTTP, templates, error pages, email/webhooks और third-party assets का निरीक्षण करें। कोई भी direct fetch origin या operator account को disclose कर सकता है।
6. यदि client authorization enabled है, तो पुष्टि करें कि uncredentialed clean Tor Browser connect नहीं कर सकता और credentialed Browser कर सकता है।
7. Test authorization key को rotate करें और पुष्टि करें कि revoked client access खो देता है, बिना onion identity बदले।

## Browser-compartment test

एक controlled page बनाएँ जो केवल test के लिए आवश्यक fields record करे और जिसकी retention period छोटी हो। Personal और privacy compartments की तुलना इन चीज़ों के लिए करें:

- cookies/local storage/service workers और cache;
- browser sync/login state;
- language, time zone, screen/window dimensions और fonts;
- WebRTC/network candidates;
- permissions और extension-visible modifications;
- server पर TLS/HTTP user-agent data।

Tor Browser को “more random” बनाने का प्रयास न करें। Pass condition उसके standard anonymity set के समान होना और personal state का अभाव है, न कि personal browser से maximum difference।

Copy/paste, drag/drop, downloaded-file opening, password-manager suggestions और identity-provider buttons का परीक्षण करें। ये compartments के बीच frequent bridges होते हैं।

## Operating-system isolation test

### Tails

1. Persistent Storage के बिना session में एक benign file/canary से शुरू करें।
2. पूरी तरह shut down करें, reboot करें और पुष्टि करें कि वह gone है।
3. केवल एक required persistence category enable करें, फिर दोहराएँ और पुष्टि करें कि unrelated browser/application state retain नहीं हुई है।
4. सत्यापित करें कि portal login के बाद sensitive activity के लिए Unsafe Browser का उपयोग नहीं किया जा सकता और Tor applications सामान्य रूप से reconnect करती हैं।

### Whonix/Qubes

1. Gateway/net qube को stop करें और सिद्ध करें कि Workstation/app qube IPv4, IPv6 या DNS तक नहीं पहुँच सकता।
2. केवल explicitly configured inter-qube clipboard/file path का प्रयास करें और पुष्टि करें कि अन्य shared-folder/device paths absent हैं।
3. Disposable qube में एक benign test document खोलें, उसे बंद करें और पुष्टि करें कि उसका state disappear हो जाता है।
4. जाँचें कि vault qube में कोई NetVM नहीं है और वह template/default change के माध्यम से इसे acquire नहीं कर सकता।
5. Test VM का snapshot/restore करें और निरीक्षण करें कि identity-bearing state unexpectedly वापस तो नहीं आती।

## Communications metadata test

प्रत्येक selected messenger के लिए:

1. Controlled devices पर केवल test के लिए participants बनाएँ।
2. Record करें कि registration के लिए क्या आवश्यक है: phone, app-store account, IP, push service, username या invitation।
3. Notification previews, linked desktops, wearables और backups का निरीक्षण करते हुए एक benign message भेजें।
4. Independent path पर safety/security codes verify करें।
5. Receipts/push disable करें या एक-एक करके Tor/local transports enable करें और reliability/metadata में बदलाव observe करें।
6. Test backup को export या restore करें और ठीक-ठीक document करें कि उसमें कौन-सा profile, contacts और history शामिल है।
7. Test device खोने या revoke करने पर पुष्टि करें कि शेष participants अपेक्षित key/device change देखते हैं।

Uninvolved लोगों से contact करके या abusive traffic generate करके test न करें।

## File-sanitization test

1. Original को encrypted evidence storage में hash करके preserve करें:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) में format-specific process का उपयोग करके एक साफ की गई copy बनाएं।  
3. Metadata inventories की तुलना करें:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. कॉपी को disposable context में render/open करें। hidden content, attachments, links, forms, layers, thumbnails और visual identifiers की जाँच करें।
5. ज्ञात canary author/email/path strings के लिए केवल staged copy में search करें।
6. अंतिम output को hash करें और दूसरे व्यक्ति से प्रकाशित की जा रही exact file का सत्यापन करवाएँ।

ExifTool output से अनुपस्थिति anonymity का प्रमाण नहीं है; format internals, pixels, prose और distribution records फिर भी मौजूद रहते हैं।

## Payment privacy test

सबसे छोटी अनुमत राशि या किसी official test network/sandbox का उपयोग करें:

1. payer, payee/merchant, issuer/exchange, network/node, public ledger और accountant/controller के लिए अपेक्षित view लिखें।
2. false identity के बिना एक unique test invoice/merchant context बनाएँ।
3. एक बार payment करें, फिर लागू होने पर **अपनी** receipt, statement, merchant dashboard, wallet/node log और public-chain view एकत्र करें।
4. जाँचें कि amount, timestamp, address/token, account, IP/device, delivery और refund route observer table से मेल खाते हैं या नहीं।
5. Bitcoin के लिए wallet के coin-control view में address reuse, selected inputs, change और बाद के consolidation का निरीक्षण करें।
6. shielded protocols के लिए actual pool/path और viewing key से दिखाई देने वाली जानकारी सत्यापित करें; wallet branding से privacy का अनुमान न लगाएँ।
7. e-cash/Taler के लिए छोटी राशि से backup/recovery, refund और redemption का परीक्षण करें; mint/exchange/federation boundary records को document करें।
8. किसी virtual card/test credential को revoke करें और पुष्टि करें कि बाद का authorization विफल हो, जबकि legitimate refund handling समझ में बनी रहे।
9. आवश्यक tax/authorization evidence का reconciliation करें और उसे encrypted रूप में सुरक्षित रखें।

“Privacy test” के रूप में कभी भी circular transfers, threshold-splitting, fake purchases या suspicious refunds न बनाएँ।

## Authorized red-team accountability drill

Exercise से पहले tabletop और technical drill चलाएँ:

1. एक operator प्रत्येक approved source path से benign canary launch करता है।
2. यदि blind testing का उद्देश्य हो, तो target SOC operator identity प्राप्त किए बिना यह record करता है कि वह क्या detect करता है।
3. Exercise controller escrowed map और signed job record से source → engagement → operator का resolve करता है।
4. Controller emergency stop भेजता है; operator और infrastructure owner ROE time के भीतर shutdown का प्रदर्शन करते हैं।
5. Provider abuse को सही 24/7 contact और authorization reference मिलता है।
6. Evidence में target, time, tool/job और operator दिखाई देते हैं, लेकिन अनावश्यक payload content retain नहीं किया जाता।
7. दूसरा operator credential revocation और resource teardown का सत्यापन करता है।

Readiness review को विफल मानें यदि SOC personal/home infrastructure को आसानी से देख सकता है **या** controller source को शीघ्र attribute और stop नहीं कर सकता।

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

- [1] [Tor Project — Connection जाँच](https://check.torproject.org/)
- [2] [WireGuard — Routing और Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ और metadata guidance](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Information Security Testing और Assessment के लिए Technical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
