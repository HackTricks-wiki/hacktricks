# Privacy-Preserving Communications and Sharing

{{#include ../banners/hacktricks-training.md}}

End-to-end encryption सामग्री की सुरक्षा करता है। यह अपने-आप account, phone number, contact graph, IP address, push token, notification preview, timing, file metadata या recipient behavior को छिपा नहीं देता। किसी tool का चयन इस आधार पर करें कि वह कौन-सा metadata हटाता है और किन observers को शामिल करता है।

## Communication models की तुलना करें

| Tool/model | उपयोगी विशेषता | शेष observers और सीमाएं |
|---|---|---|
| Signal | Mature E2EE; usernames number share किए बिना contact शुरू कर सकते हैं; sealed sender service metadata को कम करता है | Registration के लिए phone number आवश्यक है; service, push provider, contacts और endpoints कुछ observations बनाए रखते हैं |
| SimpleX | कोई global user identifier नहीं; per-contact queues; optional Tor transport | Relay timing/transport, push service, invitations और endpoints; नया/छोटा ecosystem |
| Briar | Direct synchronization; online होने पर Tor; offline होने पर Bluetooth/Wi-Fi; कोई central message store नहीं | Contacts और endpoints; local radio observers; Android-focused; दोनों sides उपलब्ध होने चाहिए या Mailbox का उपयोग करना होगा |
| OnionShare | Temporary onion service के माध्यम से direct file/receive/chat/site; कोई storage provider नहीं | Sender computer ही service है; link bearer access जानता है; timing और endpoints बने रहते हैं |
| `age` encrypted file | Transport से स्वतंत्र सरल recipient-key encryption | Transport sender/recipient/timing/size देखता है; filenames/archive metadata और endpoints बने रहते हैं |
| Ordinary email + TLS | Server-to-server channel encryption | दोनों mail providers सामान्यतः content पढ़ सकते हैं और routing/account metadata बनाए रख सकते हैं |

## Signal: number disclosure के बिना private contact

Signal usernames नए contact को user's phone number बताए बिना chat शुरू कर सकते हैं, लेकिन registration के लिए phone number अब भी आवश्यक है।<sup>[[1]](#references)</sup> Sealed sender एक incremental metadata protection है, सभी IP/timing correlation के विरुद्ध सुरक्षा नहीं।<sup>[[2]](#references)</sup>

### Workflow

1. Signal को official app store/project से install करें और पहले OS को update करें।
2. ऐसे number से register करें जिसे उपयोग करने का आपको कानूनी अधिकार हो। Rented SMS activations, किसी अन्य व्यक्ति का number या false identity से प्राप्त provider account का उपयोग न करें।
3. **Settings → Privacy → Phone Number** में threat model के अनुसार तय करें कि number कौन देख सकता है और number से account कौन खोज सकता है।
4. New-contact discovery के लिए username बनाएं। इसका exact link/QR पहले से authenticated channel के माध्यम से share करें; usernames बदल सकते हैं और profile name नहीं होते।
5. यदि convenience linkage के योग्य नहीं है, तो contact upload/permissions disable करें और जहाँ platform support करता हो वहाँ contacts manually add करें।
6. Sensitive content भेजने से पहले contact details खोलें और safety number/QR की तुलना दूसरे channel या आमने-सामने करें।
7. Linked devices, registration lock/PIN, notification previews, screen security, call relaying, disappearing-message defaults और backup behavior की समीक्षा करें।
8. Non-sensitive test message और call भेजें। दोनों sides पर lock-screen, desktop, wearable और cloud-notification traces की जाँच करें।
9. बदले हुए safety number या unexpected linked device को investigation event मानें, न कि ऐसा alert जिसे automatically dismiss कर दिया जाए।

Pseudonymous profile photo, bio, group membership या schedule को identifying Signal context के साथ mix न करें।

## SimpleX: global identifier के बिना per-contact connections

SimpleX messages को unidirectional queues के माध्यम से route करता है और network-wide user identifier assign नहीं करता। इसकी अपनी policy transport sessions, temporary server data, push-notification tradeoffs और endpoint responsibility का documentation देती है।<sup>[[3]](#references)</sup>

### Workflow

1. Official project/store से maintained client download करें और publisher verify करें। जब identities को mix नहीं करना हो, तो dedicated OS/app profile का उपयोग करें।
2. Context-specific display name और image के साथ एक **local** profile बनाएं। Backup के बिना app delete करने पर profile और connections खो सकते हैं।
3. First launch पर notification mode को सोच-समझकर चुनें। Instant mobile push Apple/Google infrastructure को अतिरिक्त metadata expose कर सकता है।
4. एक contact के लिए one-time invitation link बनाएं। इसे authenticated channel के माध्यम से transfer करें; live invitation प्राप्त करने वाला कोई भी व्यक्ति उसका उपयोग करने का प्रयास कर सकता है।
5. Connect होने के बाद contact details खोलें और security code की तुलना आमने-सामने या independent verified channel पर करें।<sup>[[4]](#references)</sup>
6. जहाँ supported हो, उसी profile को unrelated groups में recycle करने के बजाय प्रति-group incognito profile का उपयोग करें।
7. यदि local network/server को direct IP नहीं दिखना चाहिए, तो client के supported Tor transport को configure करें। बदलाव के बाद connection confirm करें; unsupported system proxy को force न करें।
8. Delivery receipts, link previews, calls, automatic downloads और database export/backup की समीक्षा करें। इनमें से प्रत्येक metadata या endpoint exposure को बदलता है।
9. किसी spare isolated device पर recovery का परीक्षण करें, लेकिन duplicated live profile state न चलाएं; project चेतावनी देता है कि concurrent copies conversations को disrupt कर सकती हैं।

Global identifier न होने से contact को content, profile reuse, invitation delivery, timing या social graph के माध्यम से user की पहचान करने से नहीं रोका जा सकता।

## Briar: direct और disruption-resistant messaging

Briar devices के बीच सीधे synchronize करता है, online होने पर Tor के माध्यम से और local outages के दौरान Bluetooth/Wi-Fi के माध्यम से। Official threat model short-range radio की केवल limited adversarial monitoring मानता है, इसलिए local wireless invisible नहीं है।<sup>[[5]](#references)</sup>

### Workflow

1. Official Briar distribution से install करें और package source verify करें। Current security updates वाले supported Android device का उपयोग करें।
2. Unique context nickname और strong password के साथ local account बनाएं। Password-reset path नहीं है; सुनिश्चित करें कि unlock secret recover किया जा सकता है।
3. जब संभव हो, एक-दूसरे के QR codes scan करके face-to-face contacts add करें। इससे contact authenticate होता है और correlatable channel के माध्यम से link भेजने से बचा जा सकता है।
4. Connectivity settings में केवल आवश्यक transports enable करें: Tor/Internet, Wi-Fi और/या Bluetooth। आवश्यकता न होने पर local radios disable करें।
5. Asynchronous delivery के लिए dedicated powered device पर Briar Mailbox का मूल्यांकन करें; इसे message server की तरह inventory करें और physical रूप से सुरक्षित रखें।
6. Internet उपलब्ध होने पर benign test भेजें, फिर owner-authorized location में Internet disable करके planned outage path का परीक्षण करें।
7. Android backups, notification previews, screenshots और exported content की जाँच करें। Endpoint unlocked/compromised होने पर local encrypted storage expose हो जाती है।
8. Lost contacts/devices हटाएं और physical custody या account password compromise होने पर पूरे context को retire करें।

## OnionShare: direct temporary transfer

OnionShare sender/receiver के computer पर onion service चलाता है; files किसी storage provider पर upload नहीं की जातीं और traffic Tor के भीतर end-to-end encrypted होता है।<sup>[[6]](#references)</sup> Complete onion URL एक bearer capability है और इसे सुरक्षित रखना आवश्यक है।

### GUI file-sharing workflow

1. OnionShare को इसकी official signed distribution से install करें और recipient side पर Tor Browser install करें।
2. Files की **sanitized copies** dedicated staging directory में रखें। OnionShare को personal home directory पर point न करें।
3. **Share Files** खोलें, केवल staged files add करें, private key/access protection enabled रहने दें और one recipient के लिए **Stop sharing after files have been sent** enabled रखें।
4. Sharing शुरू करें और complete onion URL को पहले से authenticated E2EE channel के माध्यम से भेजें। इसे email, issue trackers या public chats में paste न करें।
5. Recipient Tor Browser में URL खोलता है, sender के साथ expected filenames/size verify करता है और download करता है।
6. जब file स्वयं security boundary हो, तो दोनों sides integrity के लिए pre-agreed या separately delivered SHA-256 digest की तुलना करें।
7. Confirm करें कि download के बाद OnionShare stopped है; अन्यथा इसे manually stop करें और application बंद करें।
8. Retention policy के अनुसार staged copy delete करें और unintended filename disclosure के लिए OnionShare history/log settings की जाँच करें।

### CLI workflow

Official CLI files को positional arguments के रूप में स्वीकार करता है और default single completed share के बाद stop हो जाता है। Official CLI/Tor installed वाले host पर:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
परिणामी full URL को सुरक्षित रूप से साझा करें। जब तक threat model में परिणामी exposure की स्पष्ट आवश्यकता न हो, `--public`, `--no-autostop-sharing`, verbose filename logging या persistence न जोड़ें।<sup>[[7]](#references)</sup>

प्राप्त documents को hostile मानें। उन्हें identity-bearing host पर खोलने के बजाय disposable VM/Dangerzone-style renderer में खोलें।

## `age` से किसी file को स्वतंत्र रूप से encrypt करें

Transport-independent encryption तब उपयोगी होता है जब कोई storage/email provider object को देख सकता हो। यह sender, recipient, size, timing या filename को छिपाता नहीं है, जब तक उन्हें अलग से handle न किया जाए।

### Recipient setup
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
दूसरे चैनल के माध्यम से public recipient string को authenticate करें। इसके बाद sender चलाता है:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
प्राप्तकर्ता एक नए path पर decrypt करता है:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Official CLI चेतावनी देता है कि `-o` मौजूदा output को overwrite कर देता है, इसलिए नई directory का उपयोग करें और उसे स्थानांतरित करने से पहले digest/content सत्यापित करें।<sup>[[8]](#references)</sup> ciphertext के साथ identity file कभी न भेजें।

## पुनरुत्पाद्य file-sanitization pipeline

Metadata stripping format-specific होता है। जब authenticity, forensics या chain of custody महत्वपूर्ण हों, तो encrypted original सुरक्षित रखें; किसी copy पर कार्य करें।

### JPEG उदाहरण
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
यह ExifTool की अधिक सुरक्षित JPEG guidance का अनुसरण करता है: हर tag को बिना सोचे हटाने से color information भी हट सकती है।<sup>[[9]](#references)</sup> इसके बाद faces, reflections, screens, landmarks और damage/noise के विशिष्ट patterns के लिए pixels का दृश्य निरीक्षण करें।

### Office/PDF कार्यप्रवाह

1. Editable original को encrypted रखें और publication context से offline रखें।
2. Authoring application में comments, tracked changes, hidden slides/sheets, embedded files, personal templates और document properties हटाएँ।
3. Dedicated clean profile से नया PDF export करें; इसे cloud printer पर “print” न करें।
4. Format-aware tools और disposable visual renderer—दोनों से निरीक्षण करें:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Render किए गए output में names, paths, email addresses और revision text खोजें। Rasterization active structures को हटा सकता है, लेकिन accessibility/search को नुकसान पहुंचाता है और visible content या writing style को नहीं हटाता।
6. Final artifact का hash बनाएं और publication compartment के माध्यम से **केवल** उसी copy को transfer करें।

## Privacy Pass: service designers के लिए anonymous authorization

Privacy Pass token **issuance** को **redemption** से अलग करता है। कोई origin यह जान सकता है कि client के पास issuer-approved token है, लेकिन client के specific issuance interaction को जाने बिना। किसी token का पुनः उपयोग, unique metadata, timing या collusion फिर से linkability ला सकता है।<sup>[[10]](#references)</sup>

Safe deployment pattern:

1. वह statement define करें जिसे token prove करता है (उदाहरण के लिए, rate-limit eligibility), न कि कोई छिपी हुई global identity।
2. Standardized architecture और issuance protocols का उपयोग करें; blind-signature cryptography को scratch से implement न करें।
3. जहां वांछित property के लिए आवश्यक हो, issuer/attester और origin administration को अलग रखें।
4. Public/private token metadata को न्यूनतम रखें और सुनिश्चित करें कि anonymity sets पर्याप्त बड़े हों।
5. जहां supported हो, उपयोग से पहले batches issue करें ताकि issuance time, redemption time से आसानी से match न हो सके।
6. प्रत्येक token को केवल एक बार redeem करें, origin-bound challenge को validate करें और expired token state को delete करें।
7. Cookies, IP logging और application accounts को token privacy property को चुपचाप निष्प्रभावी करने से रोकें।
8. Test करें कि क्या issuer और origin logs timing, metadata या unique errors का उपयोग करके किसी controlled issuance और redemption event को join कर सकते हैं।

Privacy Pass एक application feature है; इसे user किसी arbitrary account पर बस जोड़ नहीं सकता।

## Communications verification checklist

- [ ] Contact/invitation/key को independently authenticated किया गया।
- [ ] Phone number, username, profile, group और contact-upload exposure को समझा गया।
- [ ] Direct IP, relay, Tor, push-provider और local-radio observers की सूची बनाई गई।
- [ ] Notification previews, wearables, linked desktops और backups का परीक्षण किया गया।
- [ ] Files को sanitized किया गया, आवश्यकता होने पर encrypted किया गया और disposable context में खोला गया।
- [ ] Recovery, unrelated identities को bridge किए बिना काम करता है।
- [ ] Logs, history और temporary share services के लिए shutdown/retention rule मौजूद है।

## References

- [1] [Signal — Phone Number Privacy और Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy और Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy और security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — यह कैसे काम करता है](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage और CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — official CLI और usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Safely removing metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
