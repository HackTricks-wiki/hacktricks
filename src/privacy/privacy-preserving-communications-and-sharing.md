# Mawasiliano na Kushiriki Yanayolinda Faragha

{{#include ../banners/hacktricks-training.md}}

Usimbaji fiche wa mwisho-hadi-mwisho hulinda maudhui. Haufichi kiotomatiki akaunti, nambari ya simu, grafu ya mawasiliano, anwani ya IP, tokeni ya push, hakikisho la arifa, muda, metadata ya faili au tabia ya mpokeaji. Chagua tool kulingana na metadata inayoweza kuondoa na waangalizi inaowaongezea.

## Linganisha miundo ya mawasiliano

| Tool/model | Sifa muhimu | Waangalizi na vikwazo vilivyosalia |
|---|---|---|
| Signal | E2EE iliyokomaa; usernames zinaweza kuanzisha mawasiliano bila kushiriki nambari; sealed sender hupunguza metadata ya service | Nambari ya simu inahitajika kwa usajili; service, mtoa huduma wa push, contacts na endpoints huhifadhi baadhi ya taarifa |
| SimpleX | Hakuna kitambulisho cha mtumiaji cha kimataifa; foleni za kila contact; Tor transport ya hiari | Muda/transport wa relay, service ya push, mialiko na endpoints; ecosystem mpya/ndogo |
| Briar | Usawazishaji wa moja kwa moja; Tor ikiwa online; Bluetooth/Wi-Fi ikiwa offline; hakuna central message store | Contacts na endpoints; waangalizi wa radio za eneo; inalenga Android; pande zote lazima zipatikane au zitumie Mailbox |
| OnionShare | Kushiriki faili/kupokea/chat/site moja kwa moja kupitia temporary onion service; hakuna storage provider | Kompyuta ya mtumaji ndiyo service; mwenye link hujua access; muda na endpoints bado vinaonekana |
| `age` encrypted file | Usimbaji fiche rahisi wa recipient-key usiotegemea transport | Transport huona mtumaji/mpokeaji/muda/ukubwa; majina ya faili/metadata ya archive na endpoints bado vinaonekana |
| Ordinary email + TLS | Usimbaji fiche wa channel kati ya servers | Watoa huduma wote wa barua kwa kawaida wanaweza kusoma maudhui na kuhifadhi routing/account metadata |

## Signal: mawasiliano ya faragha bila kufichua nambari

Signal usernames zinaweza kuanzisha chat bila kufichua nambari ya simu ya mtumiaji kwa contact mpya, lakini nambari ya simu bado inahitajika kwa usajili.<sup>[[1]](#references)</sup> Sealed sender ni ulinzi wa ziada wa metadata, si kinga dhidi ya correlation yote ya IP/muda.<sup>[[2]](#references)</sup>

### Workflow

1. Sakinisha Signal kutoka official app store/project na usasishe OS kwanza.
2. Jisajili kwa nambari ambayo una haki kisheria ya kuitumia. Usitumie rented SMS activations, nambari ya mtu mwingine au akaunti ya provider iliyopatikana kwa utambulisho wa uongo.
3. Katika **Settings → Privacy → Phone Number**, weka ni nani anayeweza kuona nambari na ni nani anayeweza kupata akaunti kwa nambari kulingana na threat model.
4. Tengeneza username kwa ajili ya new-contact discovery. Shiriki link/QR yake halisi kupitia channel iliyothibitishwa tayari; usernames zinaweza kubadilika na si profile name.
5. Zima contact upload/permissions ikiwa urahisi wake haufai kwa linkage, na ongeza contacts mwenyewe pale platform inapowezesha.
6. Fungua maelezo ya contact na ulinganishe safety number/QR kupitia channel ya pili au ana kwa ana kabla ya kutuma maudhui nyeti.
7. Kagua linked devices, registration lock/PIN, notification previews, screen security, call relaying, mipangilio chaguomsingi ya disappearing messages na tabia ya backup.
8. Tuma ujumbe wa majaribio usio nyeti na piga simu. Kagua lock-screen, desktop, wearable na cloud-notification traces kwa pande zote.
9. Chukulia safety number iliyobadilika au linked device isiyotarajiwa kama tukio la uchunguzi, si alert ya kupuuzwa kiotomatiki.

Usichanganye pseudonymous profile photo, bio, group membership au ratiba na Signal context inayokutambulisha.

## SimpleX: connections za kila contact bila global identifier

SimpleX hupitisha messages kupitia foleni za mwelekeo mmoja na haitoi network-wide user identifier. Policy yake yenyewe bado huandika kuhusu transport sessions, temporary server data, tradeoffs za push notifications na jukumu la endpoint.<sup>[[3]](#references)</sup>

### Workflow

1. Pakua client inayodumishwa kutoka official project/store na uthibitishe publisher. Tumia dedicated OS/app profile wakati identities hazipaswi kuchanganywa.
2. Tengeneza **local** profile yenye display name na image maalum kwa context. Kufuta app bila backup kunaweza kupoteza profile na connections.
3. Wakati wa uzinduzi wa kwanza, chagua notification mode kwa makusudi. Instant mobile push inaweza kufichua metadata ya ziada kwa Apple/Google infrastructure.
4. Tengeneza one-time invitation link kwa contact mmoja. Ipitishwe kupitia authenticated channel; mtu yeyote anayepata invitation hai anaweza kujaribu kuitumia.
5. Baada ya kuunganisha, fungua maelezo ya contact na ulinganishe security code ana kwa ana au kupitia independent verified channel.<sup>[[4]](#references)</sup>
6. Tumia incognito per-group profile inapowezekana badala ya kutumia tena profile ileile katika groups zisizohusiana.
7. Sanidi supported Tor transport ya client ikiwa local network/server haipaswi kuona direct IP. Thibitisha connection baada ya mabadiliko; usilazimishe unsupported system proxy.
8. Kagua delivery receipts, link previews, calls, automatic downloads na database export/backup. Kila moja hubadilisha metadata au endpoint exposure.
9. Jaribu recovery kwenye spare isolated device bila kuendesha duplicated live profile state; project inaonya kuwa concurrent copies zinaweza kuvuruga conversations.

Kutokuwepo kwa global identifier hakumzuii contact kumtambua mtumiaji kupitia maudhui, profile reuse, invitation delivery, muda au social graph.

## Briar: messaging ya moja kwa moja na inayostahimili disruptions

Briar husawazisha moja kwa moja kati ya vifaa, kupitia Tor ikiwa online na kupitia Bluetooth/Wi-Fi wakati wa outages za eneo. Official threat model inachukulia kuwa kuna ufuatiliaji mdogo tu wa adui kwenye short-range radio, hivyo local wireless si ya siri kabisa.<sup>[[5]](#references)</sup>

### Workflow

1. Sakinisha kutoka official Briar distribution na uthibitishe package source. Tumia Android device inayoungwa mkono yenye security updates za sasa.
2. Tengeneza local account yenye context nickname ya kipekee na password imara. Hakuna password-reset path; jaribu kuhakikisha unlock secret inaweza kupatikana tena.
3. Ongeza contacts ana kwa ana kwa kuscan QR codes za kila mmoja inapowezekana. Hii huthibitisha contact na huepuka kutuma link kupitia channel inayoweza ku-correlate.
4. Katika connectivity settings, washa transports zinazohitajika pekee: Tor/Internet, Wi-Fi na/au Bluetooth. Zima local radios zisipohitajika.
5. Kwa asynchronous delivery, tathmini Briar Mailbox kwenye dedicated powered device; iorodheshe na ilinde kimwili kama message server.
6. Tuma test isiyo nyeti wakati Internet inapatikana, kisha jaribu outage path iliyopangwa Internet ikiwa imezimwa katika eneo lililoidhinishwa na owner.
7. Kagua Android backups, notification previews, screenshots na exported content. Local encrypted storage hufichuka endpoint inapokuwa unlocked/compromised.
8. Ondoa contacts/devices zilizopotea na retire context nzima ikiwa physical custody au account password imecompromise.

## OnionShare: temporary transfer ya moja kwa moja

OnionShare huendesha onion service kwenye kompyuta ya mtumaji/mpokeaji; faili hazipakiwi kwa storage provider, na traffic husimbwa fiche kutoka mwisho hadi mwisho ndani ya Tor.<sup>[[6]](#references)</sup> Onion URL kamili ni bearer capability na lazima ilindwe.

### GUI file-sharing workflow

1. Sakinisha OnionShare kutoka official signed distribution yake na Tor Browser upande wa mpokeaji.
2. Weka **sanitized copies** za faili kwenye dedicated staging directory. Usielekeze OnionShare kwenye personal home directory.
3. Fungua **Share Files**, ongeza faili za staging pekee, acha private key/access protection ikiwa imewashwa, na uache **Stop sharing after files have been sent** ikiwa imewashwa kwa mpokeaji mmoja.
4. Anza kushiriki na tuma onion URL kamili kupitia authenticated E2EE channel iliyopo tayari. Usiiweke kwenye email, issue trackers au public chats.
5. Mpokeaji afungue URL katika Tor Browser, athibitishe filenames/size zinazotarajiwa na mtumaji, kisha apakue.
6. Pande zote zilinganishe SHA-256 digest iliyokubaliwa mapema au iliyowasilishwa kando kwa integrity wakati faili lenyewe ni security boundary.
7. Thibitisha OnionShare ilisimama baada ya download; la sivyo isimamishe mwenyewe na ufunge application.
8. Futa staged copy kulingana na retention policy na kagua history/log settings za OnionShare ili kubaini filename disclosure isiyokusudiwa.

### CLI workflow

Official CLI hukubali faili kama positional arguments na husimama baada ya share moja chaguomsingi iliyokamilika. Kwenye host yenye official CLI/Tor iliyosakinishwa:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Wasilisha URL kamili inayotokana kwa usalama. Usiongeze `--public`, `--no-autostop-sharing`, logging ya verbose ya majina ya faili au persistence isipokuwa threat model ihitaji waziwazi exposure inayotokana.<sup>[[7]](#references)</sup>

Chukulia nyaraka zilizopokelewa kuwa hostile. Zifungue katika VM ya kutupwa/renderer ya mtindo wa Dangerzone badala ya host yenye utambulisho.

## Encrypt a file independently with `age`

Encryption inayojitegemea na transport ni muhimu wakati storage/email provider anaweza kuona object. Haifichi mtumaji, mpokeaji, ukubwa, muda au jina la faili isipokuwa mambo hayo yashughulikiwe kando.

### Recipient setup
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Thibitisha uhalali wa string ya mpokeaji wa umma kupitia njia ya pili. Kisha mtumaji anaendesha:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Mpokeaji anadecrypt hadi kwenye path mpya:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
CLI rasmi inaonya kwamba `-o` hubadilisha output iliyopo, kwa hiyo tumia directory mpya na uthibitishe digest/content kabla ya kuihamisha.<sup>[[8]](#references)</sup> Usitume kamwe faili ya utambulisho pamoja na ciphertext.

## Pipeline ya uondoaji wa metadata inayoweza kurudiwa

Uondoaji wa metadata hutegemea format. Hifadhi original iliyosimbwa kwa encryption wakati authenticity, forensics au chain of custody ni muhimu; fanyia kazi nakala.

### Mfano wa JPEG
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
Hii inafuata mwongozo salama wa ExifTool kuhusu JPEG: kuondoa kila tag bila kuchunguza kunaweza pia kuondoa taarifa za rangi.<sup>[[9]](#references)</sup> Kisha kagua pikseli kwa macho ili kubaini nyuso, mionekano, skrini, alama za maeneo na mifumo ya kipekee ya uharibifu/kelele.

### Mtiririko wa Office/PDF

1. Hifadhi nakala asili inayoweza kuhaririwa ikiwa encrypted na nje ya mtandao wa muktadha wa uchapishaji.
2. Ondoa maoni, mabadiliko yaliyofuatiliwa, slaidi/laha zilizofichwa, faili zilizopachikwa, templates binafsi na sifa za hati katika application ya uandishi.
3. Export PDF mpya kutoka kwenye profile maalum safi; usi-“print” kwenda kwenye cloud printer.
4. Kagua kwa kutumia tools zinazotambua format pamoja na visual renderer ya matumizi ya mara moja:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Tafuta kwenye matokeo yaliyotolewa majina, paths, anwani za barua pepe na maandishi ya marekebisho. Rasterization inaweza kuondoa miundo inayotenda kazi lakini huharibu accessibility/search na haiondoi maudhui yanayoonekana au mtindo wa uandishi.
6. Tengeneza hash ya artifact ya mwisho na uhamishe **nakala hiyo pekee** kupitia publication compartment.

## Privacy Pass: idhini isiyojulikana kwa wabuni wa services

Privacy Pass hutenganisha **utoaji** wa tokeni na **ukomboaji** wake. Origin inaweza kujua kwamba client anamiliki tokeni iliyoidhinishwa na issuer bila kujua interaction mahususi ya client wakati wa utoaji. Kutumia tena tokeni, metadata ya kipekee, timing au collusion kunaweza kurejesha linkability.<sup>[[10]](#references)</sup>

Muundo salama wa deployment:

1. Bainisha taarifa inayothibitishwa na tokeni (kwa mfano, kustahiki rate-limit), badala ya identity ya kimataifa iliyofichwa.
2. Tumia architecture na issuance protocols zilizosanifishwa; usiimplement blind-signature cryptography kutoka mwanzo.
3. Tenganisha usimamizi wa issuer/attester na origin pale property inayohitajika inapohitaji hivyo.
4. Punguza metadata ya tokeni ya umma/ya faragha na uhakikishe kuwa anonymity sets ni kubwa vya kutosha.
5. Toa batches kabla ya matumizi pale inapowezekana ili muda wa issuance usilingane kwa urahisi na muda wa redemption.
6. Redeem kila tokeni mara moja, validate challenge iliyofungwa kwa origin, na delete state ya tokeni zilizo-expire.
7. Zuia cookies, IP logging na application accounts zisivuruge kimya kimya privacy property ya tokeni.
8. Test kama logs za issuer na origin zinaweza kuunganisha tukio lililodhibitiwa la issuance na redemption kwa kutumia timing, metadata au errors za kipekee.

Privacy Pass ni feature ya application, si kitu ambacho user anaweza kuongeza kwenye account yoyote kiholela.

## Communications verification checklist

- [ ] Contact/invitation/key ilithibitishwa kwa kujitegemea.
- [ ] Exposure ya nambari ya simu, username, profile, group na contact-upload imeeleweka.
- [ ] Direct IP, relay, Tor, push-provider na local-radio observers wameorodheshwa.
- [ ] Notification previews, wearables, linked desktops na backups zilifanyiwa test.
- [ ] Files zilisafishwa, zikasimbwa kwa encryption inapohitajika na kufunguliwa katika disposable context.
- [ ] Recovery inafanya kazi bila kuunganisha identities zisizohusiana.
- [ ] Logs, history na temporary share services zina shutdown/retention rule.

## References

- [1] [Signal — Faragha ya Nambari za Simu na Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy na Masharti ya Matumizi](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Mwongozo wa Privacy na Security](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Jinsi inavyofanya kazi](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Muundo wa Security](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Matumizi ya Juu na CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI rasmi na matumizi](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Kuondoa metadata kwa usalama](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architecture ya Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
