# Mawasiliano na Kushiriki Yanayolinda Faragha

Usimbaji fiche wa kutoka mwisho hadi mwisho hulinda maudhui. Haufichi kiotomatiki akaunti, nambari ya simu, grafu ya mawasiliano, anwani ya IP, push token, onyesho la arifa, muda, metadata ya faili au tabia ya mpokeaji. Chagua tool kulingana na metadata inayoweza kuondoa na watazamaji inaowaleta.

## Linganisha miundo ya mawasiliano

| Tool/model | Sifa muhimu | Watazamaji na mipaka iliyosalia |
|---|---|---|
| Signal | E2EE iliyokomaa; usernames zinaweza kuanzisha mawasiliano bila kushiriki nambari; sealed sender hupunguza service metadata | Nambari ya simu inahitajika kwa usajili; service, push provider, contacts na endpoints huhifadhi baadhi ya uangalizi |
| SimpleX | Hakuna kitambulisho cha mtumiaji cha kimataifa; foleni kwa kila contact; Tor transport ya hiari | Muda/transport wa relay, push service, mialiko na endpoints; ecosystem mpya/ndogo |
| Briar | Usawazishaji wa moja kwa moja; Tor ikiwa online; Bluetooth/Wi-Fi ikiwa offline; hakuna central message store | Contacts na endpoints; watazamaji wa local radio; inalenga Android; pande zote lazima zipatikane au zitumie Mailbox |
| OnionShare | File/receive/chat/site ya moja kwa moja kupitia temporary onion service; hakuna storage provider | Kompyuta ya mtumaji ndiyo service; mwenye link anajifunza access; muda na endpoints hubaki |
| `age` encrypted file | Usimbaji fiche rahisi wa recipient-key usiotegemea transport | Transport huona mtumaji/mpokeaji/muda/ukubwa; filenames/archive metadata na endpoints hubaki |
| Ordinary email + TLS | Usimbaji fiche wa channel kati ya server na server | Mail providers wote kwa kawaida wanaweza kusoma maudhui na kuhifadhi routing/account metadata |

## Signal: contact wa faragha bila kufichua nambari

Signal usernames zinaweza kuanzisha chat bila kufichua nambari ya simu ya mtumiaji kwa contact mpya, lakini nambari ya simu bado inahitajika kwa usajili.<sup>[[1]](#references)</sup> Sealed sender ni ulinzi wa ziada wa metadata, si kinga dhidi ya correlation yote ya IP/muda.<sup>[[2]](#references)</sup>

### Mtiririko

1. Sakinisha Signal kutoka official app store/project na usasishe OS kwanza.
2. Jisajili kwa nambari ambayo una haki ya kuitumia kisheria. Usitumie rented SMS activations, nambari ya mtu mwingine au provider account iliyopatikana kwa kutumia utambulisho wa uongo.
3. Katika **Settings → Privacy → Phone Number**, weka ni nani anayeweza kuona nambari na ni nani anayeweza kupata akaunti kwa nambari kulingana na threat model.
4. Unda username kwa ajili ya kugunduliwa na contacts wapya. Shiriki link/QR yake kamili kupitia channel ambayo tayari imethibitishwa; usernames zinaweza kubadilika na si profile name.
5. Zima contact upload/permissions ikiwa urahisi huo haufai hatari ya kuunganisha taarifa, na ongeza contacts mwenyewe pale platform inapounga mkono.
6. Fungua maelezo ya contact na linganisha safety number/QR kupitia channel ya pili au ana kwa ana kabla ya kutuma maudhui nyeti.
7. Kagua linked devices, registration lock/PIN, notification previews, screen security, call relaying, disappearing-message defaults na tabia ya backup.
8. Tuma ujumbe wa majaribio usio nyeti na piga simu. Kagua lock-screen, desktop, wearable na cloud-notification traces kwa pande zote.
9. Ichukulie safety number iliyobadilika au linked device isiyotarajiwa kama tukio la uchunguzi, si alert ya kupuuza kiotomatiki.

Usichanganye pseudonymous profile photo, bio, group membership au ratiba na Signal context inayotambulisha.

## SimpleX: connections za kila contact bila global identifier

SimpleX hupitisha messages kupitia foleni za mwelekeo mmoja na haitengei mtumiaji network-wide user identifier. Policy yake yenyewe bado inaeleza transport sessions, temporary server data, tradeoffs za push notifications na wajibu wa endpoint.<sup>[[3]](#references)</sup>

### Mtiririko

1. Pakua client inayodumishwa kutoka official project/store na uthibitishe publisher. Tumia dedicated OS/app profile wakati identities hazipaswi kuchanganywa.
2. Unda profile ya **local** yenye display name na image maalum kwa context. Kufuta app bila backup kunaweza kupoteza profile na connections.
3. Wakati wa uzinduzi wa kwanza, chagua notification mode kwa makusudi. Instant mobile push inaweza kufichua metadata ya ziada kwa Apple/Google infrastructure.
4. Unda invitation link ya matumizi ya mara moja kwa contact mmoja. Ihamishe kupitia channel iliyothibitishwa; mtu yeyote anayepata invitation inayotumika anaweza kujaribu kuitumia.
5. Baada ya kuunganisha, fungua maelezo ya contact na linganisha security code ana kwa ana au kupitia independent verified channel.<sup>[[4]](#references)</sup>
6. Tumia incognito per-group profile inapoungwa mkono badala ya kutumia tena profile ileile katika groups zisizohusiana.
7. Sanidi supported Tor transport ya client ikiwa local network/server haipaswi kuona direct IP. Thibitisha connection baada ya mabadiliko; usilazimishe unsupported system proxy.
8. Kagua delivery receipts, link previews, calls, automatic downloads na database export/backup. Kila kimoja hubadilisha metadata au endpoint exposure.
9. Jaribu recovery kwenye spare isolated device bila kuendesha duplicated live profile state; project inaonya kwamba copies zinazotumika kwa wakati mmoja zinaweza kuvuruga conversations.

Kutokuwepo kwa global identifier hakumzuii contact kumtambua mtumiaji kupitia maudhui, matumizi tena ya profile, delivery ya invitation, muda au social graph.

## Briar: messaging ya moja kwa moja inayostahimili disruptions

Briar husawazisha moja kwa moja kati ya devices, kupitia Tor ikiwa online na kupitia Bluetooth/Wi-Fi wakati wa outages za eneo. Threat model rasmi huchukulia ufuatiliaji wa kinyume wa local radio wa kiwango kidogo tu, kwa hiyo local wireless si invisible.<sup>[[5]](#references)</sup>

### Mtiririko

1. Sakinisha kutoka official Briar distribution na uthibitishe package source. Tumia supported Android device yenye security updates za sasa.
2. Unda local account yenye context nickname ya kipekee na password imara. Hakuna password-reset path; thibitisha kwamba unlock secret inaweza kurejeshwa.
3. Ongeza contacts ana kwa ana kwa kuscan QR codes za kila mmoja inapowezekana. Hii huthibitisha contact na huepuka kutuma link kupitia channel inayoweza ku-correlate.
4. Katika connectivity settings, wezesha transports zinazohitajika tu: Tor/Internet, Wi-Fi na/au Bluetooth. Zima local radios zisipohitajika.
5. Kwa asynchronous delivery, tathmini Briar Mailbox kwenye dedicated powered device; ihesabu na ilinde kimwili kama message server.
6. Tuma test isiyo na madhara wakati Internet inapatikana, kisha jaribu outage path iliyopangwa Internet ikiwa imezimwa katika eneo lililoidhinishwa na owner.
7. Kagua Android backups, notification previews, screenshots na exported content. Local encrypted storage hufichuka endpoint ikiwa unlocked/compromised.
8. Ondoa contacts/devices zilizopotea na acha kutumia context nzima ikiwa physical custody au account password imecompromise.

## OnionShare: transfer ya moja kwa moja ya muda

OnionShare huendesha onion service kwenye kompyuta ya mtumaji/mpokeaji; files hazipakizwi kwa storage provider, na traffic husimbwa fiche kutoka mwisho hadi mwisho ndani ya Tor.<sup>[[6]](#references)</sup> Onion URL kamili ni bearer capability na lazima ilindwe.

### GUI file-sharing workflow

1. Sakinisha OnionShare kutoka official signed distribution yake na Tor Browser upande wa mpokeaji.
2. Weka **sanitized copies** za files kwenye dedicated staging directory. Usielekeze OnionShare kwenye personal home directory.
3. Fungua **Share Files**, ongeza staged files pekee, acha private key/access protection ikiwa imewezeshwa, na uache **Stop sharing after files have been sent** ikiwa imewezeshwa kwa mpokeaji mmoja.
4. Anza sharing na utume onion URL kamili kupitia E2EE channel ambayo tayari imethibitishwa. Usiibandike kwenye email, issue trackers au public chats.
5. Mpokeaji hufungua URL katika Tor Browser, anathibitisha filenames/size zinazotarajiwa na mtumaji, kisha anapakua.
6. Pande zote mbili zilinganishe SHA-256 digest iliyokubaliwa mapema au iliyowasilishwa kando kwa ajili ya integrity wakati file yenyewe ndiyo security boundary.
7. Thibitisha kwamba OnionShare ilisimama baada ya download; vinginevyo isimamishe mwenyewe na ufunge application.
8. Futa staged copy kulingana na retention policy na kagua history/log settings za OnionShare ili kubaini filename disclosure isiyokusudiwa.

### CLI workflow

Official CLI hupokea files kama positional arguments na husimama baada ya share moja iliyokamilika kwa default. Kwenye host yenye official CLI/Tor iliyosakinishwa:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Wasilisha URL kamili inayotokana kwa usalama. Usiongeze `--public`, `--no-autostop-sharing`, logging ya kina ya majina ya faili au persistence isipokuwa threat model inahitaji waziwazi exposure inayotokana.<sup>[[7]](#references)</sup>

Chukulia nyaraka zilizopokelewa kuwa hatari. Zifungue kwenye VM ya matumizi ya muda mfupi/renderer ya mtindo wa Dangerzone badala ya kwenye host yenye utambulisho.

## Encrypt faili kwa kujitegemea kwa `age`

Encryption isiyotegemea transport ni muhimu wakati provider wa storage/email anaweza kuona object. Haifichi mtumaji, mpokeaji, ukubwa, muda au filename isipokuwa vitu hivyo vishughulikiwe kando.

### Usanidi wa mpokeaji
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Thibitisha public recipient string kupitia channel ya pili. Kisha sender anaendesha:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Mpokeaji hufanya decrypt kwenye path mpya:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
CLI rasmi inaonya kwamba `-o` hubatilisha output iliyopo, kwa hivyo tumia directory mpya na uthibitishe digest/content kabla ya kuihamisha.<sup>[[8]](#references)</sup> Kamwe usitume identity file pamoja na ciphertext.

## Pipeline inayoweza kurudiwa ya kusafisha faili

Kuondoa metadata hutegemea format. Hifadhi nakala asili iliyosimbwa kwa encryption wakati uhalisi, forensics au chain of custody ni muhimu; fanyia kazi nakala.

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
Hii inafuata mwongozo salama wa JPEG wa ExifTool: kuondoa kila tag bila kuchagua kunaweza pia kuondoa taarifa za rangi.<sup>[[9]](#references)</sup> Kisha kagua pikseli kwa kuonekana ili kutafuta nyuso, vielelezo, skrini, alama za maeneo na mifumo ya kipekee ya uharibifu/kelele.

### Mtiririko wa kazi wa Office/PDF

1. Hifadhi nakala asili inayoweza kuhaririwa ikiwa imesimbwa na ikiwa nje ya mtandao wa muktadha wa uchapishaji.
2. Ondoa maoni, mabadiliko yanayofuatiliwa, slaidi/laha zilizofichwa, faili zilizopachikwa, templeti za kibinafsi na sifa za hati katika application ya uandishi.
3. Export PDF mpya kutoka kwenye profile safi iliyojitolea; usitumie “print” kwenda kwenye cloud printer.
4. Kagua kwa kutumia zana zinazotambua format pamoja na visual renderer inayoweza kutupwa:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Tafuta katika matokeo yaliyotolewa majina, paths, anwani za barua pepe na maandishi ya revision. Rasterization inaweza kuondoa miundo amilifu lakini huharibu accessibility/search na haiondoi maudhui yanayoonekana au mtindo wa uandishi.
6. Tengeneza hash ya artifact ya mwisho na uhamishe **nakala hiyo pekee** kupitia publication compartment.

## Privacy Pass: uidhinishaji usiojulikana kwa wabunifu wa huduma

Privacy Pass hutenganisha **utoaji** wa token na **ukomboaji** wake. Origin inaweza kujua kwamba client ana token iliyoidhinishwa na issuer bila kujua interaction mahususi ya issuance ya client. Kutumia tena token, metadata ya kipekee, timing au collusion kunaweza kurejesha linkability.<sup>[[10]](#references)</sup>

Muundo salama wa deployment:

1. Bainisha statement ambayo token inathibitisha (kwa mfano, ustahiki wa rate-limit), badala ya identity ya kimataifa iliyofichwa.
2. Tumia architecture na issuance protocols zilizosanifiwa; usiimplement blind-signature cryptography kutoka mwanzo.
3. Tenganisha usimamizi wa issuer/attester na origin pale property inayohitajika inapohitaji hivyo.
4. Punguza metadata ya token ya umma/privati na uhakikishe kuwa anonymity sets ni kubwa vya kutosha.
5. Toa batches kabla ya matumizi pale inapowezekana ili issuance time isilingane moja kwa moja na redemption time.
6. Redeem kila token mara moja, validate origin-bound challenge, na ufute token state iliyo-expire.
7. Zuia cookies, IP logging na application accounts kushinda kwa siri property ya privacy ya token.
8. Jaribu ikiwa issuer na origin logs zinaweza kuunganisha tukio linalodhibitiwa la issuance na redemption kwa kutumia timing, metadata au errors za kipekee.

Privacy Pass ni feature ya application, si kitu ambacho user anaweza kuongeza kwenye account yoyote kiholela.

## Orodha ya ukaguzi wa verification ya mawasiliano

- [ ] Contact/invitation/key ilithibitishwa kwa kujitegemea.
- [ ] Exposure ya phone number, username, profile, group na contact-upload imeeleweka.
- [ ] Direct IP, relay, Tor, push-provider na local-radio observers zimeorodheshwa.
- [ ] Notification previews, wearables, linked desktops na backups zilijaribiwa.
- [ ] Files zilisafishwa, zikasimbwa kwa encryption inapohitajika na kufunguliwa katika disposable context.
- [ ] Recovery inafanya kazi bila kuunganisha identities zisizohusiana.
- [ ] Logs, history na temporary share services zina shutdown/retention rule.

## References

- [1] [Signal — Privacy ya Nambari ya Simu na Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy na Masharti ya Matumizi](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Mwongozo wa Privacy na Usalama](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Jinsi inavyofanya kazi](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Muundo wa Usalama](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Matumizi ya Juu na CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI rasmi na matumizi](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Kuondoa metadata kwa usalama](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architecture ya Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
