# Threat Modeling & Identity Separation

Kushindwa kwa anonymity mara nyingi hakusababishwi na cryptography iliyovunjika. Husababishwa na **linkage**: kitambulisho, muundo wa muda, kifaa, akaunti, malipo, faili, au desturi ya kibinadamu inaunganisha miktadha miwili iliyopaswa kubaki tofauti.

## Build a privacy threat model

Mpango wa EFF wa maswali sita kuhusu usalama ni msingi mzuri: nini lazima kilindwe, dhidi ya nani, athari na uwezekano wa kushindwa, juhudi zilizopo, na washirika wanaoweza kusaidia.<sup>[[1]](#references)</sup> Uufanye uwe wa kiutendaji kwa kutumia jedwali dogo:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Kutafiti mteja | ISP | Metadata ya destination/timing | Rekodi ya subscriber wa nyumbani | Tor Browser | Matumizi ya Tor yanaonekana; end-to-end correlation |
| Akaunti ya pseudonymous | Platform | IP, browser, data ya recovery | Simu/email/photo iliyotumika tena | Context na alias maalum | Correlation ya uandishi/social graph |
| Ununuzi wa mtandaoni | Merchant | Akaunti, delivery, kadi yenye token | Anwani na historia ya akaunti | Guest checkout, sehemu chache za kujaza, virtual card | Issuer na carrier huhifadhi rekodi |
| Trafiki ya red-team | Target/client | Source IP na tabia | Rekodi za provider/engagement | Dedicated authorized egress | Inahusishwa kimakusudi wakati wa escalation |

Kagua jedwali kila eneo, provider, kifaa, counterpart, au madhara yanapobadilika.

## Draw the linkability graph

Chukulia kila identity kama node tofauti. Ongeza edge kwa kila attribute inayoshirikiwa:

- email au recovery address;
- phone number au contact-book upload;
- username, avatar, photo, bio, au mtindo wa uandishi/code;
- password, passkey-sync account, au recovery question;
- device, advertising ID, browser profile, cookies, fonts, au extensions;
- IP address, time zone, language, schedule, au hali ya kuwa online kwa wakati mmoja;
- bank card, exchange account, wallet cluster, shipping address, au loyalty program;
- sehemu za author za document, eneo la EXIF, alama za printer, au owner wa cloud-share;
- colleague, uanachama wa group, na social graph.

Edge si lazima iwe hatari kubwa moja kwa moja, lakini inakuonyesha ni observer gani anaweza kufanya muunganisho huo. EFF inaonya hasa kwamba phone numbers, email addresses, na photographs zilizotumika tena zinaweza kuunganisha profiles.<sup>[[2]](#references)</sup>

## Create a compartment step by step

1. **Taja context na links zilizokatazwa.** Mfano: `client-red-2026`, isiyopaswa kuhusishwa na personal email, home browser profiles, personal payment methods, na clients zisizohusiana.
2. **Chagua isolation boundary.** Kwa kuongezeka kwa nguvu: separate browser profile → separate OS account → separate VM/qube → dedicated device. Tab tofauti au private window si security boundary.
3. **Unda identifiers mpya ndani ya boundary hiyo.** Tumia email/alias maalum ya context, username, password-manager vault au collection, na authentication keys. Usiongeze personal recovery channel ikiwa unlinkability kutoka kwa provider ni muhimu.
4. **Chagua network policy moja.** Amua ikiwa context itatumia kila mara client VPN, engagement VPS, trusted VPN, au Tor. Tekeleza fail-closed routing inapowezekana.
5. **Chagua payment policy.** Njia ya malipo lazima ilingane na observer model; virtual card inaweza kuficha PAN kutoka kwa merchant lakini bado imtambulishe mteja kwa issuer.
6. **Weka sheria za data-transfer.** Pendelea transfers zenye scope finyu na zinazofanywa kwa makusudi. Chukulia clipboard, shared folders, USB devices, cloud sync, printers, na screenshots kama madaraja yanayowezekana.
7. **Rekodi tarehe za kuunda na kuvunja context.** Bainisha ni ushahidi gani lazima uhifadhiwe kwa contracts/tax/compliance na ni data gani ya muda inapaswa ku-expire.
8. **Jaribu kama kuna links kabla ya kutumia.** Kagua account settings, recovery fields, public profile, IP/DNS, browser state, file metadata, na provider dashboards.

{% hint style="warning" %}
Usibuni taarifa za identity pale ambapo service au sheria inahitaji identification sahihi. Privacy compartment inahusu data minimization na separation, si identity fraud au kukwepa customer due diligence.
{% endhint %}

## Endpoint and account baseline

- Tumia hardware inayoungwa mkono na usakinishe kwa wakati updates za OS, browser, wallet, na firmware.
- Washa device encryption na utumie device passcode imara. Encryption at rest husaidia kifaa kilichozimwa kinapopotea au kukamatwa, lakini haisaidii wakati malware au session iliyofunguliwa inaweza kusoma data.<sup>[[3]](#references)</sup>
- Tumia passwords za kipekee zinazozalishwa bila mpangilio katika password manager.
- Pendelea authentication inayostahimili phishing kama WebAuthn/passkeys au hardware security keys pale threat model inaporuhusu recovery/sync model yake. NIST inabainisha kwamba OTPs zinazoingizwa kwa mkono hazistahimili phishing kwa sababu impostor anaweza kuzipeleka tena.<sup>[[4]](#references)</sup>
- Hifadhi recovery codes offline na uzitenganishe na endpoint. Kagua ikiwa synced passkey account inaunganisha identities zinazopaswa kubaki tofauti.
- Zima location, contacts, microphone, camera, Bluetooth, advertising-ID, na background permissions zisizo za lazima.
- Usichanganye personal cloud sync, browser sync, password-manager accounts, au app stores katika context yenye separation ya juu.

## Browser privacy

Browser fingerprinting hutumia configuration, device, environment, na behavior vinavyoweza kuonekana ili kumtambua au kumhusianisha mtumiaji. Kufuta cookies au kubadilisha IP addresses hakuzuii hili kwa uhakika, na W3C inaona kuondolewa kabisa kiufundi kwa njia zinazotumiwa kwa upana kuwa jambo lisilowezekana.<sup>[[5]](#references)</sup>

Kwa privacy ya kawaida:

1. Tumia browser inayodumishwa yenye HTTPS-only mode na tracking protection thabiti.
2. Zuia third-party tracking na partition state inapoungwa mkono.
3. Tumia browser profiles tofauti kwa contexts zinazotenganishwa kweli.
4. Zima permissions zisizohitajika na ufute site data kwa ratiba iliyobainishwa.
5. Epuka kuingia katika identity-rich accounts unapofanya utafiti mwingine nyeti.

Kwa web anonymity, tumia **Tor Browser katika standard configuration yake**. Usipitishie browser ya kawaida kupitia Tor: Tor Project inaonya kwamba browsers za kawaida zinaweza kuvuja kupitia DNS/WebRTC, persistent state, fonts, plugins, na tofauti za fingerprint.<sup>[[6]](#references)</sup> Epuka extensions za ziada, window sizes zisizo za kawaida, custom fonts, na preferences zinazofanya browser ijitofautishe.<sup>[[7]](#references)</sup>

## Communications and metadata

Metadata inajumuisha sender, recipient, time, location, na muktadha mwingine hata wakati message content imesimbwa kwa encryption.<sup>[[8]](#references)</sup>

- Pendelea tools zenye end-to-end encryption, server-side metadata iliyopunguzwa, na open protocols/clients inapowezekana.
- Thibitisha contacts nyeti kwa kutumia channel huru au ana kwa ana. Signal safety numbers zimeundwa kwa ukaguzi huu.<sup>[[9]](#references)</sup>
- Signal usernames zinaweza kuanzisha mawasiliano bila kushiriki phone number, lakini phone number bado inahitajika kwa registration; sanidi phone-number visibility/discoverability kwa makusudi.<sup>[[9]](#references)</sup>
- Disappearing messages hupunguza nakala zinazohifadhiwa; recipients bado wanaweza kupiga picha, kunakili, kutuma, au kuhifadhi content.
- Email kwa kawaida hufichua routing metadata. Hata providers wanaozingatia privacy hawawezi kufanya message iwe end-to-end encrypted wakati upande mwingine unatumia email ya kawaida isipokuwa pande zote zitumie njia inayooana ya E2EE. Proton, kwa mfano, inaeleza kwamba mail ya kawaida kwenda kwa providers wengine hutumia TLS na hubaki kusomeka na receiving provider.<sup>[[10]](#references)</sup>
- Tenganisha address books na usipakie personal contacts kwenye pseudonymous account.

## Files, photos and authorship

Tails inaonya kwamba photographs zinaweza kuwa na camera na location data, na office documents zinaweza kuwa na author na creation-time fields.<sup>[[11]](#references)</sup>

Kabla ya kushiriki:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Kisha fungua tena nakala iliyosafishwa katika kitazamaji kilichotengwa na ukague:

- sifa za hati, maoni, mabadiliko yaliyofuatiliwa, laha/slidi zilizofichwa, vijipicha na viambatisho;
- EXIF/XMP/IPTC, GPS, mihuri ya muda, majina ya kifaa/programu na vitambulisho vya kipekee;
- miakisi inayoonekana, alama za eneo, yaliyomo kwenye skrini, sauti, nyuso na sauti za mandharinyuma;
- jina la faili, njia za kumbukumbu, mmiliki wa cloud-share, cheti cha kusaini na historia ya marekebisho.

Usafishaji unaweza kuharibu ushahidi au uhalisi. Hifadhi nakala asili iliyosimbwa kwa njia fiche wakati mnyororo wa ulinzi wa ushahidi au uthibitishaji wa baadaye ni muhimu. Stylometry na mtindo wa kuandika code pia vinaweza kuhusisha uandishi na mwandishi fulani; kuondoa metadata hakubadilishi mtindo wa binadamu.

## Mifumo ya kawaida ya kushindwa

- Kuingia katika akaunti ya kibinafsi kupitia muunganisho wa “anonymous”.
- Kutumia tena simu ya kurejesha akaunti, avatar, username, public key, wallet au anwani ya donation.
- Kuendesha identities mbili kwa wakati mmoja kutoka katika miktadha inayoweza kuhusishwa.
- Kunakili maandishi/faili kupitia personal cloud clipboard au shared folder.
- Kusakinisha viendelezi vya kipekee vya Tor Browser au kubadilisha mipangilio mingi ya msingi.
- Kuamini dai la “no logs” bila kuelewa kinachorekodiwa, kwa muda gani na na subcontractors gani.
- Kudhani kuwa simu ya pili ni anonymous huku ikisafiri pamoja na simu ya kibinafsi. EFF inabainisha kuwa eneo la cellular na usafiri wa pamoja vinaweza kuhusisha vifaa hivyo.<sup>[[3]](#references)</sup>
- Kuchukulia encryption kama ufutaji; endpoints na recipients wanaweza kuhifadhi plaintext.

## Orodha hakiki ya uthibitishaji

- [ ] Muktadha hauna anwani ya kibinafsi ya kurejesha akaunti, simu, sync account au media iliyotumika tena, isipokuwa ikiwa imekubaliwa kwa makusudi.
- [ ] Njia iliyokusudiwa ya mtandao iko hai na hufeli kwa usalama.
- [ ] Time zone, locale, extensions na permissions za browser/device zinalingana na mpango.
- [ ] Hakuna akaunti za kibinafsi zilizo wazi katika compartment.
- [ ] Faili zimekaguliwa na kusafishwa; nakala asili zinashughulikiwa kando.
- [ ] Mawasiliano yamethibitishwa kupitia channel ya pili.
- [ ] Metadata inayoonekana kwa provider na kipindi cha retention vinaeleweka.
- [ ] Taratibu za teardown, kuhifadhi ushahidi na kurejesha akaunti zimeandikwa.

## References

- [1] [EFF Surveillance Self-Defense — Mpango Wako wa Usalama](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Kujilinda kwenye Mitandao ya Kijamii](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Kuhudhuria Maandamano](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Uthibitishaji na Usimamizi wa Authenticators](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Kupunguza Browser Fingerprinting katika Web Specifications](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Kutumia Tor pamoja na browsers nyingine](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins na add-ons katika Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Kwa Nini Communication Metadata ni Muhimu](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Faragha ya Nambari ya Simu na Usernames: Uchambuzi wa Kina](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Ni nini husimbwa kwa njia fiche ndani ya Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Maonyo: Tails ni salama lakini si uchawi](https://tails.net/doc/about/warnings/index.en.html)
