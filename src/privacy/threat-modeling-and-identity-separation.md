# Threat Modeling na Kutenganisha Utambulisho

{{#include ../banners/hacktricks-training.md}}

Kushindwa kwa anonymity kunakotokea mara nyingi si cryptography iliyovunjika. Ni **linkage**: kitambulisho kimoja, muundo wa muda, kifaa, akaunti, malipo, faili, au mazoea ya kibinadamu huunganisha miktadha miwili iliyopaswa kubaki tofauti.

## Tengeneza threat model ya faragha

Mpango wa usalama wa maswali sita wa EFF ni msingi mzuri: nini kinapaswa kulindwa, dhidi ya nani, athari na uwezekano wa kushindwa, juhudi zilizopo, na washirika wanaoweza kusaidia.<sup>[[1]](#references)</sup> Uufanye uwe wa kutekelezeka kwa jedwali dogo:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Kuchunguza mteja | ISP | Metadata ya destination/muda | Rekodi ya subscriber wa nyumbani | Tor Browser | Matumizi ya Tor yanaonekana; end-to-end correlation |
| Akaunti ya pseudonymous | Platform | IP, browser, data ya recovery | Namba ya simu/email/photo iliyotumika tena | Context na alias maalum | Correlation kupitia uandishi/social graph |
| Ununuzi wa mtandaoni | Merchant | Akaunti, delivery, kadi yenye token | Anwani na historia ya akaunti | Guest checkout, fields chache, virtual card | Issuer na carrier huhifadhi rekodi |
| Traffic ya Red-team | Target/client | Source IP na tabia | Rekodi za provider/engagement | Egress maalum iliyoidhinishwa | Inahusishwa kimakusudi wakati wa escalation |

Kagua jedwali kila eneo, provider, kifaa, counterpart, au madhara yanapobadilika.

## Chora linkability graph

Chukulia kila utambulisho kama node tofauti. Ongeza edge kwa kila sifa inayoshirikiwa:

- email au anwani ya recovery;
- namba ya simu au upload ya contact-book;
- username, avatar, photo, bio, au mtindo wa uandishi/code;
- password, akaunti ya passkey-sync, au swali la recovery;
- kifaa, advertising ID, browser profile, cookies, fonts, au extensions;
- IP address, time zone, lugha, ratiba, au hali ya kuwa online kwa wakati mmoja;
- bank card, akaunti ya exchange, wallet cluster, shipping address, au loyalty program;
- sehemu za author za document, eneo la EXIF, alama za printer, au owner wa cloud-share;
- colleague, membership ya group, na social graph.

Edge si hatari moja kwa moja, lakini hukuonyesha ni observer gani anaweza kufanya muunganisho. EFF inaonya mahsusi kwamba namba za simu, anwani za email, na picha zilizotumika tena zinaweza kuunganisha profiles.<sup>[[2]](#references)</sup>

## Unda compartment hatua kwa hatua

1. **Taja context na links zilizokatazwa.** Mfano: `client-red-2026`, iliyokatazwa kuhusishwa na personal email, home browser profiles, personal payment methods, na clients zisizohusiana.
2. **Chagua mpaka wa isolation.** Kwa nguvu inayoongezeka: separate browser profile → separate OS account → separate VM/qube → dedicated device. Tab tofauti au private window si security boundary.
3. **Tengeneza identifiers mpya ndani ya mpaka huo.** Tumia email/alias, username, password-manager vault au collection, na authentication keys maalum kwa context. Usiongeze personal recovery channel ikiwa kutounganishwa na provider ni muhimu.
4. **Chagua policy moja ya network.** Amua ikiwa context itatumia kila mara client VPN, engagement VPS, trusted VPN, au Tor. Tekeleza fail-closed routing inapowezekana.
5. **Chagua policy ya malipo.** Njia ya malipo lazima ilingane na observer model; virtual card inaweza kuficha PAN kwa merchant lakini bado kumtambulisha mteja kwa issuer.
6. **Weka kanuni za uhamishaji wa data.** Pendelea transfers zilizolengwa kwa upana mdogo na zilizokusudiwa. Chukulia clipboard, shared folders, USB devices, cloud sync, printers, na screenshots kama bridges zinazowezekana.
7. **Rekodi tarehe za kuunda na kuondoa.** Bainisha ushahidi gani lazima uhifadhiwe kwa contracts/tax/compliance na data gani ya muda inapaswa ku-expire.
8. **Pima links kabla ya kutumia.** Kagua account settings, recovery fields, public profile, IP/DNS, browser state, file metadata, na provider dashboards.

{% hint style="warning" %}
Usibuni taarifa za utambulisho pale ambapo service au sheria inahitaji utambulisho sahihi. Privacy compartment inahusu kupunguza na kutenganisha data, si identity fraud au kukwepa customer due diligence.
{% endhint %}

## Msingi wa endpoint na akaunti

- Tumia hardware inayoungwa mkono na usakinishe kwa wakati OS, browser, wallet, na firmware updates.
- Washa device encryption na utumie strong device passcode. Encryption at rest husaidia kifaa kilichozimwa kinapopotea au kukamatwa, lakini si wakati malware au session iliyofunguliwa inaweza kusoma data.<sup>[[3]](#references)</sup>
- Tumia passwords za kipekee, zinazotengenezwa kwa random, ndani ya password manager.
- Pendelea authentication inayostahimili phishing kama WebAuthn/passkeys au hardware security keys pale threat model inapokubali recovery/sync model yake. NIST inaeleza kwamba OTPs zinazoingizwa kwa mkono hazistahimili phishing kwa sababu impostor anaweza kuzirelay.<sup>[[4]](#references)</sup>
- Hifadhi recovery codes offline na uzitenganishe na endpoint. Kagua ikiwa synced passkey account inaunganisha identities zinazopaswa kubaki tofauti.
- Zima location, contacts, microphone, camera, Bluetooth, advertising-ID, na background permissions zisizo za lazima.
- Usichanganye personal cloud sync, browser sync, password-manager accounts, au app stores kwenye context inayohitaji separation kubwa.

## Faragha ya browser

Browser fingerprinting hutumia configuration, kifaa, mazingira, na tabia vinavyoonekana ili kumtambua au kumhusianisha mtumiaji. Kufuta cookies au kubadilisha IP addresses hakukomeshi hili kwa uaminifu, na W3C inaona kuondolewa kabisa kiufundi kwa njia zinazotumiwa kwa upana kuwa ni jambo lisilowezekana.<sup>[[5]](#references)</sup>

Kwa faragha ya kawaida:

1. Tumia browser inayotunzwa ikiwa na HTTPS-only mode na tracking protection thabiti.
2. Zuia third-party tracking na partition state pale inapoungwa mkono.
3. Tumia separate browser profiles kwa contexts zilizotenganishwa kwa kweli.
4. Zima permissions zisizohitajika na ufute site data kwa ratiba iliyoainishwa.
5. Epuka kuingia kwenye akaunti zenye taarifa nyingi za utambulisho unapofanya utafiti nyeti usiohusiana.

Kwa web anonymity, tumia **Tor Browser katika standard configuration yake**. Usipitishe browser ya kawaida kupitia Tor: Tor Project inaonya kwamba browsers za kawaida zinaweza ku-leak kupitia DNS/WebRTC, persistent state, fonts, plugins, na tofauti za fingerprint.<sup>[[6]](#references)</sup> Epuka extensions za ziada, window sizes zisizo za kawaida, fonts maalum, na preferences zinazofanya browser ijitofautishe.<sup>[[7]](#references)</sup>

## Mawasiliano na metadata

Metadata inajumuisha sender, recipient, muda, eneo, na context nyingine hata wakati message content imesimbwa kwa encryption.<sup>[[8]](#references)</sup>

- Pendelea tools zenye end-to-end encryption, server-side metadata iliyopunguzwa, na open protocols/clients pale inapowezekana.
- Thibitisha contacts nyeti ukitumia independent channel au ana kwa ana. Signal safety numbers zimeundwa kwa ukaguzi huu.<sup>[[9]](#references)</sup>
- Signal usernames zinaweza kuanzisha mawasiliano bila kushiriki namba ya simu, lakini namba ya simu bado inahitajika kwa usajili; panga phone-number visibility/discoverability kwa makusudi.<sup>[[9]](#references)</sup>
- Disappearing messages hupunguza nakala zinazohifadhiwa; recipients bado wanaweza kupiga picha, kunakili, kusambaza, au kuhifadhi content.
- Kwa kawaida email huonyesha routing metadata. Hata providers wanaolenga faragha hawawezi kufanya message iwe end-to-end encrypted wakati upande mwingine unatumia email ya kawaida, isipokuwa pande zote zitumie njia inayooana ya E2EE. Kwa mfano, Proton inaeleza kwamba mail ya kawaida kwenda kwa providers wengine hutumia TLS na hubaki kusomeka na receiving provider.<sup>[[10]](#references)</sup>
- Tenganisha address books na usipakie personal contacts kwenye akaunti ya pseudonymous.

## Files, photos na authorship

Tails inaonya kwamba photographs zinaweza kuwa na camera na location data, na office documents zinaweza kuwa na author na creation-time fields.<sup>[[11]](#references)</sup>

Kabla ya kushiriki:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Kisha fungua tena nakala iliyosafishwa katika isolated viewer na uangalie:

- sifa za hati, maoni, mabadiliko yaliyofuatiliwa, laha/slide zilizofichwa, vijipicha na viambatisho;
- EXIF/XMP/IPTC, GPS, mihuri ya muda, majina ya kifaa/programu na vitambulisho vya kipekee;
- miakisi inayoonekana, alama za maeneo, yaliyomo kwenye skrini, sauti, nyuso na sauti za mandharinyuma;
- jina la faili, njia za archive, mmiliki wa cloud-share, cheti cha kusaini na historia ya marekebisho.

Usafishaji unaweza kuharibu ushahidi au uhalisi. Hifadhi nakala ya asili iliyosimbwa kwa encryption ikiwa chain of custody au uthibitishaji wa baadaye ni muhimu. Stylometry na mtindo wa coding pia vinaweza kuhusisha uandishi na mwandishi; kuondoa metadata hakubadilishi mtindo wa binadamu.

## Mifumo ya kawaida ya kushindwa

- Kuingia katika akaunti ya kibinafsi kupitia muunganisho wa “anonymous”.
- Kutumia tena nambari ya simu ya kurejesha akaunti, avatar, username, public key, wallet, au anwani ya donation.
- Kuendesha identities mbili kwa wakati mmoja kutoka katika contexts zinazohusiana.
- Kunakili maandishi/faili kupitia personal cloud clipboard au shared folder.
- Kusakinisha Tor Browser extensions zenye sifa bainifu au kubadilisha defaults nyingi.
- Kuamini dai la “no logs” bila kuelewa kinachorekodiwa, kwa muda gani, na na subcontractors gani.
- Kudhani simu ya pili ni anonymous huku ikisafiri pamoja na simu ya kibinafsi. EFF inabainisha kuwa eneo la cellular na kusafiri pamoja vinaweza kuhusisha vifaa hivyo.<sup>[[3]](#references)</sup>
- Kuchukulia encryption kama deletion; endpoints na wapokeaji wanaweza kuhifadhi plaintext.

## Orodha hakiki ya uthibitishaji

- [ ] Context haina anwani ya kibinafsi ya kurejesha akaunti, simu, sync account, au media iliyotumika tena isipokuwa ikiwa imekubaliwa kwa makusudi.
- [ ] Njia iliyokusudiwa ya mtandao iko hai na inashindwa kwa usalama.
- [ ] Time zone, locale, extensions na permissions za browser/device zinaendana na mpango.
- [ ] Hakuna akaunti za kibinafsi zilizo wazi katika compartment.
- [ ] Faili zimekaguliwa na kusafishwa; originals zinashughulikiwa kando.
- [ ] Contacts zimethibitishwa kupitia channel ya pili.
- [ ] Metadata inayoonekana kwa provider na kipindi cha retention vinaeleweka.
- [ ] Taratibu za teardown, kuhifadhi ushahidi na kurejesha akaunti zimeandikwa.

## References

- [1] [EFF Surveillance Self-Defense — Mpango Wako wa Usalama](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Kujilinda kwenye Mitandao ya Kijamii](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Kuhudhuria Maandamano](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Uthibitishaji na Usimamizi wa Authenticators](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Kupunguza Browser Fingerprinting katika Web Specifications](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Kutumia Tor na browsers nyingine](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins na add-ons katika Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Kwa Nini Communication Metadata ni Muhimu](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Faragha ya Nambari ya Simu na Usernames: Uchambuzi wa Kina](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Ni nini husimbwa kwa encryption ndani ya Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Maonyo: Tails ni salama lakini si uchawi](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
