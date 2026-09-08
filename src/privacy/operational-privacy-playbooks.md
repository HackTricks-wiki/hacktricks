# Miongozo ya Faragha ya Kiutendaji

Miongozo hii inaunganisha vidhibiti kutoka sehemu nyingine ya sura hii. Ni sehemu za kuanzia, si dhamana: sasisha threat model kila observer, account, kifaa, eneo, malipo, faili au counterparty mpya inapoingia kwenye workflow.

## Ukaguzi wa awali wa jumla

1. Andika lengo halali na kinachopaswa kubaki private **kutoka kwa nani**.
2. Rekodi identities, vifaa, networks, accounts, payment rails, counterparties, maeneo halisi na data ambayo shughuli itatumia.
3. Tambua observer mwenye uwezo mkubwa zaidi anayetarajiwa na madhara ya kushindwa.
4. Thibitisha authorization, sheria inayotumika, masharti ya provider na sera ya shirika.
5. Amua ni nini lazima kibaki attributable ndani ya shirika kwa usalama, incident response, accounting na audit.
6. Chagua compartment ndogo zaidi inayofanya kazi; weka recovery na shutdown paths zake kabla ya matumizi.
7. Pima compartment dhidi ya service inayodhibitiwa, ikijumuisha IP/DNS/IPv6, browser identity, document metadata, payment statement na notification leakage.

Tumia model ya kina katika [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Msingi wa faragha wa kila siku

Lengo: kupunguza commercial tracking, account takeover na exposure isiyo ya lazima bila kujaribu kuwa anonymous.

- Tumia OS inayodumishwa yenye full-disk encryption, automatic updates, screen lock na secure boot inapopatikana.
- Anza kwa kupanga password manager, recovery email na phishing-resistant MFA/security keys.
- Kagua app permissions, location history, advertising identifiers, cloud sync na third-party account connections.
- Tumia mainstream browser yenye extensions chache, tracking protection, HTTPS, na profiles tofauti kwa browsing ya work/personal/high-risk.
- Tumia private relay aliases au email addresses tofauti kulingana na uhusiano; usitumie personal phone number inapokuwa optional tu.
- Pendelea end-to-end encrypted messaging kwa content, huku ukikumbuka kuwa participants, timing, groups na endpoints hubaki metadata.
- Ondoa metadata kwenye files kwa makusudi na kagua copy iliyotolewa nje—si original—kabla ya kuchapisha.
- Tumia virtual-card au wallet tokens kwa payment-credential compartmentalization; usiziite anonymous.
- Hifadhi nakala za recovery material iliyosimbwa na ujaribu restoration.

## Uchpublishishaji wa pseudonymous

Lengo: kuwazuia wasomaji wa kawaida na platforms kuunganisha publication kwa urahisi na civil identity. Hii haizuii targeted investigation yenye uwezo mkubwa.

1. Bainisha kama platform, hosting provider, readers, contacts, local network, payment provider au legal process viko kwenye threat model.
2. Unda dedicated endpoint/account context kutoka kwenye clean baseline. Zima personal browser sync, cloud documents, contact upload na notification previews.
3. Unda pseudonymous account kupitia network compartment iliyochaguliwa. Usitumie tena usernames, avatars, recovery channels, writing boilerplate au personal identity-provider login.
4. Tumia Tor Browser wakati destination unlinkability ni muhimu zaidi kuliko speed; usiongeze extensions, usibadilishe size/customize kwa kiwango kikubwa, au kufungua downloaded documents ukiwa online katika ordinary desktop session.
5. Andaa kwa process isiyoweka personal template names, revision authors, printer paths, GPS/EXIF, thumbnails au hidden layers. Export copy na ikague kwa appropriate metadata tools.
6. Kagua content kwa facts zinazoweza kujitambulisha: tarehe za kipekee, workplace details, local weather/time zone, reflections, background audio, linguistic habits na prior-publication text reuse.
7. Tumia separate reply channel. Chukulia kila direct contact, attachment na link kama potential correlation au phishing attempt.
8. Ikiwa money inahusika, tumia lawful method inayofichua data muhimu tu. Chukulia kuwa platform na regulated intermediary wanaweza kumjua payee hata kama readers hawamjui.
9. Publish, kisha kagua public result kutoka clean context tofauti. Rekodi kile platform ilichoongeza au kubadilisha.
10. Dumisha cadence iliyopangwa tu ikiwa haitengenezi stable behavioral fingerprint; retire compartment badala ya kuitumia tena kimya kimya.

Kwa journalism, activism, domestic abuse au state-level risk kubwa, pata msaada maalum kutoka kwa digital-security organization yenye uzoefu; static checklist haiwezi ku-model local law au live adversary.

## Authorized red-team engagement

Lengo: kuweka personal identities na home networks za operators nje ya target telemetry huku authorization, control na incident response vikiendelea kulindwa.

### Kabla ya start window

- Kamilisha ROE infrastructure annex, targets/exclusions, source ranges, dates, emergency stop na third-party/provider permissions.
- Tenga dedicated operator profile au VM, engagement secrets, evidence store, cloud project, domains na budget.
- Pendelea client-provided egress au fixed bastion inayodhibitiwa na organization. Pima full-tunnel IPv4/IPv6/DNS behavior na fail-closed policy.
- Hifadhi mapping kutoka operator hadi public infrastructure kwa exercise controller au agreed escrow contact.
- Weka rate limits, destination allowlists na approval tofauti kwa destructive, wireless, physical, phishing au credential-collection actions.
- Tumia organization-controlled payment rail na rekodi approvals internally.

### Wakati wa engagement

- Anza kutoka approved endpoint na tunnel; thibitisha observed egress kabla ya assessment traffic.
- Weka personal accounts, devices, phone numbers, repositories, SSH/GPG keys na cloud sync nje ya compartment.
- Log operator/job, start/stop, source, scoped destination na configuration change bila kukusanya client content isiyo ya lazima.
- Simamisha kwenye scope ambiguity, unexpected third-party systems, provider abuse notification, safety impact, lost equipment au kupotea kwa mawasiliano na controller.
- Usifanye improvisation kwa kutumia Wi-Fi ya jirani, stolen credentials, SIM/account isiyoapproved au hardware iliyofichwa venue.

### Mwisho wa engagement

- Simamisha jobs na C2; recover approved drop devices; revoke tokens, credentials na certificates.
- Linganisha infrastructure, domains, source addresses, expenses, data na provider cases dhidi ya inventory.
- Return/delete/retain client data kulingana na contract, hifadhi minimum required audit evidence, na operator wa pili athibitishe shutdown.

Angalia [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) kwa mwongozo kamili wa build na teardown.

## Lawful private purchase au donation

Lengo: kupunguza disclosure kwa merchant au public huku ukitimiza wajibu wa issuer, accounting, tax na sanctions.

1. Orodhesha ni nani hapaswi kujua nini: public audience, merchant, payment intermediary, employer/family account delegate, delivery service au blockchain observer.
2. Kagua local rules, recipient/counterparty, provider terms, cash limits na mahitaji ya recordkeeping.
3. Chagua rail:
- cash kwa lawful local payments zinazokubalika bila payment-network record;
- regulated virtual/merchant-specific card kwa online credential separation;
- cryptocurrency baada tu ya kuchanganua acquisition, ledger, wallet backend, network, counterparty na later-spend links.
4. Tumia details za kweli zinazohitajika na uache tu loyalty/marketing information iliyo optional. Usitumie identity/address ya mtu mwingine au kugawanya transaction kuzunguka threshold.
5. Tenga merchant browser/account context na epuka unrelated social login, loyalty au personal recovery channels.
6. Thibitisha kinachoonekana kwenye statements, receipts, notifications, shipping na public donor lists.
7. Hifadhi required receipt/tax/authorization evidence ikiwa encrypted; revoke disposable payment credentials baada ya refund window.

Angalia [Private Digital Payments](private-digital-payments.md) na [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Travel na networks zisizoaminika

Lengo: kulinda data na accounts kwenye networks ambazo user hazisimamii—si kuficha unauthorized activity.

- Sasisha vifaa na download credentials/maps zinazohitajika kabla ya safari.
- Punguza data iliyohifadhiwa; tumia full-disk encryption, strong unlock, remote-recovery planning na powered-off border/physical-risk procedures zinazofaa kwa legal advice.
- Thibitisha venue SSID/captive portal. Pendelea personal hotspot inapofaa, lakini kumbuka cellular subscriber na location records.
- Tumia approved VPN ya full/forced kwa organizational data; thibitisha kuwa tethered devices zinaitumia na pima IPv6/DNS behavior.
- Tumia travel router kwa client isolation na repeatable policy, si kama guarantee ya anonymity.
- Chukulia public USB charging, borrowed computers, public printers na shared meeting-room systems kama threats tofauti.
- Chukulia kuwa physical presence, radio identifiers, portal login, cameras na payment/location records zinaweza kuunganisha visit.

Maelezo ya comparison na setup yako katika [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Response ya failure na exposure

Wakati compartment inaleak au huenda imeunganishwa:

1. Simamisha activity ikiwa kuendelea kunaongeza madhara; tumia engagement emergency stop inapohusika.
2. Hifadhi evidence muhimu bila kusambaza sensitive data. Rekodi muda kamili, indicator iliyoonekana na assets zilizoathirika.
3. Mjulie owner/controller/security contact anayefaa. Usifiche incident ili kuhifadhi privacy narrative.
4. Revoke sessions, tokens, payment credentials na infrastructure access; rotate secrets kutoka clean endpoint inayojulikana.
5. Bainisha ni edges zipi ziliunganisha: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty au physical presence.
6. Chukulia affected compartment yote kuwa burned. Usibadilishe username au exit IP pekee.
7. Timiza breach, provider, client, financial na legal notification duties.
8. Rebuild baada tu ya kubadilisha process iliyosababisha link; document control na uipime.

## Ukaguzi wa mara kwa mara

- [ ] Threat model na legal/provider assumptions zimepitiwa kwa ratiba yenye tarehe.
- [ ] Devices, accounts, aliases, domains, network paths na payment credentials zimeorodheshwa.
- [ ] Recovery paths hazivuki compartments bila kutarajiwa.
- [ ] Full-tunnel, DNS, IPv6 na fail-closed behavior zimepimwa.
- [ ] Public files na profiles zimekaguliwa kwa metadata/content reuse.
- [ ] Wallet nodes/backends na crypto protocol assumptions bado ni za sasa.
- [ ] Logs na receipts ni minimal, encrypted, access-controlled na ziko ndani ya retention.
- [ ] Old compartments na engagement infrastructure ziliretired kikamilifu.
