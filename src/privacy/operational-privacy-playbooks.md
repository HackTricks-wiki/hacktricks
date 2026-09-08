# Mwongozo wa Faragha ya Kiutendaji

{{#include ../banners/hacktricks-training.md}}

Miongozo hii inaunganisha vidhibiti kutoka sehemu nyingine za sura hii. Ni sehemu za kuanzia, si dhamana: sasisha threat model kila observer, account, kifaa, eneo, malipo, faili au counterparty mpya inapoingia kwenye workflow.

## Ukaguzi wa awali wa jumla

1. Andika lengo halali na kile kinachopaswa kubaki cha faragha **kutoka kwa nani**.
2. Rekodi utambulisho, vifaa, mitandao, akaunti, njia za malipo, counterparties, maeneo halisi na data ambayo shughuli itatumia.
3. Tambua observer anayeweza kuwa na uwezo mkubwa zaidi na madhara ya kushindwa.
4. Thibitisha authorization, sheria husika, masharti ya provider na policy ya shirika.
5. Amua ni nini lazima kibaki kinachohusishwa na utambulisho ndani ya shirika kwa ajili ya usalama, incident response, accounting na audit.
6. Chagua compartment ndogo zaidi inayofanya kazi; weka recovery na shutdown paths zake kabla ya kuitumia.
7. Jaribu compartment dhidi ya service inayodhibitiwa, ikijumuisha IP/DNS/IPv6, browser identity, document metadata, payment statement na notification leakage.

Tumia model ya kina katika [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Msingi wa faragha wa kila siku

Lengo: kupunguza commercial tracking, account takeover na exposure isiyo ya lazima bila kujaribu kuwa anonymous.

- Tumia OS inayotunzwa ikiwa na full-disk encryption, automatic updates, screen lock na secure boot inapopatikana.
- Weka password manager, recovery email na phishing-resistant MFA/security keys kwa kipaumbele kwanza.
- Kagua app permissions, location history, advertising identifiers, cloud sync na third-party account connections.
- Tumia browser maarufu yenye extensions chache, tracking protection, HTTPS na profiles tofauti kwa browsing ya work/personal/high-risk.
- Tumia private relay aliases au email addresses tofauti kulingana na uhusiano; usitumie personal phone number wakati ni chaguo tu.
- Pendelea end-to-end encrypted messaging kwa maudhui, huku ukikumbuka kwamba participants, timing, groups na endpoints hubaki metadata.
- Ondoa metadata kutoka kwenye files kwa makusudi na kagua nakala iliyotolewa—si original—kabla ya kuichapisha.
- Tumia virtual-card au wallet tokens kwa payment-credential compartmentalization; usiziite anonymous.
- Fanya backup ya encrypted recovery material na ujaribu restoration.

## Uchapishaji wa pseudonymous

Lengo: kuzuia wasomaji wa kawaida na platforms kuunganisha kwa urahisi publication na civil identity. Hii haimzuii capable targeted investigation.

1. Fafanua kama platform, hosting provider, readers, contacts, local network, payment provider au legal process iko kwenye threat model.
2. Unda endpoint/account context maalum kutoka clean baseline. Zima personal browser sync, cloud documents, contact upload na notification previews.
3. Unda pseudonymous account kupitia network compartment iliyochaguliwa. Usitumie tena usernames, avatars, recovery channels, writing boilerplate au personal identity-provider login.
4. Tumia Tor Browser wakati destination unlinkability ni muhimu zaidi kuliko speed; usiongeze extensions, usibadilishe size/customize kwa kiasi kikubwa, wala kufungua downloaded documents ukiwa online katika ordinary desktop session.
5. Andaa kwa process ambayo haiingizi personal template names, revision authors, printer paths, GPS/EXIF, thumbnails au hidden layers. Toa nakala na ikague kwa appropriate metadata tools.
6. Kagua content kwa facts zinazoweza kujitambulisha: unique dates, workplace details, local weather/time zone, reflections, background audio, linguistic habits na prior-publication text reuse.
7. Tumia reply channel tofauti. Chukulia kila direct contact, attachment na link kama potential correlation au phishing attempt.
8. Ikiwa money inahusika, tumia lawful method inayofichua data inayohitajika tu. Kadiria kwamba platform na regulated intermediary wanaweza kumjua payee hata kama readers hawamjui.
9. Publish, kisha kagua public result kutoka clean context tofauti. Rekodi kile platform ilichoongeza au kubadilisha.
10. Dumisha cadence iliyopangwa tu ikiwa haitengenezi stable behavioral fingerprint; retire compartment badala ya kuirepurpose kimya kimya.

Kwa serious journalism, activism, domestic abuse au state-level risk, pata msaada maalum kutoka experienced digital-security organization; static checklist haiwezi ku-model local law au live adversary.

## Authorized red-team engagement

Lengo: kuweka personal identities na home networks za operators nje ya target telemetry huku ukihifadhi authorization, control na incident response.

### Kabla ya start window

- Kamilisha ROE infrastructure annex, targets/exclusions, source ranges, dates, emergency stop na third-party/provider permissions.
- Tenga operator profile au VM maalum, engagement secrets, evidence store, cloud project, domains na budget.
- Pendelea client-provided egress au fixed bastion inayodhibitiwa na shirika. Jaribu full-tunnel IPv4/IPv6/DNS behavior na fail-closed policy.
- Hifadhi mapping kutoka operator hadi public infrastructure kwa exercise controller au agreed escrow contact.
- Weka rate limits, destination allowlists na approval tofauti kwa destructive, wireless, physical, phishing au credential-collection actions.
- Tumia organization-controlled payment rail na rekodi approvals internally.

### Wakati wa engagement

- Anza kutoka approved endpoint na tunnel; thibitisha observed egress kabla ya assessment traffic.
- Weka personal accounts, devices, phone numbers, repositories, SSH/GPG keys na cloud sync nje ya compartment.
- Log operator/job, start/stop, source, scoped destination na configuration change bila kukusanya client content isiyo ya lazima.
- Simamisha kwenye scope ambiguity, unexpected third-party systems, provider abuse notification, safety impact, lost equipment au loss of controller contact.
- Usibuni mbinu za kutumia neighbor's Wi-Fi, stolen credentials, unapproved SIM/account au hardware iliyofichwa kwenye venue.

### Mwisho wa engagement

- Simamisha jobs na C2; recover approved drop devices; revoke tokens, credentials na certificates.
- Linganisha infrastructure, domains, source addresses, expenses, data na provider cases dhidi ya inventory.
- Return/delete/retain client data kulingana na contract, hifadhi minimum required audit evidence, na mwendeshaji wa pili athibitishe shutdown.

Tazama [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) kwa mwongozo kamili wa build na teardown.

## Ununuzi au donation ya faragha iliyo halali

Lengo: kupunguza disclosure kwa merchant au umma huku ukitimiza issuer, accounting, tax na sanctions obligations.

1. Orodhesha nani hapaswi kujua nini: public audience, merchant, payment intermediary, employer/family account delegate, delivery service au blockchain observer.
2. Kagua local rules, recipient/counterparty, provider terms, cash limits na recordkeeping needs.
3. Chagua rail:
- cash kwa lawful local payments zinazokubaliwa bila payment-network record;
- regulated virtual/merchant-specific card kwa online credential separation;
- cryptocurrency tu baada ya kuchanganua acquisition, ledger, wallet backend, network, counterparty na later-spend links.
4. Tumia required details za kweli na uache tu optional loyalty/marketing information. Usitumie identity/address ya mtu mwingine wala kugawanya transaction ili kuepuka threshold.
5. Tenga merchant browser/account context na epuka unrelated social login, loyalty au personal recovery channels.
6. Thibitisha kinachoonekana kwenye statements, receipts, notifications, shipping na public donor lists.
7. Hifadhi required receipt/tax/authorization evidence ikiwa encrypted; revoke disposable payment credentials baada ya refund window.

Tazama [Private Digital Payments](private-digital-payments.md) na [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Usafiri na mitandao isiyoaminika

Lengo: kulinda data na accounts kwenye mitandao isiyosimamiwa na user—si kuficha shughuli isiyoidhinishwa.

- Sasisha devices na download credentials/maps zinazohitajika kabla ya kusafiri.
- Punguza stored data; tumia full-disk encryption, strong unlock, remote-recovery planning na powered-off border/physical-risk procedures zinazofaa kulingana na legal advice.
- Thibitisha venue SSID/captive portal. Pendelea personal hotspot inapofaa, lakini kumbuka cellular subscriber na location records.
- Tumia full/forced approved VPN kwa organizational data; thibitisha tethered devices zinaishiriki na ujaribu IPv6/DNS behavior.
- Tumia travel router kwa client isolation na repeatable policy, si kama anonymity guarantee.
- Chukulia public USB charging, borrowed computers, public printers na shared meeting-room systems kama threats tofauti.
- Kadiria kwamba physical presence, radio identifiers, portal login, cameras na payment/location records zinaweza kuunganisha visit.

Maelezo ya comparison na setup yako katika [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Mwitikio wa failure na exposure

Wakati compartment ime-leak au huenda imeunganishwa:

1. Simamisha activity ikiwa continuation itaongeza madhara; tumia engagement emergency stop inapohusika.
2. Hifadhi evidence inayohitajika bila kusambaza sensitive data. Rekodi exact time, observed indicator na affected assets.
3. Mjulisha owner/controller/security contact anayefaa. Usifiche incident ili kuhifadhi privacy narrative.
4. Revoke sessions, tokens, payment credentials na infrastructure access; rotate secrets kutoka known-clean endpoint.
5. Amua ni edges zipi ziliunganisha: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty au physical presence.
6. Chukulia affected compartment yote kuwa burned. Usibadilishe username au exit IP tu.
7. Timiza breach, provider, client, financial na legal notification duties.
8. Rebuild baada tu ya kubadilisha process iliyosababisha link; document control na uijaribu.

## Ukaguzi wa mara kwa mara

- [ ] Threat model na legal/provider assumptions zimepitiwa kwa ratiba yenye tarehe.
- [ ] Devices, accounts, aliases, domains, network paths na payment credentials zimeorodheshwa.
- [ ] Recovery paths hazivuki compartments bila kutarajiwa.
- [ ] Full-tunnel, DNS, IPv6 na fail-closed behavior vimejaribiwa.
- [ ] Public files na profiles zimekaguliwa kwa metadata/content reuse.
- [ ] Wallet nodes/backends na crypto protocol assumptions bado ni za sasa.
- [ ] Logs na receipts ni chache, encrypted, access-controlled na ziko ndani ya retention.
- [ ] Old compartments na engagement infrastructure zimestaafishwa kikamilifu.
{{#include ../banners/hacktricks-training.md}}
