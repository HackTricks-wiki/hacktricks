# Malipo ya Kibinafsi ya Kidijitali

{{#include ../banners/hacktricks-training.md}}

Faragha ya malipo ni ufichuaji unaodhibitiwa wa data ya muamala. Si njia ya kufanya fedha haramu zionekane halali, kukwepa kodi au sanctions, kushinda KYC, kutumia utambulisho wa uongo, au kuficha ushiriki usioidhinishwa. Malipo yanaweza kuwa ya faragha dhidi ya merchant huku yakiwa yanaonekana kikamilifu kwa issuer, network, mwajiri, mamlaka ya kodi, au investigator.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) ni orodha sanifu yenye `Pros`, `Cons`, `Procedure` ya hatua kwa hatua iliyo halali, na `Detection` kwa kila familia. Ukurasa huu unapanua mbinu za kawaida za malipo.

{% hint style="danger" %}
Usitumie kamwe akaunti zilizoibwa, synthetic identities, money mules, madai ya uwongo ya ukaazi au chanzo cha fedha, kugawanya miamala (“structuring”), au mawakala wasio wazi wa “no-KYC card”. Kagua sheria za sasa na masharti ya provider katika kila jurisdiction husika.
{% endhint %}

## Define the privacy property

Mtaje observer kabla ya kuchagua rail:

| Observer | Data ya kawaida | Udhibiti unaofaa | Kinachobaki |
|---|---|---|---|
| Merchant | Jina, email, anwani, card token, IP/device, kikapu | Guest checkout, data chache za hiari, virtual card maalum kwa merchant | Uwasilishaji, account na fraud telemetry |
| Issuer/payment processor | Utambulisho wa kisheria, chanzo cha fedha, merchant, kiasi, muda, device | Chagua provider aliyedhibitiwa mwenye masharti mazuri ya faragha/security | Provider bado anachakata na anaweza kuhifadhi/kufichua rekodi |
| Mwajiri/miliki wa engagement | Gharama, operator na madhumuni | Bajeti tofauti ya engagement na ledger yenye access-control | Governance halali inahitaji attribution ya ndani |
| Public blockchain observer | Anwani, mtiririko, kiasi na muda, kulingana na chain | Protocol inayofaa na nidhamu ya wallet | Acquisition, endpoints na matumizi ya baadaye vinaweza kuunganisha tena shughuli |
| Network/RPC/node operator | IP, wallet queries, transaction broadcasts | Local node au privacy network inayofaa | Muda na tabia ya endpoint bado vinaweza kuhusishwa |
| Physical observer | Uso, eneo, gari, CCTV, risiti | Faragha ya kawaida ya kimazingira | Cash haimfanyi mtu asionekane kimwili |

CFPB inaeleza kuwa payment apps zinaweza kukusanya data ya utambulisho, device, eneo, contacts, miamala na tabia; sheria za faragha za majimbo si lazima zizuie monetization au matumizi yote ya ziada.<sup>[[1]](#references)</sup> Soma notice halisi ya provider badala ya kukisia faragha kutokana na jina la bidhaa.

## Compare payment methods

| Method | Faida ya faragha | Observers/links kuu | Matumizi yanayofaa |
|---|---|---|---|
| Cash | Hakuna ledger ya payment-network | Mpokeaji, kamera, mashahidi, sheria za kuripoti cash | Ununuzi halali wa ndani pale inapokubaliwa |
| Open-loop prepaid/gift card | Hutenganisha namba ya card na card kuu | Seller, activation/registration provider, chanzo cha fedha, merchant | Bajeti au compartmentalization ndogo kutoka kwa merchant |
| Virtual/one-time card number | Huficha PAN inayoweza kutumika tena kutoka kwa merchant; kufuta ni rahisi | Issuer bado anajua utambulisho na muamala | Compartmentalization ya merchant wa mtandaoni |
| Mobile-wallet token | Device/merchant hupokea token badala ya PAN halisi | Wallet provider, issuer, payment network na merchant | Usalama wa credential, si anonymity |
| Bank transfer/app | Audit trail rahisi | Bank/app, counterparty na utambulisho uliounganishwa | Malipo ya mashirika yenye uwajibikaji |
| Cryptocurrency | Hutofautiana kwa protocol; self-custody inaweza kupunguza exposure kwa custodian | Public ledger au privacy protocol, exchange, endpoint, counterparty | Transfers halali baada ya uchanganuzi maalum wa protocol |

## Cash

Cash bado inaonekana kuwa muhimu kwa faragha na ujumuishaji, na huepuka rekodi ya payment-network.<sup>[[2]](#references)</sup> Haizuii CCTV, mashahidi, eneo la device, risiti, ufuatiliaji wa serial number katika hali maalum, au kuripotiwa kisheria.

### Lawful workflow

1. Kagua kukubalika na mipaka ya cash ya eneo kabla ya muamala. Mipaka hutofautiana kwa nchi na aina ya mhusika na hubadilika baada ya muda.
2. Fanya ununuzi wa kawaida katika muamala mmoja wa kweli. **Usiugawanye kamwe** ili kuepuka kiwango fulani au ripoti.
3. Kataa ufuatiliaji wa loyalty au ukusanyaji wa marketing wa hiari. Toa kwa ukweli data inayohitajika kwa warranty, usalama, delivery, kodi, au sheria.
4. Hifadhi uthibitisho unaohitajika wa ununuzi na rekodi za lazima za accounting katika storage iliyosimbwa kwa encryption yenye tarehe ya retention.
5. Kwa shirika, dai reimbursement kupitia mchakato uliothibitishwa na urekodi operator, authorization, madhumuni, kiasi, tarehe na risiti.

Nchini Marekani, biashara fulani huwasilisha Form 8300 kwa mapokezi ya cash yanayozidi $10,000, pamoja na miamala inayohusiana; kuvunja miamala kimakusudi kunaweza kuwa structuring isiyo halali yenyewe.<sup>[[3]](#references)</sup> Jurisdictions nyingine hutofautiana—kwa mfano, Spain huchapisha kizuizi chake cha kisheria kuhusu malipo ya cash.<sup>[[4]](#references)</sup>

## Prepaid and gift cards

“Prepaid” haimaanishi anonymous. Duka, issuer, program manager, funding bank na merchant wanaweza kuhusisha ununuzi, activation, device, IP, eneo na matumizi. Reloads, ATM access, matumizi ya kimataifa, limits za juu au ulinzi dhidi ya upotevu kwa kawaida huhitaji registration.

Mwongozo wa watumiaji wa Marekani unaeleza kuwa issuers wanaweza kuomba data ya utambulisho kwa verification ya kisheria na wanaweza kukataa card iliyosajiliwa verification inaposhindikana.<sup>[[5]](#references)</sup> Sheria za FinCEN hufafanua ni prepaid programs na participants gani wana majukumu ya AML.<sup>[[6]](#references)</sup> Katika EU, exceptions finyu za anonymous e-money zilipunguzwa na Directive (EU) 2018/843; Regulation (EU) 2024/1624 inabadilisha mfumo tena lakini kwa ujumla inaanza kutumika kuanzia **10 July 2027**, hivyo usiieleze kana kwamba tayari inatumika mwaka 2026.<sup>[[7]](#references)</sup>

Tumia prepaid value tu inapopatikana kihalali kutoka kwa issuer anayejulikana, masharti yake yanaruhusu matumizi yaliyokusudiwa, na faida ikiwa ni budgeting au kutenganisha kutoka kwa payment credential kuu. Epuka masoko ya resale na mawakala wanaotangaza cards za “no-name” zisizoweza kuthibitishwa: value inaweza kuwa imeibwa, imeshatumika, imewekewa mipaka ya kijiografia au inaweza kutaifishwa.

## Virtual cards and wallet tokens

Virtual card number (VCN) kwa kawaida hutolewa nyuma ya account halisi iliyothibitishwa. Namba maalum za merchant au za matumizi ya mara moja hupunguza athari za breach na kuhusishwa kwa PAN kati ya merchants; **hazifichi** muamala kutoka kwa issuer. Network tokenization vilevile hubadilisha card credential na token yenye masharti maalum.<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. Fungua account na issuer aliyedhibitiwa ukitumia data sahihi ya utambulisho, ukaazi na funding.
2. Ilinde kwa password ya kipekee, phishing-resistant MFA inapopatikana, login alerts na recovery codes zilizohifadhiwa offline.
3. Tengeneza VCN iliyofungwa kwa merchant au ya matumizi ya mara moja. Weka kikomo kinachofaa cha kiasi/muda kama kinaungwa mkono.
4. Tumia guest checkout na uache tu sehemu za **hiari** za profile, loyalty na marketing. Toa data sahihi ya billing, delivery na kodi inapohitajika.
5. Epuka kuingia kwenye identity providers zisizohusiana; tumia browser compartment ya engagement/account na network path iliyoidhinishwa.
6. Hifadhi risiti na mapping ya VCN-to-purpose katika ledger ya ndani iliyosimbwa kwa encryption.
7. Freeze au revoke namba baada ya muda wa refund/chargeback; fuatilia parent account kwa authorizations zisizotarajiwa.

Capital One na Google zinaeleza kuwa virtual numbers hubaki zimefungwa kwenye account ya msingi, huku EMVCo/Visa zikieleza tokenization kama credential substitution na domain restriction badala ya anonymity ya payer.<sup>[[8]](#references)</sup>

## Delivery, accounts and refunds

Malipo ni edge moja tu katika linkage graph:

- Card ya kipekee hushindwa kuwa ya faragha unapoitumia tena na personal email, phone, browser profile, IP address au loyalty account.
- Physical delivery kwa kawaida inahitaji recipient na eneo halali. Usitumie anwani ya mtu asiyehusika au kujifanya resident. Huduma za kupokea zilizoidhinishwa za biashara ni salama zaidi kuliko details zilizobuniwa.
- Bidhaa za kidijitali zinaweza kurekodi account identity, IP, device fingerprint, license activation na downloads.
- Refunds kwa kawaida hurudishwa kwenye rail ya awali. Maombi ya kupokea fedha na kuzituma/refund sehemu nyingine ni onyo la fraud na money-mule.
- Merchant descriptors, maandishi ya invoice na notifications za shipping zinaweza kufichua ununuzi nyeti kwa account delegates; weka access na alerts kwa makusudi.

## Authorized red-team purchases

Engagement inapaswa kuwa discreet externally na accountable internally:

1. Pata scope iliyoandikwa, madhumuni, spending ceiling, approver, merchants/assets zinazoruhusiwa na kanuni ya reimbursement.
2. Tumia payment account inayodhibitiwa na shirika na VCN au sub-account tofauti kwa kila engagement au merchant.
3. Weka billing na registrant details sahihi kwa providers. Public registration privacy inaweza kupunguza exposure lakini si ruhusa ya kusema uongo.
4. Dumisha ledger iliyosimbwa kwa encryption ya operator, approval, madhumuni, tarehe, kiasi, counterparty, asset identifier na risiti.
5. Chunguza counterparties inapohitajika na fuata majukumu ya provider, sanctions, kodi na reporting.
6. Wape finance access inayohitajika pekee; wape operators uwezo mdogo wa spending wanaouhitaji pekee.
7. Funga au freeze payment credentials wakati wa teardown, reconcile charges/refunds zinazosubiri, na hifadhi rekodi kulingana na policy.

Kwa chaguo maalum za crypto, endelea kwenye [Cryptocurrency Privacy](cryptocurrency-privacy.md). Kwa infrastructure inayoungwa mkono na ununuzi huo, tazama [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Verification checklist

- [ ] Sifa ya faragha inayohitajika na observers zimeandikwa.
- [ ] Sheria za provider, merchant na jurisdiction zilikaguliwa hivi karibuni.
- [ ] Taarifa za utambulisho na chanzo cha fedha ni za kweli.
- [ ] Data ya merchant iliyo hiari imepunguzwa bila kuzuia verification inayohitajika.
- [ ] Uhusiano kati ya funding, device, network, account, delivery na refund umeeleweka.
- [ ] Hakuna kuepuka threshold, counterparty iliyokatazwa, mule, credential iliyoibwa au utambulisho wa mtu wa tatu unaohusika.
- [ ] Risiti, approvals, rekodi za kodi na taarifa za recovery zinazohitajika zimesimbwa kwa encryption na kudhibitiwa kwa access-control.

## References

- [1] [US CFPB — Ombi la Taarifa Kuhusu Ukusanyaji, Matumizi na Monetization ya Data ya Malipo ya Watumiaji na Data Nyingine ya Kifedha ya Kibinafsi](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Utafiti kuhusu mitazamo ya malipo ya watumiaji katika eneo la euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Maelekezo ya Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Kuripoti malipo ya cash](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Kwa nini ninaombwa taarifa za kibinafsi ili ku-activate au kusajili prepaid card?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) and [Je, ninaweza kukataliwa prepaid card?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Kanuni ya Mwisho kuhusu Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Kutumia virtual credit cards](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
