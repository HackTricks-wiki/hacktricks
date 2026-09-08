# Protocoli za Malipo Zinazolinda Faragha

Mifumo ya malipo ya hali ya juu inaweza kumficha mlipaji kutoka kwa merchant, kumficha mpokeaji au kiasi kutoka kwenye public ledger, au kuzuia mint kuunganisha withdrawal na redemption. Hizi ni sifa tofauti. Hakuna inayofuta rekodi za acquisition, kifaa, mtandao, delivery, accounting, sanctions au endpoint.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) hutoa vipengele vilivyosanifishwa vya `Pros`, `Cons`, `Procedure` ya hatua kwa hatua, na `Detection` kwa kila familia ya malipo. Ukurasa huu unapanua maelezo ya protocol za hali ya juu.

{% hint style="danger" %}
Tumia fedha na counterparties halali pekee. Usitumie privacy protocols kukwepa utambulisho unaohitajika, sanctions, kodi, ukaguzi wa source-of-funds au reporting ya miamala. Usiendeshe exchange, mint au huduma ya transmission bila kuelewa wajibu wa licensing, custody, AML na consumer-protection.
{% endhint %}

## Linganisha chaguo za hali ya juu

| Protocol | Huficha nini kutoka kwa public/merchant | Trusted au observing party | Ukomaavu/upatikanaji |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Watu wa nje hawawezi kuunganisha payment code inayotumika tena na outputs zake za mara moja | Public Bitcoin graph inabaki; wallet/index server inaweza kuona scans | Specification imekamilika; wallet support hutofautiana |
| Zcash fully shielded Orchard | Sender, receiver na amount zimesimbwa kwenye on-chain | Wallet backend/network na acquisition/off-ramp bado zinabaki | Imetumika; shielded support hutofautiana kwa wallet/exchange |
| GNU Taler | Merchant si lazima ajue utambulisho wa payer; mapato ya merchant yanabaki accountable | Taler exchange/bank huona funding; merchant huona order | Deployments zina mipaka ya kijiografia |
| Federated Chaumian e-cash | Federation haipaswi kuunganisha notes zilizotolewa na internal transfers/redemption | Guardian quorum huhifadhi reserves; gateways huona boundary activity | Community deployments zinazoibuka |
| Lightning BOLT 12/route blinding | Hupunguza kufichuliwa kwa receiver/node na route | Endpoints, hops zilizochaguliwa, funding chain na wallet services | Support inategemea wallet |
| Virtual card/token | Merchant hupokea credential yenye mipaka, si PAN inayoweza kutumika tena | Issuer/network huhifadhi payer na transaction | Imepevuka na inapatikana kwa upana |

## Bitcoin Silent Payments (BIP 352)

Silent Payments humruhusu receiver kuchapisha payment code moja tuli, huku kila sender akitengeneza Taproot output ya kipekee. Mchunguzi wa nje wa chain hawezi kuunganisha moja kwa moja outputs hizo na code iliyochapishwa, na hakuna ombi la anwani la mawasiliano au notification output ya on-chain linalohitajika. BIP 352 imewekwa kuwa **Complete**, lakini huongeza gharama ya scanning na haiendani na wallet ambazo hazijaiimplement.<sup>[[1]](#references)</sup>

### Mtiririko wa receiver

1. Chagua wallet inayodumishwa na inayounga mkono waziwazi upokeaji wa BIP 352; thibitisha kipengele hicho dhidi ya documentation ya sasa ya wallet, si dai la social media.
2. Fanya backup ya wallet seed na Silent Payment descriptor/key material kwa kutumia recovery method iliyoandikwa na wallet. Jaribu discovery kwa kiasi kidogo cha testnet/mainnet kabla ya kuchapisha code.
3. Tengeneza **labels** tofauti kwa campaigns, invoices au counterparties pale wallet inapounga mkono BIP 352 labels. Labels husaidia local accounting bila kuchapisha anwani zinazoweza kuunganishwa.
4. Chapisha Silent Payment code tuli kupitia authenticated channel. Inaweza kutumika tena, lakini impostor anaweza kubadilisha na kuweka code yake mwenyewe.
5. Fanya scanning kupitia local full node inapowezekana. Third-party index/scanning server inaweza kujifunza muda wa maombi au filter data hata kama haiwezi kutumia fedha.
6. Weka UTXOs zilizogunduliwa zikiwa na labels na tumia coin-control rules zilezile kama za Bitcoin ya kawaida. Kuzitumia au kuziunganisha kunaweza kufichua uhusiano wa umiliki.
7. Thibitisha kuwa recovery inagundua malipo bila kutegemea external index ambayo haijafanyiwa backup.

### Mtiririko wa sender

1. Thibitisha kuwa wallet inaunga mkono kutuma kwenda kwenye address version hiyo na authenticate receiver's long static code.
2. Ruhusu wallet itengeneze output; usiwahi kubadilisha au kufupisha code mwenyewe.
3. Kagua kwa makini inputs zilizochaguliwa. Silent Payments huboresha privacy ya recipient-address, lakini sender inputs bado ziko kwenye public graph.
4. Tumia fee bumping/PSBT behavior inayoungwa mkono na wallet. BIP 352 inahitaji output re-derivation ikiwa inputs zitabadilika, na baadhi ya signing modes si salama.
5. Hifadhi receipt au proof iliyosimbwa inayohitajika kwa disputes/accounting.

Silent Payments hutatua uchapishaji unaorudiwa wa recipient address. Hazifichi amount, muda wa transaction, sender cluster, acquisition history au co-spending ya baadaye.

## Zcash fully shielded payments

Zcash inaunga mkono transparent na shielded value pools. Orchard shielded transactions hutumia zero-knowledge proofs ili nodes ziweze kuthibitisha validity huku maelezo ya transaction yakiwa yamesimbwa; Unified Addresses zinaweza kuwa na receiver types nyingi.<sup>[[2]](#references)</sup> Privacy inategemea path halisi iliyochaguliwa na wallet, si herufi ya kwanza ya address inayoonyeshwa.

### Mtiririko wa shielded

1. Chagua wallet inayodumishwa inayotambua wazi tabia ya **shielded-by-default** na Orchard support ya sasa. Thibitisha download na ufanye backup/test ya seed.
2. Pata ZEC kwa njia halali na urekodi basis/source. Exchange bado inajua acquisition na withdrawal.
3. Pokea kwenye Unified Address inayoungwa mkono na wallet, kisha kagua kama transaction iliingia kwenye shielded pool. Usidhani shielding ya kiotomatiki bila kuthibitisha tabia ya wallet.
4. Pendelea transfers za **shielded-to-shielded**. Transparent-to-shielded na shielded-to-transparent boundary movements hufichua public values/timing na zinaweza kuwezesha amount correlation; Orchard specification inabainisha kuwa spending kwenda kwenye non-Orchard address hufichua transaction value.<sup>[[3]](#references)</sup>
5. Epuka round trips za exact-amount zinazotambulika na boundary crossings za haraka. Hii ni privacy hygiene, si ruhusa ya kuficha umiliki au reporting.
6. Tumia network-privacy path inayoungwa mkono na wallet. Shielded cryptography haifichi IP/timing kutoka kwa wallet servers au peers.
7. Weka internal compliance records na utumie viewing keys kwa audit/disclosure iliyokusudiwa pekee baada ya kuelewa scope yake.
8. Thibitisha recipient wallet/exchange support kabla ya kutuma; transparent receiver anayelazimishwa hubadilisha privacy property.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler ni open electronic-payment protocol inayotumia traditional currencies, blind signatures na regulated exchange/bank integration. Muundo wake unalenga kuwafanya customers wabaki anonymous kwa merchants huku merchants wakiendelea kutambulika na kulipa kodi.<sup>[[4]](#references)</sup> Si cryptocurrency, na upatikanaji wake hutegemea exchange, bank, wallet na merchant ya eneo inayolingana.

### Mtiririko wa user inapopatikana

1. Tambua Taler exchange na merchant inayofanya kazi katika currency/jurisdiction husika; soma terms, fees, KYC na privacy notices zao za sasa.
2. Install official wallet na thibitisha source yake. Linda wallet backup/recovery data kama cash kwa sababu wallet value inaweza kuwa bearer asset.
3. Withdraw value kupitia supported bank/exchange flow ukitumia taarifa za kweli. Funding institution/exchange inaweza kujua withdrawal hata kama blind signatures zinavunja direct coin-to-withdrawal link.
4. Kagua merchant contract ndani ya wallet: merchant identity, item/summary, amount, fees, refund na delivery terms.
5. Lipa na uhifadhi receipt data inayohitajika kwa refund, warranty, accounting au tax.
6. Usitumie tena optional merchant session/account identifiers ikiwa merchant unlinkability inahitajika.
7. Weka wallet, network na delivery metadata kwenye threat model; payment cryptography ya Taler haifichi shipping address au endpoint iliyoathiriwa.

Merchant na exchange hubaki accountable, na kuendesha component yoyote kati yao kunaweza kuwa regulated payment-service activity.

## Federated Chaumian e-cash

Chaumian e-cash hutumia blind signatures ili mint itie saini token bila kuona token iliyofunuliwa baadaye na kutumika. Fedimint husambaza custody ya reserves na signing kati ya guardian federation; documentation yake inasema guardians huona aggregate reserves/outstanding notes lakini hawapaswi kuona individual balance au nani alimlipa nani ndani ya federation.<sup>[[5]](#references)</sup>

Hii ni **custodial bearer value**. Guardian quorum ya kutosha hudhibiti reserves; federation failure, guardians wasio waaminifu, software bugs au client state iliyopotea vinaweza kusababisha hasara. Deposits, withdrawals na Lightning gateways ni boundary events zinazoonekana na zinaweza kuunganisha timing/amount.

### Mtiririko wa limited-risk

1. Tumia kiasi kidogo tu ambacho unaweza kumudu kupoteza. Chukulia public/unknown federations kuwa hatari zaidi kuliko guardians wenye accountability ya ulimwengu halisi.
2. Thibitisha federation invite kupitia authenticated channel na urekodi guardian identities, quorum, jurisdiction, fees, recovery na shutdown policy.
3. Install compatible wallet inayodumishwa, ithibitishe, na uelewe backup scheme yake kabla ya kuweka deposit.
4. Deposit Bitcoin iliyopatikana kihalali kupitia documented path. Rekodi peg-in kwa accounting na chukulia timing/amount yake kuwa ya umma au inajulikana kwenye boundary.
5. Ndani ya federation, tumia fresh payment requests na epuka kuongeza account/chat/delivery identifiers zinazounda tena link ambayo blind signature iliiondoa.
6. Kwa Lightning payments, chukulia gateway kuwa observer wa ziada wa invoices na boundary timing.
7. Redeem/withdraw kulingana na policy, ukitarajia kuwa distinctive amount na immediate timing vinaweza kuhusishwa na deposit au external payment.
8. Weka tax/source/authorization records kwa faragha; usiwaombe guardians au gateways kuwasilisha activity kwa taarifa zisizo za kweli.

Usieleze federated e-cash kuwa trustless, self-custodial au guaranteed anonymous.

## BOLT 12 offers na route blinding

BOLT 12 offers zinaweza kutumika tena bila kuchapisha stable on-chain address na zinaweza kutumia blinded paths ili payer asihitaji kujua clear node identity/path ya receiver. Hii inakamilisha, lakini haibadilishi, onion routing iliyopo ya Lightning.

Kabla ya kutumia:

1. Thibitisha kuwa sender na receiver wallets zinaunga mkono BOLT 12 features zilezile za sasa; usikadirie support kutokana na branding ya jumla ya “Lightning”.
2. Authenticate offer out of band na kagua amount, issuer/description na recurrence rules.
3. Tumia fresh invoice/payment context iliyotengenezwa kutoka kwenye offer.
4. Weka node aliases, public contact information na stable network endpoints kuwa chache iwezekanavyo.
5. Chukulia kuwa sender/receiver, first/last hop, wallet service, channel graph na on-chain funding/closure bado hufichua sehemu za uhusiano.

## Auditability bila public disclosure

Privacy na audit zinaweza kuwepo pamoja:

- Weka labels, invoices, authorization, cost basis na ownership mapping zikiwa zimesimbwa nje ya public protocol.
- Tenganisha **view/audit key** na spending key pale protocol inapotoa moja; jaribu disclosure yake halisi kwenye sample wallet kwanza.
- Mpe auditor scoped proof ya kiwango cha chini badala ya seed au unrestricted spending credential.
- Rekodi software version, protocol/pool, transaction ID au proof, counterparty purpose na exchange-rate source wakati wa transaction.
- Bainisha retention na deletion badala ya kukusanya permanent unencrypted identity graph.

## Orodha ya ukaguzi wa uteuzi

- [ ] Sehemu iliyofichwa na observer zimetajwa kwa usahihi.
- [ ] Wallet/protocol support ilithibitishwa kufikia tarehe ya transaction.
- [ ] Acquisition, network, node/RPC, counterparty, delivery na later-spend links zimeandikwa.
- [ ] Hatari za custody, recovery, liquidity, issuer/federation solvency na refund zimekubaliwa.
- [ ] Required identity, tax, sanctions, source na organizational records zinaendelea kuwa sahihi.
- [ ] Jaribio dogo la end-to-end, likijumuisha recovery na audit proof, limefaulu.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
