# Protocol za Malipo Zinazohifadhi Faragha

{{#include ../banners/hacktricks-training.md}}

Mifumo ya hali ya juu ya malipo inaweza kumficha mlipaji kutoka kwa mfanyabiashara, kumficha mpokeaji au kiasi kwenye leja ya umma, au kuzuia mint kuhusisha withdrawal na redemption. Hizi ni sifa tofauti. Hakuna inayofuta rekodi za ununuzi, kifaa, mtandao, uwasilishaji, uhasibu, sanctions au endpoint.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) hutoa maelezo sanifu ya `Pros`, `Cons`, `Procedure` ya hatua kwa hatua, na `Detection` kwa kila familia ya malipo. Ukurasa huu unapanua protocols za hali ya juu.

{% hint style="danger" %}
Tumia fedha na counterparties halali pekee. Usitumie privacy protocols kukwepa identification inayohitajika, sanctions, kodi, ukaguzi wa chanzo cha fedha au kuripoti miamala. Usiendeshe exchange, mint au huduma ya transmission bila kuelewa majukumu ya licensing, custody, AML na ulinzi wa watumiaji.
{% endhint %}

## Linganisha chaguo za hali ya juu

| Protocol | Huficha nini kutoka kwa umma/mfanyabiashara | Mhusika anayeaminika au anayeangalia | Ukomavu/upatikanaji |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Watu wa nje hawawezi kuhusisha payment code inayoweza kutumika tena na outputs zake za mara moja | Graph ya umma ya Bitcoin hubaki; wallet/index server inaweza kuona scans | Specification imekamilika; support ya wallet hutofautiana |
| Zcash fully shielded Orchard | Mtumaji, mpokeaji na kiasi husimbwa kwenye chain | Wallet backend/network na acquisition/off-ramp hubaki | Imetumwa; shielded support hutofautiana kwa wallet/exchange |
| GNU Taler | Mfanyabiashara hahitaji kujua utambulisho wa mlipaji; mapato ya mfanyabiashara hubaki accountable | Taler exchange/bank huona funding; mfanyabiashara huona oda | Deployments zimewekewa mipaka kijiografia |
| Federated Chaumian e-cash | Federation haipaswi kuhusisha notes zilizotolewa na transfers/redemption za ndani | Guardian quorum huhifadhi reserves; gateways huona shughuli za mipakani | Community deployments zinazoibukia |
| Lightning BOLT 12/route blinding | Hupunguza ufichuzi wa receiver/node na route | Endpoints, hops zilizochaguliwa, funding chain na huduma za wallet | Support hutegemea wallet |
| Virtual card/token | Mfanyabiashara hupokea credential yenye mipaka, si PAN inayoweza kutumika tena | Issuer/network huhifadhi mlipaji na transaction | Imepevuka na inapatikana kwa upana |

## Bitcoin Silent Payments (BIP 352)

Silent Payments humruhusu mpokeaji kuchapisha payment code moja tuli huku kila mtumaji akitengeneza Taproot output ya kipekee. Mwangalizi wa chain aliye nje hawezi kuhusisha moja kwa moja outputs hizo na code iliyochapishwa, na hakuna ombi shirikishi la anwani au notification output ya on-chain linalohitajika. BIP 352 imewekwa kuwa **Complete**, lakini huongeza gharama ya scanning na haiendani na wallets ambazo hazijaiimplement.<sup>[[1]](#references)</sup>

### Mtiririko wa kazi wa mpokeaji

1. Chagua wallet inayodumishwa na inayounga mkono waziwazi receiving ya BIP 352; thibitisha feature hiyo dhidi ya documentation ya sasa ya wallet, si dai la social media.
2. Fanya backup ya wallet seed na Silent Payment descriptor/key material kwa kutumia njia ya recovery iliyoelezwa na wallet. Jaribu discovery kwa kiasi kidogo cha testnet/mainnet kabla ya kuchapisha code.
3. Tengeneza **labels** tofauti za campaigns, invoices au counterparties pale wallet inapounga mkono BIP 352 labels. Labels husaidia uhasibu wa ndani bila kuchapisha anwani zinazoweza kuhusishwa.
4. Chapisha Silent Payment code tuli kupitia channel iliyothibitishwa. Inaweza kutumika tena, lakini impostor anaweza kubadilisha na kuweka code yake mwenyewe.
5. Fanya scan kupitia local full node inapowezekana. Third-party index/scanning server inaweza kujifunza muda wa maombi au filter data hata kama haiwezi kutumia fedha.
6. Weka UTXOs zilizogunduliwa zikiwa na labels na tumia coin-control rules zilezile za Bitcoin ya kawaida. Kuzitumia au kuziunganisha kunaweza kufichua uhusiano wa umiliki.
7. Thibitisha kuwa recovery inagundua malipo bila kutegemea external index ambayo haijawekewa backup.

### Mtiririko wa kazi wa mtumaji

1. Thibitisha kuwa wallet inaunga mkono kutuma kwenye address version hiyo na thibitisha static code ndefu ya mpokeaji.
2. Ruhusu wallet itengeneze output; usiwahi kubadilisha au kufupisha code wewe mwenyewe.
3. Kagua inputs zilizochaguliwa kwa makini. Silent Payments huboresha faragha ya anwani ya mpokeaji, lakini sender inputs bado ziko kwenye graph ya umma.
4. Tumia fee bumping/PSBT behavior inayoungwa mkono na wallet. BIP 352 inahitaji output iundwe upya inputs zinapobadilika, na baadhi ya signing modes si salama.
5. Hifadhi receipt au proof iliyosimbwa inayohitajika kwa disputes/uhasibu.

Silent Payments hutatua uchapishaji unaorudiwa wa anwani ya mpokeaji. Hazifichi kiasi, muda wa transaction, sender cluster, historia ya acquisition au co-spending ya baadaye.

## Malipo ya Zcash fully shielded

Zcash inaunga mkono transparent na shielded value pools. Orchard shielded transactions hutumia zero-knowledge proofs ili nodes ziweze kuthibitisha validity huku maelezo ya transaction yakisimbwa; Unified Addresses zinaweza kuwa na aina nyingi za receivers.<sup>[[2]](#references)</sup> Faragha hutegemea path halisi iliyochaguliwa na wallet, si herufi ya kwanza ya anwani inayoonyeshwa.

### Mtiririko wa shielded

1. Chagua wallet inayodumishwa na inayotambulisha wazi tabia ya **shielded-by-default** pamoja na support ya sasa ya Orchard. Thibitisha download na ufanye backup/test ya seed.
2. Pata ZEC kwa njia halali na urekodi msingi/chanzo. Exchange bado inajua acquisition na withdrawal.
3. Pokea kwenye Unified Address inayoungwa mkono na wallet, kisha kagua ikiwa transaction iliingia kwenye shielded pool. Usidhani kuwa shielding ya kiotomatiki imetokea bila kuthibitisha tabia ya wallet.
4. Pendelea transfers za **shielded-to-shielded**. Harakati za transparent-to-shielded na shielded-to-transparent mipakani hufichua public values/timing na zinaweza kuwezesha correlation ya kiasi; Orchard specification inasema kuwa kutumia kwenye non-Orchard address hufichua thamani ya transaction.<sup>[[3]](#references)</sup>
5. Epuka round trips zenye exact amounts zinazotambulika na kuvuka mipaka mara moja. Hii ni usafi wa faragha, si ruhusa ya kuficha umiliki au reporting.
6. Tumia network-privacy path inayoungwa mkono na wallet. Shielded cryptography haifichi IP/timing kutoka kwa wallet servers au peers.
7. Hifadhi compliance records za ndani na tumia viewing keys kwa audit/disclosure iliyokusudiwa tu baada ya kuelewa scope yake.
8. Thibitisha support ya wallet/exchange ya mpokeaji kabla ya kutuma; receiver wa transparent anayelazimishwa hubadilisha sifa ya faragha.

## GNU Taler: mlipaji asiyejulikana, mfanyabiashara accountable

GNU Taler ni open electronic-payment protocol inayotumia currencies za jadi, blind signatures na integration inayodhibitiwa ya exchange/bank. Muundo wake unalenga kuwafanya wateja wasijulikane kwa wafanyabiashara huku wafanyabiashara wakibaki wanaotambulika na wanaolipa kodi.<sup>[[4]](#references)</sup> Si cryptocurrency, na upatikanaji wake hutegemea exchange ya kikanda, bank, wallet na merchant vinavyoendana.

### Mtiririko wa kazi wa mtumiaji pale inapotekelezwa

1. Tambua Taler exchange na merchant inayofanya kazi katika currency/jurisdiction husika; soma masharti yao ya sasa, fees, KYC na privacy notices.
2. Sakinisha official wallet na thibitisha chanzo chake. Linda wallet backup/recovery data kama fedha taslimu kwa sababu wallet value inaweza kuwa bearer asset.
3. Fanya withdrawal ya value kupitia bank/exchange flow inayoungwa mkono ukitumia taarifa za kweli. Funding institution/exchange inaweza kujua withdrawal ingawa blind signatures huvunja uhusiano wa moja kwa moja kati ya coin na withdrawal.
4. Kagua merchant contract ndani ya wallet: utambulisho wa merchant, bidhaa/muhtasari, kiasi, fees, refund na masharti ya uwasilishaji.
5. Lipa na uhifadhi receipt data inayohitajika kwa refund, warranty, uhasibu au kodi.
6. Usitumie tena optional merchant session/account identifiers ikiwa merchant unlinkability inahitajika.
7. Weka wallet, network na delivery metadata ndani ya threat model; payment cryptography ya Taler haifichi shipping address au endpoint iliyoathirika.

Mfanyabiashara na exchange hubaki accountable, na kuendesha component yoyote kati yao kunaweza kuwa shughuli ya regulated payment-service.

## Federated Chaumian e-cash

Chaumian e-cash hutumia blind signatures ili mint isaini token bila kuona token hiyo ikiwa haijafichuliwa baadaye. Fedimint husambaza custody ya reserves na signing miongoni mwa guardian federation; documentation yake inasema guardians huona aggregate reserves/outstanding notes lakini hawapaswi kuona balance ya mtu binafsi au nani amemlipa nani ndani ya federation.<sup>[[5]](#references)</sup>

Hii ni **custodial bearer value**. Guardian quorum ya kutosha hudhibiti reserves; federation failure, guardians wasio waaminifu, software bugs au kupotea kwa client state kunaweza kusababisha hasara. Deposits, withdrawals na Lightning gateways ni boundary events zinazoonekana na zinaweza kuhusisha timing/amount.

### Mtiririko wa kazi wenye risk ndogo

1. Tumia kiasi kidogo tu unachoweza kupoteza. Chukulia federations za umma/zinazojulikana kidogo kuwa na risk kubwa kuliko guardians wenye accountability ya ulimwengu halisi.
2. Thibitisha federation invite kupitia authenticated channel na urekodi utambulisho wa guardians, quorum, jurisdiction, fees, recovery na shutdown policy.
3. Sakinisha wallet inayodumishwa na inayoendana, ithibitishe, na uelewe backup scheme yake kabla ya kuweka deposit.
4. Weka Bitcoin iliyopatikana kihalali kupitia documented path. Rekodi peg-in kwa uhasibu na chukulia timing/amount yake kuwa ya umma au inajulikana kwenye boundary.
5. Ndani ya federation, tumia payment requests mpya na epuka kuongeza account/chat/delivery identifiers zinazounda tena uhusiano ulioondolewa na blind signature.
6. Kwa malipo ya Lightning, ichukulie gateway kama mwangalizi wa ziada wa invoices na boundary timing.
7. Fanya redeem/withdraw kulingana na policy, ukitarajia kuwa kiasi kinachotambulika na timing ya mara moja vinaweza kuhusishwa na deposit au payment ya nje.
8. Hifadhi tax/source/authorization records kwa faragha; usiwaombe guardians au gateways wapotoshe taarifa za shughuli.

Usieleze federated e-cash kuwa trustless, self-custodial au anonymous iliyohakikishwa.

## BOLT 12 offers na route blinding

BOLT 12 offers zinaweza kutumika tena bila kuchapisha anwani thabiti ya on-chain na zinaweza kutumia blinded paths ili mlipaji asiwe na haja ya kujua utambulisho/path iliyo wazi ya node ya mpokeaji. Hii inakamilisha, lakini haibadilishi, onion routing iliyopo ya Lightning.

Kabla ya kutumia:

1. Thibitisha kuwa wallets za mtumaji na mpokeaji zinaunga mkono BOLT 12 features zilezile za sasa; usikadirie support kutokana na branding ya jumla ya “Lightning”.
2. Thibitisha offer out of band na kagua kiasi, issuer/description na recurrence rules.
3. Tumia invoice/payment context mpya iliyotengenezwa kutoka kwenye offer.
4. Weka node aliases, taarifa za mawasiliano za umma na stable network endpoints kwa kiwango cha chini.
5. Chukulia kuwa sender/receiver, first/last hop, wallet service, channel graph na on-chain funding/closure bado hufichua sehemu za uhusiano.

## Auditability bila ufichuzi wa umma

Faragha na audit vinaweza kuwepo pamoja:

- Hifadhi labels, invoices, authorization, cost basis na ownership mapping zikiwa zimesimbwa nje ya public protocol.
- Tenganisha **view/audit key** na spending key pale protocol inapotoa mojawapo; jaribu disclosure yake halisi kwenye sample wallet kwanza.
- Mpe auditor proof yenye scope ndogo inayohitajika badala ya seed au spending credential isiyo na mipaka.
- Rekodi software version, protocol/pool, transaction ID au proof, purpose ya counterparty na chanzo cha exchange-rate wakati wa transaction.
- Bainisha retention na deletion badala ya kukusanya identity graph ya kudumu isiyosimbwa.

## Checklist ya uchaguzi

- [ ] Field iliyofichwa na observer vimetajwa kwa usahihi.
- [ ] Support ya wallet/protocol ilithibitishwa kufikia tarehe ya transaction.
- [ ] Links za acquisition, network, node/RPC, counterparty, delivery na later-spend zimeandikwa.
- [ ] Risk za custody, recovery, liquidity, issuer/federation solvency na refund zimekubaliwa.
- [ ] Records zinazohitajika za identity, kodi, sanctions, source na shirika bado ni sahihi.
- [ ] Jaribio dogo la end-to-end, likijumuisha recovery na audit proof, limefaulu.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Jinsi inavyofanya kazi](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
