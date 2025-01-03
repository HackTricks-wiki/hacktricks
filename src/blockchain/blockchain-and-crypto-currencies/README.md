{{#include ../../banners/hacktricks-training.md}}

## Misingi ya Kimsingi

- **Smart Contracts** zin定义wa kama programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanatimizwa, zikifanya utekelezaji wa makubaliano bila wahusika wa kati.
- **Decentralized Applications (dApps)** zinajengwa juu ya smart contracts, zikiwa na muonekano wa kirafiki kwa mtumiaji na nyuma ya pazia wazi, inayoweza kukaguliwa.
- **Tokens & Coins** zinatofautisha ambapo coins hutumikia kama pesa za kidijitali, wakati tokens zinawakilisha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** zinatoa ufikiaji wa huduma, na **Security Tokens** zinamaanisha umiliki wa mali.
- **DeFi** inasimama kwa Decentralized Finance, ikitoa huduma za kifedha bila mamlaka za kati.
- **DEX** na **DAOs** zinarejelea Mifumo ya Kubadilishana Isiyo na Kati na Mashirika ya Kujitegemea Yasiyo na Kati, mtawalia.

## Mekanizimu za Makubaliano

Mekanizimu za makubaliano zinahakikisha uthibitisho salama na wa makubaliano wa muamala kwenye blockchain:

- **Proof of Work (PoW)** inategemea nguvu za kompyuta kwa ajili ya uthibitisho wa muamala.
- **Proof of Stake (PoS)** inahitaji waithibitishaji kuwa na kiasi fulani cha tokens, ikipunguza matumizi ya nishati ikilinganishwa na PoW.

## Msingi wa Bitcoin

### Muamala

Muamala wa Bitcoin unahusisha kuhamasisha fedha kati ya anwani. Muamala unathibitishwa kupitia saini za kidijitali, kuhakikisha ni mmiliki pekee wa funguo za faragha anayeweza kuanzisha uhamasishaji.

#### Vipengele Muhimu:

- **Muamala wa Multisignature** unahitaji saini nyingi ili kuidhinisha muamala.
- Muamala unajumuisha **inputs** (chanzo cha fedha), **outputs** (kikundi), **fees** (zilizolipwa kwa wachimbaji), na **scripts** (sheria za muamala).

### Mtandao wa Mwanga

Unalenga kuboresha uwezo wa Bitcoin kwa kuruhusu muamala mwingi ndani ya channel, ukitangaza tu hali ya mwisho kwenye blockchain.

## Wasiwasi wa Faragha wa Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, yanatumia mifumo ya muamala. Mikakati kama **Mixers** na **CoinJoin** inaboresha kutotambulika kwa kuficha viungo vya muamala kati ya watumiaji.

## Kupata Bitcoins kwa Siri

Mbinu zinajumuisha biashara za pesa taslimu, uchimbaji, na kutumia mixers. **CoinJoin** inachanganya muamala mingi ili kuleta ugumu katika kufuatilia, wakati **PayJoin** inaficha CoinJoins kama muamala wa kawaida kwa ajili ya faragha zaidi.

# Mashambulizi ya Faragha ya Bitcoin

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya muamala na kutotambulika kwa watumiaji mara nyingi ni mada za wasiwasi. Hapa kuna muhtasari rahisi wa mbinu kadhaa za kawaida ambazo washambuliaji wanaweza kuathiri faragha ya Bitcoin.

## **Ushirikiano wa Kawaida wa Ingizo**

Kwa kawaida ni nadra kwa ingizo kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kutokana na ugumu uliohusika. Hivyo, **anwani mbili za ingizo katika muamala mmoja mara nyingi zinadhaniwa kuwa za mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike kabisa katika muamala. Ikiwa sehemu tu yake inatumwa kwa anwani nyingine, iliyobaki inaenda kwa anwani mpya ya mabadiliko. Waangalizi wanaweza kudhani anwani hii mpya inamhusu mtumaji, ikihatarisha faragha.

### Mfano

Ili kupunguza hili, huduma za kuchanganya au kutumia anwani nyingi zinaweza kusaidia kuficha umiliki.

## **Kuwekwa kwa Mitandao ya Kijamii na Mifumo ya Majadiliano**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, na kufanya **rahisi kuunganisha anwani hiyo na mmiliki wake**.

## **Analizi ya Grafu za Muamala**

Muamala unaweza kuonyeshwa kama grafu, ikifunua uhusiano wa uwezekano kati ya watumiaji kulingana na mtiririko wa fedha.

## **Heuristics ya Ingizo Isiyo ya Lazima (Heuristics ya Mabadiliko Bora)**

Heuristics hii inategemea kuchambua muamala wenye ingizo nyingi na matokeo ili kudhani ni ipi matokeo ni mabadiliko yanayorejea kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiwa kuongeza ingizo zaidi kunafanya matokeo ya mabadiliko kuwa makubwa kuliko ingizo lolote, inaweza kuchanganya heuristics.

## **Kurudi kwa Anwani Zilizo Lazimishwa**

Washambuliaji wanaweza kutuma kiasi kidogo kwa anwani zilizotumika hapo awali, wakitumaini mpokeaji atachanganya hizi na ingizo zingine katika miamala ya baadaye, hivyo kuunganisha anwani pamoja.

### Tabia Sahihi ya Wallet

Wallet zinapaswa kuepuka kutumia sarafu zilizopokelewa kwenye anwani ambazo tayari zimetumika, ili kuzuia uvujaji huu wa faragha.

## **Mbinu Nyingine za Uchambuzi wa Blockchain**

- **Kiasi Sahihi cha Malipo:** Miamala bila mabadiliko yanaweza kuwa kati ya anwani mbili zinazomilikiwa na mtumiaji mmoja.
- **Nambari za Mzunguko:** Nambari ya mzunguko katika muamala inaonyesha ni malipo, huku matokeo yasiyo ya mzunguko yakionekana kuwa mabadiliko.
- **Fingerprinting ya Wallet:** Wallet tofauti zina mifumo ya kipekee ya kuunda miamala, ikiruhusu wachambuzi kubaini programu iliyotumika na labda anwani ya mabadiliko.
- **Uhusiano wa Kiasi na Wakati:** Kufichua nyakati au kiasi cha miamala kunaweza kufanya miamala iweze kufuatiliwa.

## **Uchambuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuunganisha miamala au vizuizi na anwani za IP, wakihatarisha faragha ya mtumiaji. Hii ni kweli hasa ikiwa shirika linaendesha nodi nyingi za Bitcoin, kuimarisha uwezo wao wa kufuatilia miamala.

## Zaidi

Kwa orodha kamili ya mashambulizi ya faragha na ulinzi, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Yasiyo na Jina

## Njia za Kupata Bitcoins kwa Njia ya Siri

- **Miamala ya Fedha Taslimu**: Kupata bitcoin kupitia fedha taslimu.
- **Mbadala za Fedha Taslimu**: Kununua kadi za zawadi na kuzibadilisha mtandaoni kwa bitcoin.
- **Uchimbaji**: Njia ya faragha zaidi ya kupata bitcoins ni kupitia uchimbaji, hasa inapofanywa peke yake kwa sababu makundi ya uchimbaji yanaweza kujua anwani ya IP ya mchimbaji. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kimsingi, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata kwa siri, ingawa ni haramu na haipendekezwi.

## Huduma za Mchanganyiko

Kwa kutumia huduma ya mchanganyiko, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kwa kurudi**, ambayo inafanya kufuatilia mmiliki wa asili kuwa ngumu. Hata hivyo, hii inahitaji kuaminika kwa huduma hiyo kutoshika kumbukumbu na kurudisha bitcoins kwa kweli. Chaguzi mbadala za mchanganyiko ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** inachanganya miamala kadhaa kutoka kwa watumiaji tofauti kuwa moja, ikifanya mchakato kuwa mgumu kwa yeyote anayejaribu kulinganisha ingizo na matokeo. Licha ya ufanisi wake, miamala yenye ukubwa wa kipekee wa ingizo na matokeo bado inaweza kufuatiliwa.

Mifano ya miamala ambayo inaweza kuwa imetumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa huduma sawa kwenye Ethereum, angalia [Tornado Cash](https://tornado.cash), ambayo inafanya miamala kuwa ya siri kwa fedha kutoka kwa wachimbaji.

## PayJoin

Tofauti ya CoinJoin, **PayJoin** (au P2EP), inaficha muamala kati ya pande mbili (kwa mfano, mteja na mfanyabiashara) kama muamala wa kawaida, bila sifa ya matokeo sawa ya CoinJoin. Hii inafanya iwe ngumu sana kugundua na inaweza kubatilisha heuristics ya umiliki wa ingizo la kawaida inayotumiwa na mashirika ya ufuatiliaji wa muamala.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions kama hizo zinaweza kuwa PayJoin, ikiongeza faragha wakati inabaki kuwa isiyo na tofauti na muamala wa kawaida wa bitcoin.

**Matumizi ya PayJoin yanaweza kuathiri kwa kiasi kikubwa mbinu za ufuatiliaji wa jadi**, na kuifanya kuwa maendeleo ya ahadi katika kutafuta faragha ya muamala.

# Mbinu Bora za Faragha katika Cryptocurrencies

## **Mbinu za Usawazishaji wa Wallet**

Ili kudumisha faragha na usalama, kusawazisha wallets na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Node kamili**: Kwa kupakua blockchain yote, node kamili inahakikisha faragha ya juu. Muamala wote ambao umewahi kufanywa huhifadhiwa kwa ndani, na kufanya iwe vigumu kwa maadui kubaini ni muamala gani au anwani ambazo mtumiaji anavutiwa nazo.
- **Filtering ya block upande wa mteja**: Mbinu hii inahusisha kuunda filters kwa kila block katika blockchain, ikiruhusu wallets kubaini muamala muhimu bila kufichua maslahi maalum kwa waangalizi wa mtandao. Wallets nyepesi hupakua filters hizi, zikichukua blocks kamili tu wakati kuna mechi na anwani za mtumiaji.

## **Kutumia Tor kwa Anonymity**

Kwa kuwa Bitcoin inafanya kazi kwenye mtandao wa mtu kwa mtu, kutumia Tor inapendekezwa kuficha anwani yako ya IP, ikiongeza faragha unaposhirikiana na mtandao.

## **Kuzuia Utumiaji wa Anwani Tena**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuunganisha muamala na entiti ile ile. Wallets za kisasa zinakataa matumizi ya anwani tena kupitia muundo wao.

## **Mikakati ya Faragha ya Muamala**

- **Muamala mingi**: Kugawanya malipo katika muamala kadhaa kunaweza kuficha kiasi cha muamala, kukatisha mashambulizi ya faragha.
- **Kuepuka mabadiliko**: Kuchagua muamala ambao hauhitaji matokeo ya mabadiliko kunaboresha faragha kwa kuvuruga mbinu za kugundua mabadiliko.
- **Matokeo mengi ya mabadiliko**: Ikiwa kuepuka mabadiliko si rahisi, kuunda matokeo mengi ya mabadiliko bado kunaweza kuboresha faragha.

# **Monero: Mwanga wa Anonymity**

Monero inakidhi hitaji la anonymity kamili katika muamala za kidijitali, ikiweka kiwango cha juu cha faragha.

# **Ethereum: Gesi na Muamala**

## **Kuelewa Gesi**

Gesi hupima juhudi za kompyuta zinazohitajika kutekeleza operesheni kwenye Ethereum, ikipimwa kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) unahusisha kikomo cha gesi na ada ya msingi, pamoja na tips ili kuwahamasisha wachimbaji. Watumiaji wanaweza kuweka ada ya juu ili kuhakikisha hawalipi zaidi, na ziada inarejeshwa.

## **Kutekeleza Muamala**

Muamala katika Ethereum unahusisha mtumaji na mpokeaji, ambao unaweza kuwa anwani za mtumiaji au mkataba smart. Wanahitaji ada na lazima wachimbwe. Taarifa muhimu katika muamala inajumuisha mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gesi, na ada. Kwa kuzingatia, anwani ya mtumaji inapatikana kutoka kwa sahihi, ikiondoa hitaji lake katika data ya muamala.

Mbinu na mifumo hii ni msingi kwa yeyote anayetaka kushiriki na cryptocurrencies huku akipa kipaumbele faragha na usalama.

## Marejeo

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

{{#include ../../banners/hacktricks-training.md}}
