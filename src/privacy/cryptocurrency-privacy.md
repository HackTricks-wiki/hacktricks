# Faragha ya Cryptocurrency

Faragha ya cryptocurrency ni suala la protocol na operations, si kisawe cha usiri au kutokabiliwa na madhara. Public ledgers, exchanges, wallet servers, network peers, merchants na miamala ya baadaye hufichua sehemu tofauti za graph.

Anza na [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) kwa muundo wa pros/cons/procedure/detection wa kila technique. Ukurasa huu unaeleza zaidi mechanics maalum za cryptocurrency na mipaka ya kiutendaji.

{% hint style="danger" %}
Sura hii ni kwa self-custody halali na kupunguza data. Usiitumie kuficha mapato haramu, kukwepa sanctions/tax/reporting, kufanya miamala na wahusika waliokatazwa, kumpotosha mtoa huduma anayesimamiwa, au kuendesha huduma ya transmission isiyo na leseni. Privacy technology haibadilishi chanzo halali au umiliki wa funds.
{% endhint %}

## Threat model kwa kila layer

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Utambulisho, funding account, destination, device, IP, muda |
| Ledger | Mtu yeyote anayeendesha analytics | Addresses/outputs, amounts na muda kwenye transparent chains; protocol-specific metadata kwingineko |
| Wallet backend | RPC provider, explorer, remote node | Address queries, balances, IP, transaction broadcast |
| Network | ISP, peers, anonymity-network entry | IP, timing, volume na matumizi ya protocol |
| Counterparty | Payer/payee | Invoice/address, delivery, conversation, account na timing |
| Endpoint | Malware, cloud backup, physical seizure | Seed, keys, labels, history, screenshots na clipboard |

Self-custody inaweza kumuondoa custodian kwenye control path, lakini haifuti ledger, acquisition record, network metadata au endpoint evidence.

## Ulinganisho wa protocols

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh addresses huepuka address reuse rahisi | Public permanent transaction graph; amount/timing na spending heuristics |
| Bitcoin PayJoin | Receiver input inaweza kuvunja common-input-ownership heuristic | Wallet zote zinahitaji support; transaction hubaki public; support si ya kiwango sawa |
| Bitcoin CoinJoin | Huleta ambiguity miongoni mwa coordinated participants | Recognizable patterns, pre/post links, consolidation, policy/legal/provider risk |
| Lightning | Onion-routed payments hazichapishwi globally kama transfers za kawaida | Channels hufunguliwa/kufungwa on-chain; endpoints, peers, probes au custodian wanaweza kukadiria data |
| Monero | Stronger default on-chain confidentiality kwa receiver, amount na sender set | Exchange, node, timing, endpoint na counterparty links hubaki |
| Ethereum/stablecoins | Broad availability na smart-contract interoperability | Public state/actions; RPC metadata; centralized issuers wanaweza ku-block/freeze/report |

## Bitcoin: privacy-preserving baseline

Bitcoin ni pseudonymous, si anonymous. Confirmed transactions ni public na hudumu; address reuse, common-input ownership, change detection na publicly identified addresses zinaweza kujenga clusters.<sup>[[1]](#references)</sup>

### Workflow

1. **Chagua wallet ya self-custody inayotunzwa.** Download kutoka official project, verify signatures/hashes zinapotolewa, na tumia security updates.
2. **Unda wallet kwenye endpoint inayoaminika.** Hifadhi recovery seed offline; usiiweke kamwe kwenye email, chat, screenshots au cloud notes za kawaida. Jaribu recovery kabla ya kuweka value kubwa.
3. **Weka operational value pekee ikiwa hot.** Tumia offline/hardware custody inayofaa kwa value ya muda mrefu, pamoja na recovery plan ambayo haiweki seed kwenye location moja dhaifu.
4. **Generate fresh receive address/invoice kwa kila transaction.** Usichapishe static address wakati invoice server au authenticated private delivery inawezekana.
5. **Tumia full node yako inapowezekana.** Third-party explorer/electrum server inaweza kujua queried addresses na IP metadata. Configure tu Tor/proxy behavior inayoungwa mkono na wallet; Tor huficha network edge, si blockchain graph.
6. **Label kila UTXO kwa faragha** kwa source, owner, purpose na compliance state. Enable coin control ili identity contexts zisizohusiana zisitumike pamoja.
7. **Preview transaction:** selected inputs, change destination, amount, fee, counterparty na kama spend inaunganisha compartments. Epuka unnecessary consolidation.
8. **Hifadhi lawful records kando na kwa encryption.** Hifadhi acquisition basis, invoices, authorization na tax/reporting information bila kuchapisha mapping.
9. **Chukulia later spending kama sehemu ya uamuzi huohuo wa faragha.** Receipt iliyotenganishwa vizuri inaweza kuunganishwa tena output yake inapotumika pamoja na identified funds.

Bitcoin Core's privacy documentation inaeleza kuwa full node huepuka kufichua wallet queries kwa third-party servers, lakini transaction broadcast na public history bado vinahitaji analysis.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin ni collaborative payment ambapo receiver anaongeza input. Hii inazuia assumption rahisi kwamba inputs zote ni za sender. BIP 78 inaeleza original interactive protocol; draft BIP 77 inafafanua asynchronous v2 design inayotumia encrypted mailbox/OHTTP.<sup>[[3]](#references)</sup>

Matumizi salama:

1. Thibitisha kuwa wallets zote mbili zina-support PayJoin version ileile inayotunzwa.
2. Pata PayJoin-capable invoice kupitia authenticated channel; ilinde kama payment request yoyote.
3. Kagua original amount na destination, kisha iruhusu wallet ivalidate proposal/PSBT, fee contribution na prohibited substitutions.
4. Thibitisha final wallet summary. Usikubali manually output, amount au excessive fee usiyoitarajia.
5. Negotiation ikishindikana, elewa kama wallet inarudi kwa usalama kwenye ordinary payment au inahitaji invoice mpya.
6. Hifadhi private receipt/records zinazohitajika kwa ownership, accounting na disputes.

PayJoin huboresha chain-analysis heuristic moja; haifichi payment dhidi ya parties, acquisition platform, endpoints au public ledger.

## CoinJoin: faida na mipaka

CoinJoin huwaratibu users wengi kwenye transaction moja ili kufanya input-output mapping isiwe na uhakika zaidi. Research kuhusu specific historical Wasabi na Samourai designs ilipata transactions zinazotambulika kwa urahisi na ikaonyesha kuwa pre/post-mix behavior inaweza kupunguza anonymity kwa kiasi kikubwa.<sup>[[4]](#references)</sup> Matokeo hayo hayapaswi kujumlishwa kwa kila implementation au future version, lakini yanaonyesha kwa nini namba ya “anonymity-set” si guarantee.

Kabla ya matumizi yoyote halali:

- kagua sheria za eneo lako za sasa, sanctions status, exchange/custodian policy na tax/reporting duties;
- tumia non-custodial software inayotunzwa, iliyopatikana kutoka official project yake;
- elewa coordinator model, fees, denial-of-service controls na kama current service bado inaendesha—zkSNACKs ilimaliza coordinator wake mwaka 2024, ingawa Wasabi coordinators wengine wanaweza kuwepo;
- hifadhi source-of-funds na transaction records kwa faragha;
- usiwahi kupokea unknown funds kwa niaba ya mtu mwingine au kutumia custodial “mixer” inayoahidi untraceable withdrawals;
- weka outputs zikitenganishwa kulingana na source/context na epuka later consolidation inayoharibu ambiguity iliyokusudiwa.

Matokeo ya kisheria hutegemea facts na jurisdiction. Guilty pleas za Samourai za mwaka 2025 zilihusu kuendesha kwa kujua money transmitter isiyo na leseni iliyohamisha criminal proceeds; hazithibitishi kuwa kila collaborative transaction au user anayetafuta privacy ni criminal.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning's Sphinx onion routing imeundwa ili intermediate hop ijue predecessor na successor wake badala ya route nzima.<sup>[[6]](#references)</sup> Si blanket anonymity: channel funding/closure ni public, nodes hutangaza topology, counterparties zinajua endpoints, routing/probing inaweza kukadiria balances au parties, na custodial wallet huona account activity ya user wake.

Kwa privacy bora:

1. Prefer maintained non-custodial wallet ikiwa intermediary privacy ni muhimu; panga channel backup/recovery kwanza.
2. Tumia fresh invoice au offer kwa kila payment. Thibitisha kama wallet hiyo ina-support BOLT 12/route blinding haswa badala ya kudhani ina-support.
3. Epuka kuchapisha node aliases, contact details na stable network endpoints zisizo za lazima.
4. Unganisha kupitia supported privacy network inapofaa, ukielewa kuwa uptime/timing patterns bado zinaweza kuhusishwa.
5. Usidhani kuwa off-chain payment haina records: sender, receiver, peers, watchtowers, liquidity providers na wallet services wanaweza kuhifadhi observations.

Published research imeonyesha sender/recipient na channel-balance inference kutokana na public data na active probing, ingawa attacks na mitigations hubadilika.<sup>[[7]](#references)</sup>

## Monero

Monero hutumia one-time stealth addresses kwa outputs, RingCT kuficha amounts, na ring signatures kutoa probabilistic sender ambiguity; technical specifications zake za sasa zinaandika ring size ya 16 (decoys 15).<sup>[[8]](#references)</sup> Hizi ni stronger defaults kwa on-chain confidentiality kuliko transparent ledgers, si magic protection dhidi ya endpoint au operational mistakes.

### Lawful workflow

1. **Acquire lawfully.** Regulated exchange inaweza kujua purchase na withdrawal hata wakati later on-chain details ni confidential. Hifadhi source, basis na reporting records.
2. **Install official maintained wallet** na verify download yake kulingana na project instructions. Back up seed offline na jaribu restoration kwa amount ndogo.
3. **Prefer local node** kwa wallet-query privacy ya juu zaidi. Ikiwa haiwezekani, chagua trusted remote node inayopatikana kupitia officially supported onion/I2P configuration. Remote node inaweza kurekodi IP, requests, timing na transaction IDs; baadhi ya lightweight designs hufichua view key.
4. **Tumia new subaddress kwa kila payer, campaign au invoice.** Payer anaweza kuhusisha matumizi yanayorudiwa ya subaddress ileile.<sup>[[9]](#references)</sup>
5. **Label incoming contexts locally.** Epuka operationally merging separated receipts ambapo payer mwenye ujuzi anaweza kutambua subsequent behavior.
6. **Linda network metadata.** Fuata official anonymity-network configuration; tambua documented leaks kutokana na timestamps, intermittent synchronization, bandwidth shape na stream reuse.<sup>[[10]](#references)</sup>
7. **Weka compliance/audit data kwa faragha.** Fichua view key au transaction proof kwa makusudi tu, kwa auditor/party aliyelengwa, na elewa hasa inachofichua.

Historical traceability studies zinajumuisha bugs na decoy-selection eras ambazo zimebadilika tangu wakati huo; usitumie old success percentages kwa current transactions. Vilevile, FCMP++ bado ni roadmap work kufikia research cutoff ya sura hii ya Septemba 2026, si deployed protection.<sup>[[11]](#references)</sup>

## Ethereum na stablecoins

Ethereum's own privacy material inabainisha kuwa on-chain actions zinaonekana na kwamba wallet/RPC infrastructure huongeza IP na metadata exposure.<sup>[[12]](#references)</sup> Token transfers, approvals, smart-contract interactions, name services na gas funding zote zinaweza kuunganisha identities.

Centralized stablecoins huongeza issuer control. Current USDC na Tether terms zinahifadhi powers za ku-block/freeze addresses au assets na kutii legal/process obligations.<sup>[[13]](#references)</sup> Zinaweza kuwa payment instruments zenye manufaa, lakini ni chaguo dhaifu pale hitaji ni censorship resistance au on-chain anonymity.

## Compliance boundaries

- FATF recommendations hutekelezwa kupitia national law na hubadilika baada ya muda; update yake ya 2026 inasisitiza VASP licensing/registration na Travel Rule implementation.<sup>[[14]](#references)</sup>
- Nchini Marekani, FinCEN hutofautisha mtu anayetumia convertible virtual currency kwa goods/services zake mwenyewe na biashara inayokubali na ku-transmit au ku-exchange hiyo; facts na later rules ni muhimu.<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation inahitaji originator/beneficiary information pale crypto-asset service provider anapohusika na inaongeza verification rules kwa transfers fulani kwenda/kutoka self-hosted addresses.<sup>[[16]](#references)</sup>
- Sanctions na tax duties zinaendelea kutumika. Fanya screening inavyohitajika, kataa prohibited parties, na hifadhi records; lists na legal status zinaweza kubadilika haraka.<sup>[[17]](#references)</sup>

Kabla ya material value, cross-border activity, privacy-enhancing coordination au exchange/transmission yenye tabia ya biashara, pata ushauri wa sasa wa mtaalamu kwa jurisdictions zinazohusika.

Kwa Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash, na BOLT 12, endelea kwenye [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Linda faragha yako](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Vipengele vya faragha](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Pendekezo rahisi la PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adoption and Actual Privacy of Decentralized CoinJoin Implementations in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Founders of Samourai Wallet plead guilty (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Uchambuzi wa kimajaribio wa faragha katika Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html), na [Technical specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Exploring the Evolution of Monero's Privacy (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Faragha kwenye Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Masharti ya USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — 2026 Targeted Update on Virtual Assets and VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Application of FinCEN's Regulations to Persons Administering, Exchanging, or Using Virtual Currencies](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Sanctions Compliance Guidance for the Virtual Currency Industry](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
