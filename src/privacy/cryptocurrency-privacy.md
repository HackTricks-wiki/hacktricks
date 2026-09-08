# Cryptocurrency Privacy

{{#include ../banners/hacktricks-training.md}}

Cryptocurrency privacy bir gizlilik veya bağışıklık eş anlamlısı değil, protokol ve operasyon sorunudur. Public ledger'lar, borsalar, wallet server'ları, network peer'ları, merchant'lar ve sonraki transaction'lar graph'ın farklı bölümlerini açığa çıkarır.

Teknik başına pros/cons/procedure/detection formatı için [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) ile başlayın. Bu sayfa, cryptocurrency'ye özgü mekanikleri ve operasyonel sınırları genişletir.

{% hint style="danger" %}
Bu bölüm yasal self-custody ve data minimization içindir. Gelirleri aklamak, yaptırımlardan/vergi bildirimlerinden kaçınmak, yasaklı taraflarla işlem yapmak, düzenlemeye tabi bir provider'ı yanıltmak veya lisanssız bir transmission service işletmek için kullanmayın. Privacy technology, fonların yasal kaynağını veya sahipliğini değiştirmez.
{% endhint %}

## Threat model by layer

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Identity, funding account, destination, device, IP, time |
| Ledger | Anyone running analytics | Addresses/outputs, amounts and time on transparent chains; protocol-specific metadata elsewhere |
| Wallet backend | RPC provider, explorer, remote node | Address queries, balances, IP, transaction broadcast |
| Network | ISP, peers, anonymity-network entry | IP, timing, volume and protocol use |
| Counterparty | Payer/payee | Invoice/address, delivery, conversation, account and timing |
| Endpoint | Malware, cloud backup, physical seizure | Seed, keys, labels, history, screenshots and clipboard |

Self-custody, control path'inden bir custodian'ı çıkarabilir ancak ledger'ı, acquisition record'ını, network metadata'sını veya endpoint evidence'ını silmez.

## Protocol comparison

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh addresses avoid simple address reuse | Public permanent transaction graph; amount/timing and spending heuristics |
| Bitcoin PayJoin | Receiver input can break the common-input-ownership heuristic | Both wallets need support; transaction remains public; support is uneven |
| Bitcoin CoinJoin | Creates ambiguity among coordinated participants | Recognizable patterns, pre/post links, consolidation, policy/legal/provider risk |
| Lightning | Onion-routed payments are not globally published as ordinary transfers | Channels open/close on-chain; endpoints, peers, probes or custodian may infer data |
| Monero | Stronger default on-chain confidentiality for receiver, amount and sender set | Exchange, node, timing, endpoint and counterparty links remain |
| Ethereum/stablecoins | Broad availability and smart-contract interoperability | Public state/actions; RPC metadata; centralized issuers may block/freeze/report |

## Bitcoin: privacy-preserving baseline

Bitcoin pseudonymous'tur, anonymous değildir. Confirmed transaction'lar public ve kalıcıdır; address reuse, common-input ownership, change detection ve public olarak tanımlanmış address'ler cluster'lar oluşturabilir.<sup>[[1]](#references)</sup>

### Workflow

1. **Bakımı yapılan bir self-custody wallet seçin.** Resmi project'ten indirin, sunulduğunda signature/hash'leri doğrulayın ve security update'lerini uygulayın.
2. **Wallet'ı güvenilir bir endpoint üzerinde oluşturun.** Recovery seed'i offline olarak kaydedin; asla email, chat, screenshot veya sıradan cloud note'larına koymayın. Önemli miktarları kullanmadan önce recovery'yi test edin.
3. **Hot durumda yalnızca operasyonel miktarı tutun.** Uzun vadeli değer için uygun offline/hardware custody kullanın ve seed'i tek bir kırılgan konuma açığa çıkarmayan bir recovery planınız olsun.
4. **Her transaction için fresh receive address/invoice oluşturun.** Bir invoice server veya authenticated private delivery mümkünken static address yayınlamayın.
5. **Mümkün olduğunda kendi full node'unuzu kullanın.** Third-party explorer/electrum server, sorgulanan address'leri ve IP metadata'sını öğrenebilir. Yalnızca wallet tarafından desteklenen Tor/proxy davranışını yapılandırın; Tor bir network edge'ini gizler, blockchain graph'ını değil.
6. **Her UTXO'yu source, owner, purpose ve compliance state ile private olarak etiketleyin.** İlişkisiz identity context'lerinin birlikte harcanmaması için coin control'ü etkinleştirin.
7. **Transaction'ı önizleyin:** seçilen input'lar, change destination, miktar, fee, counterparty ve spend'in compartment'ları birleştirip birleştirmediği. Gereksiz consolidation'dan kaçının.
8. **Yasal kayıtları ayrı ve encrypted olarak tutun.** Acquisition basis, invoice'lar, authorization ve tax/reporting bilgilerini mapping'i yayınlamadan saklayın.
9. **Sonraki spending'i aynı privacy kararının bir parçası olarak değerlendirin.** İyi ayrılmış bir receipt, output'u identified fund'larla birlikte harcadığınızda yeniden ilişkilendirilebilir.

Bitcoin Core'un privacy documentation'ı, full node'un wallet sorgularının third-party server'lara açığa çıkmasını önlediğini; ancak transaction broadcast'inin ve public history'nin yine de analiz edilmesi gerektiğini açıklar.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin, receiver'ın bir input eklediği collaborative payment'tır. Bu, tüm input'ların sender'a ait olduğu yönündeki basit varsayımı bozar. BIP 78 original interactive protocol'ü tanımlar; draft BIP 77 ise encrypted mailbox/OHTTP kullanan asynchronous v2 design'ını tanımlar.<sup>[[3]](#references)</sup>

Güvenli kullanım:

1. Her iki maintained wallet'ın aynı PayJoin version'ını desteklediğini doğrulayın.
2. PayJoin-capable invoice'ı authenticated channel üzerinden alın; ona her payment request gibi koruma uygulayın.
3. Original amount ve destination'ı kontrol edin, ardından wallet'ın proposal/PSBT, fee contribution ve prohibited substitution'ları doğrulamasına izin verin.
4. Final wallet summary'yi doğrulayın. Beklenmeyen bir output, amount veya excessive fee'yi manuel olarak onaylamayın.
5. Negotiation başarısız olursa wallet'ın güvenli biçimde ordinary payment'a fallback yapıp yapmadığını veya yeni bir invoice gerektirip gerektirmediğini anlayın.
6. Ownership, accounting ve disputes için gereken private receipt/record'ları saklayın.

PayJoin bir chain-analysis heuristic'ini iyileştirir; payment'ı taraflardan, acquisition platform'undan, endpoint'lerden veya public ledger'dan gizlemez.

## CoinJoin: benefits and limits

CoinJoin, input-output mapping'ini daha belirsiz hâle getirmek için birden fazla user'ı tek bir transaction'da koordine eder. Belirli historical Wasabi ve Samourai design'ları üzerine yapılan research, kolayca tanınabilen transaction'lar bulmuş ve pre/post-mix davranışının anonymity'yi önemli ölçüde daraltabileceğini göstermiştir.<sup>[[4]](#references)</sup> Bu sonuç her implementation veya future version için genellenmemelidir; ancak bir “anonymity-set” sayısının garanti olmadığını gösterir.

Herhangi bir yasal kullanımdan önce:

- mevcut yerel hukuku, sanctions status'ünü, exchange/custodian policy'sini ve tax/reporting yükümlülüklerini kontrol edin;
- official project'ten edinilmiş, bakımı yapılan non-custodial software kullanın;
- coordinator model'ini, fee'leri, denial-of-service kontrollerini ve mevcut service'in hâlâ çalışıp çalışmadığını anlayın—zkSNACKs coordinator'ünü 2024'te sonlandırdı, ancak başka Wasabi coordinator'leri mevcut olabilir;
- source-of-funds ve transaction kayıtlarını private olarak saklayın;
- başkasının adına unknown fund kabul etmeyin veya trace edilemez withdrawal vaat eden custodial bir “mixer” kullanmayın;
- output'ları source/context'e göre ayrı tutun ve amaçlanan ambiguity'yi yok eden sonraki consolidation'dan kaçının.

Yasal sonuçlar olguya ve jurisdiction'a özgüdür. 2025 Samourai guilty plea'leri, criminal proceeds'i taşıyan lisanssız bir money transmitter'ı bilerek işletmekle ilgiliydi; her collaborative transaction'ın veya privacy arayan user'ın criminal olduğunu ortaya koymaz.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning'in Sphinx onion routing'i, intermediate hop'un tüm route yerine predecessor'ını ve successor'ını öğrenmesi için tasarlanmıştır.<sup>[[6]](#references)</sup> Bu, genel bir anonymity sağlamaz: channel funding/closure public'tir, node'lar topology yayınlar, counterparties endpoint'leri bilir, routing/probing balance'ları veya tarafları çıkarabilir ve custodial wallet kullanıcısının account activity'sini görür.

Daha iyi privacy için:

1. Intermediary privacy önemliyse maintained non-custodial wallet'ı tercih edin; önce channel backup/recovery planlayın.
2. Her payment için fresh invoice veya offer kullanın. Exact wallet'ın BOLT 12/route blinding'i destekleyip desteklemediğini varsaymak yerine doğrulayın.
3. Gereksiz node alias'larını, contact detail'lerini ve stable network endpoint'lerini yayınlamaktan kaçının.
4. Uygunsa supported privacy network üzerinden bağlanın; uptime/timing pattern'lerinin yine de correlate edilebileceğini anlayın.
5. Off-chain payment'ın record bırakmadığını varsaymayın: sender, receiver, peer'lar, watchtower'lar, liquidity provider'lar ve wallet service'leri gözlemleri saklayabilir.

Yayınlanmış research, public data ve active probing üzerinden sender/recipient ve channel-balance inference yapılabildiğini göstermiştir; ancak attack'ler ve mitigation'lar gelişmektedir.<sup>[[7]](#references)</sup>

## Monero

Monero output'lar için one-time stealth address'ler, amount'ları gizlemek için RingCT ve probabilistic sender ambiguity sağlamak için ring signature'lar kullanır; mevcut technical specification'lar 16 ring size (15 decoy) belirtir.<sup>[[8]](#references)</sup> Bunlar transparent ledger'lara kıyasla on-chain confidentiality için daha güçlü default'lardır; endpoint veya operational mistake'lere karşı sihirli bir koruma değildir.

### Lawful workflow

1. **Yasal olarak acquire edin.** Regulated exchange, sonraki on-chain details confidential olsa bile purchase ve withdrawal'ı bilebilir. Source, basis ve reporting kayıtlarını tutun.
2. **Official maintained wallet'ı yükleyin** ve download'ı project instructions doğrultusunda doğrulayın. Seed'i offline olarak back up edin ve küçük bir miktarla restoration'ı test edin.
3. **Maksimum wallet-query privacy için local node'u tercih edin.** Bu pratik değilse officially supported onion/I2P configuration üzerinden erişilebilen trusted remote node seçin. Remote node IP, request'ler, timing ve transaction ID'lerini loglayabilir; bazı lightweight design'lar bir view key açığa çıkarır.
4. **Her payer, campaign veya invoice için yeni bir subaddress kullanın.** Payer, aynı subaddress'in tekrar kullanımını correlate edebilir.<sup>[[9]](#references)</sup>
5. **Incoming context'leri local olarak etiketleyin.** Bilgili bir payer'ın sonraki davranışı tanıyabileceği durumlarda ayrılmış receipt'leri operational olarak merge etmekten kaçının.
6. **Network metadata'sını koruyun.** Official anonymity-network configuration'ı izleyin; timestamp'ler, intermittent synchronization, bandwidth shape ve stream reuse kaynaklı belgelenmiş leak'leri dikkate alın.<sup>[[10]](#references)</sup>
7. **Compliance/audit data'sını private tutun.** Bir view key'i veya transaction proof'u yalnızca bilinçli olarak, amaçlanan auditor/party'ye açıklayın ve tam olarak neyi açığa çıkardığını anlayın.

Historical traceability studies, o zamandan beri değişmiş bug'ları ve decoy-selection dönemlerini içerir; eski success percentage'larını current transaction'lara uygulamayın. Benzer şekilde FCMP++ bu bölümün September 2026 research cutoff tarihi itibarıyla hâlâ roadmap çalışmasıdır ve deployed protection değildir.<sup>[[11]](#references)</sup>

## Ethereum and stablecoins

Ethereum'un kendi privacy material'ı, on-chain action'ların görünür olduğunu ve wallet/RPC infrastructure'ın IP ve metadata exposure eklediğini belirtir.<sup>[[12]](#references)</sup> Token transfer'ları, approval'lar, smart-contract interaction'ları, name service'leri ve gas funding identity'leri birbirine bağlayabilir.

Centralized stablecoin'ler issuer control ekler. Güncel USDC ve Tether terms, address veya asset'leri block/freeze etme ve legal/process yükümlülüklerine uyma yetkilerini saklı tutar.<sup>[[13]](#references)</sup> Kullanışlı payment instrument'ları olabilirler; ancak requirement censorship resistance veya on-chain anonymity olduğunda zayıf tercihlerdir.

## Compliance boundaries

- FATF recommendations national law üzerinden uygulanır ve zamanla değişir; 2026 update'i VASP licensing/registration ve Travel Rule implementation'ını vurgular.<sup>[[14]](#references)</sup>
- US'te FinCEN, convertible virtual currency'yi kendi goods/services'i için kullanan bir kişi ile bunu kabul edip ileten veya exchange eden bir business arasında ayrım yapar; olgular ve sonraki kurallar önem taşır.<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation, bir crypto-asset service provider dahil olduğunda originator/beneficiary bilgilerini gerektirir ve self-hosted address'lere yapılan veya bu address'lerden gelen belirli transferler için verification rules ekler.<sup>[[16]](#references)</sup>
- Sanctions ve tax yükümlülükleri geçerliliğini korur. Gerektiğinde screening yapın, prohibited party'leri reddedin ve kayıtları tutun; listeler ve legal status hızla değişebilir.<sup>[[17]](#references)</sup>

Material value, cross-border activity, privacy-enhancing coordination veya business-like exchange/transmission öncesinde ilgili jurisdiction'lar için güncel professional advice alın.

Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash ve BOLT 12 için [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) sayfasına devam edin.

## References

- [1] [Bitcoin.org — Privacy'nizi koruyun](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy özellikleri](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Basit bir PayJoin önerisi](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Bitcoin'de Decentralized CoinJoin Implementations'ın Adoption ve Actual Privacy'si (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet kurucuları guilty plea verdi (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Lightning Network'te Privacy'nin Empirical Analysis'i](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth address'ler](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signature'lar](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) ve [Technical specification'lar](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Network'ler](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Monero Privacy'sinin Evolution'ını incelemek (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum'da Privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Virtual Asset'ler ve VASP'ler hakkında 2026 Targeted Update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Virtual Currency'leri Administer, Exchange veya Use Eden Kişilere FinCEN Regulations'ın Uygulanması](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry için Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
