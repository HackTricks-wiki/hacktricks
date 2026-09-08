# Cryptocurrency Privacy

Cryptocurrency privacy, gizlilik veya bağışıklıkla eş anlamlı değil, protokol ve operasyon sorusudur. Public ledger'lar, exchange'ler, wallet server'ları, network peer'ları, merchant'lar ve sonraki transaction'lar grafiğin farklı bölümlerini açığa çıkarır.

Teknik başına artı/eksi/prosedür/detection formatı için [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) ile başlayın. Bu sayfa cryptocurrency'ye özgü mekanikleri ve operasyonel sınırları genişletir.

{% hint style="danger" %}
Bu bölüm yasal self-custody ve veri minimizasyonu içindir. Gelirleri aklamak, yaptırımlardan/vergi bildiriminden kaçınmak, yasaklı taraflarla işlem yapmak, düzenlemeye tabi bir sağlayıcıyı yanıltmak veya lisanssız bir transmission service işletmek için kullanmayın. Privacy technology, fonların yasal kaynağını veya sahipliğini değiştirmez.
{% endhint %}

## Threat model by layer

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Kimlik, funding hesabı, hedef, cihaz, IP, zaman |
| Ledger | Analytics çalıştıran herkes | Transparent chain'lerde address/output'lar, tutarlar ve zaman; başka yerlerde protokole özgü metadata |
| Wallet backend | RPC provider, explorer, remote node | Address sorguları, bakiyeler, IP, transaction broadcast |
| Network | ISP, peer'lar, anonymity-network girişi | IP, zamanlama, hacim ve protokol kullanımı |
| Counterparty | Payer/payee | Invoice/address, teslimat, konuşma, hesap ve zamanlama |
| Endpoint | Malware, cloud backup, fiziksel el koyma | Seed, key'ler, etiketler, geçmiş, screenshot'lar ve clipboard |

Self-custody bir custodian'ı kontrol yolundan çıkarabilir ancak ledger'ı, acquisition kaydını, network metadata'sını veya endpoint kanıtlarını silmez.

## Protocol comparison

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh address'ler basit address reuse'u önler | Public kalıcı transaction grafiği; tutar/zamanlama ve spending heuristic'leri |
| Bitcoin PayJoin | Receiver input'u common-input-ownership heuristic'ini kırabilir | Her iki wallet'ın da desteklemesi gerekir; transaction public kalır; destek eşit değildir |
| Bitcoin CoinJoin | Coordinated participant'lar arasında belirsizlik oluşturur | Tanınabilir pattern'ler, pre/post bağlantıları, consolidation, policy/legal/provider riski |
| Lightning | Onion-routed payment'lar ordinary transfer'lar gibi global olarak yayınlanmaz | Channel'lar on-chain açılır/kapanır; endpoint'ler, peer'lar, probe'lar veya custodian veri çıkarabilir |
| Monero | Receiver, tutar ve sender set'i için on-chain'de daha güçlü varsayılan confidentiality | Exchange, node, timing, endpoint ve counterparty bağlantıları devam eder |
| Ethereum/stablecoins | Yaygın erişilebilirlik ve smart-contract interoperability | Public state/action'lar; RPC metadata'sı; centralized issuer'lar engelleyebilir/dondurabilir/bildirebilir |

## Bitcoin: privacy-preserving baseline

Bitcoin pseudonymous'tur, anonymous değildir. Confirmed transaction'lar public ve kalıcıdır; address reuse, common-input ownership, change detection ve public olarak tanımlanmış address'ler cluster'lar oluşturabilir.<sup>[[1]](#references)</sup>

### Workflow

1. **Maintained bir self-custody wallet seçin.** Official project'ten indirin, sunulduğunda signature/hash'leri doğrulayın ve security update'lerini uygulayın.
2. **Wallet'ı trusted bir endpoint üzerinde oluşturun.** Recovery seed'i offline kaydedin; seed'i asla email, chat, screenshot veya normal cloud note'larına koymayın. Önemli değer taşımadan önce recovery'yi test edin.
3. **Hot wallet'ta yalnızca operasyonel değeri tutun.** Uzun vadeli değer için uygun offline/hardware custody kullanın ve seed'i tek bir hassas konuma maruz bırakmayan bir recovery planı oluşturun.
4. **Her transaction için fresh bir receive address/invoice üretin.** Invoice server veya authenticated private delivery mümkünken static address yayınlamayın.
5. **Mümkün olduğunda kendi full node'unuzu kullanın.** Third-party explorer/electrum server, sorgulanan address'leri ve IP metadata'sını öğrenebilir. Yalnızca wallet'ın desteklediği Tor/proxy davranışını yapılandırın; Tor network edge'ini gizler, blockchain grafiğini değil.
6. **Her UTXO'yu privately label'layın:** kaynak, sahip, amaç ve compliance state. İlişkisiz identity context'lerinin birlikte spend edilmemesi için coin control'ü etkinleştirin.
7. **Transaction'ı preview edin:** seçilen input'lar, change hedefi, tutar, fee, counterparty ve spend'in compartment'ları birleştirip birleştirmediği. Gereksiz consolidation'dan kaçının.
8. **Yasal kayıtları ayrı ve encrypted tutun.** Acquisition basis, invoice, authorization ve tax/reporting bilgilerini mapping'i yayınlamadan saklayın.
9. **Sonraki spending'i aynı privacy kararının parçası olarak değerlendirin.** İyi ayrılmış bir receipt, output'u identified fund'larla birlikte spend edildiğinde yeniden ilişkilendirilebilir.

Bitcoin Core'un privacy documentation'ı, full node'un wallet sorgularını third-party server'lara açığa çıkarmadığını, ancak transaction broadcast ve public history'nin yine de analiz edilmesi gerektiğini açıklar.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin, receiver'ın bir input eklediği collaborative bir payment'tır. Bu, tüm input'ların sender'a ait olduğu yönündeki basit varsayımı bozar. BIP 78 original interactive protocol'ü açıklar; draft BIP 77 ise encrypted mailbox/OHTTP kullanan asynchronous v2 design'ı tanımlar.<sup>[[3]](#references)</sup>

Güvenli kullanım:

1. Her iki maintained wallet'ın aynı PayJoin version'ını desteklediğini doğrulayın.
2. PayJoin-capable invoice'u authenticated channel üzerinden alın; her payment request gibi koruyun.
3. Original amount ve destination'ı kontrol edin; ardından wallet'ın proposal/PSBT'yi, fee contribution'ı ve yasaklı substitution'ları doğrulamasına izin verin.
4. Final wallet summary'yi onaylayın. Beklenmeyen output, tutar veya excessive fee'yi manuel olarak onaylamayın.
5. Negotiation başarısız olursa wallet'ın güvenli şekilde ordinary payment'a fallback yapıp yapmadığını veya yeni invoice gerektirip gerektirmediğini anlayın.
6. Ownership, accounting ve disputes için gerekli private receipt/record'ları saklayın.

PayJoin bir chain-analysis heuristic'ini iyileştirir; payment'ı taraflardan, acquisition platformundan, endpoint'lerden veya public ledger'dan gizlemez.

## CoinJoin: benefits and limits

CoinJoin, input-output mapping'ini daha belirsiz hale getirmek için birden fazla kullanıcıyı tek transaction'da koordine eder. Belirli tarihsel Wasabi ve Samourai design'ları üzerine yapılan araştırma, yüksek ölçüde tanınabilir transaction'lar bulmuş ve pre/post-mix davranışının anonymity'yi önemli ölçüde daraltabileceğini göstermiştir.<sup>[[4]](#references)</sup> Bu sonuç her implementation veya future version'a genellenmemelidir; ancak bir “anonymity-set” sayısının garanti olmadığını gösterir.

Herhangi bir yasal kullanımdan önce:

- mevcut yerel hukuku, yaptırım durumunu, exchange/custodian politikasını ve vergi/bildirim yükümlülüklerini kontrol edin;
- official project'ten edinilmiş maintained, non-custodial software kullanın;
- coordinator modelini, fee'leri, denial-of-service kontrollerini ve mevcut service'in hâlâ çalışıp çalışmadığını anlayın—zkSNACKs coordinator'ını 2024'te sonlandırdı, ancak başka Wasabi coordinator'ları mevcut olabilir;
- source-of-funds ve transaction kayıtlarını privately koruyun;
- başkasının adına unknown fund kabul etmeyin veya trace edilemez withdrawal vaat eden custodial “mixer” kullanmayın;
- output'ları source/context'e göre ayrı tutun ve amaçlanan belirsizliği yok eden sonraki consolidation'dan kaçının.

Legal sonuçlar olguya ve jurisdiction'a özgüdür. 2025 Samourai guilty plea'leri, criminal proceeds'i taşıyan lisanssız bir money transmitter'ın bilerek işletilmesiyle ilgiliydi; her collaborative transaction'ın veya privacy arayan kullanıcının criminal olduğunu ortaya koymaz.<sup>[[5]](#references)</sup>

## Lightning Network

Lightning'in Sphinx onion routing'i, intermediate hop'un tüm route yerine predecessor'ını ve successor'ını öğrenmesi için tasarlanmıştır.<sup>[[6]](#references)</sup> Bu, genel anonymity anlamına gelmez: channel funding/closure public'tir, node'lar topology yayınlar, counterparties endpoint'leri bilir, routing/probing balance'ları veya tarafları ortaya çıkarabilir ve custodial wallet kullanıcısının account activity'sini görür.

Daha iyi privacy için:

1. Intermediary privacy önemliyse maintained bir non-custodial wallet tercih edin; önce channel backup/recovery planlayın.
2. Her payment için fresh invoice veya offer kullanın. Exact wallet'ın BOLT 12/route blinding destekleyip desteklemediğini varsaymadan doğrulayın.
3. Gereksiz node alias'ları, contact detail'leri ve stable network endpoint'lerini yayınlamaktan kaçının.
4. Uygunsa supported bir privacy network üzerinden bağlanın; uptime/timing pattern'lerinin yine de correlation oluşturabileceğini anlayın.
5. Off-chain payment'ın kayıtsız olduğunu varsaymayın: sender, receiver, peer'lar, watchtower'lar, liquidity provider'lar ve wallet service'leri gözlemleri saklayabilir.

Yayınlanmış araştırmalar, public data ve active probing üzerinden sender/recipient ve channel-balance inference yapılabildiğini göstermiştir; ancak attack'lar ve mitigation'lar gelişmektedir.<sup>[[7]](#references)</sup>

## Monero

Monero output'lar için one-time stealth address'ler, tutarları gizlemek için RingCT ve olasılıksal sender belirsizliği sağlamak için ring signature'lar kullanır; mevcut technical specification, 16 ring size (15 decoy) belirtir.<sup>[[8]](#references)</sup> Bunlar transparent ledger'lara kıyasla on-chain confidentiality için daha güçlü varsayılanlardır; endpoint veya operational hatalara karşı sihirli koruma değildir.

### Lawful workflow

1. **Yasal yollarla acquire edin.** Regulated bir exchange, sonraki on-chain detaylar confidential olsa bile purchase ve withdrawal'ı bilebilir. Source, basis ve reporting kayıtlarını tutun.
2. **Official maintained wallet'ı kurun** ve download'ı project talimatlarına göre doğrulayın. Seed'i offline yedekleyin ve restoration'ı küçük bir tutarla test edin.
3. **Maksimum wallet-query privacy için local node tercih edin.** Bu pratik değilse officially supported onion/I2P configuration üzerinden erişilebilen trusted remote node seçin. Remote node IP, request, timing ve transaction ID'lerini log'layabilir; bazı lightweight design'lar view key açığa çıkarır.
4. **Her payer, campaign veya invoice için yeni subaddress kullanın.** Payer, aynı subaddress'ın tekrarlanan kullanımını correlate edebilir.<sup>[[9]](#references)</sup>
5. **Incoming context'leri locally label'layın.** Bilgili bir payer'ın sonraki davranışı tanıyabileceği durumlarda ayrılmış receipt'leri operasyonel olarak merge etmekten kaçının.
6. **Network metadata'sını koruyun.** Official anonymity-network configuration'ını izleyin; timestamp, intermittent synchronization, bandwidth shape ve stream reuse kaynaklı belgelenmiş leak'leri göz önünde bulundurun.<sup>[[10]](#references)</sup>
7. **Compliance/audit verilerini private tutun.** View key veya transaction proof'u yalnızca bilinçli şekilde, hedeflenen auditor/party'ye açıklayın ve tam olarak ne açığa çıkardığını anlayın.

Tarihsel traceability çalışmaları, o zamandan beri değişmiş bug'ları ve decoy-selection dönemlerini içerir; eski success percentage'larını current transaction'lara uygulamayın. Benzer şekilde FCMP++ bu chapter'ın September 2026 research cutoff'u itibarıyla hâlâ roadmap çalışmasıdır, deployed bir protection değildir.<sup>[[11]](#references)</sup>

## Ethereum and stablecoins

Ethereum'un kendi privacy material'ı, on-chain action'ların görünür olduğunu ve wallet/RPC infrastructure'ının IP ve metadata exposure eklediğini belirtir.<sup>[[12]](#references)</sup> Token transfer'ları, approval'lar, smart-contract interaction'ları, name service'leri ve gas funding identity'leri birbirine bağlayabilir.

Centralized stablecoin'ler issuer control ekler. Current USDC ve Tether terms, address veya asset'leri block/freeze etme ve legal/process yükümlülüklerine uyma yetkilerini saklı tutar.<sup>[[13]](#references)</sup> Yararlı payment instrument'ları olabilirler, ancak gereksinim censorship resistance veya on-chain anonymity olduğunda kötü seçeneklerdir.

## Compliance boundaries

- FATF recommendation'ları national law yoluyla uygulanır ve zaman içinde değişir; 2026 update'i VASP licensing/registration ve Travel Rule implementation'ını vurgular.<sup>[[14]](#references)</sup>
- US'te FinCEN, convertible virtual currency'yi kendi goods/services'i için kullanan kişi ile bunu kabul eden, ileten veya exchange eden business arasında ayrım yapar; olgular ve sonraki rules önemlidir.<sup>[[15]](#references)</sup>
- EU Transfer of Funds Regulation, crypto-asset service provider involved olduğunda originator/beneficiary information gerektirir ve self-hosted address'lere yapılan/bunlardan gelen belirli transferler için verification rules ekler.<sup>[[16]](#references)</sup>
- Sanctions ve tax yükümlülükleri geçerliliğini sürdürür. Gerektiğinde screening yapın, prohibited party'leri reddedin ve kayıt tutun; listeler ve legal status hızla değişebilir.<sup>[[17]](#references)</sup>

Material value, cross-border activity, privacy-enhancing coordination veya business-like exchange/transmission öncesinde ilgili jurisdiction'lar için güncel professional advice alın.

Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash ve BOLT 12 için [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) sayfasına devam edin.

## References

- [1] [Bitcoin.org — Privacy'nizi koruyun](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy özellikleri](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Basit bir PayJoin önerisi](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Bitcoin'de Decentralized CoinJoin Implementation'larının Adoption ve Actual Privacy'si (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Samourai Wallet kurucuları guilty plea verdi (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol'ü](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Lightning Network'te Privacy'nin Empirical Analysis'i](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth address'ler](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signature'lar](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) ve [Technical specification'lar](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Network'ler](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Monero Privacy'sinin Evolution'ını İncelemek (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Ethereum'da Privacy](https://ethereum.org/privacy/ethereum)
- [13] [Circle — USDC Terms](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Virtual Asset'ler ve VASP'ler Hakkında 2026 Targeted Update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — FinCEN Regulations'ın Virtual Currency'leri Administer, Exchange veya Use Eden Kişilere Uygulanması](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Virtual Currency Industry için Sanctions Compliance Guidance](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
