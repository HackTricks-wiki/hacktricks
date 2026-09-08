# Privacy-Preserving Payment Protocols

{{#include ../banners/hacktricks-training.md}}

Gelişmiş ödeme sistemleri, merchant'ın payer'ı tanımasını, public ledger'da recipient'ı veya amount'ı görmesini ya da bir mint'in withdrawal işlemini redemption ile ilişkilendirmesini engelleyebilir. Bunlar farklı özelliklerdir. Hiçbiri acquisition, device, network, delivery, accounting, sanctions veya endpoint kayıtlarını ortadan kaldırmaz.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md), her payment ailesi için standartlaştırılmış `Pros`, `Cons`, adım adım `Procedure` ve `Detection` girdileri sağlar. Bu sayfa gelişmiş protokolleri genişletir.

{% hint style="danger" %}
Yalnızca yasal funds ve counterparties kullanın. Privacy protocols'ü gerekli identification, sanctions, tax, source-of-funds kontrollerini veya transaction reporting'i aşmak için kullanmayın. Licensing, custody, AML ve consumer-protection yükümlülüklerini anlamadan exchange, mint veya transmission service işletmeyin.
{% endhint %}

## Gelişmiş seçenekleri karşılaştırma

| Protocol | Public/merchant'tan gizlenen | Trusted veya observing party | Maturity/availability |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Dışarıdaki kişiler, yeniden kullanılabilir payment code'u one-time outputs ile ilişkilendiremez | Public Bitcoin graph devam eder; wallet/index server taramaları görebilir | Specification complete; wallet desteği değişken |
| Zcash fully shielded Orchard | Sender, receiver ve amount on-chain üzerinde şifrelenir | Wallet backend/network ve acquisition/off-ramp yine görünür | Deployed; shielded desteği wallet/exchange'e göre değişir |
| GNU Taler | Merchant'ın payer identity'sini öğrenmesi gerekmez; merchant income accountable kalır | Taler exchange/bank funding'i görür; merchant order'ı görür | Deployments coğrafi olarak sınırlıdır |
| Federated Chaumian e-cash | Federation, issued notes'ları internal transfers/redemption ile ilişkilendirmemelidir | Guardian quorum reserves'i custody altında tutar; gateways boundary activity'yi görür | Emerging community deployments |
| Lightning BOLT 12/route blinding | Receiver/node ve route disclosure'ı azaltır | Endpoints, selected hops, funding chain ve wallet services | Support wallet'a bağlıdır |
| Virtual card/token | Merchant, reusable PAN yerine kısıtlı bir credential alır | Issuer/network payer ve transaction bilgilerini saklar | Mature ve yaygın olarak kullanılabilir |

## Bitcoin Silent Payments (BIP 352)

Silent Payments, receiver'ın tek bir static payment code yayınlamasına ve her sender'ın benzersiz bir Taproot output türetmesine olanak tanır. Dışarıdaki bir chain observer, bu output'ları yayınlanan code ile doğrudan ilişkilendiremez ve interaktif bir address request veya on-chain notification output gerekmez. BIP 352 **Complete** olarak işaretlenmiştir, ancak scanning cost getirir ve bunu uygulamamış wallet'larla uyumlu değildir.<sup>[[1]](#references)</sup>

### Receiver workflow

1. BIP 352 receiving'i açıkça destekleyen, bakımı sürdürülen bir wallet seçin; özelliği bir social-media iddiasına göre değil, wallet'ın güncel documentation'ına göre doğrulayın.
2. Wallet seed'ini ve Silent Payment descriptor/key material'ını wallet'ın belgelenmiş recovery method'unu kullanarak yedekleyin. Code'u yayınlamadan önce küçük bir testnet/mainnet amount ile discovery'yi test edin.
3. Wallet BIP 352 labels'ı destekliyorsa campaigns, invoices veya counterparties için ayrı **labels** oluşturun. Labels, linkable addresses yayınlamadan local accounting'e yardımcı olur.
4. Static Silent Payment code'u authenticated channel üzerinden yayınlayın. Yeniden kullanılabilir, ancak bir impostor kendi code'unu bunun yerine koyabilir.
5. Uygun olduğunda local full node üzerinden scan yapın. Third-party index/scanning server, spend edemese bile request timing veya filter data öğrenebilir.
6. Discovered UTXO'ları etiketli tutun ve ordinary Bitcoin ile aynı coin-control kurallarını uygulayın. Bunları spend etmek veya consolidate etmek ownership relationships'i açığa çıkarabilir.
7. Recovery'nin, yedeklenmemiş external index'e güvenmeden payments'ı keşfettiğini doğrulayın.

### Sender workflow

1. Wallet'ın address version'a gönderimi desteklediğini doğrulayın ve receiver'ın uzun static code'unu authenticate edin.
2. Output'u wallet'ın oluşturmasına izin verin; code'u manuel olarak convert veya truncate etmeyin.
3. Selected inputs'ı dikkatle inceleyin. Silent Payments recipient-address privacy'yi iyileştirir, ancak sender inputs hâlâ public graph üzerindedir.
4. Wallet-supported fee bumping/PSBT behavior kullanın. BIP 352, inputs değişirse output'un yeniden türetilmesini gerektirir ve bazı signing modes güvenli değildir.
5. Disputes/accounting için gereken encrypted receipt veya proof'u saklayın.

Silent Payments, tekrarlanan recipient-address publication sorununu çözer. Amount, transaction timing, sender cluster, acquisition history veya later co-spending'i gizlemez.

## Zcash fully shielded payments

Zcash, transparent ve shielded value pools destekler. Orchard shielded transactions, nodes'ların transaction details şifreliyken validity'yi doğrulayabilmesi için zero-knowledge proofs kullanır; Unified Addresses birden fazla receiver type içerebilir.<sup>[[2]](#references)</sup> Privacy, görüntülenen address'in ilk karakterine değil, wallet tarafından seçilen gerçek path'e bağlıdır.

### Shielded workflow

1. **shielded-by-default** davranışını ve güncel Orchard desteğini açıkça belirten, bakımı sürdürülen bir wallet seçin. Download'ı doğrulayın ve seed'i yedekleyip test edin.
2. ZEC'i yasal olarak edinin ve basis/source kaydını tutun. Exchange acquisition ve withdrawal'ı yine bilir.
3. Wallet tarafından desteklenen bir Unified Address'e receive edin, ardından transaction'ın shielded pool'a ulaşıp ulaşmadığını inceleyin. Wallet behavior'ı doğrulamadan automatic shielding varsaymayın.
4. **shielded-to-shielded** transfers'ı tercih edin. Transparent-to-shielded ve shielded-to-transparent boundary movements public values/timing'i açığa çıkarır ve amount correlation sağlayabilir; Orchard specification, non-Orchard address'e yapılan spend'in transaction value'yu açığa çıkardığını belirtir.<sup>[[3]](#references)</sup>
5. Belirgin exact-amount round trip'lerden ve immediate boundary crossing'lerden kaçının. Bu privacy hygiene'dır; ownership veya reporting'i gizleme izni değildir.
6. Wallet'ın desteklediği network-privacy path'i kullanın. Shielded cryptography, IP/timing'i wallet servers veya peers'tan gizlemez.
7. Internal compliance records'ı saklayın ve viewing keys'i yalnızca kapsamlarını anladıktan sonra bilinçli audit/disclosure için kullanın.
8. Göndermeden önce recipient wallet/exchange desteğini doğrulayın; forced transparent receiver privacy özelliğini değiştirir.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler, traditional currencies, blind signatures ve regulated exchange/bank integration kullanan açık bir electronic-payment protocol'dür. Tasarımı, merchants'ın customers'ı anonymous tutmasını, merchants'ın ise identifiable ve taxable kalmasını amaçlar.<sup>[[4]](#references)</sup> Cryptocurrency değildir ve availability, uyumlu bir regional exchange, bank, wallet ve merchant'a bağlıdır.

### User workflow where deployed

1. İlgili currency/jurisdiction'ta faaliyet gösteren bir Taler exchange ve merchant belirleyin; güncel terms, fees, KYC ve privacy notices'larını okuyun.
2. Official wallet'ı yükleyin ve source'unu doğrulayın. Wallet backup/recovery data'sını cash gibi koruyun, çünkü wallet value bir bearer asset olabilir.
3. Supported bank/exchange flow üzerinden truthful information kullanarak value withdraw edin. Funding institution/exchange, blind signatures direct coin-to-withdrawal link'ini kırsa bile withdrawal'ı bilebilir.
4. Wallet'taki merchant contract'ını inceleyin: merchant identity, item/summary, amount, fees, refund ve delivery terms.
5. Payment yapın ve refund, warranty, accounting veya tax için gereken receipt data'sını saklayın.
6. Merchant unlinkability gerekiyorsa optional merchant session/account identifiers'ı yeniden kullanmayın.
7. Wallet, network ve delivery metadata'sını threat model içinde tutun; Taler'ın payment cryptography'si shipping address'i veya compromised endpoint'i gizlemez.

Merchant ve exchange accountable kalır; bu bileşenlerden herhangi birini işletmek regulated payment-service activity olabilir.

## Federated Chaumian e-cash

Chaumian e-cash, bir mint'in daha sonra spend edilen unblinded token'ı görmeden bir token imzalamasını sağlamak için blind signatures kullanır. Fedimint, reserve custody ve signing işlemlerini bir guardian federation genelinde dağıtır; documentation'ı, guardians'ın aggregate reserves/outstanding notes'u gördüğünü, ancak federation içindeki individual balance'ı veya kimin kime payment yaptığını görmemesi gerektiğini belirtir.<sup>[[5]](#references)</sup>

Bu, **custodial bearer value**'dur. Yeterli bir guardian quorum reserves'i kontrol eder; federation failure, dishonest guardians, software bugs veya lost client state loss'a neden olabilir. Deposits, withdrawals ve Lightning gateways görünür boundary events'tir ve timing/amount ile correlation kurabilir.

### Limited-risk workflow

1. Yalnızca kaybetmeyi göze alabileceğiniz küçük bir amount kullanın. Public/unknown federations'ı, gerçek dünyada accountability'si bulunan guardians'a göre daha yüksek riskli kabul edin.
2. Federation invite'ını authenticated channel üzerinden doğrulayın ve guardian identities, quorum, jurisdiction, fees, recovery ve shutdown policy'yi kaydedin.
3. Maintained compatible wallet yükleyin, doğrulayın ve deposit yapmadan önce backup scheme'ini anlayın.
4. Lawfully acquired Bitcoin'i documented path üzerinden deposit edin. Peg-in'i accounting için kaydedin ve timing/amount'un boundary'de public veya biliniyor olduğunu varsayın.
5. Federation içinde fresh payment requests kullanın ve blind signature'ın kaldırdığı link'i yeniden oluşturan account/chat/delivery identifiers eklemekten kaçının.
6. Lightning payments için gateway'i invoices ve boundary timing'in ek bir observer'ı olarak kabul edin.
7. Policy'ye göre redeem/withdraw edin; distinctive amount ve immediate timing'in deposit veya external payment ile correlation kurabileceğini bekleyin.
8. Tax/source/authorization records'ı private tutun; guardians veya gateways'ten activity'yi yanlış beyan etmelerini istemeyin.

Federated e-cash'i trustless, self-custodial veya guaranteed anonymous olarak tanımlamayın.

## BOLT 12 offers and route blinding

BOLT 12 offers, stable on-chain address yayınlamadan reusable olabilir ve payer'ın receiver'ın clear node identity/path'ini öğrenmesine gerek kalmaması için blinded paths kullanabilir. Bu, Lightning'in mevcut onion routing özelliğini tamamlar ancak onun yerini almaz.

Kullanmadan önce:

1. Sender ve receiver wallet'larının aynı güncel BOLT 12 features'ı desteklediğini doğrulayın; generic “Lightning” branding'inden support sonucu çıkarmayın.
2. Offer'ı out of band authenticate edin ve amount, issuer/description ile recurrence rules'u kontrol edin.
3. Offer'dan oluşturulan fresh invoice/payment context kullanın.
4. Node aliases, public contact information ve stable network endpoints'i minimumda tutun.
5. Sender/receiver, first/last hop, wallet service, channel graph ve on-chain funding/closure'ın relationship'in bazı bölümlerini hâlâ açığa çıkardığını varsayın.

## Public disclosure olmadan auditability

Privacy ve audit birlikte var olabilir:

- Labels, invoices, authorization, cost basis ve ownership mapping'i public protocol dışında encrypted olarak saklayın.
- Protocol bir view/audit key sağlıyorsa spending key'den ayırın; exact disclosure'ını önce sample wallet üzerinde test edin.
- Auditor'a seed veya unrestricted spending credential yerine minimum kapsamlı proof verin.
- Transaction sırasında software version, protocol/pool, transaction ID veya proof, counterparty purpose ve exchange-rate source'u kaydedin.
- Kalıcı, unencrypted bir identity graph biriktirmek yerine retention ve deletion politikalarını tanımlayın.

## Selection checklist

- [ ] Hidden field ve observer kesin olarak belirtilmiştir.
- [ ] Wallet/protocol support transaction date itibarıyla doğrulanmıştır.
- [ ] Acquisition, network, node/RPC, counterparty, delivery ve later-spend links belgelenmiştir.
- [ ] Custody, recovery, liquidity, issuer/federation solvency ve refund risks kabul edilmiştir.
- [ ] Gerekli identity, tax, sanctions, source ve organizational records doğru kalmıştır.
- [ ] Recovery ve audit proof dahil küçük bir end-to-end test başarıyla tamamlanmıştır.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
