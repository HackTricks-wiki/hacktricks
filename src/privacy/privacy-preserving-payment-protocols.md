# Privacy-Preserving Payment Protocols

Gelişmiş ödeme sistemleri, ödeyeni merchant'tan gizleyebilir, alıcıyı veya tutarı public ledger'dan gizleyebilir ya da bir mint'in withdrawal ile redemption işlemlerini ilişkilendirmesini engelleyebilir. Bunlar farklı özelliklerdir. Hiçbiri acquisition, device, network, delivery, accounting, sanctions veya endpoint kayıtlarını ortadan kaldırmaz.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md), her payment ailesi için standartlaştırılmış bir `Pros`, `Cons`, adım adım `Procedure` ve `Detection` girdisi sağlar. Bu sayfa gelişmiş protocol'leri genişletir.

{% hint style="danger" %}
Yalnızca yasal fonlar ve karşı taraflar kullanın. Gerekli identification, sanctions, tax, source-of-funds kontrollerini veya transaction reporting yükümlülüklerini aşmak için privacy protocol'lerini kullanmayın. Licensing, custody, AML ve consumer-protection yükümlülüklerini anlamadan exchange, mint veya transmission service işletmeyin.
{% endhint %}

## Gelişmiş seçenekleri karşılaştırma

| Protocol | Public/merchant'tan gizlenen | Güvenilen veya gözlemleyen taraf | Olgunluk/kullanılabilirlik |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Dış gözlemciler, yeniden kullanılabilir bir payment code'u tek kullanımlık output'larıyla ilişkilendiremez | Public Bitcoin graph kalır; wallet/index server taramaları görebilir | Specification tamamlandı; wallet desteği değişken |
| Zcash fully shielded Orchard | Sender, receiver ve amount on-chain şifrelenir | Wallet backend/network ve acquisition/off-ramp görünür olmaya devam eder | Deployed; shielded desteği wallet/exchange'e göre değişir |
| GNU Taler | Merchant'ın payer identity'sini öğrenmesi gerekmez; merchant geliri accountable kalır | Taler exchange/bank funding'i görür; merchant order'ı görür | Deployment'lar coğrafi olarak sınırlı |
| Federated Chaumian e-cash | Federation, verilen note'ları internal transfer/redemption işlemleriyle ilişkilendirmemelidir | Guardian quorum reserve'leri custody eder; gateway'ler sınır etkinliklerini görür | Gelişmekte olan community deployment'ları |
| Lightning BOLT 12/route blinding | Receiver/node ve route disclosure'ını azaltır | Endpoint'ler, seçilen hop'lar, funding chain ve wallet service'ler | Destek wallet'a bağlı |
| Virtual card/token | Merchant, yeniden kullanılabilir PAN yerine kısıtlı credential alır | Issuer/network payer'ı ve transaction'ı saklar | Olgun ve yaygın biçimde kullanılabilir |

## Bitcoin Silent Payments (BIP 352)

Silent Payments, receiver'ın tek bir static payment code yayımlamasına ve her sender'ın benzersiz bir Taproot output türetmesine olanak tanır. Dışarıdan bir chain observer, bu output'ları yayımlanan code'a doğrudan bağlayamaz; ayrıca interactive address request veya on-chain notification output gerekmez. BIP 352 **Complete** olarak işaretlenmiştir, ancak scanning maliyeti getirir ve bunu uygulamamış wallet'larla uyumlu değildir.<sup>[[1]](#references)</sup>

### Receiver workflow

1. BIP 352 receiving'i açıkça destekleyen, bakımı sürdürülen bir wallet seçin; özelliği bir social-media iddiasına değil, wallet'ın güncel documentation'ına göre doğrulayın.
2. Wallet seed'ini ve Silent Payment descriptor/key material'ını wallet'ın belgelenmiş recovery yöntemiyle yedekleyin. Code'u yayımlamadan önce küçük bir testnet/mainnet amount ile discovery'yi test edin.
3. Wallet BIP 352 labels destekliyorsa campaign, invoice veya counterparty'ler için ayrı **labels** oluşturun. Labels, linkable address yayımlamadan local accounting'e yardımcı olur.
4. Static Silent Payment code'u authenticated channel üzerinden yayımlayın. Yeniden kullanılabilir olsa da bir impostor kendi code'unu bunun yerine koyabilir.
5. Mümkün olduğunda local full node üzerinden scan yapın. Third-party index/scanning server, harcama yapamasa bile request timing veya filter data öğrenebilir.
6. Discovered UTXO'ları etiketli tutun ve ordinary Bitcoin ile aynı coin-control kurallarını uygulayın. Bunları harcamak veya consolidate etmek ownership ilişkilerini açığa çıkarabilir.
7. Recovery'nin, yedeklenmemiş bir external index'e güvenmeden payment'ları keşfettiğini doğrulayın.

### Sender workflow

1. Wallet'ın address version'a gönderimi desteklediğini doğrulayın ve receiver'ın uzun static code'unu authenticate edin.
2. Output'u wallet'ın oluşturmasına izin verin; code'u manuel olarak dönüştürmeyin veya kısaltmayın.
3. Seçilen input'ları dikkatle inceleyin. Silent Payments recipient-address privacy'yi iyileştirir, ancak sender input'ları hâlâ public graph üzerindedir.
4. Wallet tarafından desteklenen fee bumping/PSBT davranışını kullanın. BIP 352, input'lar değişirse output'un yeniden türetilmesini gerektirir ve bazı signing mode'ları güvenli değildir.
5. Dispute/accounting için gereken şifrelenmiş receipt veya proof'u saklayın.

Silent Payments, repeated recipient-address publication sorununu çözer. Amount, transaction timing, sender cluster, acquisition history veya sonraki co-spending işlemlerini gizlemez.

## Zcash fully shielded payments

Zcash, transparent ve shielded value pool'larını destekler. Orchard shielded transaction'ları, node'ların transaction details şifreliyken validity'yi doğrulayabilmesi için zero-knowledge proof'lar kullanır; Unified Address'ler birden fazla receiver type içerebilir.<sup>[[2]](#references)</sup> Privacy, gösterilen address'in ilk karakterine değil, wallet tarafından seçilen gerçek path'e bağlıdır.

### Shielded workflow

1. **shielded-by-default** davranışını ve güncel Orchard desteğini açıkça belirten, bakımı sürdürülen bir wallet seçin. Download'ı doğrulayın ve seed'i yedekleyip test edin.
2. ZEC'i yasal yollarla edinin ve basis/source kaydını tutun. Exchange acquisition ve withdrawal işlemlerini hâlâ bilir.
3. Wallet tarafından desteklenen bir Unified Address'e receive edin, ardından transaction'ın shielded pool'a ulaşıp ulaşmadığını kontrol edin. Wallet davranışını doğrulamadan automatic shielding varsaymayın.
4. **shielded-to-shielded** transfer'ları tercih edin. Transparent-to-shielded ve shielded-to-transparent boundary hareketleri public value/timing bilgilerini açığa çıkarır ve amount correlation'ı mümkün kılabilir; Orchard specification, non-Orchard address'e spending yapılmasının transaction value'yu açığa çıkardığını belirtir.<sup>[[3]](#references)</sup>
5. Distinctive exact-amount round trip'lerden ve immediate boundary crossing'lerden kaçının. Bu privacy hygiene'dir; ownership veya reporting'i gizlemek için izin değildir.
6. Wallet'ın desteklediği network-privacy path'ini kullanın. Shielded cryptography, IP/timing bilgilerini wallet server'larından veya peer'lerden gizlemez.
7. Internal compliance kayıtlarını tutun ve viewing key'leri, kapsamlarını anladıktan sonra yalnızca kasıtlı audit/disclosure için kullanın.
8. Göndermeden önce recipient wallet/exchange desteğini doğrulayın; forced transparent receiver privacy özelliğini değiştirir.

## GNU Taler: anonymous payer, accountable merchant

GNU Taler, traditional currency'leri, blind signature'ları ve regulated exchange/bank integration'ını kullanan açık bir electronic-payment protocol'üdür. Tasarımı, merchant'ların customer'ları anonymous tutmasını ve merchant'ların identifiable ve taxable kalmasını amaçlar.<sup>[[4]](#references)</sup> Cryptocurrency değildir ve kullanılabilirliği compatible regional exchange, bank, wallet ve merchant'a bağlıdır.

### Deployed olduğu yerde user workflow

1. İlgili currency/jurisdiction'ta çalışan bir Taler exchange ve merchant belirleyin; güncel terms, fees, KYC ve privacy notice'larını okuyun.
2. Official wallet'ı kurun ve kaynağını doğrulayın. Wallet backup/recovery data'sını cash gibi koruyun, çünkü wallet value bearer asset olabilir.
3. Supported bank/exchange flow üzerinden doğru bilgiler kullanarak withdrawal yapın. Blind signature'lar doğrudan coin-to-withdrawal link'ini kırsa da funding institution/exchange withdrawal'ı bilebilir.
4. Wallet'taki merchant contract'ını inceleyin: merchant identity, item/summary, amount, fees, refund ve delivery terms.
5. Ödeme yapın ve refund, warranty, accounting veya tax için gereken receipt data'sını saklayın.
6. Merchant unlinkability gerekiyorsa optional merchant session/account identifier'ları yeniden kullanmayın.
7. Wallet, network ve delivery metadata'sını threat model'e dahil edin; Taler payment cryptography, shipping address'i veya ele geçirilmiş endpoint'i gizlemez.

Merchant ve exchange accountable kalır; bu bileşenlerden herhangi birini işletmek regulated payment-service activity olabilir.

## Federated Chaumian e-cash

Chaumian e-cash, bir mint'in daha sonra harcanacak unblinded token'ı görmeden token imzalayabilmesi için blind signature'lar kullanır. Fedimint, reserve custody ve signing işlemlerini bir guardian federation genelinde dağıtır; documentation'ı, guardian'ların aggregate reserve'leri ve outstanding note'ları gördüğünü, ancak federation içindeki individual balance'ı veya kimin kime ödeme yaptığını görmemesi gerektiğini belirtir.<sup>[[5]](#references)</sup>

Bu, **custodial bearer value**'dur. Yeterli bir guardian quorum reserve'leri kontrol eder; federation failure, dishonest guardian'lar, software bug'ları veya kaybedilen client state loss'a neden olabilir. Deposit, withdrawal ve Lightning gateway'leri görünür boundary event'leridir ve timing/amount correlation oluşturabilir.

### Limited-risk workflow

1. Kaybetmeyi göze alabileceğiniz yalnızca küçük bir amount kullanın. Public/unknown federation'ları, gerçek dünyada accountability'si olan guardian'lara kıyasla daha yüksek riskli kabul edin.
2. Federation invite'ını authenticated channel üzerinden doğrulayın ve guardian identity'lerini, quorum'u, jurisdiction'ı, fees'i, recovery'yi ve shutdown policy'yi kaydedin.
3. Bakımı sürdürülen, compatible bir wallet kurun; doğrulayın ve deposit yapmadan önce backup scheme'ini anlayın.
4. Lawfully acquired Bitcoin'i documented path üzerinden deposit edin. Peg-in'i accounting için kaydedin ve timing/amount bilgilerinin boundary'de public veya biliniyor olduğunu varsayın.
5. Federation içinde fresh payment request'ler kullanın ve blind signature'ın kaldırdığı link'i yeniden oluşturan account/chat/delivery identifier'ları eklemekten kaçının.
6. Lightning payment'ları için gateway'i invoice'ların ve boundary timing'inin ek bir observer'ı olarak kabul edin.
7. Policy'ye göre redeem/withdraw yapın; distinctive amount ve immediate timing'in bir deposit veya external payment ile correlate olabileceğini bekleyin.
8. Tax/source/authorization kayıtlarını private olarak tutun; guardian'lar veya gateway'lerden activity'yi yanlış beyan etmelerini istemeyin.

Federated e-cash'i trustless, self-custodial veya guaranteed anonymous olarak tanımlamayın.

## BOLT 12 offers and route blinding

BOLT 12 offer'ları, stable on-chain address yayımlamadan reusable olabilir ve payer'ın receiver'ın clear node identity/path'ini öğrenmesini gerektirmemek için blinded path'ler kullanabilir. Bu, Lightning'in mevcut onion routing yapısını tamamlar, ancak onun yerini almaz.

Kullanmadan önce:

1. Sender ve receiver wallet'larının aynı güncel BOLT 12 feature'larını desteklediğini doğrulayın; generic “Lightning” branding'inden destek sonucu çıkarmayın.
2. Offer'ı out of band authenticate edin ve amount, issuer/description ile recurrence rule'larını kontrol edin.
3. Offer'dan oluşturulan fresh invoice/payment context kullanın.
4. Node alias'larını, public contact information'ı ve stable network endpoint'lerini minimumda tutun.
5. Sender/receiver, first/last hop, wallet service, channel graph ve on-chain funding/closure bilgilerinin ilişkinin bazı bölümlerini hâlâ açığa çıkardığını varsayın.

## Public disclosure olmadan auditability

Privacy ve audit bir arada bulunabilir:

- Label'ları, invoice'ları, authorization'ı, cost basis'i ve ownership mapping'i public protocol dışında şifrelenmiş olarak tutun.
- Protocol bir tane sağlıyorsa **view/audit key** ile spending key'i ayırın; exact disclosure davranışını önce örnek bir wallet üzerinde test edin.
- Auditor'a seed veya unrestricted spending credential yerine minimum kapsamlı proof verin.
- Transaction sırasında software version, protocol/pool, transaction ID veya proof, counterparty purpose ve exchange-rate source bilgilerini kaydedin.
- Kalıcı, şifrelenmemiş bir identity graph biriktirmek yerine retention ve deletion kuralları tanımlayın.

## Selection checklist

- [ ] Hidden field ve observer kesin olarak tanımlandı.
- [ ] Wallet/protocol desteği transaction date itibarıyla doğrulandı.
- [ ] Acquisition, network, node/RPC, counterparty, delivery ve sonraki-spend link'leri belgelendi.
- [ ] Custody, recovery, liquidity, issuer/federation solvency ve refund risk'leri kabul edildi.
- [ ] Gerekli identity, tax, sanctions, source ve organizational kayıtlar doğru tutulmaya devam ediyor.
- [ ] Recovery ve audit proof dahil küçük bir uçtan uca test başarılı oldu.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
