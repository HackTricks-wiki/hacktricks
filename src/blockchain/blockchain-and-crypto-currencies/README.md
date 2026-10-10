# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts**, belirli koşullar karşılandığında blockchain üzerinde çalışan programlardır; aracı olmadan anlaşmaların yürütülmesini otomatikleştirir.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç sunarak smart contract’lar üzerine kurulur.
- **Tokens & Coins** farklı kavramlardır: coin’ler dijital para olarak kullanılırken token’lar belirli bağlamlarda değeri veya sahipliği temsil eder.
  - **Utility Tokens** hizmetlere erişim sağlar; **Security Tokens** ise varlık sahipliğini ifade eder.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Decentralized Finance anlamına gelir.
- **DEX** ve **DAO** sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations anlamına gelir.

## Mutabakat Mekanizmaları

Mutabakat mekanizmaları, blockchain üzerindeki işlemlerin güvenli ve üzerinde anlaşılmış biçimde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlemleri doğrulamak için hesaplama gücünden yararlanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token bulundurmasını gerektirir ve PoW’a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin’in Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon aktarımını kapsar. İşlemler dijital imzalarla doğrulanır; böylece yalnızca private key’in sahibi aktarım başlatabilir.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature Transactions**, bir işlemi yetkilendirmek için birden fazla imza gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **inputs** (fonların kaynağı), **outputs** (hedef), **fees** (madencilere ödenen ücretler) ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Bir kanal içinde birden fazla işleme izin vererek ve blockchain’e yalnızca son durumu yayınlayarak Bitcoin’in ölçeklenebilirliğini artırmayı amaçlar.

## Bitcoin Gizliliğine İlişkin Endişeler

**Common Input Ownership** ve **UTXO Change Address Detection** gibi gizlilik saldırıları, işlem örüntülerinden yararlanır. **Mixers** ve **CoinJoin** gibi yöntemler, kullanıcılar arasındaki işlem bağlantılarını belirsizleştirerek anonimliği artırır.

## Bitcoin’leri Anonim Olarak Edinme

Yöntemler arasında nakit işlemleri, mining ve mixer kullanımı bulunur. **CoinJoin**, iz sürmeyi zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha fazla gizlilik sağlamak amacıyla CoinJoin işlemlerini normal işlemler gibi gösterir.

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusu olur. Aşağıda, saldırganların Bitcoin gizliliğini tehlikeye atabileceği bazı yaygın yöntemlere ilişkin basitleştirilmiş bir genel bakış yer alıyor.<sup>[[6]](#references)</sup>

## **Ortak Girdi Sahipliği Varsayımı**

İşin karmaşıklığı nedeniyle farklı kullanıcılara ait girdilerin tek bir işlemde birleştirilmesi genellikle nadir görülür. Bu nedenle, **aynı işlemdeki iki girdi adresinin genellikle aynı sahibine ait olduğu varsayılır**.

## **UTXO Değişim Adresi Tespiti**

Bir UTXO, yani **Harcanmamış İşlem Çıktısı**, bir işlemde tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse geri kalanı yeni bir değişim adresine aktarılır. Gözlemciler bu yeni adresin gönderene ait olduğunu varsayabilir; bu da gizliliği tehlikeye atar.

### Örnek

Bunu azaltmak için mixing hizmetleri kullanmak veya birden fazla adres kullanmak sahipliği belirsizleştirmeye yardımcı olabilir.

## **Sosyal Ağlarda ve Forumlarda Bilgilerin Açığa Çıkması**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da **adresi sahibine bağlamayı kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler grafikler halinde görselleştirilebilir ve fon akışına dayanarak kullanıcılar arasındaki olası bağlantılar ortaya çıkarılabilir.

## **Gereksiz Girdi Sezgiseli (Optimal Change Heuristic)**

Bu sezgisel yöntem, gönderene geri dönen değişim çıktısını tahmin etmek için birden fazla girdi ve çıktı içeren işlemlerin analizine dayanır.

### Örnek

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Daha fazla input eklemek, change çıktısını tek bir input'tan daha büyük hâle getirirse sezgisel yöntemi yanıltabilir.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının bu tutarları gelecekteki işlemlerde başka input'larla birleştirerek adresleri birbirine bağlamasını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu privacy leak'i önlemek için daha önce kullanılmış ve boş olan adreslere alınan coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analizi Teknikleri**

- **Kesin Ödeme Tutarları:** Change içermeyen işlemler, muhtemelen aynı kullanıcıya ait iki adres arasında gerçekleşmiştir.
- **Yuvarlak Tutarlar:** Bir işlemdeki yuvarlak tutar, bunun bir ödeme olduğunu düşündürür; yuvarlak olmayan çıktı ise muhtemelen change'tir.
- **Cüzdan Parmak İzi Çıkarma:** Farklı cüzdanların kendilerine özgü işlem oluşturma örüntüleri vardır. Bu örüntüler, analistlerin kullanılan yazılımı ve muhtemelen change adresini belirlemesine olanak tanır.
- **Tutar ve Zaman Korelasyonları:** İşlem zamanlarının veya tutarlarının açıklanması, işlemlerin izlenebilir hâle gelmesine yol açabilir.

## **Trafik Analizi**

Saldırganlar, ağ trafiğini izleyerek işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bir kuruluşun çok sayıda Bitcoin node'u işletmesi, işlemleri izleme kapasitesini artırdığından bu risk özellikle yüksektir.

## Daha Fazla Bilgi

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Wiki'deki Bitcoin Gizliliği](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Anonim Olarak Bitcoin Edinme Yöntemleri

- **Nakit İşlemler**: Bitcoin'i nakit kullanarak edinmek.
- **Nakit Alternatifleri**: Hediye kartları satın alıp bunları çevrimiçi olarak Bitcoin ile takas etmek.
- **Mining**: Bitcoin kazanmanın en gizli yöntemi mining yapmaktır. Bu işlem özellikle tek başına yapıldığında daha gizlidir; çünkü mining pool'ları madencinin IP adresini öğrenebilir. [Mining Pool'ları Hakkında Bilgi](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak Bitcoin çalmak, onu anonim olarak edinmenin başka bir yolu olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Servisleri

Bir mixing service kullanarak kullanıcı **bitcoin gönderip** karşılığında **farklı bitcoin'ler alabilir**; bu da asıl sahibin izini sürmeyi zorlaştırır. Ancak bunun için servisin kayıt tutmayacağına ve bitcoin'leri gerçekten iade edeceğine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casinoları da bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek input'ları output'larla eşleştirmeye çalışanların işini zorlaştırır. Etkili olmasına rağmen, benzersiz input ve output boyutlarına sahip işlemlerin izi yine de sürülebilir.

CoinJoin kullanmış olabilecek örnek işlemler: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Para yatırma işlemlerini daha sonraki çekimlerden ayıran bir Ethereum smart contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir çeşidi olan **PayJoin** (veya P2EP), iki taraf arasındaki (ör. müşteri ve satıcı) işlemi, CoinJoin'in ayırt edici eşit output özelliğini taşımayan sıradan bir işlem gibi gösterir. Bu, PayJoin'i tespit etmeyi son derece zorlaştırır ve işlem gözetimi yapan kuruluşların kullandığı yaygın-input-sahipliği sezgisel yöntemini geçersiz kılabilir.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Yukarıdakine benzer işlemler, standart bitcoin işlemlerinden ayırt edilemezken gizliliği artıran PayJoin işlemleri olabilir.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlemsel gizlilik arayışında umut verici bir gelişme sunar.

# Kripto Para Gizliliği İçin En İyi Uygulamalar

## **Cüzdan Eşitleme Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blockchain ile eşitlemek çok önemlidir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek maksimum gizlilik sağlar. Şimdiye kadar yapılmış tüm işlemler yerel olarak saklandığından, saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesi imkânsız hale gelir.
- **İstemci tarafında blok filtreleme**: Bu yöntemde, cüzdanların belirli ilgi alanlarını ağ gözlemcilerine açığa çıkarmadan ilgili işlemleri belirleyebilmesi için blockchain'deki her blok için filtreler oluşturulur. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları alır.

## **Anonimlik İçin Tor Kullanımı**

Bitcoin eşler arası bir ağda çalıştığından, IP adresinizi gizlemek ve ağla etkileşim kurarken gizliliği artırmak için Tor kullanmanız önerilir.

## **Adres Yeniden Kullanımını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak önemlidir. Adresleri yeniden kullanmak, işlemleri aynı varlığa bağlayarak gizliliği tehlikeye atabilir. Modern cüzdanlar, tasarımları gereği adreslerin yeniden kullanımını caydırır.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını belirsizleştirerek gizlilik saldırılarını engelleyebilir.
- **Para üstünü önleme**: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, para üstü tespit yöntemlerini bozarak gizliliği artırır.
- **Birden fazla para üstü çıktısı**: Para üstünü önlemek mümkün değilse, birden fazla para üstü çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimlik Feneri**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlamak**

Gas, Ethereum'da işlemleri yürütmek için gereken hesaplama eforunu ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) tutarındaki bir işlemde gas limiti ve taban ücret bulunur; doğrulayıcıların işlemi dahil etmesini teşvik etmek için öncelik ücreti de eklenir. Kullanıcılar fazla ödeme yapmadıklarından emin olmak için bir maksimum ücret belirleyebilir; artan tutar iade edilir.<sup>[[5]](#references)</sup>

## **İşlemleri Gerçekleştirme**

Ethereum işlemlerinde, kullanıcı adresi veya akıllı sözleşme adresi olabilen bir gönderici ve alıcı bulunur. İşlemler ücret gerektirir ve bir bloğa dahil edilmelidir. İşlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Özellikle, göndericinin adresi imzadan çıkarılır; dolayısıyla işlem verilerinde bulunması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizliliğe ve güvenliğe öncelik verirken kripto para kullanmak isteyen herkes için temel niteliktedir.

## Değer Odaklı Web3 Red Teaming

- Fonları kimin ve nasıl hareket ettirebileceğini anlamak için değer taşıyan bileşenlerin (imzalayıcılar, oracle'lar, bridge'ler, otomasyon) envanterini çıkarın.
- Ayrıcalık yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT taktikleriyle eşleyin.
- Etkiyi doğrulamak ve istismar edilebilir önkoşulları belgelemek için flash loan/oracle/kimlik bilgisi zincirler arası saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışının Ele Geçirilmesi

- Wallet UI'larının tedarik zincirine müdahale edilmesi, imzalama işleminden hemen önce EIP-712 yüklerini değiştirebilir ve delegatecall tabanlı proxy ele geçirmeleri için geçerli imzaları toplayabilir (ör. Safe masterCopy'nin slot-0 üzerine yazılması).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Hesap Soyutlama (ERC-4337)

- Akıllı hesaplarda yaygın hata türleri arasında `EntryPoint` erişim denetiminin atlanması, imzasız gas alanları, durum bilgili doğrulama, ERC-1271 replay ve doğrulama sonrasında revert yoluyla ücretlerin tüketilmesi bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Akıllı Sözleşme Güvenliği

- Test paketlerindeki kör noktaları bulmak için mutasyon testi:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Kanıtı / zkVM Guest Bütünlüğü

Bir prover, bir iddiayı doğrulamak için **zkVM** veya uygulamaya özgü bir kanıt devresi kullandığında, verifier yalnızca **guest programının yazıldığı şekilde çalıştığını** öğrenir. Guest'te **güvenli olmayan serileştirme**, **tanımsız davranış** veya **eksik anlamsal kısıtlamalar** varsa kötü amaçlı bir prover, **genel metrikler veya iddia edilen değişmez yanlış olduğu halde** doğrulanan bir kanıt üretebilir.<sup>[[7]](#references)</sup>

### Kanıt guest'leri içinde güvenli olmayan serileştirme

- Kanıt tarafından gizlenmiş olsalar bile özel witness/devre baytlarını **güvenilmeyen saldırgan girdisi** olarak ele alın.
- Baytlar daha önce başka bir yolla doğrulanmadıysa `rkyv::access_unchecked` gibi denetimsiz yardımcılarla serileştirmeyi açmayın.
- Güvenilmeyen serileştirilmiş verilerden yüklenen enum ayıraçları, göreli işaretçiler, uzunluklar ve dizinler; kontrol akışını veya bellek erişimini etkilemeden önce doğrulanmalıdır.

Uygulamalı denetim kalıbı:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` gibi bir alan enum ise ve saldırgan **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerindeki sonraki her `match` şüpheli hâle gelir.

### Jump-table / UB denetimini atlatma

Rust büyük bir `match` ifadesini **jump table**'a dönüştürürse, geçersiz bir enum discriminant’ı **tanımsız kontrol akışına** yol açabilir. Tehlikeli bir örüntü:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtlamaları** günceller.
2. İkinci bir `match`, **gerçek komut semantiğini** uygular.
3. Aralık dışı bir discriminant ilk jump table'ın dışındaki bir indekse karşılık gelir ve ikinci jump table'la ilişkili bir koda atlar.

Sonuç: İşlem yine yürütülür, ancak muhasebe yolu atlanır. Bir zkVM'de bu, imkânsız metrikler bildiren sahte kanıtlar üretebilir; örneğin daha az gate, daha az maliyetli işlem veya diğer kaynak sınırlarının yanlış bildirilmesi.

İnceleme kontrol listesi:

- Witness/özel girdiden deserialize edilen, saldırganın kontrolündeki enum değerlerini arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + denetimsiz deserialization + büyük opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde derlenmiş binary üzerinde tersine mühendislik yapın; jump table düzeni, kaynak koddan daha önemli olabilir.

### Tersinir/özelleştirilmiş yorumlayıcılarda eksik semantik kısıtlamalar

Yalnızca bellek güvenliğini doğrulamayın; kanıtın uygulaması gereken **semantik kuralları** da doğrulayın.

Tersinir/kuantum benzeri komut kümelerinde, birbirinden farklı olması gereken operandların gerçekten farklı olmasını sağlayan kısıtlamalar bulunduğundan emin olun. Şu şekilde uygulanmış Toffoli/CCX benzeri bir işlem:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

konuk reddetmezse güvensiz hale gelir:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Bu durumda geçiş şu hale gelir:

```text
q = q ^ (q & q) = 0
```

Bu, **deterministik bir sıfırlama primitive'i** oluşturur; tersinirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha düşük maliyetle yapılmasını sağlar. Kaynak kullanımını doğrulayan proof sistemlerinde saldırganların, doğrulayıcının uygulandığını sandığı maliyet modelini atlatırken işlevsel kontrolleri geçmesini sağlayabilir.

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser'ları hatalı witness/private-input kodlamalarıyla fuzz edin.
- Opcode dispatch işleminden önce enum aralıklarının doğrulandığından emin olun.
- Operand aliasing ve diğer geçersiz instruction biçimleri için anlamsal kontroller ekleyin.
- Bildirilen/public sayaçları bağımsız bir referans uygulamasıyla karşılaştırın.
- Guest program hatalıysa geçerli bir proof'un yine de **yanlış bir ifadeyi** kanıtlayabileceğini unutmayın.

## Duruma Bağlı Yetkilendirme

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX ve AMM'lerin pratikte nasıl exploit edildiğini araştırıyorsanız (Uniswap v4 hooks, yuvarlama/hassasiyet suistimali, flash loan ile güçlendirilmiş eşik aşan swap'ler), şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri önbelleğe alan ve `supply == 0` olduğunda zehirlenebilen çok varlıklı weighted pool'lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Açıklaması - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Çoklu imzalı işlemler nedir? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [İşlemler | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas ve ücretler | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Gizlilik - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google'ın kuantum kriptanaliz sıfır bilgi proof'unu yendik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Eliptik Eğri Kripto Para Birimlerini Kuantum Açıklarına Karşı Güvence Altına Alma: Kaynak Tahminleri ve Önlemler (yamalanmış sürüm)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept deposu](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
