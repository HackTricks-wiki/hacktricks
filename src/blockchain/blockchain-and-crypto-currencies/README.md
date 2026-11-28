# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm blockchain kavramlarını ve on-chain güvenliği ele alır. Dışarıya açık bir Bitcoin peer için [Bitcoin P2P hizmeti numaralandırma](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md) ile başlayın; bir tarayıcı frontend'i, cüzdan bağlantısı veya off-chain backend için [DApp pentesting](../../pentesting-web/dapps-DecentralizedApplications.md) kullanın. Kripto para gizliliği işlemleri ve bunların sınırları için [kripto para gizliliği bölümü](../../privacy/cryptocurrency-privacy.md)'ne bakın.

## Temel Kavramlar

- **Smart Contracts**, belirli koşullar karşılandığında blockchain üzerinde yürütülen ve aracı olmadan anlaşmaların yerine getirilmesini otomatikleştiren programlar olarak tanımlanır.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir frontend ve şeffaf, denetlenebilir bir backend sunarak smart contract'lar üzerine kurulur.
- **Tokens & Coins** arasındaki fark, coin'lerin dijital para olarak hizmet etmesi; token'ların ise belirli bağlamlarda değer veya sahiplik temsil etmesidir.
  - **Utility Tokens** hizmetlere erişim sağlar; **Security Tokens** ise varlık sahipliğini ifade eder.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Decentralized Finance anlamına gelir.
- **DEX** ve **DAO** sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations anlamına gelir.

Kripto piyasalarında spot emirler, futures, kaldıraç ve opsiyonlar için kullanılan terminolojiye [Yatırım Terimleri](investment-terms.md) bölümünden bakın. Perpetual protokollerde funding rate istismarları için [Perpetual Funding-Rate Exploitation](perpetual-funding-rate-exploitation.md) bölümüne bakın.

## Consensus Mechanisms

Consensus mechanism'ler, blockchain üzerindeki işlemlerin güvenli ve üzerinde anlaşmaya varılmış şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlemleri doğrulamak için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token bulundurmasını gerektirir ve PoW'a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin'in Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon aktarımını kapsar. İşlemler dijital imzalarla doğrulanır; böylece yalnızca özel anahtarın sahibi transfer başlatabilir.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature Transactions**, bir işlemi yetkilendirmek için birden fazla imza gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenir) ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Bir kanalda birden fazla işleme izin vererek ve blockchain'e yalnızca son durumu yayınlayarak Bitcoin'in ölçeklenebilirliğini artırmayı amaçlar.

## Bitcoin Gizliliğine Yönelik Tehditler

**Common Input Ownership** ve **UTXO Change Address Detection** gibi gizlilik saldırıları, işlem kalıplarından yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Anonim Olarak Bitcoin Edinme

Yöntemler arasında nakit işlemler, mining ve mixer kullanımı bulunur. **CoinJoin**, iz sürmeyi zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, gizliliği artırmak üzere CoinJoin işlemlerini sıradan işlemler gibi gösterir.

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusudur. Aşağıda, saldırganların Bitcoin gizliliğini tehlikeye atabileceği yaygın yöntemlerin basitleştirilmiş bir özeti verilmiştir.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

İşlemin karmaşıklığı nedeniyle farklı kullanıcılara ait input'ların tek bir işlemde birleştirilmesi genellikle nadir görülür. Bu nedenle, **aynı işlemdeki iki input adresinin çoğunlukla aynı sahibine ait olduğu varsayılır**.

## **UTXO Change Address Detection**

Bir UTXO, yani **Unspent Transaction Output**, bir işlemde bütünüyle harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir change address'e gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir ve bu da gizliliği tehlikeye atar.

### Örnek

Bunu önlemek için mixing hizmetleri veya birden fazla adres kullanmak sahipliği gizlemeye yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini internette paylaşır; bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **Transaction Graph Analysis**

İşlemler grafikler halinde görselleştirilebilir ve fon akışına dayalı olarak kullanıcılar arasındaki olası bağlantıları ortaya çıkarabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu sezgisel yöntem, göndericiye geri dönen change'in hangi output olduğunu tahmin etmek için birden fazla input ve output içeren işlemlerin analizine dayanır.

### Örnek

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Daha fazla input eklemek, change çıktısını herhangi bir tekil input'tan daha büyük hâle getirirse sezgisel yöntemi yanıltabilir.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının bu miktarları gelecekteki işlemlerde başka input'larla birleştirip adresleri birbirine bağlamasını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu gizlilik leak'ini önlemek için daha önce kullanılmış ve boş adreslere alınan coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analiz Teknikleri**

- **Kesin Ödeme Tutarları:** Change içermeyen işlemler, aynı kullanıcıya ait iki adres arasında gerçekleşmiş olabilir.
- **Yuvarlak Tutarlar:** Bir işlemdeki yuvarlak tutar, bunun bir ödeme olduğunu; yuvarlak olmayan çıktının ise muhtemelen change olduğunu düşündürür.
- **Cüzdan Parmak İzi:** Farklı cüzdanların kendilerine özgü işlem oluşturma kalıpları vardır. Bu sayede analistler kullanılan yazılımı ve muhtemelen change adresini belirleyebilir.
- **Tutar ve Zaman Korelasyonları:** İşlem zamanlarının veya tutarlarının açıklanması, işlemlerin izlenebilir hâle gelmesine yol açabilir.

## **Trafik Analizi**

Saldırganlar, ağ trafiğini izleyerek işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Çok sayıda Bitcoin node'u işleten bir kuruluş söz konusu olduğunda bu risk özellikle yüksektir; çünkü bu, işlemleri izleme kapasitesini artırır.

## Daha Fazla Bilgi

Gizlilik saldırılarının ve savunmalarının kapsamlı bir listesi için [Bitcoin Wiki'deki Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Anonim Olarak Bitcoin Edinme Yöntemleri

- **Nakit İşlemler:** Bitcoin'i nakit karşılığında edinmek.
- **Nakit Alternatifleri:** Hediye kartları satın alıp bunları çevrimiçi olarak Bitcoin ile takas etmek.
- **Mining:** Bitcoin kazanmanın en gizli yöntemi mining'dir; özellikle de tek başına yapıldığında. Çünkü mining pool'ları madencinin IP adresini biliyor olabilir. [Mining Pool Bilgileri](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık:** Teorik olarak Bitcoin çalmak, onu anonim olarak edinmenin başka bir yolu olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Hizmetleri

Bir mixing hizmeti kullanarak kullanıcı **bitcoin gönderip** karşılığında **farklı bitcoin'ler alabilir**; bu da orijinal sahibin izini sürmeyi zorlaştırır. Ancak bunun için hizmetin kayıt tutmayacağına ve bitcoin'leri gerçekten geri göndereceğine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casinoları bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek input'ları output'larla eşleştirmeye çalışanların işini zorlaştırır. Etkili olsa da input ve output boyutları benzersiz olan işlemlerin izi yine de sürülebilir.

CoinJoin kullanmış olabilecek örnek işlemler: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Yatırma işlemlerini daha sonraki çekimlerden ayıran bir Ethereum smart contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir çeşidi olan **PayJoin** (veya P2EP), iki taraf arasındaki (ör. müşteri ve satıcı) işlemi, CoinJoin'in ayırt edici eşit output'larını kullanmadan sıradan bir işlem gibi gösterir. Bu, işlemin tespit edilmesini son derece zorlaştırır ve işlem gözetimi yapan kuruluşların kullandığı yaygın-input-sahipliği sezgisel yöntemini geçersiz kılabilir.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Yukarıdaki gibi işlemler, standart bitcoin işlemlerinden ayırt edilemez kalırken gizliliği artıran PayJoin işlemleri olabilir.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlem gizliliği arayışında umut vadeden bir gelişme olabilir.

# Kripto Para Gizliliği için En İyi Uygulamalar

## **Cüzdan Senkronizasyon Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blokzincir ile senkronize etmek çok önemlidir. İki yöntem öne çıkar:

- **Full node**: Tüm blokzinciri indirerek maksimum gizlilik sağlar. Şimdiye kadar yapılan tüm işlemler yerel olarak saklanır; bu da saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkânsız hâle getirir.
- **İstemci tarafında blok filtreleme**: Bu yöntemde, blokzincirdeki her blok için filtreler oluşturulur. Böylece cüzdanlar, belirli ilgi alanlarını ağ gözlemcilerine ifşa etmeden ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları getirir.

## **Anonimlik için Tor Kullanımı**

Bitcoin eşler arası bir ağda çalıştığından, IP adresinizi gizlemek ve ağla etkileşim kurarken gizliliği artırmak için Tor kullanmanız önerilir.

## **Adreslerin Yeniden Kullanılmasını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak hayati önem taşır. Adresleri yeniden kullanmak, işlemleri aynı varlığa bağlayarak gizliliği tehlikeye atabilir. Modern cüzdanların tasarımı, adreslerin yeniden kullanılmasını önler.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını gizleyerek gizlilik saldırılarını engelleyebilir.
- **Para üstünden kaçınma**: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, para üstü tespit yöntemlerini sekteye uğratarak gizliliği artırır.
- **Birden fazla para üstü çıktısı**: Para üstünden kaçınmak mümkün değilse, birden fazla para üstü çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimliğin Öncüsü**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlamak**

Gas, Ethereum'da işlemleri yürütmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) tutarındaki bir işlemde gas limiti ve taban ücret bulunur; ayrıca doğrulayıcıların işlemi bloğa eklemesini teşvik etmek için bir öncelik ücreti de vardır. Kullanıcılar fazla ödeme yapmamak için azami ücret belirleyebilir; aşan tutar iade edilir.<sup>[[5]](#references)</sup>

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemlerde, kullanıcı adresi veya akıllı sözleşme adresi olabilen bir gönderici ve alıcı bulunur. İşlemler ücret gerektirir ve bir bloğa eklenmelidir. Bir işlemdeki temel bilgiler arasında alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretler yer alır. Özellikle, göndericinin adresi imzadan çıkarılır; bu nedenle işlem verilerinde yer alması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik vererek kripto paralarla işlem yapmak isteyen herkes için temel niteliktedir.

## Değer Odaklı Web3 Red Team Çalışmaları

- Fonları kimin ve nasıl hareket ettirebileceğini anlamak için değer taşıyan bileşenlerin (imzalayıcılar, oracle'lar, köprüler, otomasyon) envanterini çıkarın.
- Yetki yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT taktikleriyle eşleştirin.
- Etkiyi doğrulamak ve istismar edilebilir önkoşulları belgelemek için flash loan/oracle/kimlik bilgisi zincirler arası saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışının Ele Geçirilmesi

- Cüzdan kullanıcı arayüzlerindeki tedarik zinciri müdahaleleri, imzalama işleminden hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall tabanlı proxy ele geçirmeleri için geçerli imzaları toplayabilir (ör. Safe masterCopy'nin slot-0 üzerine yazılması).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Hesap Soyutlama (ERC-4337)

- Yaygın akıllı hesap hata türleri arasında `EntryPoint` erişim denetiminin atlatılması, imzalanmamış gas alanları, durum bilgili doğrulama, ERC-1271 replay ve doğrulama sonrası revert yoluyla ücretlerin tüketilmesi bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Akıllı Sözleşme Güvenliği

- Test paketlerindeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Kanıtı / zkVM Guest Bütünlüğü

Bir prover, bir iddiayı doğrulamak için **zkVM** veya uygulamaya özel bir kanıt devresi kullandığında, doğrulayıcı yalnızca **guest programının yazıldığı şekilde yürütüldüğünü** öğrenir. Guest içinde **güvenli olmayan serileştirme**, **tanımsız davranış** veya **eksik anlamsal kısıtlamalar** varsa, kötü niyetli bir prover, **herkese açık metrikler veya iddia edilen değişmez yanlış olsa bile** doğrulanan bir kanıt üretebilir.<sup>[[7]](#references)</sup>

### Kanıt guest'leri içindeki güvenli olmayan serileştirme

- Özel witness/devre baytlarını, kanıt tarafından gizlenmiş olsalar bile **güvenilmeyen saldırgan girdisi** olarak değerlendirin.
- Baytlar daha önce bant dışı doğrulanmadıysa, `rkyv::access_unchecked` gibi denetlenmemiş yardımcı işlevlerle serileştirme çözme işlemi yapmaktan kaçının.
- Güvenilmeyen serileştirilmiş verilerden yüklenen enum ayırt edicileri, göreli işaretçiler, uzunluklar ve indeksler; kontrol akışını veya bellek erişimini etkilemeden önce doğrulanmalıdır.

Pratik denetim örüntüsü:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

If `op.kind` gibi bir alan enum ise ve saldırgan **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerindeki sonraki her `match` şüpheli hâle gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini **jump table**'a dönüştürürse, geçersiz bir enum discriminant'ı **tanımsız kontrol akışına** yol açabilir. Tehlikeli bir örüntü şöyledir:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtları** günceller.
2. İkinci bir `match`, **gerçek talimat semantiğini** uygular.
3. Aralık dışı bir discriminant, ilk jump table sınırlarının dışına indekslenerek ikinci jump table ile ilişkili koda ulaşır.

Sonuç: İşlem yürütülür, ancak muhasebe yolu atlanır. Bir zkVM'de bu, daha az gate, daha az maliyetli işlem veya sınırlandırılmış diğer kaynaklar gibi imkânsız metrikler bildiren sahte proof'lar oluşturabilir.

İnceleme kontrol listesi:

- Witness/private input'tan deserialize edilen, saldırganın kontrolündeki enum'ları arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + kontrolsüz deserialization + büyük opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde oluşturulan binary'yi reverse engineer edin; jump table yerleşimi kaynak koddan daha önemli olabilir.

### Reversible/specialized interpreter'larda eksik semantik kısıtlamalar

Yalnızca bellek güvenliğini doğrulamayın; proof'un uygulaması gereken **semantik kuralları** da doğrulayın.

Reversible/quantum-like instruction set'lerde, farklı olması gereken operand'ların gerçekten farklı olmalarının kısıtlandığından emin olun. Şu şekilde uygulanan Toffoli/CCX benzeri bir işlem:<sup>[[7]](#references)[[8]](#references)</sup>

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

Bu, **deterministik bir sıfırlama primitive’i** oluşturur; tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha düşük maliyetle yapılmasını sağlar. Kaynak kullanımını doğrulayan proof sistemlerinde bu, saldırganların işlevsel kontrolleri geçerken doğrulayıcının uygulandığını sandığı maliyet modelini atlatmasına olanak tanıyabilir.

### Yetersiz kısıtlanmış prover tavsiyeleri ve modüler aritmetik

Bir **advice/witness stack**’ten yüklenen değerler, önceden hesaplanmış bölüm, kalan, ters veya ipucu olarak tanımlansalar bile prover tarafından kontrol edilir. Bir proof yalnızca witness’in uygulanmış kısıtları karşıladığını gösterir; bu kısıtlar tür, aralık veya kanonik biçim kontrolünü içermiyorsa amaçlanan hesaplamanın yapıldığını göstermez.<sup>[[13]](#references)</sup>

Bir indirgeme veya Öklid bölmesi yardımcısı için yalnızca son çıkarma ya da çarpma işlemini değil, tam sayı bağıntısının tamamını denetleyin. `q` ve `r` değerlerinin her limb’i tanımlanan genişliğe göre kısıtlanmalı, `x = q * m + r` yeniden oluşturma bağıntısı amaçlanan tam sayı gösteriminde sağlanmalı ve kanonik `0 <= r < m` sınırı uygulanmalıdır. Bir değeri daha dar bir `u32`/`u64` talimatına **iletmeden önce** doğrulayın; dar kapsamlı bir işlem, özgün field element’in veya çok limb’li değerin beklenen türe sahip olduğunu geriye dönük olarak kanıtlamaz.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

`mod_12289` hatası, Miden'deki exploit modelini gözler önüne seriyor: quotient, iki limb'li 64 bitlik bir değer olarak denetleniyordu ancak advice tarafından sağlanan remainder, eşdeğer bir doğrulama olmadan `u32overflowing_sub`'a ulaşıyordu. Kötü niyetli bir prover, uygulanan çıkarma kısıtları sağlanırken prosedürün matematiksel olmayan bir remainder döndürmesini sağlayacak geçersiz quotient/remainder değerlerini koordine edebilirdi. Bu sonuç Falcon doğrulamasına aktarıldığından, soundness hatası yalnızca yanlış bir aritmetik sonuç üretmekle kalmayıp sahte yetkilendirme imzalarına da dönüştürülebilirdi.<sup>[[13]](#references)</sup>

### Implicit-stack cryptographic VM'leri denetleme

Stack dilleri operand'ları gizler; bu nedenle öncelikle talimatları, tüketilen ve üretilen her stack değerinin provenance bilgisine sahip bir ifade olduğu IR'ye dönüştürün. Ardından temkinli bir analiz hattı şunları yapabilir:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Çağrı grafiğini oluşturun ve prosedürlerin input/output stack etkilerini çıkarın.
2. Desteklenen talimatları sembolik olarak çalıştırın ve kontrol akışını SSA/yapılandırılmış ifadelere dönüştürün.
3. `Unknown`, `ProvenU32`, `Bool`, değer provenance bilgisi ve yerel değişken başlatma gibi soyut olguları sabit noktaya ulaşana kadar ilerletin.
4. Advice kaynaklı değerlerin, her gelen yolda bir sanitizer uygulanmadan, türlenmiş aritmetiğe veya sıfır olmayan değer gerektiren noktalara ulaştığını işaretleyin.
5. Bildirilen ve çıkarılan imzaları karşılaştırın; her çıkışın çağırana ait stack değerlerini koruduğunu doğrulayın.

Bilinmeyen bir imzayı veya desteklenmeyen bir yapıyı temiz sonuç değil, **analiz boşluğu** olarak değerlendirin. Dinamik çağrılar, stack etkisini korumayan döngüler ve farklı stack etkilerine sahip dallar, stack slotlarının güvenilir biçimde izlenmesini imkânsız kılabilir; daha güvenli bir decompiler, makul görünen ama hatalı pseudocode üretmek yerine bu durumları reddeder veya işaretler.<sup>[[10]](#references)[[13]](#references)</sup>

Kontrol akışı birleşimlerinde bir özelliği yalnızca tüm öncüllerde geçerliyse koruyun (örneğin, `ProvenU32 join Unknown = Unknown`). Ayrıca sabit nokta yakınsamasını yineleme sınırına ulaşmaktan ayırın: yalnızca yakınsamış, sound bir üst yaklaşım, bir tanılamanın bulunmamasını temsil edilen tüm yürütmelerin özelliği sağladığına dair kanıt olarak değerlendirmeyi haklı çıkarabilir.<sup>[[11]](#references)</sup>

### Gizli önkoşulları ortaya çıkarmak için proof obligation'ları kullanın

Küçük talimat kümeleri için prosedürleri çalıştırılabilir bir formal VM modeline dönüştürün ve hem sonucu hem de stack'in tamamındaki dönüşümü kanıtlayın. Teorem; sonlanmayı, türlenmiş girdileri, beklenen çıktı önekini ve dokunulmamış çağıran stack'inin korunmasını kapsamalıdır. Teorem ifadesini kanıt kadar dikkatle denetleyin: kernel, yanlışlıkla zayıflatılmış bir iddianın kanıtını doğrulayabilir.<sup>[[12]](#references)[[13]](#references)</sup>

Beklenmedik varsayımlar yararlı bulgulardır. Miden incelemesinde, 64 bit sağa döndürme işleminin bir kanıtı `shift mod 32 != 0` koşulunu gerektiriyordu ve bu, shift değeri 32'nin katı olduğunda büyük girdiler için başarısız bir uç durumu ortaya çıkardı; başka bir kanıt ise 256 bitlik `wrapping_mul` işleminin çağırana ait stack değerlerini sildiğini gösterdi. Bulunan sınır durumunu testlere ekleyin; ardından bu ek varsayımı sessizce kabul etmek yerine uygulamayı düzeltin veya herkese açık önkoşulu bilinçli biçimde güçlendirin.<sup>[[12]](#references)[[13]](#references)</sup>

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser'larını hatalı witness/private-input kodlamalarıyla fuzz edin.
- Opcode dispatch'inden önce enum aralığı doğrulamasının yapıldığını doğrulayın.
- Operand aliasing ve diğer geçersiz talimat biçimleri için anlamsal denetimler ekleyin.
- Her advice/witness kaynağını tüm türlenmiş aritmetik noktalarına kadar izleyin ve her yolda doğrulama yapılmasını zorunlu tutun.<sup>[[11]](#references)[[13]](#references)</sup>
- Aritmetik yardımcılarını kanonik olmayan limb'ler, aralık dışı remainder değerleri ve sınır shift sayılarıyla test edin.<sup>[[12]](#references)[[13]](#references)</sup>
- Her dönüşte stack yüksekliğini ve prosedürün bildirilen argümanlarının altındaki değerlerin korunduğunu doğrulayın.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Bildirilen/genel sayaçları bağımsız bir referans uygulamasıyla karşılaştırın.
- Guest programı hatalıysa geçerli bir proof'un yine de **yanlış önermeyi** kanıtlayabileceğini unutmayın.

## Duruma Bağlı Yetkilendirme

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX'lerin ve AMM'lerin pratik exploitation'ını (Uniswap v4 hooks, yuvarlama/hassasiyet istismarı, flash loan ile büyütülmüş eşik aşan swap'ler) araştırıyorsanız şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri önbelleğe alan ve `supply == 0` olduğunda zehirlenebilen çok varlıklı ağırlıklı pool'lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Vikipedi](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key ve Private Key Açıklaması - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Çoklu imzalı işlemler nedir? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [İşlemler | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas ve ücretler | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Gizlilik - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google's zero-knowledge proof of quantum cryptanalysis'ını yendik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Eliptik Eğri Kripto Para Birimlerini Kuantum Güvenlik Açıklarına Karşı Koruma: Kaynak Tahminleri ve Azaltma Yöntemleri (yamalanmış sürüm)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept deposu](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler mimarisi](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM static-analysis altyapısı](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean modeli ve doğruluk kanıtları](https://github.com/trailofbits/masm-lean)
- [13] [(Yeterince iyi) AI çağında denetim](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
