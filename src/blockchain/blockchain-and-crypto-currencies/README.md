# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Akıllı Sözleşmeler**, belirli koşullar karşılandığında blockchain üzerinde çalışan ve aracı olmadan anlaşmaların yürütülmesini otomatikleştiren programlardır.
- **Merkeziyetsiz Uygulamalar (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç sunarak akıllı sözleşmeler üzerine kurulur.
- **Token'lar ve Coin'ler** farklı amaçlara sahiptir: coin'ler dijital para işlevi görürken token'lar belirli bağlamlarda değeri veya mülkiyeti temsil eder.
  - **Utility Token'lar** hizmetlere erişim sağlar; **Security Token'lar** ise varlık sahipliğini ifade eder.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Merkeziyetsiz Finans'ın kısaltmasıdır.
- **DEX** ve **DAO**, sırasıyla Merkeziyetsiz Borsa Platformlarını ve Merkeziyetsiz Otonom Organizasyonları ifade eder.

Kripto piyasalarında kullanılan spot emirler, vadeli işlemler, kaldıraç ve opsiyon terminolojisi için [Yatırım Terimleri](investment-terms.md) sayfasına bakın.

## Mutabakat Mekanizmaları

Mutabakat mekanizmaları, blockchain üzerindeki işlemlerin güvenli ve üzerinde uzlaşılmış şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlemleri doğrulamak için işlem gücünden yararlanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token bulundurmasını gerektirir ve PoW'a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon aktarımını içerir. İşlemler dijital imzalarla doğrulanır ve böylece yalnızca özel anahtarın sahibi transfer başlatabilir.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Çoklu imza işlemleri**, bir işlemi yetkilendirmek için birden fazla imza gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **girdilerden** (fonların kaynağı), **çıktılardan** (varış noktası), **ücretlerden** (madencilere ödenen) ve **script'lerden** (işlem kuralları) oluşur.

### Lightning Network

Bir kanalda birden fazla işleme izin vererek Bitcoin'in ölçeklenebilirliğini artırmayı ve blockchain'e yalnızca son durumu yayınlamayı amaçlar.

## Bitcoin Gizliliğine İlişkin Endişeler

**Ortak Girdi Sahipliği** ve **UTXO Değişim Adresi Tespiti** gibi gizlilik saldırıları, işlem örüntülerinden yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Bitcoin'leri Anonim Olarak Edinme

Yöntemler arasında nakit işlemler, madencilik ve mixers kullanımı bulunur. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha fazla gizlilik sağlamak için CoinJoin işlemlerini sıradan işlemler gibi gösterir.

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusu olur. Aşağıda, saldırganların Bitcoin gizliliğini tehlikeye atabileceği yaygın yöntemlere dair basitleştirilmiş bir genel bakış yer almaktadır.<sup>[[6]](#references)</sup>

## **Ortak Girdi Sahipliği Varsayımı**

İşin karmaşıklığı nedeniyle farklı kullanıcılara ait girdilerin tek bir işlemde birleştirilmesi genellikle nadirdir. Bu nedenle, **aynı işlemdeki iki girdi adresinin çoğunlukla aynı sahibine ait olduğu varsayılır**.

## **UTXO Değişim Adresi Tespiti**

UTXO, yani **Harcanmamış İşlem Çıktısı**, bir işlemde tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir değişim adresine gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir; bu da gizliliği tehlikeye atar.

### Örnek

Bunu önlemek için karıştırma hizmetleri kullanmak veya birden fazla adres kullanmak sahipliği gizlemeye yardımcı olabilir.

## **Sosyal Ağlarda ve Forumlarda İfşa**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır ve bu da **adresi sahibine bağlamayı kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler grafikler halinde görselleştirilebilir ve fon akışına göre kullanıcılar arasındaki olası bağlantıları ortaya çıkarabilir.

## **Gereksiz Girdi Sezgiseli (Optimal Change Heuristic)**

Bu sezgisel yöntem, göndericiye geri dönen değişim çıktısının hangisi olduğunu tahmin etmek için birden fazla girdi ve çıktı içeren işlemleri analiz etmeye dayanır.

### Örnek

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Daha fazla input eklemek, change çıktısını tek bir input'tan daha büyük hâle getirirse sezgisel yöntemi yanıltabilir.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının bu tutarları gelecekteki işlemlerde başka input'larla birleştirerek adresleri ilişkilendirmesini umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu privacy leak'ini önlemek için daha önce kullanılmış ve bakiyesi boş olan adreslerden alınan coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analiz Teknikleri**

- **Kesin Ödeme Tutarları:** Para üstü içermeyen işlemler, aynı kullanıcıya ait iki adres arasında gerçekleşmiş olabilir.
- **Yuvarlak Tutarlar:** Bir işlemdeki yuvarlak bir tutar, bunun bir ödeme olduğunu düşündürür; yuvarlak olmayan çıktı ise muhtemelen para üstüdür.
- **Cüzdan Parmak İzi:** Farklı cüzdanların kendilerine özgü işlem oluşturma kalıpları vardır. Bu kalıplar analistlerin kullanılan yazılımı ve potansiyel olarak para üstü adresini belirlemesine olanak tanır.
- **Tutar ve Zaman Korelasyonları:** İşlem zamanlarının veya tutarlarının açıklanması, işlemlerin izlenebilir hâle gelmesine neden olabilir.

## **Trafik Analizi**

Saldırganlar ağ trafiğini izleyerek işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bir kuruluş çok sayıda Bitcoin node'u işletiyorsa işlem trafiğini izleme kapasitesi artacağından bu risk özellikle yüksektir.

## Daha Fazla Bilgi

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Wiki'deki Bitcoin Gizliliği](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Anonim Olarak Bitcoin Edinme Yolları

- **Nakit İşlemler**: Bitcoin'i nakit kullanarak edinme.
- **Nakit Alternatifleri**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin ile takas etme.
- **Mining**: Bitcoin kazanmanın en gizli yöntemi mining yapmaktır. Bu, özellikle tek başına yapıldığında geçerlidir; çünkü mining pool'ları madencinin IP adresini biliyor olabilir. [Mining Pool'ları Hakkında Bilgi](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak bitcoin çalmak, anonim olarak edinmenin başka bir yöntemi olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Hizmetleri

Bir mixing hizmeti kullanarak kullanıcı **bitcoin gönderip** karşılığında **farklı bitcoin'ler alabilir**. Bu, ilk sahibinin izini sürmeyi zorlaştırır. Ancak bunun için hizmete, kayıt tutmayacağı ve bitcoin'leri gerçekten geri göndereceği konusunda güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin kumarhaneleri bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek input'ları output'larla eşleştirmeye çalışanların işini zorlaştırır. Etkili olmasına rağmen, input ve output boyutları benzersiz olan işlemlerin izi yine de sürülebilir.

CoinJoin kullanmış olabilecek örnek işlemler arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunur.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Yatırma işlemlerini daha sonraki çekimlerden ayıran bir Ethereum smart contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir çeşidi olan **PayJoin** (veya P2EP), iki taraf (ör. bir müşteri ve bir satıcı) arasındaki işlemi, CoinJoin'in ayırt edici eşit output'ları olmadan sıradan bir işlem gibi gösterir. Bu, işlemin tespit edilmesini son derece zorlaştırır ve işlem gözetimi yapan kuruluşların kullandığı ortak input sahipliği sezgisel yöntemini geçersiz kılabilir.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Yukarıdaki gibi işlemler, standart bitcoin işlemlerinden ayırt edilemezken gizliliği artıran PayJoin işlemleri olabilir.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlem gizliliği arayışında umut verici bir gelişme olabilir.

# Kripto Para Gizliliği İçin En İyi Uygulamalar

## **Cüzdan Eşitleme Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blockchain ile eşitlemek çok önemlidir. Öne çıkan iki yöntem vardır:

- **Full node**: Tüm blockchain'i indirerek maksimum gizlilik sağlar. Bugüne kadar yapılmış tüm işlemler yerel olarak saklanır; böylece kötü niyetli kişilerin kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesi imkânsız hâle gelir.
- **İstemci tarafında blok filtreleme**: Bu yöntemde, blockchain'deki her blok için filtreler oluşturulur. Böylece cüzdanlar, belirli ilgi alanlarını ağ gözlemcilerine ifşa etmeden ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları alır.

## **Anonimlik İçin Tor Kullanımı**

Bitcoin eşler arası bir ağ üzerinde çalıştığından, IP adresinizi gizlemek ve ağla etkileşim kurarken gizliliği artırmak için Tor kullanmanız önerilir.

## **Adreslerin Yeniden Kullanılmasını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak çok önemlidir. Adresleri yeniden kullanmak, işlemleri aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern cüzdanlar, tasarımları gereği adreslerin yeniden kullanılmasını önler.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birden fazla işleme bölmek, işlem tutarını belirsizleştirerek gizlilik saldırılarını engelleyebilir.
- **Para üstünü önleme**: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, para üstü tespit yöntemlerini sekteye uğratarak gizliliği artırır.
- **Birden fazla para üstü çıktısı**: Para üstünden kaçınmak mümkün değilse, birden fazla para üstü çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimliğin Öncüsü**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlamak**

Gas, Ethereum'da işlemleri gerçekleştirmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) tutarındaki bir işlemde gas limiti ve taban ücretin yanı sıra, doğrulayıcıların işlemi dahil etmesini teşvik eden bir öncelik ücreti bulunur. Kullanıcılar fazla ödeme yapmamak için maksimum ücret belirleyebilir; artan tutar iade edilir.<sup>[[5]](#references)</sup>

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemlerde, kullanıcı adresleri veya smart contract adresleri olabilen bir gönderici ve alıcı bulunur. İşlemler ücret gerektirir ve bir bloğa dahil edilmelidir. Bir işlemdeki temel bilgiler; alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretleri içerir. Özellikle, göndericinin adresi imzadan çıkarılır; bu nedenle işlem verilerinde yer alması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik vererek kripto paralarla işlem yapmak isteyen herkes için temel niteliktedir.

## Değere Odaklı Web3 Red Teaming

- Fonları kimin ve nasıl hareket ettirebileceğini anlamak için değer taşıyan bileşenlerin (imza sahipleri, oracle'lar, bridge'ler, otomasyon) envanterini çıkarın.
- Ayrıcalık yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT taktikleriyle eşleştirin.
- Etkiyi doğrulamak ve istismar edilebilir ön koşulları belgelemek için flash loan/oracle/kimlik bilgisi/çapraz zincir saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışının Ele Geçirilmesi

- Wallet UI'larının tedarik zincirinde yapılan kurcalamalar, imzalama işleminden hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall tabanlı proxy ele geçirmeleri (ör. Safe masterCopy'nin slot-0 üzerine yazılması) için geçerli imzaları ele geçirebilir.

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Yaygın smart-account hata biçimleri arasında `EntryPoint` erişim denetiminin atlatılması, imzasız gas alanları, durum bilgili doğrulama, ERC-1271 replay ve doğrulama sonrasında revert edilerek ücretlerin tüketilmesi bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Güvenliği

- Test paketlerindeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Bütünlüğü

Bir prover, bir iddiayı doğrulamak için **zkVM** veya uygulamaya özel bir proof circuit kullandığında, verifier yalnızca **guest program'ın yazıldığı şekilde çalıştığını** öğrenir. Guest'te **güvensiz deserialization**, **tanımsız davranış** veya **eksik anlamsal kısıtlamalar** varsa, kötü niyetli bir prover, **herkese açık metrikler veya iddia edilen değişmez doğru olmadığı hâlde** doğrulamadan geçen bir proof oluşturabilir.<sup>[[7]](#references)</sup>

### Proof guest'leri içinde güvensiz deserialization

- Private witness/circuit byte'larını, proof tarafından gizleniyor olsalar bile **güvenilmeyen saldırgan girdisi** olarak değerlendirin.
- Byte'lar daha önce bağımsız bir yöntemle doğrulanmadıysa `rkyv::access_unchecked` gibi denetimsiz yardımcılarla deserialize etmekten kaçının.
- Güvenilmeyen serileştirilmiş verilerden yüklenen enum discriminant'ları, göreli pointer'lar, uzunluklar ve index'ler; kontrol akışını veya bellek erişimini etkilemeden önce doğrulanmalıdır.

Pratik denetim kalıbı:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` gibi bir alan enum ise ve saldırgan **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerindeki sonraki her `match` şüpheli hale gelir.

### Jump-table / UB denetimini atlatma

Rust büyük bir `match` ifadesini **jump table** olarak derliyorsa, geçersiz bir enum discriminant’ı **tanımsız kontrol akışına** yol açabilir. Tehlikeli bir örüntü:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtlamaları** günceller.
2. İkinci bir `match`, **gerçek komut semantiğini** uygular.
3. Aralık dışı bir discriminant ilk jump table’ın sınırlarını aşarak ikinci tabloyla ilişkili bir kod konumuna atlar.

Sonuç: işlem yine gerçekleştirilir, ancak muhasebe yolu atlanır. Bir zkVM’de bu durum, daha az gate, daha az maliyetli işlem veya sınırlandırılmış diğer kaynakların yanlış bildirilmesi gibi imkânsız metrikler raporlayan sahte kanıtlar üretmeye yol açabilir.

İnceleme kontrol listesi:

- Witness/özel girdiden deserialize edilen ve saldırgan tarafından kontrol edilen enum’ları arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + denetimsiz deserialization + büyük opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde derlenmiş binary’yi tersine mühendislikle inceleyin; jump table düzeni kaynak koddan daha önemli olabilir.

### Tersinir/özelleştirilmiş yorumlayıcılarda eksik semantik kısıtlamalar

Yalnızca bellek güvenliğini doğrulamayın; kanıtın uygulaması gereken **semantik kuralları** da doğrulayın.

Tersinir/kuantum benzeri komut kümelerinde, farklı olması gereken operand’ların gerçekten farklı olmasının kısıtlandığından emin olun. Toffoli/CCX benzeri bir işlem şu şekilde uygulanmışsa:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

guest reddetmezse güvensiz hale gelir:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Bu durumda geçiş şu hale indirgenir:

```text
q = q ^ (q & q) = 0
```

Bu, **deterministik bir sıfırlama ilkeli** oluşturarak tersinirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha ucuza yapılmasını sağlar. Kaynak kullanımını doğrulayan ispat sistemlerinde bu, saldırganların işlevsel kontrolleri geçerken doğrulayıcının uygulandığına inandığı maliyet modelini atlatmasına olanak tanıyabilir.

### Yetersiz kısıtlanmış prover tavsiyeleri ve modüler aritmetik

Bir **advice/witness stack**'ten yüklenen değerler; önceden hesaplanmış bölüm, kalan, ters veya ipucu olarak tanımlansalar bile prover tarafından kontrol edilir. Bir ispat yalnızca witness'ın uygulanmış kısıtları karşıladığını gösterir; bu kısıtlar tür, aralık veya kanonik biçim kontrolü içermiyorsa amaçlanan hesaplamanın yapıldığını göstermez.<sup>[[13]](#references)</sup>

Bir indirgeme veya Öklid bölmesi yardımcı işlevini denetlerken yalnızca son çıkarma ya da çarpma işlemine değil, tam sayı bağıntısının tamamına bakın. `q` ve `r` değerlerinin her limb'i, tanımlanan bit genişliğiyle kısıtlanmalı; yeniden oluşturma işlemi `x = q * m + r`, amaçlanan tam sayı gösteriminde geçerli olmalı ve kanonik sınır olan `0 <= r < m` uygulanmalıdır. Bir değeri daha dar bir `u32`/`u64` talimatına geçirmeden **önce** doğrulayın; dar kapsamlı bir işlem, özgün field element'in veya çok limb'li değerin beklenen türe sahip olduğunu geriye dönük olarak kanıtlamaz.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

The `mod_12289` hatası Miden'de exploit modelini ortaya koyuyor: bölüm iki parçalı 64-bit değer olarak doğrulanıyordu, ancak advice tarafından sağlanan kalan değer eşdeğer bir doğrulamadan geçmeden `u32overflowing_sub` işlemine ulaşıyordu. Kötü niyetli bir prover, uygulanan çıkarma kısıtları sağlanmaya devam ederken prosedürün matematiksel olmayan bir kalan döndürmesini sağlayacak şekilde geçersiz bölüm ve kalan değerlerini koordine edebilirdi. Bu sonuç Falcon doğrulamasında kullanıldığından, soundness hatası yalnızca yanlış bir aritmetik sonuç üretmekle kalmayıp sahte yetkilendirme imzalarına dönüştürülebilirdi.<sup>[[13]](#references)</sup>

### Implicit-stack kriptografik VM'leri denetleme

Stack dilleri operandları gizler; bu nedenle önce talimatları, tüketilen ve üretilen her stack değerinin provenance bilgisini taşıyan birer ifade olduğu IR biçimine dönüştürün. Ardından ihtiyatlı bir analiz hattı şunları yapabilir:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Çağrı grafiğini oluşturun ve prosedürlerin stack giriş/çıkış etkilerini çıkarın.
2. Desteklenen talimatları sembolik olarak yürütün ve kontrol akışını SSA/yapılandırılmış ifadelere dönüştürün.
3. `Unknown`, `ProvenU32`, `Bool`, değer provenance bilgisi ve yerel başlatma gibi soyut olguları sabit noktaya ulaşana kadar aktarın.
4. Advice kaynaklı değerlerin, **her** gelen yolda bir sanitizer olmadan türlenmiş aritmetiğe veya sıfır olmayan sink'lere ulaştığını işaretleyin.
5. Bildirilen ve çıkarılan imzaları karşılaştırın; her çıkışın çağırana ait stack değerlerini koruduğunu doğrulayın.

Bilinmeyen bir imzayı veya desteklenmeyen yapıyı temiz sonuç olarak değil, bir **analiz boşluğu** olarak değerlendirin. Dinamik çağrılar, stack açısından nötr olmayan döngüler ve farklı stack etkilerine sahip dallar, stack slotlarının güvenilir biçimde izlenmesini imkânsız kılabilir. Daha güvenli bir decompiler, makul görünen ancak yanlış pseudocode üretmek yerine bu durumları reddeder veya işaretler.<sup>[[10]](#references)[[13]](#references)</sup>

Kontrol akışı birleşim noktalarında bir özelliği yalnızca tüm öncüllerde geçerliyse koruyun (örneğin, `ProvenU32 join Unknown = Unknown`). Ayrıca sabit nokta yakınsamasını yineleme sınırına ulaşmaktan ayırın: yalnızca yakınsamış, sound bir üst yaklaşım, tanı bulunmamasını temsil edilen tüm yürütmelerin özelliği sağladığına dair kanıt olarak değerlendirmeyi haklı çıkarabilir.<sup>[[11]](#references)</sup>

### Gizli önkoşulları ortaya çıkarmak için kanıt yükümlülüklerini kullanın

Küçük talimat kümeleri için prosedürleri yürütülebilir bir formal VM modeline dönüştürün ve hem sonucu hem de stack'in eksiksiz dönüşümünü kanıtlayın. Teorem; sonlanmayı, türlenmiş girdileri, beklenen çıktı önekini ve dokunulmayan çağıran stack'inin korunmasını kapsamalıdır. Teorem ifadesini de kanıt kadar dikkatle denetleyin: kernel, yanlışlıkla zayıflatılmış bir iddianın kanıtını doğrulayabilir.<sup>[[12]](#references)[[13]](#references)</sup>

Beklenmedik hipotezler değerli bulgulardır. Miden incelemesinde, 64-bit sağa döndürme işlemi için `shift mod 32 != 0` koşulunu gerektiren bir kanıt, shift miktarının 32'nin katı olduğu büyük girdilerde başarısız olan bir sınır durumunu ortaya çıkardı; başka bir kanıt ise 256-bit `wrapping_mul` işleminin çağırana ait stack değerlerini attığını buldu. Bulunan sınır durumunu testlere ekleyin, ardından bu ek varsayımı sessizce kabul etmek yerine uygulamayı düzeltin veya genel önkoşulu bilinçli olarak güçlendirin.<sup>[[12]](#references)[[13]](#references)</sup>

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser'larını bozuk witness/private-input kodlamalarıyla fuzz edin.
- Opcode dispatch işleminden önce enum aralık doğrulamasının yapıldığını doğrulayın.
- Operand aliasing ve diğer geçersiz talimat biçimleri için semantik kontroller ekleyin.
- Her advice/witness kaynağını tüm türlenmiş aritmetik sink'lerine kadar izleyin ve her yolda doğrulama yapılmasını zorunlu kılın.<sup>[[11]](#references)[[13]](#references)</sup>
- Aritmetik yardımcılarını canonical olmayan limb'ler, aralık dışı kalanlar ve sınır shift miktarlarıyla test edin.<sup>[[12]](#references)[[13]](#references)</sup>
- Her dönüşte stack yüksekliğini ve prosedürün bildirilen argümanlarının altındaki değerlerin korunduğunu doğrulayın.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Bildirilen/genel sayaçları bağımsız bir referans uygulamasıyla karşılaştırın.
- Guest programı hatalıysa, geçerli bir kanıtın yine de **yanlış bir önermeyi** kanıtlayabileceğini unutmayın.

## Duruma Bağlı Yetkilendirme

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX'lerin ve AMM'lerin pratik exploitation yöntemlerini (Uniswap v4 hooks, rounding/precision abuse, flash-loan ile büyütülmüş eşik aşan swap'ler) araştırıyorsanız şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri önbelleğe alan ve `supply == 0` olduğunda zehirlenebilen çok varlıklı weighted pool'lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Açık Anahtar ve Özel Anahtar Açıklaması - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Çoklu imzalı işlemler nedir? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [İşlemler | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas ve ücretler | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Gizlilik - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google'ın kuantum kriptanalizine yönelik sıfır bilgi kanıtını yendik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Eliptik Eğri Kripto Para Birimlerini Kuantum Açıklarına Karşı Güvenceye Alma: Kaynak Tahminleri ve Azaltma Yöntemleri (yamalanmış sürüm)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept deposu](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler mimarisi](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM statik analiz motoru](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-Lean modeli ve doğruluk kanıtları](https://github.com/trailofbits/masm-lean)
- [13] [Yeterince iyi AI çağında denetim](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
