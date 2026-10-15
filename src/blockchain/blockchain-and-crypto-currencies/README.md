# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm blockchain kavramlarını ve zincir üstü güvenliği ele alır. İnternete açık bir Bitcoin peer için [Bitcoin P2P service enumeration](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md) ile başlayın; bir tarayıcı frontend’i, wallet bağlantısı veya zincir dışı backend için [DApp pentesting](../../pentesting-web/dapps-DecentralizedApplications.md) kullanın. Kripto para gizliliği işlemleri ve sınırları için [cryptocurrency privacy chapter](../../privacy/cryptocurrency-privacy.md) bölümüne bakın.

## Temel Kavramlar

- **Akıllı Sözleşmeler**, belirli koşullar karşılandığında blockchain üzerinde çalışan ve aracı olmadan sözleşmelerin yürütülmesini otomatikleştiren programlar olarak tanımlanır.
- **Merkeziyetsiz Uygulamalar (dApps)**, akıllı sözleşmeler üzerine kurulur; kullanıcı dostu bir frontend’e ve şeffaf, denetlenebilir bir backend’e sahiptir.
- **Token’lar ve Coin’ler** farklı amaçlara sahiptir: coin’ler dijital para olarak kullanılırken token’lar belirli bağlamlarda değeri veya mülkiyeti temsil eder.
  - **Utility Token’lar** hizmetlere erişim sağlar; **Security Token’lar** ise varlık sahipliğini ifade eder.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Merkeziyetsiz Finans anlamına gelir.
- **DEX** ve **DAO**, sırasıyla Merkeziyetsiz Borsa Platformları ve Merkeziyetsiz Otonom Organizasyonları ifade eder.

Kripto piyasalarında kullanılan spot emirler, vadeli işlemler, kaldıraç ve opsiyon terminolojisi için [Investment Terms](investment-terms.md) sayfasına bakın.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blockchain üzerindeki işlemlerin güvenli ve üzerinde uzlaşılmış biçimde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlemleri doğrulamak için hesaplama gücünden yararlanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token tutmasını gerektirir ve PoW’a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin’in Temel Özellikleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon aktarımını içerir. İşlemler dijital imzalarla doğrulanır; böylece yalnızca private key sahibi transfer başlatabilir.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature işlemler**, bir işlemi onaylamak için birden fazla imza gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **input’lardan** (fon kaynağı), **output’lardan** (hedef), **ücretlerden** (madencilere ödenir) ve **script’lerden** (işlem kuralları) oluşur.

### Lightning Network

Bir kanalda birden fazla işleme izin vererek ve yalnızca son durumu blockchain’e yayınlayarak Bitcoin’in ölçeklenebilirliğini artırmayı amaçlar.

## Bitcoin Gizliliğine Yönelik Endişeler

**Common Input Ownership** ve **UTXO Change Address Detection** gibi gizlilik saldırıları, işlem örüntülerinden yararlanır. **Mixer** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını belirsizleştirerek anonimliği artırır.

## Bitcoin’leri Anonim Olarak Edinme

Yöntemler arasında nakit işlemleri, mining ve mixer kullanımı bulunur. **CoinJoin**, iz sürmeyi zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha fazla gizlilik sağlamak amacıyla CoinJoin’leri sıradan işlemler gibi gösterir.

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusudur. Aşağıda, saldırganların Bitcoin gizliliğini ihlal edebildiği yaygın yöntemlerden bazılarına dair basitleştirilmiş bir genel bakış yer alıyor.<sup>[[6]](#references)</sup>

## **Ortak Input Sahipliği Varsayımı**

Karmaşıklığı nedeniyle farklı kullanıcılara ait input’ların tek bir işlemde birleştirilmesi genellikle nadir görülür. Bu nedenle, **aynı işlemdeki iki input adresinin aynı sahibine ait olduğu sıklıkla varsayılır**.

## **UTXO Change Adresi Tespiti**

Bir UTXO, yani **Harcanmamış İşlem Çıktısı**, bir işlemde tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir change adresine gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir; bu da gizliliği tehlikeye atar.

### Örnek

Bunu önlemek için mixing servisleri veya birden fazla adres kullanmak, sahiplik bilgisini belirsizleştirmeye yardımcı olabilir.

## **Sosyal Ağlarda ve Forumlarda İfşa**

Kullanıcılar bazen Bitcoin adreslerini internette paylaşır; bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler grafikler olarak görselleştirilebilir ve fon akışına dayanarak kullanıcılar arasındaki olası bağlantıları ortaya çıkarabilir.

## **Gereksiz Input Sezgiseli (Optimal Change Sezgiseli)**

Bu sezgisel yöntem, göndericiye geri dönen change’in hangi output olduğunu tahmin etmek için birden fazla input ve output içeren işlemleri analiz etmeye dayanır.

### Örnek

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Daha fazla girdi eklemek, para üstü çıktısını herhangi bir tekil girdiden daha büyük hâle getirirse sezgisel yöntemi yanıltabilir.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının gelecekteki işlemlerde bu küçük miktarları başka girdilerle birleştirmesini ve böylece adresleri birbirine bağlamasını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu gizlilik sızıntısını önlemek için daha önce kullanılmış ve bakiyesi sıfırlanmış adreslere alınan coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analizi Teknikleri**

- **Tam Ödeme Tutarları:** Para üstü içermeyen işlemler, aynı kullanıcıya ait iki adres arasında gerçekleşmiş olabilir.
- **Yuvarlak Tutarlar:** İşlemdeki yuvarlak bir tutar, bunun bir ödeme olduğunu; yuvarlak olmayan çıktının ise muhtemelen para üstü olduğunu düşündürür.
- **Cüzdan Parmak İzi:** Farklı cüzdanların kendilerine özgü işlem oluşturma kalıpları vardır. Bu kalıplar, analistlerin kullanılan yazılımı ve muhtemelen para üstü adresini belirlemesini sağlar.
- **Tutar ve Zamanlama Korelasyonları:** İşlem zamanlarının veya tutarlarının açıklanması, işlemlerin izlenebilir hâle gelmesine yol açabilir.

## **Trafik Analizi**

Saldırganlar, ağ trafiğini izleyerek işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bu durum, özellikle bir kuruluşun çok sayıda Bitcoin düğümü işletmesi hâlinde geçerlidir; bu, işlemleri izleme kapasitesini artırır.

## Daha Fazla Bilgi

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Wiki'deki Bitcoin Gizliliği sayfasını](https://en.bitcoin.it/wiki/Privacy) ziyaret edin.

# Anonim Bitcoin İşlemleri

## Anonim Olarak Bitcoin Edinme Yöntemleri

- **Nakit İşlemler**: Nakit kullanarak bitcoin edinme.
- **Nakit Alternatifleri**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin ile takas etme.
- **Mining**: Bitcoin kazanmanın en gizli yöntemi mining yapmaktır; özellikle tek başına yapıldığında, çünkü mining havuzları miner'ın IP adresini öğrenebilir. [Mining Havuzları Hakkında Bilgi](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak bitcoin çalmak, anonim olarak bitcoin edinmenin başka bir yolu olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Hizmetleri

Bir mixing hizmeti kullanıldığında, kullanıcı **bitcoin gönderip** karşılığında **farklı bitcoin'ler alabilir**; bu da asıl sahibin izini sürmeyi zorlaştırır. Ancak bunun için, hizmetin kayıt tutmayacağına ve bitcoin'leri gerçekten iade edeceğine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casinoları da bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek girdileri çıktılarla eşleştirmeye çalışanların işini zorlaştırır. Etkili olmasına rağmen, girdi ve çıktı boyutları benzersiz olan işlemler yine de izlenebilir.

CoinJoin kullanmış olabilecek örnek işlemler: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Para yatırma işlemlerini daha sonraki para çekme işlemlerinden ayıran bir Ethereum smart contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir çeşidi olan **PayJoin** (veya P2EP), iki taraf arasındaki işlemi (ör. müşteri ile satıcı arasındaki işlemi), CoinJoin'in ayırt edici eşit çıktılarından yoksun, sıradan bir işlem gibi gösterir. Bu, tespit edilmesini son derece zorlaştırır ve işlem gözetimi yapan kuruluşların kullandığı yaygın girdi sahipliği sezgisel yöntemini geçersiz kılabilir.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Yukarıdaki gibi işlemler PayJoin olabilir; gizliliği artırırken standart bitcoin işlemlerinden ayırt edilemez kalırlar.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlemsel gizlilik arayışında umut verici bir gelişme olabilir.

# Kripto Para Gizliliği İçin En İyi Uygulamalar

## **Cüzdan Senkronizasyon Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blockchain ile senkronize etmek kritik önem taşır. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek maksimum gizlilik sağlar. Şimdiye kadar yapılmış tüm işlemler yerel olarak saklanır; böylece saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesi imkânsız hâle gelir.
- **İstemci tarafında blok filtreleme**: Bu yöntem, blockchain'deki her blok için filtreler oluşturmayı içerir. Böylece cüzdanlar, ağ gözlemcilerine belirli ilgi alanlarını açığa çıkarmadan ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları alır.

## **Anonimlik İçin Tor Kullanımı**

Bitcoin eşler arası bir ağda çalıştığından, IP adresinizi gizlemek ve ağla etkileşim kurarken gizliliği artırmak için Tor kullanmanız önerilir.

## **Adreslerin Yeniden Kullanılmasını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak çok önemlidir. Adresleri yeniden kullanmak, işlemleri aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern cüzdanlar, tasarımları gereği adreslerin yeniden kullanılmasını caydırır.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını belirsizleştirerek gizlilik saldırılarını engelleyebilir.
- **Para üstünden kaçınma**: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, para üstü tespit yöntemlerini bozarak gizliliği artırır.
- **Birden fazla para üstü çıktısı**: Para üstünden kaçınmak mümkün değilse, birden fazla para üstü çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimliğin Öncüsü**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlama**

Gas, Ethereum'da işlemleri yürütmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) maliyetli bir işlemde gas limiti ve temel ücret bulunur; doğrulayıcıları işlemi dahil etmeye teşvik etmek için öncelik ücreti de eklenir. Kullanıcılar fazla ödeme yapmamak için maksimum ücret belirleyebilir; aşan tutar iade edilir.<sup>[[5]](#references)</sup>

## **İşlemleri Gerçekleştirme**

Ethereum işlemlerinde, kullanıcı adresleri veya akıllı sözleşme adresleri olabilen bir gönderici ve alıcı bulunur. İşlemler ücret gerektirir ve bir bloğa dahil edilmelidir. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Göndericinin adresi imzadan çıkarıldığından işlem verilerinde yer alması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik vererek kripto paralarla etkileşim kurmak isteyen herkes için temel niteliktedir.

## Değer Odaklı Web3 Red Teaming

- Fonları kimin, nasıl taşıyabildiğini anlamak için değer taşıyan bileşenlerin (imzalayıcılar, oracle'lar, bridge'ler, otomasyon) envanterini çıkarın.
- Ayrıcalık yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT taktikleriyle eşleştirin.
- Etkiyi doğrulamak ve istismar edilebilir ön koşulları belgelemek için flash-loan/oracle/kimlik bilgisi/çapraz zincir saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışının Ele Geçirilmesi

- Cüzdan arayüzlerine yönelik tedarik zinciri müdahaleleri, imzalamadan hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall tabanlı proxy ele geçirmeleri için geçerli imzaları ele geçirebilir (ör. Safe masterCopy'nin slot-0 üzerine yazılması).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Hesap Soyutlama (ERC-4337)

- Yaygın akıllı hesap arıza türleri arasında `EntryPoint` erişim denetiminin atlatılması, imzasız gas alanları, durum bilgili doğrulama, ERC-1271 replay ve doğrulama sonrasında revert yoluyla ücretlerin tüketilmesi yer alır.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Akıllı Sözleşme Güvenliği

- Test paketlerindeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Kanıtı / zkVM Guest Bütünlüğü

Bir prover bir iddiayı doğrulamak için **zkVM** veya uygulamaya özgü bir kanıt devresi kullandığında, verifier yalnızca **guest programının yazıldığı şekilde yürütüldüğünü** öğrenir. Guest içinde **güvensiz serileştirme**, **tanımsız davranış** veya **eksik anlamsal kısıtlamalar** varsa kötü niyetli bir prover, **herkese açık metrikler veya iddia edilen değişmez yanlış olduğu hâlde** doğrulamadan geçen bir kanıt üretebilir.<sup>[[7]](#references)</sup>

### Kanıt guest'leri içinde güvensiz serileştirme

- Özel witness/devre baytlarını, kanıt tarafından gizlenmiş olsalar bile **güvenilmeyen saldırgan girdisi** olarak değerlendirin.
- Baytlar daha önce başka bir yolla doğrulanmadıysa `rkyv::access_unchecked` gibi denetlenmeyen yardımcılarla serileştirme verilerini çözümlemekten kaçının.
- Güvenilmeyen serileştirilmiş verilerden yüklenen enum ayraçları, göreli işaretçiler, uzunluklar ve indeksler; kontrol akışını veya bellek erişimini etkilemeden önce doğrulanmalıdır.

Pratik denetim örüntüsü:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` gibi bir alan enum ise ve saldırgan **aralık dışı bir discriminant** ekleyebiliyorsa, bu değer üzerindeki sonraki tüm `match` ifadeleri şüpheli hale gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini **jump table**'a dönüştürürse, geçersiz bir enum discriminant'ı **tanımsız kontrol akışına** yol açabilir. Tehlikeli bir örüntü:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtlamaları** günceller.
2. İkinci bir `match`, **gerçek talimat semantiğini** uygular.
3. Aralık dışı bir discriminant, ilk jump table'ın sonrasını indeksleyerek ikinci jump table ile ilişkili koda ulaşır.

Sonuç: İşlem yine de yürütülür, ancak muhasebe yolu atlanır. Bir zkVM'de bu, daha az gate, daha az maliyetli işlem veya diğer sınırlandırılmış kaynaklar gibi imkânsız ölçümler bildiren sahte kanıtlar oluşturabilir.

İnceleme kontrol listesi:

- Witness/private input üzerinden deserialize edilen, saldırganın kontrolündeki enum'ları arayın.
- Aynı opcode/kind alanı üzerinde yinelenen `match` ifadelerini inceleyin.
- `unsafe` + doğrulamasız deserialization + geniş opcode dispatch kombinasyonunu yüksek riskli kabul edin.
- Gerektiğinde oluşturulan binary'yi reverse engineer edin; jump table'ın düzeni, kaynak koddan daha önemli olabilir.

### Tersinir/özelleştirilmiş interpreter'larda eksik semantik kısıtlamalar

Yalnızca bellek güvenliğini doğrulamayın; kanıtın uygulanmasını amaçladığı **semantik kuralları** da doğrulayın.

Tersinir/kuantum benzeri talimat kümelerinde, birbirinden farklı olması gereken operand'ların gerçekten farklı olmalarının kısıtlandığından emin olun. Şu şekilde uygulanmış Toffoli/CCX benzeri bir işlem:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

Konuk reddetmezse güvensiz hale gelir:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Bu durumda geçiş şu hale indirgenir:

```text
q = q ^ (q & q) = 0
```

Bu, **deterministik bir sıfırlama primitive'i** oluşturarak tersinirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha düşük maliyetle yapılmasını sağlar. Kaynak kullanımını doğrulayan kanıt sistemlerinde bu, saldırganların işlevsel kontrolleri geçerken doğrulayıcının uygulandığını sandığı maliyet modelini atlatmasına olanak tanıyabilir.

### Eksik kısıtlanmış prover advice ve modüler aritmetik

Bir **advice/witness stack**'ten yüklenen değerler, önceden hesaplanmış bölüm, kalan, ters veya ipucu olarak tanımlansalar bile prover tarafından kontrol edilir. Bir kanıt yalnızca witness'ın uygulanmış kısıtları karşıladığını gösterir; bu kısıtlar tür, aralık veya kanonik biçim kontrolünü içermiyorsa amaçlanan hesaplamanın yapıldığını göstermez.<sup>[[13]](#references)</sup>

Bir indirgeme veya Öklid bölmesi yardımcısını denetlerken yalnızca son çıkarma veya çarpma işlemine değil, tam sayı bağıntısının tamamına bakın. `q` ve `r` değerlerinin her limb'i belirtilen genişlikle kısıtlanmalı, `x = q * m + r` yeniden oluşturma bağıntısı amaçlanan tam sayı gösteriminde sağlanmalı ve kanonik sınır olan `0 <= r < m` uygulanmalıdır. Bir değeri daha dar bir `u32`/`u64` talimatına aktarmadan **önce** doğrulayın; dar kapsamlı bir işlem, özgün alan elemanının veya çok limb'li değerin beklenen türe sahip olduğunu geriye dönük olarak kanıtlamaz.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Miden'deki `mod_12289` hatası exploit modelini gösteriyor: bölüm iki parçalı 64 bitlik bir değer olarak denetleniyordu, ancak advice tarafından sağlanan kalan değer eşdeğer bir doğrulamadan geçmeden `u32overflowing_sub`'a ulaşıyordu. Kötü niyetli bir prover, uygulanan çıkarma kısıtlamaları geçerli kalırken yordamın matematiksel olmayan bir kalan döndürmesini sağlayacak geçersiz bölüm/kalan değerlerini koordine edebilirdi. Bu sonuç Falcon doğrulamasına girdiğinden, soundness hatası yalnızca yanlış bir aritmetik sonuç üretmekle kalmayıp sahte yetkilendirme imzalarına kadar genişletilebilirdi.<sup>[[13]](#references)</sup>

### Örtük stack kullanan kriptografik VM'leri denetleme

Stack dilleri operandları gizler; bu nedenle önce talimatları, tüketilen ve üretilen her stack değerinin köken bilgisi bulunan bir ifade olduğu bir IR'ye dönüştürün. Ardından tutucu bir analiz hattı şu adımları uygulayabilir:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Çağrı grafiğini oluşturun ve yordamların stack girdi/çıktı etkilerini çıkarın.
2. Desteklenen talimatları sembolik olarak yürütün ve kontrol akışını SSA/yapılandırılmış ifadelere dönüştürün.
3. `Unknown`, `ProvenU32`, `Bool`, değer kökeni ve yerel değişken başlatma durumu gibi soyut bilgileri sabit noktaya ulaşana kadar aktarın.
4. Advice kaynaklı değerlerin, **her** giriş yolunda bir temizleyici olmadan türlenmiş aritmetiğe veya sıfır olmayan bir hedefe ulaştığı durumları işaretleyin.
5. Bildirilen ve çıkarılan imzaları karşılaştırın; her çıkışın çağırana ait stack değerlerini koruduğunu doğrulayın.

Bilinmeyen imzayı veya desteklenmeyen yapıyı temiz sonuç değil, bir **analiz boşluğu** olarak değerlendirin. Dinamik çağrılar, stack dengesini korumayan döngüler ve farklı stack etkilerine sahip dallar, stack konumlarının güvenilir biçimde izlenmesini imkânsız kılabilir. Daha güvenli bir decompiler, makul görünen ama hatalı sözde kod üretmek yerine bu durumları reddeder veya işaretler.<sup>[[10]](#references)[[13]](#references)</sup>

Kontrol akışı birleşimlerinde bir özelliği yalnızca tüm öncüllerde geçerliyse koruyun (örneğin, `ProvenU32 join Unknown = Unknown`). Ayrıca sabit noktaya yakınsamayı yineleme sınırına ulaşmaktan ayırın: yalnızca yakınsamış, sound bir üst yaklaşım; tanı bulunmamasını, temsil edilen tüm yürütmelerin özelliği karşıladığına dair kanıt olarak görmeyi haklı çıkarabilir.<sup>[[11]](#references)</sup>

### Gizli önkoşulları ortaya çıkarmak için ispat yükümlülükleri kullanın

Küçük talimat kümeleri için yordamları çalıştırılabilir bir biçimsel VM modeline dönüştürün ve hem sonucu hem de stack'in eksiksiz dönüşümünü ispatlayın. Teorem; sonlanmayı, türlenmiş girdileri, beklenen çıktı önekini ve değiştirilmemiş çağıran stack'inin korunmasını kapsamalıdır. Teorem ifadesini de ispat kadar dikkatli denetleyin: kernel, yanlışlıkla zayıflatılmış bir iddianın ispatını doğrulayabilir.<sup>[[12]](#references)[[13]](#references)</sup>

Beklenmedik hipotezler faydalı bulgulardır. Miden incelemesinde, 64 bit sağa döndürme için `shift mod 32 != 0` koşulu gerektiğini gösteren bir ispat, kaydırma miktarı 32'nin katı olduğunda büyük girdilerde ortaya çıkan bir sınır durumunu açığa çıkardı; başka bir ispat ise 256 bitlik `wrapping_mul` işleminin çağırana ait stack değerlerini attığını buldu. Bulunan sınır durumunu testlere ekleyin, ardından ek varsayımı sessizce kabul etmek yerine uygulamayı düzeltin veya herkese açık önkoşulu bilinçli olarak güçlendirin.<sup>[[12]](#references)[[13]](#references)</sup>

### ZK sistemlerinde neler test edilmeli

- Tüm guest parser'larını hatalı witness/private-input kodlamalarıyla fuzz edin.
- Opcode dispatch öncesinde enum aralığı doğrulamasını zorunlu kılın.
- Operand aliasing ve diğer geçersiz talimat biçimleri için semantik kontroller ekleyin.
- Her advice/witness kaynağını türlenmiş aritmetik hedeflerine kadar izleyin ve her yolda doğrulama yapılmasını zorunlu kılın.<sup>[[11]](#references)[[13]](#references)</sup>
- Aritmetik yardımcılarını kanonik olmayan limb'lerle, aralık dışı kalanlarla ve sınır kaydırma miktarlarıyla test edin.<sup>[[12]](#references)[[13]](#references)</sup>
- Her dönüşte stack yüksekliğini ve yordamın bildirilmiş argümanlarının altındaki değerlerin korunmasını doğrulayın.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Raporlanan/genel sayaçları bağımsız bir referans uygulamasıyla karşılaştırın.
- Guest programı hatalıysa geçerli bir ispatın yine de **yanlış önermeyi** ispatlayabileceğini unutmayın.

## Duruma Bağlı Yetkilendirme

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX'lerin ve AMM'lerin pratik exploitation'ını (Uniswap v4 hooks, yuvarlama/hassasiyet istismarı, flash-loan ile güçlendirilmiş eşik aşan swap'ler) araştırıyorsanız şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri önbelleğe alan ve `supply == 0` olduğunda zehirlenebilen çok varlıklı ağırlıklı havuzlar için şunu inceleyin:

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
- [7] [Trail of Bits - Google'ın kuantum kriptanalizine yönelik zero-knowledge proof'unu alt ettik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Eliptik Eğri Kripto Para Birimlerini Kuantum Zafiyetlerine Karşı Güvenceye Alma: Kaynak Tahminleri ve Azaltımlar (yamalanmış sürüm)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept deposu](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler mimarisi](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM statik analiz motoru](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM'den Lean'e model ve doğruluk ispatları](https://github.com/trailofbits/masm-lean)
- [13] [Yeterince iyi AI çağında denetim](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
