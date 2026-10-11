# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts**, belirli koşullar karşılandığında blockchain üzerinde çalışan ve anlaşmaların aracı olmadan yürütülmesini otomatikleştiren programlar olarak tanımlanır.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç sunarak smart contract’ları temel alır.
- **Tokens & Coins** arasındaki fark, coin’lerin dijital para olarak işlev görmesi, token’ların ise belirli bağlamlarda değeri veya sahipliği temsil etmesidir.
  - **Utility Tokens** hizmetlere erişim sağlar; **Security Tokens** ise varlık sahipliğini belirtir.
- **DeFi**, merkezi olmayan finans anlamına gelir ve merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAOs**, sırasıyla merkezi olmayan borsa platformlarını ve merkezi olmayan otonom organizasyonları ifade eder.

## Consensus Mechanisms

Consensus mechanisms, blockchain üzerindeki işlemlerin güvenli biçimde doğrulanmasını ve doğrulamalar üzerinde uzlaşılmasını sağlar:

- **Proof of Work (PoW)**, işlemleri doğrulamak için hesaplama gücünden yararlanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token tutmasını gerektirir ve PoW'a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin'in Temel Unsurları

### İşlemler

Bitcoin işlemleri, adresler arasında fon aktarılmasını içerir. İşlemler dijital imzalarla doğrulanır; böylece yalnızca özel anahtarın sahibi transfer başlatabilir.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature Transactions**, bir işlemi yetkilendirmek için birden fazla imza gerektirir.<sup>[[3]](#references)</sup>
- İşlemler; **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenen ücretler) ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Bir kanal içinde birden fazla işleme izin vererek Bitcoin'in ölçeklenebilirliğini artırmayı hedefler; blockchain'e yalnızca son durumu yayınlar.

## Bitcoin Gizliliğine İlişkin Endişeler

**Common Input Ownership** ve **UTXO Change Address Detection** gibi gizlilik saldırıları, işlem kalıplarından yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Anonim Olarak Bitcoin Edinme

Yöntemler arasında nakit karşılığında alım satım, mining ve mixers kullanımı bulunur. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha fazla gizlilik sağlamak amacıyla CoinJoin işlemlerini sıradan işlemler gibi gösterir.

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusu olur. Aşağıda, saldırganların Bitcoin gizliliğini ihlal edebileceği yaygın yöntemlerden bazılarına ilişkin basitleştirilmiş bir genel bakış yer alıyor.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

İşlemlerin karmaşıklığı nedeniyle farklı kullanıcılara ait input'ların tek bir işlemde birleştirilmesi genellikle nadirdir. Bu nedenle **aynı işlemdeki iki input adresinin aynı sahibine ait olduğu varsayılır**.

## **UTXO Change Address Detection**

UTXO veya **Unspent Transaction Output**, bir işlemde tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir change address'e aktarılır. Gözlemciler, bu yeni adresin gönderene ait olduğunu varsayabilir; bu da gizliliği tehlikeye atar.

### Örnek

Bunu önlemek için mixing hizmetleri kullanmak veya birden fazla adres kullanmak sahipliği gizlemeye yardımcı olabilir.

## **Sosyal Ağlarda ve Forumlarda İfşa**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler grafikler biçiminde görselleştirilebilir ve fon akışına dayanarak kullanıcılar arasındaki olası bağlantıları ortaya çıkarabilir.

## **Gereksiz Input Sezgiseli (Optimal Change Heuristic)**

Bu sezgisel yöntem, gönderene geri dönen change'in hangi output olduğunu tahmin etmek için birden fazla input ve output içeren işlemlerin analizine dayanır.

### Örnek

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Daha fazla girdi eklemek, change çıktısını herhangi bir tek girdiden daha büyük hâle getirirse sezgiseli yanıltabilir.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının bu küçük miktarları gelecekteki işlemlerde başka girdilerle birleştirerek adresleri birbirine bağlamasını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu gizlilik leak'ini önlemek için daha önce kullanılmış ve bakiyesi boş olan adreslere gönderilen coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analizi Teknikleri**

- **Kesin Ödeme Tutarları:** Change içermeyen işlemler, büyük olasılıkla aynı kullanıcıya ait iki adres arasındadır.
- **Yuvarlak Sayılar:** İşlemdeki yuvarlak bir sayı, bunun bir ödeme olduğunu; yuvarlak olmayan çıktının ise büyük olasılıkla change olduğunu düşündürür.
- **Cüzdan Parmak İzi:** Farklı cüzdanların işlem oluşturma biçimleri kendilerine özgüdür. Bu sayede analistler kullanılan yazılımı ve muhtemelen change adresini belirleyebilir.
- **Tutar ve Zaman Korelasyonları:** İşlem zamanlarının veya tutarlarının açıklanması, işlemlerin izlenebilir hâle gelmesine neden olabilir.

## **Trafik Analizi**

Saldırganlar, ağ trafiğini izleyerek işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bir kuruluşun çok sayıda Bitcoin node'u işletmesi, işlemleri izleme kapasitesini artırarak bu riski özellikle yükseltir.

## Daha Fazla Bilgi

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Wiki'deki Bitcoin Gizliliği](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Anonim Olarak Bitcoin Edinme Yöntemleri

- **Nakit İşlemler**: Bitcoin'i nakit kullanarak edinmek.
- **Nakit Alternatifleri**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin ile takas etmek.
- **Mining**: Bitcoin kazanmanın en gizli yöntemi mining'dir. Özellikle tek başına yapıldığında daha gizlidir; çünkü mining havuzları madencinin IP adresini biliyor olabilir. [Mining Havuzları Hakkında Bilgi](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak bitcoin çalmak, anonim olarak edinmenin başka bir yolu olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Hizmetleri

Bir mixing hizmeti kullanarak kullanıcı **bitcoin gönderip** karşılığında **farklı bitcoin'ler alabilir**; bu da orijinal sahibin izini sürmeyi zorlaştırır. Ancak bunun için hizmete, kayıt tutmayacağına ve bitcoin'leri gerçekten geri göndereceğine dair güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin kumarhaneleri de bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek girdileri çıktılarla eşleştirmeye çalışanların işini zorlaştırır. Etkili olmasına rağmen, girdi ve çıktı boyutları benzersiz olan işlemlerin izi yine de sürülebilir.

CoinJoin kullanmış olabilecek örnek işlemler: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Yatırma işlemlerini daha sonraki çekim işlemlerinden ayıran bir Ethereum smart contract mixer'ı için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir türü olan **PayJoin** (veya P2EP), iki taraf arasındaki (ör. müşteri ve satıcı) işlemi, CoinJoin'in ayırt edici eşit çıktılar özelliğini taşımayan sıradan bir işlem gibi gösterir. Bu, tespit edilmesini son derece zorlaştırır ve işlem gözetimi yapan kuruluşların kullandığı ortak girdi sahipliği sezgiselliğini geçersiz kılabilir.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Yukarıdakine benzer işlemler, standart bitcoin işlemlerinden ayırt edilemez kalırken gizliliği artıran PayJoin işlemleri olabilir.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlem gizliliği arayışında umut vadeden bir gelişme sunar.

# Kripto Para Gizliliği için En İyi Uygulamalar

## **Cüzdan Eşitleme Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blockchain ile eşitlemek çok önemlidir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain’i indirerek maksimum gizlilik sağlar. Şimdiye kadar yapılmış tüm işlemler yerel olarak saklanır; bu da saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkânsız hâle getirir.
- **İstemci tarafında blok filtreleme**: Bu yöntem, blockchain’deki her blok için filtreler oluşturmayı içerir. Böylece cüzdanlar, belirli ilgi alanlarını ağ gözlemcilerine ifşa etmeden ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları alır.

## **Anonimlik için Tor Kullanımı**

Bitcoin eşler arası bir ağda çalıştığından, IP adresinizi gizlemek ve ağla etkileşim sırasında gizliliği artırmak için Tor kullanmanız önerilir.

## **Adreslerin Yeniden Kullanılmasını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak çok önemlidir. Adresleri yeniden kullanmak, işlemleri aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern cüzdanlar, tasarımları gereği adreslerin yeniden kullanılmasını engeller.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını belirsizleştirerek gizlilik saldırılarını engelleyebilir.
- **Para üstünden kaçınma**: Para üstü çıktıları gerektirmeyen işlemleri tercih etmek, para üstü tespit yöntemlerini sekteye uğratarak gizliliği artırır.
- **Birden fazla para üstü çıktısı**: Para üstünden kaçınmak mümkün değilse, birden fazla para üstü çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimliğin Öncüsü**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve İşlemler**

## **Gas’ı Anlamak**

Gas, Ethereum’da işlemleri yürütmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) tutarındaki bir işlemde gas limiti ve taban ücret bulunur; doğrulayıcıların işlemi bloğa eklemesini teşvik etmek için ayrıca öncelik ücreti ödenir. Kullanıcılar fazla ödeme yapmamak için azami ücret belirleyebilir; aşan tutar iade edilir.<sup>[[5]](#references)</sup>

## **İşlemleri Yürütme**

Ethereum işlemlerinde, kullanıcı veya akıllı sözleşme adresi olabilen bir gönderici ve alıcı bulunur. İşlemler ücret gerektirir ve bir bloğa eklenmelidir. Bir işlemdeki temel bilgiler; alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Özellikle, göndericinin adresi imzadan çıkarılır; bu nedenle işlem verilerinde yer alması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik vererek kripto paralarla ilgilenmek isteyen herkes için temel niteliktedir.

## Değer Odaklı Web3 Red Teaming

- Fonları kimin, nasıl aktarabileceğini anlamak için değer taşıyan bileşenlerin (imzalayıcılar, oracle’lar, bridge’ler, otomasyon) envanterini çıkarın.
- Ayrıcalık yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT taktikleriyle eşleştirin.
- Etkiyi doğrulamak ve istismar edilebilir ön koşulları belgelemek için flash-loan/oracle/kimlik bilgisi zincirler arası saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışının Ele Geçirilmesi

- Wallet UI’larına yönelik tedarik zinciri müdahaleleri, imzalamadan hemen önce EIP-712 payload’larını değiştirebilir ve delegatecall tabanlı proxy ele geçirmeleri için geçerli imzaları ele geçirebilir (ör. Safe masterCopy’nin slot-0 üzerine yazılması).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Hesap Soyutlama (ERC-4337)

- Yaygın akıllı hesap hata türleri arasında `EntryPoint` erişim denetimini atlatma, imzalanmamış gas alanları, durum bilgisi kullanan doğrulama, ERC-1271 replay saldırıları ve doğrulama sonrasında revert yoluyla ücretlerin tüketilmesi bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Akıllı Sözleşme Güvenliği

- Test paketlerindeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Kanıtı / zkVM Guest Bütünlüğü

Bir prover, bir iddiayı doğrulamak için **zkVM** veya uygulamaya özgü bir kanıt devresi kullandığında, verifier yalnızca **guest programının yazıldığı şekilde yürütüldüğünü** öğrenir. Guest içinde **güvenli olmayan serileştirme**, **tanımsız davranış** veya **eksik anlamsal kısıtlamalar** varsa, kötü niyetli bir prover doğrulamadan geçen bir kanıt üretebilir; ancak **genel metrikler veya iddia edilen değişmez yanlış olabilir**.<sup>[[7]](#references)</sup>

### Kanıt guest’leri içinde güvenli olmayan serileştirme

- Özel witness/devre baytlarını, kanıtla gizlenmiş olsalar bile **güvenilmeyen saldırgan girdisi** olarak değerlendirin.
- Baytlar önceden başka bir yerde doğrulanmadıysa `rkyv::access_unchecked` gibi denetimsiz yardımcılarla bunları serileştirmekten kaçının.
- Güvenilmeyen serileştirilmiş verilerden yüklenen enum ayırt edicileri, göreli işaretçiler, uzunluklar ve indeksler; kontrol akışını veya bellek erişimini etkilemeden önce doğrulanmalıdır.

Uygulanabilir denetim yöntemi:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Bir `op.kind` gibi alan enum ise ve saldırgan **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerinde yapılan sonraki her `match` şüpheli hâle gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini **jump table** hâline getirirse, geçersiz bir enum discriminant’ı **tanımsız kontrol akışına** yol açabilir. Tehlikeli bir örüntü:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtlamaları** günceller.
2. İkinci bir `match`, **gerçek instruction semantiğini** uygular.
3. Aralık dışı bir discriminant ilk jump table’ın dışındaki bir konumu indeksler ve ikinci jump table’la ilişkili bir kodda sonlanır.

Sonuç: işlem yine yürütülür, ancak muhasebe yolu atlanır. Bir zkVM’de bu, daha az gate, daha az maliyetli işlem veya sınırlandırılmış diğer kaynaklar gibi imkânsız metrikler bildiren sahte proof’lar üretebilir.

İnceleme kontrol listesi:

- Witness/private input’tan deserialize edilen, saldırganın kontrolündeki enum’ları arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + kontrolsüz deserialization + büyük opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde üretilen binary’yi reverse engineer edin; jump table düzeni, kaynak koddan daha önemli olabilir.

### Reversible/özel amaçlı interpreter’larda eksik semantik kısıtlamalar

Yalnızca memory safety’yi doğrulamayın; proof’un uygulaması gereken **semantik kuralları** da doğrulayın.

Reversible/quantum benzeri instruction set’lerinde, farklı olması gereken operand’ların gerçekten farklı olmalarının kısıtlandığından emin olun. Şu şekilde uygulanan Toffoli/CCX benzeri bir işlem:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

konuk şunları reddetmezse güvensiz hâle gelir:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Bu durumda geçiş şuna indirgenir:

```text
q = q ^ (q & q) = 0
```

Bu, **deterministik bir sıfırlama primitive’i** oluşturarak tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha ucuza yapılmasını sağlar. Kaynak kullanımını tasdik eden proof sistemlerinde saldırganların işlevsel kontrolleri geçerken doğrulayıcının uygulandığını sandığı maliyet modelini atlatmasına imkân tanıyabilir.

### Yetersiz kısıtlanmış prover tavsiyeleri ve modüler aritmetik

**Advice/witness stack**’ten yüklenen değerler, önceden hesaplanmış bölüm, kalan, ters veya ipucu olarak tanımlansalar bile prover tarafından kontrol edilir. Bir proof yalnızca witness’ın uygulanan kısıtları karşıladığını kanıtlar; bu kısıtlar tür, aralık veya kanonik biçim kontrolünü içermiyorsa amaçlanan hesaplamayı kanıtlamaz.<sup>[[13]](#references)</sup>

Bir indirgeme veya Öklid bölmesi helper’ını denetlerken yalnızca son çıkarma ya da çarpma işlemine değil, tam sayı bağıntısının tamamına bakın. `q` ve `r` değerlerinin her limb’i tanımlı genişliğe göre kısıtlanmalı, `x = q * m + r` yeniden oluşturma bağıntısı amaçlanan tam sayı gösteriminde sağlanmalı ve kanonik `0 <= r < m` sınırı uygulanmalıdır. Bir değeri daha dar bir `u32`/`u64` talimatına geçirmeden **önce** doğrulayın; dar bir işlem, özgün field element’ın veya çok limb’li değerin beklenen türe sahip olduğunu geriye dönük olarak kanıtlamaz.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

The `mod_12289` hatası, Miden'deki exploit kalıbını gösteriyor: quotient iki parçalı 64-bit değer olarak kontrol edildi, ancak advice tarafından sağlanan remainder eşdeğer bir doğrulamadan geçmeden `u32overflowing_sub` işlemine ulaştı. Kötü niyetli bir prover, uygulanan çıkarma kısıtları sağlanırken prosedürün matematiksel olmayan bir remainder döndürmesini sağlayacak geçersiz quotient/remainder değerlerini koordine edebilirdi. Bu sonuç Falcon doğrulamasına girdiğinden, soundness hatası yalnızca yanlış bir aritmetik sonuç üretmekle kalmayıp sahte authorization imzalarına dönüştürülebilirdi.<sup>[[13]](#references)</sup>

### Implicit-stack cryptographic VM'leri denetleme

Stack dilleri operandları gizler; bu nedenle önce talimatları, tüketilen ve üretilen her stack değerinin provenance bilgisine sahip bir ifade olduğu bir IR'ye dönüştürün. Ardından ihtiyatlı bir analiz hattı şunları yapabilir:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Call graph'ı oluşturun ve prosedürlerin input/output stack etkilerini çıkarın.
2. Desteklenen talimatları sembolik olarak çalıştırın ve control flow'u SSA/yapılandırılmış ifadelere dönüştürün.
3. `Unknown`, `ProvenU32`, `Bool`, value provenance ve yerel başlatma gibi soyut olguları sabit noktaya ulaşana kadar ilerletin.
4. Advice kaynaklı değerlerin her gelen yolda bir sanitizer olmadan typed arithmetic'e veya non-zero sink'lere ulaştığını işaretleyin.
5. Tanımlı ve çıkarımsal imzaları karşılaştırın ve her çıkışın caller'a ait stack değerlerini koruduğunu doğrulayın.

Bilinmeyen imzaları veya desteklenmeyen yapıları temiz sonuç değil, bir **analysis gap** olarak değerlendirin. Dynamic call'lar, stack-neutral olmayan döngüler ve farklı stack etkilerine sahip dallar, sound stack-slot takibini olanaksız hâle getirebilir; daha güvenli bir decompiler, makul görünen ancak yanlış pseudocode üretmek yerine bu durumları reddeder veya işaretler.<sup>[[10]](#references)[[13]](#references)</sup>

Control-flow birleşimlerinde, bir özelliği yalnızca tüm predecessor'larda geçerliyse koruyun (örneğin, `ProvenU32 join Unknown = Unknown`). Ayrıca sabit nokta yakınsamasıyla yineleme sınırına ulaşmayı birbirinden ayırın: yalnızca yakınsamış, sound bir üst yaklaşım, tanı yokluğunun temsil edilen tüm çalıştırmaların özelliği karşıladığına kanıt sayılmasını haklı çıkarabilir.<sup>[[11]](#references)</sup>

### Gizli önkoşulları ortaya çıkarmak için proof obligation'ları kullanın

Küçük instruction set'ler için prosedürleri çalıştırılabilir bir formal VM modeline dönüştürün ve hem sonucu hem de stack dönüşümünün tamamını kanıtlayın. Teorem; sonlanmayı, typed input'ları, beklenen output prefix'ini ve dokunulmamış caller stack'inin korunmasını kapsamalıdır. Teorem ifadesini de kanıt kadar dikkatli denetleyin: kernel, yanlışlıkla zayıflatılmış bir iddiaya ilişkin kanıtı doğrulayabilir.<sup>[[12]](#references)[[13]](#references)</sup>

Beklenmeyen varsayımlar önemli bulgulardır. Miden incelemesinde, 64-bit sağa döndürme işleminin kanıtı `shift mod 32 != 0` koşulunu gerektiriyordu; bu da shift'in 32'nin katı olduğu büyük input'lar için başarısız bir uç durumu ortaya çıkardı. Başka bir kanıt, 256-bit `wrapping_mul` işleminin caller'a ait stack değerlerini attığını buldu. Bulunan sınır durumunu testlere ekleyin; ardından uygulamayı düzeltin veya fazladan varsayımı sessizce kabul etmek yerine public precondition'ı bilinçli olarak güçlendirin.<sup>[[12]](#references)[[13]](#references)</sup>

### ZK sistemlerinde test edilecekler

- Tüm guest parser'larını bozuk witness/private-input kodlamalarıyla fuzz edin.
- Opcode dispatch öncesinde enum range validation yapıldığını doğrulayın.
- Operand aliasing ve diğer geçersiz talimat biçimleri için semantic kontroller ekleyin.
- Her advice/witness kaynağını her typed arithmetic sink'e kadar izleyin ve her yolda validation isteyin.<sup>[[11]](#references)[[13]](#references)</sup>
- Aritmetik yardımcılarını canonical olmayan limb'ler, aralık dışı remainder'lar ve sınır shift count'larıyla test edin.<sup>[[12]](#references)[[13]](#references)</sup>
- Her return noktasında stack yüksekliğini ve prosedürün tanımlı argümanlarının altındaki değerlerin korunduğunu doğrulayın.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Bildirilen/public counter'ları bağımsız bir referans uygulamayla karşılaştırın.
- Guest program buggy ise geçerli bir proof'un yine de **yanlış bir ifadeyi** kanıtlayabileceğini unutmayın.

## Duruma Bağlı Yetkilendirme

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX'lerin ve AMM'lerin pratik exploitation'ını araştırıyorsanız (Uniswap v4 hooks, rounding/precision abuse, flash-loan ile büyütülmüş threshold-crossing swap'leri), şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri cache'leyen ve `supply == 0` olduğunda zehirlenebilen çok varlıklı weighted pool'lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key ve Private Key Açıklaması - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Çoklu imzalı işlemler nedir? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [İşlemler | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas ve ücretler | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Gizlilik - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google'ın quantum cryptanalysis için zero-knowledge proof'unu yendik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Elliptic Curve Cryptocurrency'leri Quantum Güvenlik Açıklarına Karşı Güvence Altına Alma: Kaynak Tahminleri ve Azaltımlar (yamalanmış sürüm)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept deposu](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler mimarisi](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM static-analysis motoru](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean modeli ve doğruluk kanıtları](https://github.com/trailofbits/masm-lean)
- [13] [(Yeterince iyi) AI çağında denetim](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
