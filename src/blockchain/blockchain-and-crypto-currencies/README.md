# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts (Akıllı Sözleşmeler)**, belirli koşullar karşılandığında blockchain üzerinde çalışan ve aracı olmadan anlaşmaların yürütülmesini otomatikleştiren programlardır.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç sunarak smart contract'lar üzerine kurulur.
- **Token'lar ve Coin'ler** farklı kavramlardır: coin'ler dijital para işlevi görürken token'lar belirli bağlamlarda değeri veya mülkiyeti temsil eder.
  - **Utility Token'lar** hizmetlere erişim sağlar; **Security Token'lar** ise varlık sahipliğini temsil eder.
- **DeFi**, Decentralized Finance anlamına gelir ve merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAO'lar**, sırasıyla Decentralized Exchange Platform'ları ve Decentralized Autonomous Organization'ları ifade eder.

## Consensus Mechanism'ler

Consensus mechanism'ler, blockchain üzerindeki işlemlerin güvenli ve üzerinde uzlaşılmış biçimde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlemleri doğrulamak için hesaplama gücünden yararlanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token tutmasını gerektirir ve PoW'a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin'in Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon aktarımını içerir. İşlemler dijital imzalarla doğrulanır; böylece transferleri yalnızca özel anahtarın sahibi başlatabilir.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature İşlemleri**, bir işlemi onaylamak için birden fazla imza gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **girdilerden** (fonların kaynağı), **çıktılardan** (hedef), **ücretlerden** (madencilere ödenen) ve **script'lerden** (işlem kuralları) oluşur.

### Lightning Network

Bir kanal içinde birden fazla işleme izin vererek Bitcoin'in ölçeklenebilirliğini artırmayı amaçlar; blockchain'e yalnızca son durumu yayınlar.

## Bitcoin Gizliliğiyle İlgili Endişeler

**Ortak Girdi Sahipliği** ve **UTXO Değişiklik Adresi Tespiti** gibi gizlilik saldırıları, işlem örüntülerinden yararlanır. **Mixers** ve **CoinJoin** gibi yöntemler, kullanıcılar arasındaki işlem bağlantılarını belirsizleştirerek anonimliği artırır.

## Anonim Olarak Bitcoin Edinme

Yöntemler arasında nakit karşılığı alım satım, madencilik ve mixers kullanımı yer alır. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha yüksek gizlilik sağlamak amacıyla CoinJoin'leri normal işlemler gibi gösterir.

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe kaynağı olur. Saldırganların Bitcoin gizliliğini tehlikeye atabileceği yaygın yöntemlerin basitleştirilmiş bir özeti aşağıdadır.<sup>[[6]](#references)</sup>

## **Ortak Girdi Sahipliği Varsayımı**

İlgili karmaşıklık nedeniyle, farklı kullanıcılara ait girdilerin tek bir işlemde birleştirilmesi genellikle nadir görülür. Bu nedenle, **aynı işlemdeki iki girdi adresinin çoğunlukla aynı sahibine ait olduğu varsayılır**.

## **UTXO Değişiklik Adresi Tespiti**

UTXO veya **Harcanmamış İşlem Çıktısı**, bir işlemde bütünüyle harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse, kalanı yeni bir değişiklik adresine aktarılır. Gözlemciler, bu yeni adresin gönderene ait olduğunu varsayabilir; bu da gizliliği tehlikeye atar.

### Örnek

Bunu önlemek için mixing hizmetleri veya birden fazla adres kullanmak, sahipliği belirsizleştirmeye yardımcı olabilir.

## **Sosyal Ağlarda ve Forumlarda İfşa**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi olarak paylaşır; bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler grafikler olarak görselleştirilebilir ve fon akışına göre kullanıcılar arasındaki olası bağlantıları ortaya çıkarabilir.

## **Gereksiz Girdi Sezgiseli (Optimal Change Heuristic)**

Bu sezgisel yöntem, gönderene geri dönen değişiklik çıktısının hangisi olduğunu tahmin etmek için birden fazla girdi ve çıktı içeren işlemleri analiz etmeye dayanır.

### Örnek

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Daha fazla girdi eklemek, change çıktısını herhangi bir girdiden daha büyük hâle getirirse sezgisel yöntemin kafasını karıştırabilir.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının bu küçük tutarları gelecekteki işlemlerde başka girdilerle birleştirerek adresleri ilişkilendirmesini umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu gizlilik sızıntısını önlemek için daha önce kullanılmış ve bakiyesi boş olan adreslerden alınan coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analiz Teknikleri**

- **Kesin Ödeme Tutarları:** Change içermeyen işlemler, aynı kullanıcıya ait iki adres arasında gerçekleşmiş olabilir.
- **Yuvarlak Tutarlar:** Bir işlemdeki yuvarlak tutar, bunun bir ödeme olduğunu; yuvarlak olmayan çıktının ise muhtemelen change olduğunu düşündürür.
- **Cüzdan Parmak İzi Oluşturma:** Farklı cüzdanların işlem oluşturma biçimleri kendilerine özgüdür. Bu, analistlerin kullanılan yazılımı ve muhtemelen change adresini belirlemesine olanak tanır.
- **Tutar ve Zaman Korelasyonları:** İşlem zamanlarını veya tutarlarını açıklamak, işlemlerin izlenebilir olmasına yol açabilir.

## **Trafik Analizi**

Saldırganlar, ağ trafiğini izleyerek işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bir kuruluşun çok sayıda Bitcoin node'u işletmesi, işlemleri izleme kapasitesini artıracağından bu durum özellikle geçerlidir.

## Daha Fazla Bilgi

Gizlilik saldırıları ve savunmalarının kapsamlı listesi için [Bitcoin Wiki'deki Bitcoin Gizliliği](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Anonim Olarak Bitcoin Edinme Yöntemleri

- **Nakit İşlemler**: Bitcoin'i nakit karşılığında edinmek.
- **Nakit Alternatifleri**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin ile değiştirmek.
- **Mining**: Bitcoin kazanmanın en gizli yöntemi mining yapmaktır. Özellikle tek başına mining yapıldığında bu yöntem daha gizlidir; çünkü mining pool'ları miner'ın IP adresini biliyor olabilir. [Mining Pool Bilgileri](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak bitcoin çalmak, anonim olarak edinmenin başka bir yöntemi olabilir; ancak bu yasa dışıdır ve önerilmez.

## Karıştırma Hizmetleri

Bir karıştırma hizmeti kullanarak kullanıcı **bitcoin gönderebilir** ve karşılığında **farklı bitcoin'ler alabilir**; bu da asıl sahibin izinin sürülmesini zorlaştırır. Ancak bunun için hizmetin kayıtları tutmayacağına ve bitcoin'leri gerçekten iade edeceğine güvenmek gerekir. Bitcoin casinoları alternatif karıştırma seçenekleri arasındadır.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek girdileri çıktılarla eşleştirmeye çalışan herkesin işini zorlaştırır. Etkili olmasına rağmen, girdi ve çıktı boyutları benzersiz olan işlemlerin izi yine de sürülebilir.

CoinJoin kullanmış olabilecek örnek işlemler: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Yatırma işlemlerini daha sonraki çekimlerden ayıran bir Ethereum smart contract mixer'ı için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir çeşidi olan **PayJoin** (veya P2EP), iki taraf (ör. bir müşteri ve bir satıcı) arasındaki işlemi, CoinJoin'in ayırt edici eşit çıktılar özelliğini göstermeyen sıradan bir işlem gibi gizler. Bu, tespit edilmesini son derece zorlaştırır ve işlem gözetimi yapan kuruluşların kullandığı ortak girdi sahipliği sezgisel yöntemini geçersiz kılabilir.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Yukarıdakine benzer işlemler, standart bitcoin işlemlerinden ayırt edilemezken gizliliği artıran PayJoin işlemleri olabilir.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlemsel gizlilik arayışında umut verici bir gelişme olabilir.

# Kripto Para Gizliliği için En İyi Uygulamalar

## **Cüzdan Senkronizasyon Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blockchain ile senkronize etmek çok önemlidir. Öne çıkan iki yöntem vardır:

- **Full node**: Tüm blockchain'i indirerek maksimum gizlilik sağlar. Şimdiye kadar yapılmış tüm işlemler yerel olarak saklanır; böylece saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesi imkânsız hâle gelir.
- **İstemci tarafında blok filtreleme**: Bu yöntemde blockchain'deki her blok için filtreler oluşturulur. Böylece cüzdanlar, belirli ilgi alanlarını ağ gözlemcilerine açığa çıkarmadan ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tüm bloğu indirir.

## **Anonimlik için Tor Kullanımı**

Bitcoin eşler arası bir ağ üzerinden çalıştığından, IP adresinizi gizlemek ve ağla etkileşim kurarken gizliliği artırmak için Tor kullanmanız önerilir.

## **Adreslerin Yeniden Kullanılmasını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak önemlidir. Adresleri yeniden kullanmak, işlemleri aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern cüzdanların tasarımı, adreslerin yeniden kullanılmasını önler.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını belirsizleştirerek gizlilik saldırılarını engelleyebilir.
- **Para üstünü önleme**: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, para üstü tespit yöntemlerini sekteye uğratarak gizliliği artırır.
- **Birden fazla para üstü çıktısı**: Para üstünü önlemek mümkün değilse, birden fazla para üstü çıktısı oluşturmak yine de gizliliği iyileştirebilir.

# **Monero: Anonimliğin Öncüsü**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlamak**

Gas, Ethereum'da işlemleri yürütmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) tutarındaki bir işlemde gas limiti ve temel ücret bulunur; doğrulayıcıların işlemi bloğa eklemesini teşvik etmek için öncelik ücreti de eklenir. Kullanıcılar fazla ödeme yapmamak için bir azami ücret belirleyebilir; aşan tutar iade edilir.<sup>[[5]](#references)</sup>

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemlerde, kullanıcı veya akıllı sözleşme adresi olabilen bir gönderici ve alıcı bulunur. İşlemler ücret gerektirir ve bir bloğa eklenmelidir. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Özellikle, göndericinin adresi imzadan çıkarılır; bu nedenle işlem verilerinde bulunması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik vererek kripto para kullanmak isteyen herkes için temel niteliktedir.

## Değer Odaklı Web3 Red Teaming

- Fonları kimin ve nasıl taşıyabileceğini anlamak için değer taşıyan bileşenlerin (imzalayıcılar, oracles, bridge'ler, otomasyon) envanterini çıkarın.
- Ayrıcalık yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT taktikleriyle eşleştirin.
- Etkiyi doğrulamak ve istismar edilebilir ön koşulları belgelemek için flash-loan/oracle/kimlik bilgisi/çapraz zincir saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışının Ele Geçirilmesi

- Cüzdan arayüzlerine yönelik tedarik zinciri manipülasyonu, imzalamadan hemen önce EIP-712 yüklerini değiştirebilir ve delegatecall tabanlı proxy ele geçirmelerinde kullanılabilecek geçerli imzaları toplayabilir (ör. Safe masterCopy'nin slot 0'ının üzerine yazılması).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Hesap Soyutlama (ERC-4337)

- Yaygın akıllı hesap hata türleri arasında `EntryPoint` erişim denetiminin atlatılması, imzalanmamış gas alanları, durum değiştiren doğrulama, ERC-1271 replay saldırıları ve doğrulama sonrasında revert yoluyla ücretlerin tüketilmesi yer alır.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Akıllı Sözleşme Güvenliği

- Test paketlerindeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Kanıtı / zkVM Guest Bütünlüğü

Bir prover, bir iddiayı doğrulamak için **zkVM** veya uygulamaya özgü bir kanıt devresi kullandığında, verifier yalnızca **guest programının yazıldığı şekilde yürütüldüğünü** öğrenir. Guest programında **güvenli olmayan serileştirme**, **tanımsız davranış** veya **eksik anlamsal kısıtlamalar** varsa, kötü niyetli bir prover **genel ölçümler veya iddia edilen değişmez yanlış olduğu hâlde** doğrulamadan geçen bir kanıt oluşturabilir.<sup>[[7]](#references)</sup>

### Kanıt guest'lerinde güvenli olmayan serileştirme

- Gizli olsalar bile, özel witness/devre baytlarını **güvenilmeyen saldırgan girdisi** olarak değerlendirin.
- Baytlar daha önce harici olarak doğrulanmadıysa `rkyv::access_unchecked` gibi denetimsiz yardımcılarla serileştirmelerini açmaktan kaçının.
- Güvenilmeyen serileştirilmiş verilerden yüklenen enum ayırt edicileri, göreli işaretçiler, uzunluklar ve indeksler; kontrol akışını veya belleğe erişimi etkilemeden önce doğrulanmalıdır.

Pratik denetim örüntüsü:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` gibi bir alan enum ise ve saldırgan **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerindeki sonraki her `match` şüpheli hâle gelir.

### Jump table / UB ile sayaçları atlatma

Rust büyük bir `match` ifadesini **jump table** hâline getirirse, geçersiz bir enum discriminant’ı **tanımsız kontrol akışına** yol açabilir. Tehlikeli bir örüntü:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtları** günceller.
2. İkinci bir `match`, **gerçek komut semantiğini** uygular.
3. Aralık dışı bir discriminant, ilk jump table’ın sonrasındaki bir konumu indeksler ve ikinci jump table’la ilişkili koda atlar.

Sonuç: İşlem yine yürütülür, ancak hesaplama yolu atlanır. Bir zkVM’de bu, imkânsız ölçümler (ör. daha az gate, daha az maliyetli işlem veya sınırlandırılmış diğer kaynakların sahte değerleri) bildiren sahte proof’lar oluşturabilir.

İnceleme kontrol listesi:

- Witness/private input üzerinden deserialize edilen, saldırganın kontrolündeki enum’ları arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + doğrulama yapmadan deserialization + büyük opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde oluşturulan binary’yi reverse engineer edin; jump table düzeni, kaynak koddan daha önemli olabilir.

### Tersinir/özelleştirilmiş interpreter’larda eksik semantik kısıtlar

Yalnızca bellek güvenliğini doğrulamayın; proof’un uygulaması gereken **semantik kuralları** da doğrulayın.

Tersinir/kuantum benzeri komut kümelerinde, birbirinden farklı olması gereken operand’ların gerçekten farklı olmasının kısıtlandığından emin olun. Şu şekilde uygulanmış bir Toffoli/CCX benzeri işlem:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

konuk reddetmezse güvensiz hale gelir:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Bu durumda geçiş şu hâle indirgenir:

```text
q = q ^ (q & q) = 0
```

Bu, **deterministik bir sıfırlama primitive’i** oluşturur; tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha düşük maliyetle yapılmasını sağlar. Kaynak kullanımını doğrulayan ispat sistemlerinde bu, saldırganların işlevsel kontrolleri geçerken doğrulayıcının uygulandığına inandığı maliyet modelini aşmasına olanak tanıyabilir.

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser’larını bozuk witness/private-input kodlamalarıyla fuzz testine tabi tutun.
- Opcode dispatch öncesinde enum aralığının doğrulandığından emin olun.
- Operand aliasing ve diğer geçersiz komut biçimleri için anlamsal kontroller ekleyin.
- Bildirilen/public sayaçları bağımsız bir referans uygulamasıyla karşılaştırın.
- Guest programı hatalıysa geçerli bir ispatın yine de **yanlış bir ifadeyi** ispatlayabileceğini unutmayın.

## Duruma Bağlı Yetkilendirme

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX’lerin ve AMM’lerin pratikte nasıl exploit edildiğini araştırıyorsanız (Uniswap v4 hooks, yuvarlama/hassasiyet suistimali, flash loan ile güçlendirilmiş eşik aşan swap’ler), şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri önbelleğe alan ve `supply == 0` olduğunda zehirlenebilen çok varlıklı weighted pool’lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Açık Anahtar ve Özel Anahtar Açıklaması - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Çoklu imzalı işlemler nedir? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [İşlemler | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas ve ücretler | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Gizlilik - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google'ın kuantum kriptanalizine yönelik zero-knowledge proof'unu yendik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Eliptik Eğri Kripto Para Birimlerini Kuantum Açıklarına Karşı Güvenceye Alma: Kaynak Tahminleri ve Azaltma Yöntemleri (yamalı sürüm)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept deposu](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
