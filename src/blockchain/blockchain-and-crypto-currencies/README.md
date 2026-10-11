# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Akıllı Sözleşmeler**, belirli koşullar karşılandığında blockchain üzerinde çalışan ve aracı olmadan anlaşmaların yürütülmesini otomatikleştiren programlar olarak tanımlanır.
- **Merkeziyetsiz Uygulamalar (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç sunarak akıllı sözleşmeler üzerine kurulur.
- **Token’lar ve Coin’ler** farklı işlevlere sahiptir: coin’ler dijital para olarak kullanılırken token’lar belirli bağlamlarda değeri veya sahipliği temsil eder.
  - **Utility Token’lar** hizmetlere erişim sağlar; **Security Token’lar** ise varlık sahipliğini temsil eder.
- **DeFi**, Merkeziyetsiz Finans anlamına gelir ve merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAO’lar** sırasıyla Merkeziyetsiz Borsa Platformları ve Merkeziyetsiz Otonom Organizasyonlar anlamına gelir.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blockchain üzerindeki işlemlerin güvenli ve mutabık kalınmış biçimde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlemleri doğrulamak için hesaplama gücünden yararlanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token bulundurmasını gerektirir ve PoW’a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon aktarılmasını sağlar. İşlemler dijital imzalarla doğrulanır; böylece yalnızca özel anahtarın sahibi transfer başlatabilir.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Çoklu İmzalı İşlemler**, bir işlemi yetkilendirmek için birden fazla imza gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **girdilerden** (fon kaynağı), **çıktılardan** (hedef), **ücretlerden** (madencilere ödenen) ve **script’lerden** (işlem kuralları) oluşur.

### Lightning Network

Bir kanal içinde birden fazla işleme izin vererek Bitcoin’in ölçeklenebilirliğini artırmayı ve yalnızca son durumu blockchain’e yayınlamayı amaçlar.

## Bitcoin Gizliliğiyle İlgili Endişeler

**Ortak Girdi Sahipliği** ve **UTXO Değişim Adresi Tespiti** gibi gizlilik saldırıları, işlem kalıplarından yararlanır. **Mixer** ve **CoinJoin** gibi yöntemler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Anonim Olarak Bitcoin Edinme

Yöntemler arasında nakit işlemleri, madencilik ve mixer kullanımı bulunur. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha yüksek gizlilik sağlamak amacıyla CoinJoin’leri sıradan işlemler gibi gösterir.

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlem gizliliği ve kullanıcı anonimliği sıklıkla endişe konusu olur. Aşağıda, saldırganların Bitcoin gizliliğini tehlikeye atabileceği yaygın yöntemlerin basitleştirilmiş bir özeti yer alıyor.<sup>[[6]](#references)</sup>

## **Ortak Girdi Sahipliği Varsayımı**

Farklı kullanıcılara ait girdilerin karmaşıklık nedeniyle tek bir işlemde birleştirilmesi genellikle nadirdir. Bu nedenle, **aynı işlemdeki iki girdi adresinin çoğunlukla aynı sahibine ait olduğu varsayılır**.

## **UTXO Değişim Adresi Tespiti**

Bir UTXO veya **Harcanmamış İşlem Çıktısı**, bir işlemde bütünüyle harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir değişim adresine gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir; bu da gizliliği tehlikeye atar.

### Örnek

Bunu önlemek için karıştırma hizmetleri kullanmak veya birden fazla adres kullanmak sahipliğin gizlenmesine yardımcı olabilir.

## **Sosyal Ağlarda ve Forumlarda İfşa**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler grafiklerle görselleştirilebilir ve fon akışına dayanarak kullanıcılar arasındaki olası bağlantılar ortaya çıkarılabilir.

## **Gereksiz Girdi Sezgiseli (Optimal Değişim Sezgiseli)**

Bu sezgisel yöntem, göndericiye geri dönen değişim çıktısını tahmin etmek için birden fazla girdi ve çıktı içeren işlemlerin analizine dayanır.

### Örnek

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Daha fazla input eklemek, change output'un herhangi bir tekil input'tan daha büyük olmasına neden olursa heuristic'i yanıltabilir.

## **Zorunlu Address Reuse**

Saldırganlar, alıcının bu miktarları gelecekteki işlemlerde başka input'larla birleştirmesini ve böylece adresleri birbirine bağlamasını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu privacy leak'i önlemek için daha önce kullanılmış, bakiyesi boş adreslere gelen coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analizi Teknikleri**

- **Tam Ödeme Tutarları:** Change içermeyen işlemler, aynı kullanıcıya ait iki adres arasında gerçekleşmiş olabilir.
- **Yuvarlak Sayılar:** İşlemdeki yuvarlak bir sayı, bunun bir ödeme olduğuna işaret eder; yuvarlak olmayan çıktı ise muhtemelen change'tir.
- **Cüzdan Parmak İzi:** Farklı cüzdanların kendilerine özgü işlem oluşturma kalıpları vardır. Bu sayede analistler kullanılan yazılımı ve muhtemelen change adresini belirleyebilir.
- **Tutar ve Zamanlama Korelasyonları:** İşlem zamanlarını veya tutarlarını açıklamak, işlemlerin izlenebilir olmasına yol açabilir.

## **Trafik Analizi**

Saldırganlar, ağ trafiğini izleyerek işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bu, özellikle bir kuruluşun çok sayıda Bitcoin node'u çalıştırması durumunda geçerlidir; bu, işlemleri izleme kabiliyetini artırır.

## Daha Fazla Bilgi

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Wiki'deki Bitcoin Gizliliği](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Anonim Olarak Bitcoin Edinme Yolları

- **Nakit İşlemler**: Bitcoin'i nakit kullanarak edinme.
- **Nakit Alternatifleri**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin ile takas etme.
- **Mining**: Bitcoin kazanmanın en gizli yolu mining'dir; özellikle tek başına yapıldığında, çünkü mining pool'ları miner'ın IP adresini öğrenebilir. [Mining Pool'ları Hakkında Bilgi](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak bitcoin çalmak, onu anonim olarak edinmenin başka bir yolu olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Services

Bir mixing service kullanarak kullanıcı **bitcoin gönderip** karşılığında **farklı bitcoin'ler alabilir**; bu da asıl sahibin izini sürmeyi zorlaştırır. Ancak bunun için service'in log tutmayacağına ve bitcoin'leri gerçekten geri göndereceğine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casinoları bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek input'ları output'larla eşleştirmeye çalışanların işini zorlaştırır. Etkili olmasına rağmen, benzersiz input ve output boyutlarına sahip işlemler yine de izlenebilir.

CoinJoin kullanmış olabilecek örnek işlemler: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Yatırma işlemlerini daha sonraki çekimlerden ayıran bir Ethereum smart-contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir çeşidi olan **PayJoin** (veya P2EP), iki taraf (ör. müşteri ve satıcı) arasındaki işlemi, CoinJoin'in karakteristik eşit output'larını kullanmadan, sıradan bir işlem gibi gösterir. Bu, tespit edilmesini son derece zorlaştırır ve işlem gözetimi yapan kuruluşların kullandığı yaygın input sahipliği heuristic'ini geçersiz kılabilir.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Yukarıdakine benzer işlemler, standart bitcoin işlemlerinden ayırt edilemezken gizliliği artıran PayJoin işlemleri olabilir.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlem gizliliği arayışında umut verici bir gelişme olabilir.

# Kripto Para Gizliliği için En İyi Uygulamalar

## **Cüzdan Senkronizasyon Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanları blockchain ile senkronize etmek çok önemlidir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek maksimum gizlilik sağlar. Şimdiye kadar yapılmış tüm işlemler yerel olarak saklanır; böylece saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesi imkânsız hâle gelir.
- **İstemci tarafında blok filtreleme**: Bu yöntemde blockchain'deki her blok için filtreler oluşturulur. Böylece cüzdanlar, ağ gözlemcilerine belirli ilgi alanlarını açığa çıkarmadan ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları alır.

## **Anonimlik için Tor Kullanımı**

Bitcoin eşler arası bir ağ üzerinde çalıştığından, IP adresinizi gizlemek ve ağla etkileşim kurarken gizliliği artırmak için Tor kullanmanız önerilir.

## **Adreslerin Yeniden Kullanılmasını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak çok önemlidir. Adresleri yeniden kullanmak, işlemleri aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern cüzdanlar tasarımları gereği adreslerin yeniden kullanılmasını önler.

## **İşlem Gizliliği Stratejileri**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını gizleyerek gizliliğe yönelik saldırıları engelleyebilir.
- **Para üstünden kaçınma**: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, para üstü tespit yöntemlerini sekteye uğratarak gizliliği artırır.
- **Birden fazla para üstü çıktısı**: Para üstünden kaçınmak mümkün değilse birden fazla para üstü çıktısı oluşturmak gizliliği yine de artırabilir.

# **Monero: Anonimliğin Simgesi**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlama**

Gas, Ethereum'da işlemleri yürütmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) tutarındaki bir işlemde gas limiti ve taban ücret bulunur; ayrıca doğrulayıcıları işlemi bloğa eklemeye teşvik etmek için bir öncelik ücreti ödenir. Kullanıcılar fazla ödeme yapmamak için bir azami ücret belirleyebilir; fazla tutar iade edilir.<sup>[[5]](#references)</sup>

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemlerde, kullanıcı adresleri veya akıllı sözleşme adresleri olabilen bir gönderici ve alıcı bulunur. İşlemler ücret gerektirir ve bir bloğa eklenmelidir. İşlemdeki temel bilgiler; alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretleri içerir. Özellikle göndericinin adresi imzadan çıkarılır; bu nedenle işlem verisinde bulunması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik verirken kripto para kullanmak isteyen herkes için temel niteliktedir.

## Değer Odaklı Web3 Red Team Çalışmaları

- Fonları kimin ve nasıl taşıyabileceğini anlamak için değer taşıyan bileşenlerin (imzalayıcılar, oracle'lar, bridge'ler, otomasyon) envanterini çıkarın.
- Yetki yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT taktikleriyle eşleştirin.
- Etkiyi doğrulamak ve istismar edilebilir ön koşulları belgelemek için flash loan/oracle/kimlik bilgisi zincirler arası saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışının Ele Geçirilmesi

- Wallet UI'larında yapılan tedarik zinciri müdahaleleri, imzalama işleminden hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall tabanlı proxy ele geçirmeleri için geçerli imzaları toplayabilir (ör. Safe masterCopy'nin slot-0 üzerine yazılması).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Hesap Soyutlama (ERC-4337)

- Akıllı hesaplarda sık görülen hata türleri arasında `EntryPoint` erişim denetiminin atlatılması, imzasız gas alanları, durum değiştiren doğrulama, ERC-1271 replay ve doğrulama sonrasında revert yoluyla ücretlerin tüketilmesi bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Akıllı Sözleşme Güvenliği

- Test paketlerindeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK İspatı / zkVM Guest Bütünlüğü

Bir prover, bir iddiayı doğrulamak için **zkVM** veya uygulamaya özgü bir ispat devresi kullandığında, verifier yalnızca **guest programın yazıldığı şekilde çalıştığını** öğrenir. Guest'te **güvenli olmayan deserialization**, **tanımsız davranış** veya **eksik anlamsal kısıtlar** varsa kötü niyetli bir prover, **herkese açık metrikler veya iddia edilen değişmez yanlış olsa bile** doğrulamadan geçen bir ispat üretebilir.<sup>[[7]](#references)</sup>

### İspat guest'leri içinde güvenli olmayan deserialization

- Özel witness/devre baytlarını, ispat tarafından gizlenmiş olsalar bile **güvenilmeyen saldırgan girdisi** olarak değerlendirin.
- Baytlar önceden bağımsız biçimde doğrulanmadıysa `rkyv::access_unchecked` gibi denetimsiz yardımcılarla bunları deserialize etmekten kaçının.
- Güvenilmeyen serileştirilmiş verilerden yüklenen enum discriminant'ları, relative pointer'lar, uzunluklar ve indeksler; kontrol akışını veya bellek erişimini etkilemeden önce doğrulanmalıdır.

Uygulanabilir denetim yöntemi:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

`op.kind` gibi bir alan enum ise ve bir saldırgan **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerinde yapılan sonraki her `match` şüpheli hâle gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini **jump table** biçimine dönüştürürse, geçersiz bir enum discriminant’ı **tanımsız kontrol akışına** yol açabilir. Tehlikeli bir örüntü:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtları** günceller.
2. İkinci bir `match`, **gerçek talimat semantiğini** uygular.
3. Aralık dışı bir discriminant ilk jump table’ın sınırlarının dışına çıkar ve ikinci jump table ile ilişkili bir kod konumuna atlar.

Sonuç: İşlem yine de yürütülür, ancak muhasebe yolu atlanır. Bir zkVM’de bu, daha az gate, daha az maliyetli işlem veya başka yanlış beyan edilmiş sınırlı kaynaklar gibi imkânsız metrikler bildiren sahte proof’lar üretebilir.

İnceleme kontrol listesi:

- Witness/private input’tan deserialize edilen, saldırganın kontrol edebildiği enum’ları arayın.
- Aynı opcode/kind alanı üzerinde yinelenen `match` ifadelerini inceleyin.
- `unsafe` + denetimsiz deserialization + büyük opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde üretilen binary’yi reverse engineer edin; jump table yerleşimi, kaynak koddan daha önemli olabilir.

### Tersinir/özelleştirilmiş interpreter’larda eksik semantik kısıtlar

Yalnızca bellek güvenliğini doğrulamayın; proof’un uygulaması gereken **semantik kuralları** da doğrulayın.

Tersinir/kuantum benzeri instruction set’lerde, birbirinden farklı olması gereken operand’ların gerçekten farklı olmalarının kısıtlandığından emin olun. Şu şekilde uygulanan Toffoli/CCX benzeri bir işlem:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

konuk reddetmezse güvensiz hâle gelir:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Bu durumda geçiş şu hâle gelir:

```text
q = q ^ (q & q) = 0
```

This, **deterministik bir reset primitive’i** oluşturarak tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha ucuza yapılmasını sağlar. Kaynak kullanımını doğrulayan proof sistemlerinde bu, saldırganların işlevsel kontrolleri geçerken doğrulayıcının uygulandığına inandığı maliyet modelini atlatmasına olanak tanıyabilir.

### ZK sistemlerinde test edilecekler

- Tüm guest parser’ları bozuk witness/private-input kodlamalarıyla fuzz testine tabi tutun.
- Opcode dispatch işleminden önce enum aralığı doğrulaması yapıldığını doğrulayın.
- Operand aliasing ve diğer geçersiz talimat biçimleri için anlamsal kontroller ekleyin.
- Raporlanan/genel sayaçları bağımsız bir referans uygulamasıyla karşılaştırın.
- Guest programı hatalıysa geçerli bir proof’un yine de **yanlış bir ifadeyi** kanıtlayabileceğini unutmayın.

## Duruma Bağlı Yetkilendirme

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX’lerin ve AMM’lerin pratikte exploit edilmesi üzerine araştırma yapıyorsanız (Uniswap v4 hooks, yuvarlama/kesinlik kötüye kullanımı, flash loan ile eşik aşımını büyüten swap’ler), şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri cache’leyen ve `supply == 0` olduğunda zehirlenebilen çok varlıklı weighted pool’lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Vikipedi](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Açık Anahtar ve Özel Anahtar Açıklaması - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Çoklu imzalı işlemler nelerdir? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [İşlemler | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas ve ücretler | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Gizlilik - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google'ın kuantum kriptanalizine ilişkin zero-knowledge proof’unu yendik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Eliptik Eğri Kripto Para Birimlerini Kuantum Güvenlik Açıklarına Karşı Güvenceye Alma: Kaynak Tahminleri ve Azaltma Yöntemleri (yamalı sürüm)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept deposu](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
