# Akıllı Sözleşmeler için Mutasyon Testi (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutasyon testi, sözleşme koduna sistematik olarak küçük değişiklikler (mutantlar) uygulayıp test paketini yeniden çalıştırarak "testlerinizi test eder". Bir test başarısız olursa mutant öldürülür. Testler hâlâ başarılı olursa mutant hayatta kalır ve satır/dal kapsamının tespit edemeyeceği bir kör noktayı ortaya çıkarır.

Temel fikir: Kapsam, kodun yürütüldüğünü gösterir; mutasyon testi ise davranışın gerçekten doğrulanıp doğrulanmadığını gösterir.<sup>[[2]](#references)</sup>

## Kapsam neden yanıltıcı olabilir?

Şu basit eşik kontrolünü ele alalım:

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

Yalnızca eşik değerinin altındaki ve üstündeki bir değeri kontrol eden birim testleri, eşitlik sınırını (`==`) doğrulamadan %100 satır/dal kapsamına ulaşabilir. `deposit >= 2 ether` şeklinde bir refactor da bu testleri geçer ve protokol mantığını sessizce bozar.<sup>[[2]](#references)</sup>

Mutation testing, koşulu mutate edip testlerin başarısız olduğunu doğrulayarak bu açığı ortaya çıkarır.

Smart contract’larda hayatta kalan mutantlar genellikle şu kontrollerin eksik olduğuna işaret eder:
- Yetkilendirme ve rol sınırları
- Muhasebe/değer aktarımı değişmezleri
- Revert koşulları ve hata yolları
- Sınır koşulları (`==`, sıfır değerler, boş diziler, azami/asgari değerler)

## En yüksek güvenlik sinyalini veren mutation operator’ları

Contract denetimi için kullanışlı mutation sınıfları:<sup>[[1]](#references)[[2]](#references)</sup>
- **Yüksek önem derecesi**: Yürütülmeyen yolları ortaya çıkarmak için ifadeleri `revert()` ile değiştirme
- **Orta önem derecesi**: Doğrulanmamış yan etkileri ortaya çıkarmak için satırları yorum satırına alma / mantığı kaldırma
- **Düşük önem derecesi**: `>=` -> `>` veya `+` -> `-` gibi ince operatör ya da sabit değişiklikleri
- Diğer yaygın düzenlemeler: atama değiştirme, boolean değerleri tersine çevirme, koşulları olumsuzlama ve tür değişiklikleri

Pratik hedef: anlamlı tüm mutantları öldürmek ve önemsiz ya da anlamsal olarak eşdeğer olan hayatta kalanları açıkça gerekçelendirmek.

## Syntax-aware mutation neden regex’ten daha iyidir

Eski mutation motorları regex tabanlı veya satır odaklı yeniden yazımlara dayanıyordu. Bu işe yarar, ancak önemli sınırlamaları vardır:<sup>[[1]](#references)</sup>
- Birden çok satıra yayılan ifadeleri güvenli biçimde mutate etmek zordur
- Dil yapısı anlaşılmadığından yorumlar/token’lar hatalı biçimde hedef alınabilir
- Zayıf bir satırda olası tüm varyantları üretmek çalışma süresini ciddi ölçüde artırır

AST veya Tree-sitter tabanlı araçlar, ham satırlar yerine yapılandırılmış düğümleri hedefleyerek bunu iyileştirir:<sup>[[1]](#references)</sup>
- **slither-mutate**, Slither'ın Solidity AST'sini kullanır.<sup>[[4]](#references)</sup>
- **mewt**, dilden bağımsız bir çekirdek olarak Tree-sitter'ı kullanır.<sup>[[6]](#references)</sup>
- **MuTON**, `mewt` üzerine kuruludur ve FunC, Tolk ve Tact gibi TON dillerine yerleşik destek ekler.<sup>[[7]](#references)</sup>

Bu sayede çok satırlı yapılar ve ifade düzeyindeki mutation’lar, yalnızca regex kullanan yaklaşımlara kıyasla çok daha güvenilir olur.

## slither-mutate ile mutation testing çalıştırma

Gereksinimler: Slither v0.10.2+.

- Seçenekleri ve mutator’ları listeleme:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Foundry örneği (sonuçları kaydedin ve tam bir günlük tutun):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Foundry kullanmıyorsanız `--test-cmd` yerine testleri nasıl çalıştırdığınızı yazın (ör. `npx hardhat test`, `npm test`).

Artifact'lar varsayılan olarak `./mutation_campaign` içinde saklanır. Yakalanmamış (hayatta kalan) mutantlar incelemeniz için buraya kopyalanır.<sup>[[5]](#references)</sup>

### Çıktıyı anlama

Rapor satırları şu şekilde görünür:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Köşeli parantez içindeki etiket, mutator takma adıdır (ör. `CR` = Comment Replacement).
- `UNCAUGHT`, testlerin değiştirilmiş davranışla geçtiği anlamına gelir → eksik assertion.

## Çalışma süresini azaltma: etkili mutantlara öncelik verin

Mutation kampanyaları saatler, hatta günler sürebilir. Maliyeti azaltmaya yönelik ipuçları:<sup>[[1]](#references)[[2]](#references)</sup>
- Kapsam: Önce yalnızca kritik contract ve dizinlerle başlayın, ardından kapsamı genişletin.
- Mutatorlara öncelik verin: Bir satırdaki yüksek öncelikli mutant hayatta kalırsa (örneğin `revert()` veya yorum satırına alma), o satır için daha düşük öncelikli varyantları atlayın.
- İki aşamalı kampanyalar yürütün: Önce odaklı/hızlı testleri çalıştırın, sonra yalnızca yakalanmamış mutantları tam test paketiyle yeniden test edin.
- Mümkün olduğunda mutasyon hedeflerini belirli test komutlarıyla eşleştirin (örneğin auth kodu -> auth testleri).
- Zaman kısıtlıysa kampanyaları yüksek/orta önem dereceli mutantlarla sınırlandırın.
- Test çalıştırıcınız destekliyorsa testleri paralel çalıştırın; bağımlılıkları/derlemeleri önbelleğe alın.
- Fail-fast: Bir değişiklik assertion eksikliğini açıkça ortaya koyduğunda erkenden durun.

Çalışma süresi hesabı acımasızdır: `1000 mutants x 5-minute tests ~= 83 hours`; bu nedenle kampanya tasarımı, mutatorın kendisi kadar önemlidir.<sup>[[1]](#references)</sup>

## Kalıcı kampanyalar ve büyük ölçekte triyaj

Eski iş akışlarının zayıf yönlerinden biri, sonuçları yalnızca `stdout`'a dökmeleridir. Uzun kampanyalarda bu durum duraklatmayı/sürdürmeyi, filtrelemeyi ve incelemeyi zorlaştırır.<sup>[[1]](#references)</sup>

`mewt`/`MuTON`, mutantları ve sonuçları SQLite destekli kampanyalarda saklayarak bu sorunu iyileştirir. Faydaları:<sup>[[1]](#references)</sup>
- İlerlemeyi kaybetmeden uzun çalışmaları duraklatıp sürdürme
- Yalnızca belirli bir dosyadaki veya mutasyon sınıfındaki yakalanmamış mutantları filtreleme
- İnceleme araçları için sonuçları SARIF biçimine aktarma/dönüştürme
- Ham terminal günlükleri yerine yapay zeka destekli triyaj için daha küçük, filtrelenmiş sonuç kümeleri sağlama

Kalıcı sonuçlar, mutation testing tek seferlik bir manuel inceleme olmaktan çıkıp denetim hattının parçası hâline geldiğinde özellikle yararlıdır.

## Hayatta kalan mutantlar için triyaj iş akışı

1) Değiştirilmiş satırı ve davranışı inceleyin.
   - Değiştirilmiş satırı uygulayıp odaklı bir test çalıştırarak yerel ortamda yeniden üretin.

2) Testleri yalnızca dönüş değerlerini değil, durumu da doğrulayacak şekilde güçlendirin.
   - Eşitlik sınırı kontrolleri ekleyin (ör. eşik değerinin `==` olduğu durumu test edin).
   - Son koşulları doğrulayın: bakiyeler, toplam arz, yetkilendirme etkileri ve yayımlanan event'ler.

3) Aşırı izin verici mock'ları gerçekçi davranışlarla değiştirin.
   - Mock'ların zincir üzerinde gerçekleşen transferleri, hata yollarını ve event yayımlarını uyguladığından emin olun.

4) Fuzz testleri için invariant'lar ekleyin.
   - Örneğin, değerin korunumu, negatif olmayan bakiyeler, yetkilendirme invariant'ları ve uygun olduğunda arzın monotonluğu.

5) Gerçek pozitifleri anlamsal olarak etkisiz değişikliklerden ayırın.
   - Örnek: `x > 0` -> `x != 0`, `x` işaretsiz bir tür olduğunda anlamsızdır.

6) Hayatta kalan mutantlar öldürülene veya açıkça gerekçelendirilene kadar kampanyayı yeniden çalıştırın.

## Vaka çalışması: eksik durum assertion'larını ortaya çıkarma (Arkis protokolü)

Arkis DeFi protokolünün denetimi sırasında yürütülen bir mutation kampanyası, şu mutantların hayatta kaldığını ortaya çıkardı:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Atamanın yorum satırına alınması testleri bozmadı; bu da son durum assertion'larının eksik olduğunu kanıtladı. Temel neden: kod, gerçek token transferlerini doğrulamak yerine kullanıcı denetimindeki `_cmd.value` değerine güveniyordu. Bir saldırgan, beklenen ve gerçekleşen transferleri uyumsuz hâle getirerek fonları boşaltabilirdi. Sonuç: protokolün ödeme gücü açısından yüksek önem dereceli risk.<sup>[[2]](#references)[[3]](#references)</sup>

Yönerge: Değer transferlerini, muhasebeyi veya erişim kontrolünü etkileyen ve hayatta kalan mutantları, etkisiz hâle getirilene kadar yüksek riskli kabul edin.

## Her mutantı etkisiz hâle getirmek için körü körüne test üretmeyin

Mutation-driven test üretimi, mevcut uygulama yanlışsa ters tepebilir. Örnek: `priority >= 2` ifadesini `priority > 2` olarak değiştirmek davranışı değiştirir; ancak doğru düzeltme her zaman "`priority == 2` için bir test yazmak" değildir. Bu davranışın kendisi hata olabilir.<sup>[[1]](#references)</sup>

Daha güvenli iş akışı:
- Belirsiz gereksinimleri belirlemek için hayatta kalan mutantları kullanın
- Beklenen davranışı spesifikasyonlardan, protokol belgelerinden veya incelemeyi yapan kişilerden doğrulayın
- Ancak bundan sonra davranışı bir test/invariant olarak kodlayın

Aksi takdirde, uygulamadaki tesadüfi davranışları test paketine sabitleme ve sahte güven kazanma riski taşırsınız.

## Uygulamaya dönük kontrol listesi

- Hedefli bir kampanya yürütün:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Mümkün olduğunda yalnızca regex kullanan mutatörler yerine sözdizimini dikkate alan mutatörleri (AST/Tree-sitter) tercih edin.
- Hayatta kalan mutantları değerlendirin ve değiştirilmiş davranışta başarısız olacak testler/invariant'lar yazın.
- Bakiyeleri, arzı, yetkilendirmeleri ve event'leri doğrulayın.
- Sınır değerleri için testler ekleyin (`==`, taşmalar/alt taşmalar, sıfır adres, sıfır miktar, boş diziler).
- Gerçekçi olmayan mock'ları değiştirin; hata senaryolarını simüle edin.
- Araç destekliyorsa sonuçları kalıcı olarak saklayın ve değerlendirmeden önce yakalanmamış mutantları filtreleyin.
- Çalışma süresini yönetilebilir tutmak için iki aşamalı veya hedef başına kampanyalar yürütün.
- Tüm mutantlar etkisiz hâle getirilene ya da yorumlar ve gerekçelerle açıklanana kadar yineleyin.

## References

- [1] [Ajan tabanlı çağ için mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Testlerinizin yakalayamadığı hataları bulmak için mutation testing kullanın (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Güvenlik İncelemesi (Ek C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator belgeleri](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
