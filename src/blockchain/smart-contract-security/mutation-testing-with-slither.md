# Smart Contract'lar için Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing, contract koduna sistematik olarak küçük değişiklikler (mutant'lar) uygulayarak ve test paketini yeniden çalıştırarak "testlerinizi test eder". Bir test başarısız olursa mutant öldürülür. Testler geçmeye devam ederse mutant hayatta kalır ve satır/dal coverage'ının tespit edemediği bir kör noktayı ortaya çıkarır.

Temel fikir: Coverage kodun çalıştırıldığını gösterir; mutation testing ise davranışın gerçekten doğrulanıp doğrulanmadığını gösterir.<sup>[[2]](#references)</sup>

## Coverage neden yanıltabilir

Bu basit threshold kontrolünü ele alalım:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Yalnızca eşik değerinin altında ve üstünde bir değeri kontrol eden unit test'ler, eşitlik sınırını (`==`) doğrulamadan %100 satır/dal coverage'a ulaşabilir. `deposit >= 2 ether` şeklinde yapılacak bir refactor, bu testlerin yine başarılı olmasına ve protokol mantığının sessizce bozulmasına neden olur.<sup>[[2]](#references)</sup>

Mutation testing, koşulu mutate ederek ve testlerin başarısız olduğunu doğrulayarak bu açığı ortaya çıkarır.

Smart contract'larda hayatta kalan mutant'lar genellikle şu kontrollerin eksik olduğunu gösterir:
- Authorization ve rol sınırları
- Accounting/değer transferi invariant'ları
- Revert koşulları ve failure path'leri
- Sınır koşulları (`==`, sıfır değerler, boş array'ler, maksimum/minimum değerler)

## En yüksek güvenlik sinyaline sahip mutation operator'ları

Contract auditing için kullanışlı mutation sınıfları:<sup>[[1]](#references)[[2]](#references)</sup>
- **Yüksek severity**: Çalıştırılmayan path'leri ortaya çıkarmak için ifadeleri `revert()` ile değiştirme
- **Orta severity**: Doğrulanmamış yan etkileri ortaya çıkarmak için satırları comment'leme / mantığı kaldırma
- **Düşük severity**: `>=` -> `>` veya `+` -> `-` gibi ince operator ya da constant değişiklikleri
- Diğer yaygın değişiklikler: assignment değiştirme, boolean flip'leri, condition negation ve type değişiklikleri

Pratik hedef: Anlamlı tüm mutant'ları kill etmek ve ilgisiz ya da semantically equivalent olan hayatta kalan mutant'ları açıkça gerekçelendirmektir.

## Regex'ten syntax-aware mutation neden daha iyidir

Daha eski mutation engine'leri regex veya satır tabanlı yeniden yazımlara dayanıyordu. Bu yöntem çalışır, ancak önemli sınırlamaları vardır:<sup>[[1]](#references)</sup>
- Birden çok satıra yayılan ifadeleri güvenli şekilde mutate etmek zordur
- Dil yapısı anlaşılmadığından comment'ler/token'lar hatalı şekilde hedeflenebilir
- Zayıf bir satır üzerinde her olası varyantı üretmek, büyük miktarda runtime harcanmasına neden olur

AST veya Tree-sitter tabanlı tooling, ham satırlar yerine yapılandırılmış node'ları hedefleyerek bunu iyileştirir:<sup>[[1]](#references)</sup>
- **slither-mutate**, Slither'ın Solidity AST'sini kullanır.<sup>[[4]](#references)</sup>
- **mewt**, language-agnostic bir core olarak Tree-sitter kullanır.<sup>[[6]](#references)</sup>
- **MuTON**, `mewt` üzerine kuruludur ve FunC, Tolk ve Tact gibi TON language'leri için first-class support ekler.<sup>[[7]](#references)</sup>

Bu, çok satırlı construct'ları ve expression-level mutation'ları regex-only yaklaşımlardan çok daha güvenilir hale getirir.

## slither-mutate ile mutation testing çalıştırma

Gereksinimler: Slither v0.10.2+.

- Seçenekleri ve mutator'ları listeleme:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry örneği (sonuçları kaydedin ve tam bir log tutun):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry kullanmıyorsanız, `--test-cmd` seçeneğini testleri çalıştırma yönteminizle değiştirin (ör. `npx hardhat test`, `npm test`).

Artifacts varsayılan olarak `./mutation_campaign` dizininde depolanır. Yakalanamayan (hayatta kalan) mutantlar incelenmek üzere buraya kopyalanır.<sup>[[5]](#references)</sup>

### Çıktıyı anlama

Rapor satırları şu şekilde görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki etiket, mutator alias'ıdır (ör. `CR` = Comment Replacement).
- `UNCAUGHT`, mutated davranış altında testlerin geçtiği anlamına gelir → eksik assertion.

## Çalışma süresini azaltma: etkili mutantlara öncelik verme

Mutation campaign'leri saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:<sup>[[1]](#references)[[2]](#references)</sup>
- Kapsam: Yalnızca kritik contract/dizinlerle başlayın, ardından kapsamı genişletin.
- Mutator'lara öncelik verin: Bir satırdaki yüksek öncelikli mutant hayatta kalırsa (örneğin `revert()` veya comment-out), o satır için daha düşük öncelikli varyantları atlayın.
- İki aşamalı campaign'ler kullanın: Önce odaklanmış/hızlı testleri çalıştırın, ardından yalnızca yakalanamayan mutantları tam test suite'iyle yeniden test edin.
- Mümkün olduğunda mutation hedeflerini belirli test komutlarıyla eşleyin (örneğin auth kodu -> auth testleri).
- Zaman kısıtlıysa campaign'leri high/medium severity mutantlarla sınırlayın.
- Test runner destekliyorsa testleri paralel çalıştırın; dependency/build'leri cache'leyin.
- Fail-fast: Bir değişiklik assertion açığını açıkça gösterdiğinde erken durun.

Çalışma süresi hesabı acımasızdır: `1000 mutants x 5-minute tests ~= 83 hours`; bu nedenle campaign tasarımı, mutator'ın kendisi kadar önemlidir.<sup>[[1]](#references)</sup>

## Kalıcı campaign'ler ve geniş ölçekte triage

Daha eski workflow'ların bir zayıflığı, sonuçları yalnızca `stdout`'a dökmeleridir. Uzun campaign'lerde bu durum duraklatma/devam ettirme, filtreleme ve incelemeyi zorlaştırır.<sup>[[1]](#references)</sup>

`mewt`/`MuTON`, mutant'ları ve sonuçları SQLite destekli campaign'lerde depolayarak bunu iyileştirir. Faydaları:<sup>[[1]](#references)</sup>
- Uzun çalıştırmaları ilerlemeyi kaybetmeden duraklatma ve devam ettirme
- Belirli bir dosyadaki veya mutation class'taki yalnızca yakalanamayan mutantları filtreleme
- İnceleme araçları için sonuçları SARIF'e export etme/çevirme
- AI destekli triage'a ham terminal log'ları yerine daha küçük ve filtrelenmiş sonuç kümeleri sağlama

Kalıcı sonuçlar, mutation testing tek seferlik manuel inceleme yerine bir audit pipeline'ının parçası olduğunda özellikle faydalıdır.

## Hayatta kalan mutantlar için triage workflow'u

1) Mutated satırı ve davranışı inceleyin.
- Mutated satırı uygulayıp odaklanmış bir test çalıştırarak local olarak yeniden üretin.

2) Testleri yalnızca return value'ları değil, state'i de assert edecek şekilde güçlendirin.
- Equality boundary kontrolleri ekleyin (ör. threshold `==` değerini test edin).
- Post-condition'ları assert edin: bakiyeler, total supply, authorization etkileri ve emit edilen event'ler.

3) Aşırı izin verici mock'ları gerçekçi davranışlarla değiştirin.
- Mock'ların on-chain gerçekleşen transferleri, failure path'lerini ve event emission'larını uyguladığından emin olun.

4) Fuzz test'leri için invariant'lar ekleyin.
- Örn. value conservation, non-negative bakiyeler, authorization invariant'ları ve uygun durumlarda monotonic supply.

5) Gerçek pozitifleri semantic no-op'lerden ayırın.
- Örnek: `x > 0` -> `x != 0`, `x` unsigned olduğunda anlamsızdır.

6) Hayatta kalanlar öldürülene veya açıkça gerekçelendirilene kadar campaign'i yeniden çalıştırın.

## Vaka çalışması: eksik state assertion'larını ortaya çıkarma (Arkis protocol)

Arkis DeFi protocol'ünün audit'i sırasında yürütülen bir mutation campaign, aşağıdakilere benzer hayatta kalan mutantları ortaya çıkardı:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Atamanın yorum satırına alınması testleri bozmadı; bu da post-state assertion'larının eksik olduğunu kanıtladı. Temel neden, gerçek token transferlerini doğrulamak yerine kullanıcı tarafından kontrol edilen `_cmd.value` değerine güvenilmesiydi. Bir saldırgan, beklenen ve gerçek transferleri senkron dışına çıkararak fonları boşaltabilirdi. Sonuç: protokolün ödeme gücü açısından yüksek önem derecesine sahip risk.<sup>[[2]](#references)[[3]](#references)</sup>

Yol gösterici kural: Değer transferlerini, muhasebeyi veya access control'ü etkileyen mutantlar öldürülene kadar hayatta kalan mutantları yüksek riskli kabul edin.

## Her mutantı öldürmek için körü körüne test oluşturmayın

Mutation-driven test generation, mevcut implementation hatalıysa geri tepebilir. Örnek: `priority >= 2` ifadesini `priority > 2` olarak mutate etmek davranışı değiştirir; ancak doğru çözüm her zaman "`priority == 2` için bir test yazmak" değildir. Bu davranışın kendisi de bug olabilir.<sup>[[1]](#references)</sup>

Daha güvenli workflow:
- Hayatta kalan mutantları belirsiz gereksinimleri belirlemek için kullanın
- Beklenen davranışı spec'lerden, protokol dokümanlarından veya reviewer'lardan doğrulayın
- Ancak bundan sonra davranışı bir test/invariant olarak kodlayın

Aksi takdirde implementation kazalarını test suite'e sabitleme ve yanlış bir güven duygusu edinme riski taşırsınız.

## Uygulamalı kontrol listesi

- Hedefli bir campaign çalıştırın:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Mümkün olduğunda yalnızca regex tabanlı mutation yerine syntax-aware mutator'ları (AST/Tree-sitter) tercih edin.
- Hayatta kalan mutantları triage edin ve mutate edilmiş davranış altında başarısız olacak testler/invariant'lar yazın.
- Bakiyeleri, supply'ı, authorization'ları ve event'leri assert edin.
- Sınır durumları için testler ekleyin (`==`, overflow/underflow, zero-address, zero-amount, empty arrays).
- Gerçekçi olmayan mock'ları değiştirin; failure mode'ları simüle edin.
- Tooling desteklediğinde sonuçları kalıcı olarak saklayın ve triage öncesinde yakalanmamış mutantları filtreleyin.
- Runtime'ı yönetilebilir tutmak için iki aşamalı veya hedef başına campaign'ler kullanın.
- Tüm mutantlar öldürülene veya yorumlar ve gerekçelerle açıklanana kadar yineleyin.

## References

- [1] [Agentic era için mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Testlerinizin yakalayamadığı bug'ları bulmak için mutation testing kullanın (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
