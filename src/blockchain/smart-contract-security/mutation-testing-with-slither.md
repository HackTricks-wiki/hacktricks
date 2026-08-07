# Akıllı Sözleşmeler için Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing, sözleşme koduna sistematik olarak küçük değişiklikler (mutant'lar) uygulayıp test paketini yeniden çalıştırarak "testlerinizi test eder". Bir test başarısız olursa mutant öldürülür. Testler hâlâ başarılı olursa mutant hayatta kalır ve line/branch coverage'ın tespit edemediği bir kör noktayı ortaya çıkarır.

Temel fikir: Coverage, kodun çalıştırıldığını gösterir; mutation testing ise davranışın gerçekten doğrulanıp doğrulanmadığını gösterir.<sup>[[2]](#references)</sup>

## Coverage neden yanıltabilir?

Şu basit eşik kontrolünü düşünün:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Yalnızca eşik değerinin altında ve üstünde bir değeri kontrol eden Unit testleri, eşitlik sınırını (`==`) doğrulamadan %100 satır/dal kapsamına ulaşabilir. `deposit >= 2 ether` ifadesine yapılacak bir refactor, bu testlerin yine de başarılı olmasını sağlayarak protokol mantığını sessizce bozabilir.<sup>[[2]](#references)</sup>

Mutation testing, koşulu mutate ederek ve testlerin başarısız olduğunu doğrulayarak bu boşluğu ortaya çıkarır.

Smart contract'lar için hayatta kalan mutant'lar sıklıkla şu konulardaki eksik kontrollerle eşleşir:
- Authorization ve rol sınırları
- Muhasebe/değer transferi invariant'ları
- Revert koşulları ve hata yolları
- Sınır koşulları (`==`, sıfır değerler, boş diziler, maksimum/minimum değerler)

## En yüksek security sinyaline sahip mutation operator'ları

Contract auditing için kullanışlı mutation sınıfları:<sup>[[1]](#references)[[2]](#references)</sup>
- **Yüksek önem**: Çalıştırılmayan yolları ortaya çıkarmak için ifadeleri `revert()` ile değiştirme
- **Orta önem**: Doğrulanmamış side effect'leri ortaya çıkarmak için satırları comment out etme / mantığı kaldırma
- **Düşük önem**: `>=` -> `>` veya `+` -> `-` gibi ince operator ya da constant değişiklikleri
- Diğer yaygın düzenlemeler: assignment değiştirme, boolean flip'leri, condition negation ve type değişiklikleri

Pratik hedef: Anlamlı tüm mutant'ları kill etmek ve alakasız veya semantically equivalent olan hayatta kalan mutant'ları açıkça gerekçelendirmektir.

## Syntax-aware mutation neden regex'ten daha iyidir

Daha eski mutation engine'leri regex veya satır odaklı yeniden yazımlara dayanıyordu. Bu işe yarar, ancak önemli sınırlamaları vardır:<sup>[[1]](#references)</sup>
- Çok satırlı ifadeleri güvenli bir şekilde mutate etmek zordur
- Dil yapısı anlaşılmadığından comment/token'lar hatalı şekilde hedeflenebilir
- Zayıf bir satır üzerinde mümkün olan her varyantı üretmek, runtime'ın büyük miktarının boşa harcanmasına neden olur

AST veya Tree-sitter tabanlı tooling, ham satırlar yerine yapılandırılmış node'ları hedefleyerek bunu iyileştirir:<sup>[[1]](#references)</sup>
- **slither-mutate**, Slither'ın Solidity AST'sini kullanır
- **mewt**, language-agnostic bir core olarak Tree-sitter kullanır
- **MuTON**, `mewt` üzerine kuruludur ve FunC, Tolk ve Tact gibi TON dilleri için first-class support ekler

Bu, çok satırlı construct'ları ve expression-level mutation'ları regex-only yaklaşımlara kıyasla çok daha güvenilir hale getirir.

## slither-mutate ile mutation testing çalıştırma

Gereksinimler: Slither v0.10.2+.

- Seçenekleri ve mutator'ları listeleme:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry örneği (sonuçları yakalayın ve tam bir log tutun):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry kullanmıyorsanız, `--test-cmd` seçeneğini testleri çalıştırma yönteminizle değiştirin (ör. `npx hardhat test`, `npm test`).

Artifacts varsayılan olarak `./mutation_campaign` konumunda depolanır. Yakalanmayan (hayatta kalan) mutantlar incelenmek üzere buraya kopyalanır.<sup>[[5]](#references)</sup>

### Çıktıyı anlama

Rapor satırları şu şekilde görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki tag, mutator alias'ıdır (ör. `CR` = Comment Replacement).
- `UNCAUGHT`, mutant davranışı altında testlerin geçtiği anlamına gelir → eksik assertion.

## Çalışma süresini azaltma: etkili mutantlara öncelik verme

Mutation campaign'ler saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:<sup>[[1]](#references)[[2]](#references)</sup>
- Kapsam: Önce yalnızca kritik contract/directory'lerle başlayın, ardından kapsamı genişletin.
- Mutator'lara öncelik verin: Bir satırdaki yüksek öncelikli mutant hayatta kalırsa (örneğin `revert()` veya comment-out), o satır için daha düşük öncelikli varyantları atlayın.
- İki aşamalı campaign'ler kullanın: Önce odaklanmış/hızlı testleri çalıştırın, ardından yalnızca yakalanmamış mutantları full suite ile yeniden test edin.
- Mümkün olduğunda mutation target'larını belirli test command'leriyle eşleyin (örneğin auth code -> auth tests).
- Zaman kısıtlıysa campaign'leri high/medium severity mutant'larla sınırlayın.
- Runner destekliyorsa testleri paralel çalıştırın; dependency/build'leri cache'leyin.
- Fail-fast: Bir değişiklik assertion gap'i açıkça gösterdiğinde erken durun.

Çalışma süresi hesabı acımasızdır: `1000 mutants x 5-minute tests ~= 83 hours`; bu nedenle campaign tasarımı, mutator'ın kendisi kadar önemlidir.

## Kalıcı campaign'ler ve geniş ölçekte triage

Daha eski workflow'ların bir zayıflığı, sonuçları yalnızca `stdout`'a dökmeleridir. Uzun campaign'lerde bu durum pause/resume, filtering ve review işlemlerini zorlaştırır.<sup>[[1]](#references)</sup>

`mewt`/`MuTON`, mutant'ları ve sonuçları SQLite-backed campaign'lerde saklayarak bunu iyileştirir. Faydaları:<sup>[[1]](#references)</sup>
- Uzun çalışmaları ilerlemeyi kaybetmeden pause ve resume etme
- Belirli bir file veya mutation class içindeki yalnızca yakalanmamış mutantları filtreleme
- Sonuçları review tooling için SARIF'e export/translate etme
- AI-assisted triage'a raw terminal log'ları yerine daha küçük ve filtrelenmiş result set'leri sağlama

Kalıcı sonuçlar, mutation testing tek seferlik manual review yerine bir audit pipeline'ın parçası olduğunda özellikle kullanışlıdır.

## Hayatta kalan mutantlar için triage workflow'u

1) Mutated line'ı ve davranışı inceleyin.
- Mutated line'ı uygulayıp focused test çalıştırarak local ortamda yeniden üretin.

2) Testleri yalnızca return value'ları değil, state'i de assert edecek şekilde güçlendirin.
- Equality boundary kontrolleri ekleyin (ör. threshold `==` değerini test edin).
- Post-condition'ları assert edin: balances, total supply, authorization effects ve emitted events.

3) Aşırı permissive mock'ları realistic behavior ile değiştirin.
- Mock'ların on-chain gerçekleşen transfer'leri, failure path'lerini ve event emission'larını enforce ettiğinden emin olun.

4) Fuzz test'leri için invariant'lar ekleyin.
- Örn. value conservation, non-negative balances, authorization invariant'ları ve uygun olduğunda monotonic supply.

5) True positive'ları semantic no-op'lerden ayırın.
- Örnek: `x > 0` -> `x != 0`, `x` unsigned olduğunda anlamsızdır.

6) Survivor'lar öldürülene veya açıkça gerekçelendirilene kadar campaign'i yeniden çalıştırın.

## Case study: eksik state assertion'larını ortaya çıkarma (Arkis protocol)

Arkis DeFi protocol'ünün audit'i sırasında gerçekleştirilen bir mutation campaign, şu survivor'lar gibi sonuçları ortaya çıkardı:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Atamanın yorum satırına alınması testleri bozmadı; bu da eksik post-state assertion'larının bulunduğunu kanıtladı. Kök neden: kod, gerçek token transferlerini doğrulamak yerine kullanıcı tarafından kontrol edilen `_cmd.value` değerine güveniyordu. Bir saldırgan, beklenen ve gerçek transferleri senkron dışına çıkararak fonları boşaltabilirdi. Sonuç: protocol solvency açısından yüksek önem dereceli risk.<sup>[[2]](#references)[[3]](#references)</sup>

Yol gösterici ilke: Value transfer'larını, accounting'i veya access control'ü etkileyen ve hayatta kalan mutantları, etkisiz hale getirilene kadar yüksek riskli kabul edin.

## Her mutantı etkisiz hale getirmek için körü körüne test üretmeyin

Mutation-driven test generation, mevcut implementation hatalıysa ters tepebilir. Örneğin `priority >= 2` ifadesini `priority > 2` olarak mutate etmek davranışı değiştirir; ancak doğru çözüm her zaman "`priority == 2` için bir test yazmak" değildir. Bu davranışın kendisi de bug olabilir.<sup>[[1]](#references)</sup>

Daha güvenli workflow:
- Hayatta kalan mutantları belirsiz gereksinimleri belirlemek için kullanın
- Beklenen davranışı spec'lerden, protocol dokümanlarından veya reviewer'lardan doğrulayın
- Ancak bundan sonra davranışı bir test/invariant olarak kodlayın

Aksi takdirde implementation kazalarını test suite içine sabitleme ve yanlış güven kazanma riskiyle karşılaşırsınız.

## Pratik checklist

- Hedefli bir campaign çalıştırın:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Kullanılabilir olduğunda regex-only mutation yerine syntax-aware mutator'ları (AST/Tree-sitter) tercih edin.
- Hayatta kalan mutantları triage edin ve mutate edilmiş davranış altında başarısız olacak testler/invariant'lar yazın.
- Balance'ları, supply'yi, authorization'ları ve event'leri assert edin.
- Boundary test'leri ekleyin (`==`, overflow/underflow, zero-address, zero-amount, empty array'ler).
- Gerçekçi olmayan mock'ları değiştirin; failure mode'ları simulate edin.
- Tooling destekliyorsa sonuçları persist edin ve triage öncesinde yakalanmamış mutantları filter edin.
- Runtime'ı yönetilebilir tutmak için two-phase veya per-target campaign'ler kullanın.
- Tüm mutantlar etkisiz hale getirilene veya yorumlar ve gerekçelerle açıklanana kadar iterate edin.

## References

- [1] [Agentic era için mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Testlerinizin yakalayamadığı bug'ları bulmak için mutation testing kullanın (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
