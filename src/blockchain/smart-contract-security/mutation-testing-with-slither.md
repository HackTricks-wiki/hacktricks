# Smart Contract'lar için Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing, contract koduna sistematik olarak küçük değişiklikler (mutant'lar) ekleyip test suite'ini yeniden çalıştırarak "test'lerinizi test eder". Bir test başarısız olursa mutant öldürülür. Testler hâlâ başarılı olursa mutant hayatta kalır ve line/branch coverage'ın tespit edemediği bir kör noktayı ortaya çıkarır.

Temel fikir: Coverage, kodun çalıştırıldığını gösterir; mutation testing ise davranışın gerçekten assert edilip edilmediğini gösterir.<sup>[[2]](#references)</sup>

## Coverage neden yanıltıcı olabilir?

Şu basit threshold kontrolünü düşünün:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Yalnızca bir değerin eşik değerinin altında ve bir değerin üstünde olduğunu kontrol eden unit test'ler, eşitlik sınırını (`==`) doğrulamayı başaramasına rağmen %100 satır/dal kapsamına ulaşabilir. `deposit >= 2 ether` şeklinde yapılacak bir refactor yine de bu testlerden geçerek protokol mantığını sessizce bozabilir.<sup>[[2]](#references)</sup>

Mutation testing, koşulu mutate ederek ve testlerin başarısız olduğunu doğrulayarak bu boşluğu ortaya çıkarır.

Smart contract'lar için hayatta kalan mutant'lar sıklıkla şu konulardaki eksik kontrollerle eşleşir:
- Authorization ve role sınırları
- Accounting/değer transferi invariant'ları
- Revert koşulları ve failure path'ler
- Sınır koşulları (`==`, sıfır değerler, boş array'ler, maksimum/minimum değerler)

## En yüksek security sinyaline sahip mutation operatörleri

Contract auditing için kullanışlı mutation sınıfları:<sup>[[1]](#references)[[2]](#references)</sup>
- **Yüksek önem derecesi**: Çalıştırılmayan path'leri ortaya çıkarmak için statement'ları `revert()` ile değiştirme
- **Orta önem derecesi**: Doğrulanmamış side effect'leri ortaya çıkarmak için satırları comment'leme / logic'i kaldırma
- **Düşük önem derecesi**: `>=` -> `>` veya `+` -> `-` gibi ince operator ya da constant değişiklikleri
- Diğer yaygın değişiklikler: assignment replacement, boolean flip'leri, condition negation ve type değişiklikleri

Pratik hedef: Anlamlı tüm mutant'ları kill etmek ve ilgisiz veya semantic olarak eşdeğer olan hayatta kalan mutant'ları açıkça gerekçelendirmektir.

## Syntax-aware mutation neden regex'ten daha iyidir

Daha eski mutation engine'leri regex veya satır tabanlı yeniden yazımlara dayanıyordu. Bu yöntem işe yarar, ancak önemli sınırlamaları vardır:<sup>[[1]](#references)</sup>
- Multi-line statement'ları güvenli şekilde mutate etmek zordur
- Language structure anlaşılmadığından comment'ler/token'lar hatalı şekilde hedeflenebilir
- Zayıf bir satır üzerinde mümkün olan her variant'ı üretmek büyük miktarda runtime harcar

AST veya Tree-sitter tabanlı tooling, raw satırlar yerine structured node'ları hedefleyerek bunu iyileştirir:<sup>[[1]](#references)</sup>
- **slither-mutate**, Slither'ın Solidity AST'sini kullanır<sup>[[4]](#references)</sup>
- **mewt**, language-agnostic bir core olarak Tree-sitter kullanır<sup>[[6]](#references)</sup>
- **MuTON**, `mewt` üzerine kuruludur ve FunC, Tolk ve Tact gibi TON language'leri için first-class support ekler<sup>[[7]](#references)</sup>

Bu sayede multi-line construct'lar ve expression-level mutation'lar, yalnızca regex kullanan yaklaşımlara kıyasla çok daha güvenilir hale gelir.

## slither-mutate ile mutation testing çalıştırma

Requirements: Slither v0.10.2+.

- Seçenekleri ve mutator'ları listeleme:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry örneği (sonuçları yakalayın ve tam bir günlük tutun):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry kullanmıyorsanız, `--test-cmd` seçeneğini testleri nasıl çalıştırdığınızla değiştirin (ör. `npx hardhat test`, `npm test`).

Artifacts varsayılan olarak `./mutation_campaign` dizininde saklanır. Yakalanmayan (hayatta kalan) mutantlar incelenmek üzere buraya kopyalanır.<sup>[[5]](#references)</sup>

### Çıktıyı anlama

Rapor satırları şu şekilde görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki tag, mutator alias'ıdır (ör. `CR` = Comment Replacement).
- `UNCAUGHT`, testlerin mutated behavior altında geçtiği anlamına gelir → eksik assertion.

## Runtime'ı azaltma: etkili mutantlara öncelik verme

Mutation campaign'leri saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:<sup>[[1]](#references)[[2]](#references)</sup>
- Kapsam: Yalnızca kritik contract/directory'lerle başlayın, ardından kapsamı genişletin.
- Mutator'lara öncelik verin: Bir satırdaki high-priority mutant hayatta kalırsa (örneğin `revert()` veya comment-out), o satır için lower-priority varyantları atlayın.
- İki aşamalı campaign kullanın: Önce odaklanmış/hızlı testleri çalıştırın, ardından yalnızca yakalanmamış mutant'ları full suite ile yeniden test edin.
- Mümkün olduğunda mutation target'larını belirli test command'lerine eşleyin (örneğin auth code -> auth tests).
- Zaman kısıtlıysa campaign'leri high/medium severity mutant'larla sınırlandırın.
- Runner destekliyorsa testleri paralel çalıştırın; dependency/build cache kullanın.
- Fail-fast: Bir değişiklik assertion gap'i açıkça gösterdiğinde erken durdurun.

Runtime hesabı acımasızdır: `1000 mutants x 5-minute tests ~= 83 hours`; bu nedenle campaign tasarımı mutator'ın kendisi kadar önemlidir.<sup>[[1]](#references)</sup>

## Kalıcı campaign'ler ve geniş ölçekte triage

Eski workflow'ların bir zayıflığı, sonuçları yalnızca `stdout`'a yazmasıdır. Uzun campaign'lerde bu durum pause/resume, filtering ve review işlemlerini zorlaştırır.<sup>[[1]](#references)[[2]](#references)</sup>

`mewt`/`MuTON`, mutant'ları ve sonuçları SQLite-backed campaign'lerde depolayarak bunu iyileştirir. Faydaları:<sup>[[1]](#references)</sup>
- İlerlemeyi kaybetmeden uzun çalışmaları pause ve resume etme
- Belirli bir file veya mutation class içindeki yalnızca yakalanmamış mutant'ları filtreleme
- Sonuçları review tooling için SARIF'e export/translate etme
- AI-assisted triage işlemlerine raw terminal log'ları yerine daha küçük ve filtrelenmiş result set'leri sağlama

Persistent results, mutation testing tek seferlik bir manual review yerine audit pipeline'ın parçası olduğunda özellikle kullanışlıdır.

## Hayatta kalan mutant'lar için triage workflow'u

1) Mutated line'ı ve behavior'ı inceleyin.
- Mutated line'ı uygulayıp focused test çalıştırarak local ortamda reproduce edin.

2) Test'leri yalnızca return value'ları değil, state'i assert edecek şekilde güçlendirin.
- Equality boundary check'leri ekleyin (ör. threshold `==` test edin).
- Post-condition'ları assert edin: balance'lar, total supply, authorization etkileri ve emit edilen event'ler.

3) Aşırı permissive mock'ları realistic behavior ile değiştirin.
- Mock'ların on-chain gerçekleşen transfer'leri, failure path'lerini ve event emission'larını enforce ettiğinden emin olun.

4) Fuzz test'leri için invariant'lar ekleyin.
- Örn. value conservation, non-negative balance'lar, authorization invariant'ları ve uygulanabildiği yerlerde monotonic supply.

5) True positive'ları semantic no-op'lardan ayırın.
- Örnek: `x > 0` -> `x != 0`, `x` unsigned olduğunda anlamsızdır.

6) Survivor'lar öldürülene veya açıkça gerekçelendirilene kadar campaign'i yeniden çalıştırın.

## Case study: eksik state assertion'larının ortaya çıkarılması (Arkis protocol)

Arkis DeFi protocol'ünün audit'i sırasında yürütülen bir mutation campaign, şu tür survivor'ları ortaya çıkardı:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Atamanın yorum satırına alınması testleri bozmadı; bu da eksik post-state assertion'larını kanıtladı. Temel neden: kod, gerçek token transferlerini doğrulamak yerine kullanıcı tarafından kontrol edilen `_cmd.value` değerine güveniyordu. Bir saldırgan, beklenen ve gerçek transferleri senkron dışına çıkararak fonları boşaltabilirdi. Sonuç: protocol solvency açısından yüksek önem dereceli risk.<sup>[[2]](#references)[[3]](#references)</sup>

Rehber: Value transfer'larını, accounting'i veya access control'ü etkileyen hayatta kalan mutant'ları öldürülene kadar yüksek riskli kabul edin.

## Her mutant'ı öldürmek için körü körüne test üretmeyin

Mutation-driven test generation, mevcut implementation yanlışsa ters tepebilir. Örnek: `priority >= 2` ifadesini `priority > 2` olarak mutate etmek davranışı değiştirir, ancak doğru düzeltme her zaman "`priority == 2` için bir test yazmak" değildir. Bu davranışın kendisi bug olabilir.<sup>[[1]](#references)</sup>

Daha güvenli workflow:
- Belirsiz gereksinimleri tespit etmek için hayatta kalan mutant'ları kullanın
- Beklenen davranışı spec'lerden, protocol dokümanlarından veya reviewer'lar aracılığıyla doğrulayın
- Ancak bundan sonra davranışı bir test/invariant olarak kodlayın

Aksi takdirde implementation kazalarını test suite içine sabitleme ve yanlış güven kazanma riski taşırsınız.

## Pratik checklist

- Hedefli bir campaign çalıştırın:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Mevcut olduğunda regex-only mutation yerine syntax-aware mutator'ları (AST/Tree-sitter) tercih edin.
- Hayatta kalan mutant'ları triage edin ve mutated davranış altında başarısız olacak testler/invariant'lar yazın.
- Bakiyeleri, supply'yi, authorization'ları ve event'leri assert edin.
- Sınır testleri ekleyin (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Gerçekçi olmayan mock'ları değiştirin; failure mode'ları simüle edin.
- Tooling desteklediğinde sonuçları persist edin ve triage öncesinde yakalanmamış mutant'ları filtreleyin.
- Runtime'ı yönetilebilir tutmak için two-phase veya per-target campaign'ler kullanın.
- Tüm mutant'lar öldürülene veya comments ve rationale ile gerekçelendirilene kadar yineleyin.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
