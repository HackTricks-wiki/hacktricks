# Akıllı Sözleşmeler için Mutation Testing (slither-mutate, mewt, MuTON)

Mutation testing, sözleşme koduna sistematik olarak küçük değişiklikler (mutantlar) ekleyip test paketini yeniden çalıştırarak "testlerinizi test eder". Bir test başarısız olursa mutant öldürülür. Testler yine başarılı olursa mutant hayatta kalır; bu da satır/branch coverage'ın tespit edemeyeceği bir kör noktayı ortaya çıkarır.

Temel fikir: Coverage, kodun çalıştırıldığını gösterir; mutation testing ise davranışın gerçekten assert edilip edilmediğini gösterir.<sup>[[2]](#references)</sup>

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
Yalnızca eşik değerinin altında ve üstünde bir değeri kontrol eden unit test'ler, eşitlik sınırını (`==`) doğrulamadan %100 line/branch coverage'a ulaşabilir. `deposit >= 2 ether` şeklinde yapılacak bir refactor, bu testlerden yine geçer ve protocol logic'i sessizce bozabilir.<sup>[[2]](#references)</sup>

Mutation testing, condition'ı mutate ederek ve testlerin başarısız olduğunu doğrulayarak bu açığı ortaya çıkarır.

Smart contract'lar için hayatta kalan mutant'lar sıklıkla şu eksik kontrollerle ilişkilidir:
- Authorization ve role sınırları
- Accounting/value-transfer invariant'ları
- Revert koşulları ve failure path'leri
- Sınır koşulları (`==`, sıfır değerler, boş array'ler, max/min değerler)

## En yüksek security sinyaline sahip mutation operator'ları

Contract auditing için kullanışlı mutation sınıfları:<sup>[[1]](#references)[[2]](#references)</sup>
- **Yüksek severity**: Çalıştırılmayan path'leri ortaya çıkarmak için statement'ları `revert()` ile değiştirme
- **Orta severity**: Doğrulanmamış side effect'leri ortaya çıkarmak için satırları comment out etme / logic'i kaldırma
- **Düşük severity**: `>=` -> `>` veya `+` -> `-` gibi ince operator ya da constant değişiklikleri
- Diğer yaygın değişiklikler: assignment replacement, boolean flip'leri, condition negation ve type değişiklikleri

Pratik hedef: Anlamlı tüm mutant'ları öldürmek ve ilgisiz veya semantically equivalent olan hayatta kalan mutant'ları açıkça gerekçelendirmektir.

## Syntax-aware mutation neden regex'ten daha iyidir

Eski mutation engine'leri regex veya line-oriented rewrite'lara dayanıyordu. Bu yöntem çalışır, ancak önemli sınırlamaları vardır:<sup>[[1]](#references)</sup>
- Multi-line statement'ları güvenli şekilde mutate etmek zordur
- Language structure anlaşılmadığından comment/token'lar hatalı şekilde hedeflenebilir
- Zayıf bir satır üzerinde her olası variant'ı üretmek büyük miktarda runtime harcar

AST veya Tree-sitter tabanlı tooling, raw line'lar yerine structured node'ları hedefleyerek bunu iyileştirir:<sup>[[1]](#references)</sup>
- **slither-mutate**, Slither'ın Solidity AST'sini kullanır.<sup>[[4]](#references)</sup>
- **mewt**, language-agnostic bir core olarak Tree-sitter kullanır.<sup>[[6]](#references)</sup>
- **MuTON**, `mewt` üzerine kuruludur ve FunC, Tolk ve Tact gibi TON language'leri için first-class support ekler.<sup>[[7]](#references)</sup>

Bu sayede multi-line construct'lar ve expression-level mutation'lar, yalnızca regex kullanan yaklaşımlara göre çok daha güvenilir hale gelir.

## slither-mutate ile mutation testing çalıştırma

Gereksinimler: Slither v0.10.2+.

- Option'ları ve mutator'ları listeleme:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry örneği (sonuçları yakalayın ve tam bir log tutun):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry kullanmıyorsanız, `--test-cmd` seçeneğini testleri çalıştırma yönteminizle değiştirin (ör. `npx hardhat test`, `npm test`).

Artifacts varsayılan olarak `./mutation_campaign` konumunda saklanır. Yakalanmamış (hayatta kalan) mutantlar incelenmek üzere buraya kopyalanır.<sup>[[5]](#references)</sup>

### Çıktıyı anlama

Rapor satırları şu şekilde görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki etiket, mutator alias'ıdır (ör. `CR` = Comment Replacement).
- `UNCAUGHT`, mutated davranış altında testlerin geçtiği anlamına gelir → eksik assertion.

## Runtime'ı azaltma: etkili mutantlara öncelik verme

Mutation campaign'leri saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:<sup>[[1]](#references)[[2]](#references)</sup>
- Kapsam: Yalnızca kritik contract/directory'lerle başlayın, ardından genişletin.
- Mutator'lara öncelik verin: Bir satırdaki yüksek öncelikli mutant hayatta kalırsa (örneğin `revert()` veya comment-out), o satır için daha düşük öncelikli varyantları atlayın.
- İki aşamalı campaign'ler kullanın: Önce odaklanmış/hızlı testleri çalıştırın, ardından yalnızca `UNCAUGHT` mutant'ları tüm test suite'iyle yeniden test edin.
- Mümkün olduğunda mutation target'larını belirli test komutlarıyla eşleyin (örneğin auth code -> auth testleri).
- Zaman kısıtlıysa campaign'leri high/medium severity mutant'larla sınırlandırın.
- Runner destekliyorsa testleri paralel çalıştırın; dependency/build'leri cache'leyin.
- Fail-fast: Bir değişiklik assertion gap'i açıkça gösterdiğinde erken durun.

Runtime hesabı acımasızdır: `1000 mutants x 5-minute tests ~= 83 hours`; bu nedenle campaign tasarımı, mutator'ın kendisi kadar önemlidir.<sup>[[1]](#references)</sup>

## Kalıcı campaign'ler ve büyük ölçekte triage

Eski workflow'ların bir zayıflığı, sonuçları yalnızca `stdout`'a dökmeleridir. Uzun campaign'lerde bu durum pause/resume, filtering ve review işlemlerini zorlaştırır.<sup>[[1]](#references)</sup>

`mewt`/`MuTON`, mutant'ları ve sonuçları SQLite-backed campaign'lerde saklayarak bunu geliştirir. Faydaları:<sup>[[1]](#references)</sup>
- Uzun çalışmaları ilerlemeyi kaybetmeden pause ve resume etme
- Belirli bir file veya mutation class içindeki yalnızca `UNCAUGHT` mutant'ları filtreleme
- Review tooling için sonuçları SARIF'e export/translate etme
- AI-assisted triage'a ham terminal log'ları yerine daha küçük, filtrelenmiş result set'leri sağlama

Kalıcı sonuçlar, mutation testing tek seferlik manual review yerine bir audit pipeline'ın parçası olduğunda özellikle kullanışlıdır.

## Hayatta kalan mutant'lar için triage workflow'u

1) Mutated satırı ve davranışı inceleyin.
- Mutated satırı uygulayıp odaklanmış bir test çalıştırarak local olarak reproduce edin.

2) Testleri yalnızca return value'ları değil, state'i de assert edecek şekilde güçlendirin.
- Equality boundary check'leri ekleyin (ör. threshold `==` değerini test edin).
- Post-condition'ları assert edin: balance'lar, total supply, authorization etkileri ve emit edilen event'ler.

3) Aşırı permissive mock'ları gerçekçi davranışlarla değiştirin.
- Mock'ların on-chain gerçekleşen transfer'leri, failure path'lerini ve event emission'larını enforce ettiğinden emin olun.

4) Fuzz test'leri için invariant'lar ekleyin.
- Örn. value conservation, non-negative balance'lar, authorization invariant'ları ve uygun olduğunda monotonic supply.

5) True positive'ları semantic no-op'lardan ayırın.
- Örnek: `x > 0` -> `x != 0`, `x` unsigned olduğunda anlamsızdır.

6) Survivor'lar kill edilene veya açıkça gerekçelendirilene kadar campaign'i yeniden çalıştırın.

## Vaka çalışması: eksik state assertion'larının ortaya çıkarılması (Arkis protocol)

Arkis DeFi protocol'ünün audit'i sırasında yürütülen bir mutation campaign, şu tür hayatta kalan mutant'ları ortaya çıkardı:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Atamanın yorum satırına alınması testleri bozmadı; bu da post-state assertions eksikliğini kanıtladı. Temel neden: kod, gerçek token transferlerini doğrulamak yerine kullanıcı tarafından kontrol edilen `_cmd.value` değerine güveniyordu. Bir attacker, beklenen ve gerçek transferleri senkron dışına çıkararak fonları boşaltabilirdi. Sonuç: protocol solvency açısından yüksek severity riski.<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: Value transferlarını, accounting'i veya access control'ü etkileyen survivor'ları öldürülene kadar yüksek riskli kabul edin.

## Her mutantı öldürmek için körü körüne test üretmeyin

Mutation-driven test generation, mevcut implementation yanlışsa ters tepebilir. Örnek: `priority >= 2` ifadesini `priority > 2` olarak mutate etmek davranışı değiştirir, ancak doğru çözüm her zaman `priority == 2` için bir test yazmak değildir. Bu davranışın kendisi bug olabilir.<sup>[[1]](#references)</sup>

Daha güvenli workflow:
- Belirsiz gereksinimleri tespit etmek için surviving mutant'ları kullanın
- Beklenen davranışı spec'lerden, protocol dokümanlarından veya reviewer'lardan doğrulayın
- Ancak bundan sonra davranışı bir test/invariant olarak kodlayın

Aksi takdirde implementation kazalarını test suite'e sabitleme ve false confidence kazanma riski taşırsınız.

## Pratik checklist

- Hedefli bir campaign çalıştırın:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Mevcut olduğunda regex-only mutation yerine syntax-aware mutator'ları (AST/Tree-sitter) tercih edin.
- Survivor'ları triage edin ve mutated davranış altında fail edecek testler/invariant'lar yazın.
- Balance'ları, supply'yi, authorization'ları ve event'leri assert edin.
- Boundary test'leri ekleyin (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Gerçekçi olmayan mock'ları değiştirin; failure mode'larını simulate edin.
- Tooling desteklediğinde sonuçları persist edin ve triage öncesinde yakalanmamış mutant'ları filter'layın.
- Runtime'ı yönetilebilir tutmak için two-phase veya per-target campaign'ler kullanın.
- Tüm mutant'lar öldürülene veya comments ve rationale ile gerekçelendirilene kadar iterate edin.

## References

- [1] [Agentic era için mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Testlerinizin yakalayamadığı bug'ları bulmak için mutation testing kullanın (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator dokümantasyonu](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
