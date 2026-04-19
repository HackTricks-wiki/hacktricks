# Akıllı Sözleşmeler için Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing, sözleşme koduna sistematik olarak küçük değişiklikler (mutants) ekleyip test setini yeniden çalıştırarak "testlerinizi test eder". Bir test başarısız olursa, mutant öldürülür. Testler yine de geçerse, mutant hayatta kalır ve line/branch coverage ile tespit edilemeyen bir kör noktayı ortaya çıkarır.

Temel fikir: Coverage, kodun çalıştırıldığını gösterir; mutation testing ise davranışın gerçekten assert edilip edilmediğini gösterir.

## Why coverage can deceive

Bu basit threshold kontrolünü düşünün:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Sadece eşik altındaki ve eşik üstündeki bir değeri kontrol eden unit tests, eşitlik sınırını (==) doğrulamayı atlayarak %100 line/branch coverage elde edebilir. `deposit >= 2 ether` için yapılan bir refactor bu tür tests'i yine geçebilir ve protocol logic'i sessizce bozabilir.

Mutation testing, condition'ı mutate edip tests'in fail olmasını doğrulayarak bu boşluğu ortaya çıkarır.

Smart contracts için surviving mutants çoğu zaman şu eksik kontrollerle eşleşir:
- Authorization ve role sınırları
- Accounting/value-transfer invariants
- Revert koşulları ve failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## En yüksek security signal'a sahip mutation operators

Contract auditing için faydalı mutation sınıfları:
- **High severity**: execute edilmemiş paths'i ortaya çıkarmak için statements'i `revert()` ile değiştirin
- **Medium severity**: doğrulanmamış side effects'i açığa çıkarmak için satırları yorum satırı yapın / logic'i kaldırın
- **Low severity**: `>=` -> `>` veya `+` -> `-` gibi ince operator veya constant değişimleri
- Diğer yaygın edits: assignment replacement, boolean flips, condition negation ve type changes

Pratik hedef: anlamlı tüm mutants'ları öldürmek ve alakasız veya semantically equivalent olan survivors için açıkça gerekçe sunmak.

## Neden syntax-aware mutation regex'ten daha iyidir

Eski mutation engines regex veya line-oriented rewrites'a dayanıyordu. Bu çalışır, ama önemli sınırlamaları vardır:
- Multi-line statements güvenli şekilde mutate etmek zordur
- Language structure anlaşılmaz, bu yüzden comments/tokens yanlış hedeflenebilir
- Zayıf bir line üzerinde her olası variant'ı üretmek büyük miktarda runtime israf eder

AST- veya Tree-sitter-tabanlı tooling, raw lines yerine structured nodes'u hedefleyerek bunu iyileştirir:
- **slither-mutate** Slither'ın Solidity AST'sini kullanır
- **mewt** language-agnostic bir core olarak Tree-sitter kullanır
- **MuTON**, `mewt` üzerine kurulur ve FunC, Tolk ve Tact gibi TON dilleri için first-class support ekler

Bu, multi-line construct'ları ve expression-level mutations'ı regex-only yaklaşımlardan çok daha güvenilir hale getirir.

## slither-mutate ile mutation testing çalıştırma

Requirements: Slither v0.10.2+.

- Options ve mutators listesini çıkarın:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry örneği (sonuçları yakala ve tam bir log tut):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Foundry kullanmıyorsanız, `--test-cmd` yerine testleri nasıl çalıştırıyorsanız onu yazın (ör. `npx hardhat test`, `npm test`).

Artifacts varsayılan olarak `./mutation_campaign` içinde saklanır. Yakalanmayan (surviving) mutantlar inceleme için oraya kopyalanır.

### Çıktıyı anlama

Rapor satırları şöyle görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki tag, mutator alias’ıdır (ör. `CR` = Comment Replacement).
- `UNCAUGHT`, testlerin mutated behavior altında geçtiği anlamına gelir → missing assertion.

## Runtime’ı azaltma: etkili mutants’ları önceliklendirin

Mutation kampanyaları saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:
- Scope: Önce yalnızca kritik contracts/directory’lerden başlayın, sonra genişletin.
- Mutators’ı önceliklendirin: Bir satırdaki yüksek öncelikli mutant hayatta kalırsa (ör. `revert()` veya comment-out), o satır için daha düşük öncelikli varyantları atlayın.
- İki aşamalı kampanyalar kullanın: önce odaklı/hızlı testleri çalıştırın, sonra sadece uncaught mutants’ları full suite ile yeniden test edin.
- Mümkünse mutation targets’ı belirli test commands ile eşleştirin (ör. auth code -> auth tests).
- Zaman kısıtlıysa kampanyaları yüksek/orta severity mutant’larla sınırlayın.
- Runner’ınız destekliyorsa testleri paralelleştirin; dependencies/builds için cache kullanın.
- Fail-fast: bir değişiklik assertion gap’i açıkça gösteriyorsa erken durun.

Runtime hesabı acımasızdır: `1000 mutants x 5-minute tests ~= 83 hours`, bu yüzden kampanya tasarımı mutator’ın kendisi kadar önemlidir.

## Kalıcı kampanyalar ve ölçekli triage

Eski workflow’ların bir zayıflığı, sonuçları yalnızca `stdout`’a dökmeleridir. Uzun kampanyalarda bu, pause/resume, filtreleme ve review’u zorlaştırır.

`mewt`/`MuTON` bunu, mutants ve outcomes’ları SQLite-backed campaigns içinde saklayarak iyileştirir. Faydaları:
- İlerlemeyi kaybetmeden uzun çalışmaları duraklatıp devam ettirebilme
- Belirli bir file veya mutation class içindeki sadece uncaught mutants’ları filtreleme
- Review tooling için sonuçları SARIF’e export/translate etme
- AI-assisted triage’a ham terminal logs yerine daha küçük, filtrelenmiş result sets verme

Kalıcı sonuçlar, mutation testing tek seferlik manuel review yerine audit pipeline’ın bir parçası haline geldiğinde özellikle faydalıdır.

## Hayatta kalan mutants’lar için triage workflow’u

1) Mutated line ve behavior’ı inceleyin.
- Mutated line’ı uygulayıp odaklı bir test çalıştırarak yerelde yeniden üretin.

2) Testleri yalnızca return values değil, state’i de assert edecek şekilde güçlendirin.
- Equality-boundary kontrolleri ekleyin (ör. threshold `==` test edin).
- Post-conditions’ları assert edin: balances, total supply, authorization effects ve emitted events.

3) Fazla permissive mocks’ları gerçekçi behavior ile değiştirin.
- Mocks’un transfers, failure paths ve on-chain gerçekleşen event emissions’ları enforce ettiğinden emin olun.

4) Fuzz tests için invariants ekleyin.
- Örn. value conservation, negative olmayan balances, authorization invariants, uygun olduğu yerlerde monotonic supply.

5) Gerçek positives ile semantic no-op’ları ayırın.
- Örnek: `x > 0` -> `x != 0`, `x` unsigned ise anlamsızdır.

6) Survivors öldürülene veya açıkça gerekçelendirilene kadar kampanyayı yeniden çalıştırın.

## Case study: eksik state assertions’ları ortaya çıkarma (Arkis protocol)

Arkis DeFi protocol’ünün audit’i sırasında yapılan bir mutation campaign şu survivors’ları ortaya çıkardı:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Atamanın yorum satırına alınması testleri bozmadı; bu da eksik post-state assertions olduğunu kanıtlıyor. Kök neden: kod, gerçek token transferlerini doğrulamak yerine kullanıcı kontrollü bir `_cmd.value` değerine güvendi. Bir saldırgan, beklenen ve gerçek transferleri desynchronize ederek fonları drain edebilirdi. Sonuç: protokol solvency için yüksek şiddette risk.

Guidance: Değer transferlerini, accounting’i veya access control’u etkileyen survivors’ları öldürülene kadar high-risk olarak ele alın.

## Her mutantı öldürmek için körlemesine test üretmeyin

Mutation-driven test generation, mevcut implementation yanlışsa geri tepebilir. Örnek: `priority >= 2` ifadesini `priority > 2` olarak mutating davranışı değiştirir, ancak doğru fix her zaman " `priority == 2` için bir test yaz" değildir. Bu davranışın kendisi bug olabilir.

Daha güvenli workflow:
- Surviving mutants’ları ambiguous requirements’ları belirlemek için kullanın
- Beklenen davranışı specs, protocol docs veya reviewers’dan doğrulayın
- Ancak ondan sonra bu davranışı test/invariant olarak encode edin

Aksi halde, implementation kazalarını test suite içine hard-code eder ve yanlış bir güven hissi kazanırsınız.

## Pratik checklist

- Hedefli bir campaign çalıştırın:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Regex-only mutation yerine mümkün olduğunda syntax-aware mutators (AST/Tree-sitter) tercih edin.
- Survivors’ları triage edin ve mutating davranış altında başarısız olacak tests/invariants yazın.
- Balances, supply, authorizations ve events için assertions ekleyin.
- Boundary tests ekleyin (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Gerçekçi olmayan mocks’ları değiştirin; failure modes’u simüle edin.
- Tooling destekliyorsa results’ları persist edin ve triage öncesi uncaught mutants’ları filtreleyin.
- Runtime’ı yönetilebilir tutmak için iki aşamalı veya target başına campaign’ler kullanın.
- Tüm mutants öldürülene ya da comments ve rationale ile justified edilene kadar iterate edin.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
