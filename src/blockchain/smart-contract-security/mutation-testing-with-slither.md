# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" by systematically introducing small changes (mutants) into your Solidity code and re-running your test suite. If a test fails, the mutant is killed. If the tests still pass, the mutant survives, revealing a blind spot in your test suite that line/branch coverage cannot detect.

Ana fikir: Coverage, kodun çalıştırıldığını gösterir; mutation testing ise davranışın gerçekten doğrulandığını gösterir.

## Neden coverage yanıltıcı olabilir

Basit bir eşik kontrolünü düşünün:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Birim testleri yalnızca eşik değerinin altında bir değeri ve üzerinde bir değeri kontrol ediyorsa, equality boundary (==) eşitliğini doğrulamadan %100 line/branch coverage elde edebilir. `deposit >= 2 ether` şeklinde yapılacak bir refactor bu testleri yine geçer ve protokol mantığını sessizce bozabilir.

Mutation testing, koşulu değiştirip testlerinizin başarısız olduğunu doğrulayarak bu boşluğu ortaya çıkarır.

## Yaygın Solidity mutasyon operatörleri

Slither’in mutasyon motoru, semantiği değiştiren birçok küçük düzenleme uygular, örneğin:
- Operatör değiştirme: `+` ↔ `-`, `*` ↔ `/`, vb.
- Atama değiştirme: `+=` → `=`, `-=` → `=`
- Sabit değiştirme: sıfır olmayan → `0`, `true` ↔ `false`
- `if`/loop içindeki koşulun tersine çevrilmesi/değiştirilmesi
- Tüm satırları yorum satırı haline getirme (CR: Comment Replacement)
- Bir satırı `revert()` ile değiştirme
- Veri tipi değişimleri: örn., `int128` → `int64`

Hedef: Oluşturulan mutantların %100'ünün testler tarafından tespit edilip başarısızlığa yol açmasının sağlanması veya hayatta kalanlar için net gerekçe sunulması.

## slither-mutate ile mutasyon testi çalıştırma

Gereksinimler: Slither v0.10.2+.

- Seçenekleri ve mutator'ları listele:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry örneği (sonuçları yakala ve tam bir günlük tut):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Eğer Foundry kullanmıyorsanız, `--test-cmd`'i testleri nasıl çalıştırıyorsanız onunla değiştirin (örneğin, `npx hardhat test`, `npm test`).

Artefaktlar ve raporlar varsayılan olarak `./mutation_campaign` dizinine kaydedilir. Yakalanmamış (hayatta kalan) mutantlar inceleme için oraya kopyalanır.

### Çıktıyı anlamak

Rapor satırları şu şekilde görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki etiket mutatör takma adıdır (örn., `CR` = Comment Replacement).
- `UNCAUGHT` mutasyona uğramış davranış altında testlerin geçtiği anlamına gelir → eksik assertion.

## Reducing runtime: prioritize impactful mutants

Mutasyon kampanyaları saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:
- Scope: Önce yalnızca kritik contracts/directories ile başlayın, sonra genişletin.
- Prioritize mutators: Eğer bir satırdaki yüksek öncelikli bir mutant hayatta kalırsa (örn., tüm satır yorum haline gelmiş), o satır için düşük öncelikli varyantları atlayabilirsiniz.
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast: bir değişiklik açıkça bir assertion boşluğunu gösterdiğinde erken durdurun.

## Triage workflow for surviving mutants

1) Mutasyona uğramış satırı ve davranışı inceleyin.
- Mutasyona uğramış satırı uygulayıp yerelde odaklanmış bir test çalıştırarak yeniden üretin.

2) Testleri sadece dönüş değerlerini değil durumu assert edecek şekilde güçlendirin.
- Eşitlik-sınır kontrolleri ekleyin (örn., test threshold `==`).
- Post-koşulları assert edin: bakiyeler, total supply, yetkilendirme etkileri ve emit edilen event'ler.

3) Aşırı izin veren mock'ları gerçekçi davranışlarla değiştirin.
- Mock'ların on-chain gerçekleşen transferleri, hata yollarını ve event emit'lerini zorladığından emin olun.

4) Fuzz testleri için invariant'lar ekleyin.
- Örn., değer korunumu, negatif olmayan bakiyeler, yetkilendirme invariant'ları, uygulanabiliyorsa monoton supply.

5) slither-mutate'i, hayatta kalanlar öldürülene veya açıkça gerekçelendirilene kadar yeniden çalıştırın.

## Case study: revealing missing state assertions (Arkis protocol)

Arkis DeFi protokolünün bir audit sırasında yapılan bir mutasyon kampanyası şu tip hayatta kalanlar ortaya çıkardı:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Guidance: Treat survivors that affect value transfers, accounting, or access control as high-risk until killed.

## Pratik kontrol listesi

- Hedefe yönelik bir kampanya çalıştırın:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Survivor'ları önceliklendirin ve mutated davranış altında başarısız olacak testler/invariantler yazın.
- Bakiye, supply, authorizations ve events'i assert edin.
- Sınır testleri ekleyin (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Gerçekçi olmayan mocks'ları değiştirin; failure modlarını simüle edin.
- Tüm mutants öldürülene veya yorum ve gerekçe ile haklı çıkarılana kadar yineleyin.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
