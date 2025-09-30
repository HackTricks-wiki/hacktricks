# Mutation Testing Solidity için Slither ile (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" — Solidity kodunuza sistematik olarak küçük değişiklikler (mutantlar) ekleyip test süitinizi yeniden çalıştırarak yapılır. Bir test başarısız olursa mutant öldürülür. Testler hâlâ geçerse mutant hayatta kalır; bu, line/branch coverage'ın tespit edemeyeceği test süitinizdeki bir kör noktayı ortaya çıkarır.

Ana fikir: Coverage kodun çalıştırıldığını gösterir; mutation testing ise davranışın gerçekten doğrulanıp doğrulanmadığını gösterir.

## Coverage neden yanıltıcı olabilir

Bu basit eşik kontrolünü düşünün:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit tests that only check a value below and a value above the threshold can reach 100% line/branch coverage while failing to assert the equality boundary (==). A refactor to `deposit >= 2 ether` would still pass such tests, silently breaking protocol logic.

Mutation testing exposes this gap by mutating the condition and verifying your tests fail.

## Yaygın Solidity mutasyon operatörleri

Slither’s mutation engine applies many small, semantics-changing edits, such as:
- Operator replacement: `+` ↔ `-`, `*` ↔ `/`, etc.
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement inside `if`/loops
- Comment out whole lines (CR: Comment Replacement)
- Replace a line with `revert()`
- Data type swaps: e.g., `int128` → `int64`

Goal: Kill 100% of generated mutants, or justify survivors with clear reasoning.

## slither-mutate ile mutation testing çalıştırma

Gereksinimler: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry örneği (sonuçları yakalayın ve tam bir log tutun):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Eğer Foundry kullanmıyorsanız, testleri nasıl çalıştırıyorsanız ona göre `--test-cmd`'i değiştirin (ör. `npx hardhat test`, `npm test`).

Çıktılar ve raporlar varsayılan olarak `./mutation_campaign` dizininde saklanır. Yakalanmamış (hayatta kalan) mutantlar inceleme için oraya kopyalanır.

### Çıktıyı Anlamak

Rapor satırları şu şekilde görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki etiket mutator takma adıdır (ör. `CR` = Comment Replacement).
- `UNCAUGHT` testlerin mutant davranışı altında geçtiği anlamına gelir → eksik assertion.

## Çalışma süresini azaltma: etkili mutantlara öncelik verin

Mutation kampanyaları saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:
- Scope: Önce yalnızca kritik contracts/dizinlerle başlayın, sonra genişletin.
- Mutatorlara öncelik verin: Bir satırdaki yüksek öncelikli mutant sağ kalırsa (ör. tüm satır yorum haline getirilmiş gibi), o satır için daha düşük öncelikli varyantları atlayabilirsiniz.
- Testleri paralelleştirin; runner'ınız izin veriyorsa; bağımlılıkları/build'leri cache'leyin.
- Fail-fast: bir değişiklik belirgin şekilde bir assertion açığını gösterdiğinde erken durun.

## Hayatta kalan mutantlar için triage iş akışı

1) Mutasyona uğramış satırı ve davranışı inceleyin.
- Değiştirilmiş satırı uygulayıp odaklanmış bir testi çalıştırarak yerelde yeniden üretin.

2) Testleri sadece dönüş değerlerine değil, durum doğrulamaya güçlendirin.
- Eşitlik-sınır kontrolleri ekleyin (ör. test threshold `==`).
- Post-conditions doğrulayın: bakiyeler, toplam arz, yetkilendirme etkileri ve yayınlanan event'ler.

3) Aşırı izin verici mock'ları gerçekçi davranışlarla değiştirin.
- Mock'ların zincirde gerçekleşen transferleri, hata yollarını ve event yayınlamayı zorunlu kıldığından emin olun.

4) Fuzz testleri için invariants ekleyin.
- Ör. değer korunumu, negatif olmayan bakiyeler, yetkilendirme invariants, uygulanabiliyorsa monotonik arz.

5) slither-mutate'i, hayatta kalanlar öldürülene ya da açıkça gerekçelendirilene kadar yeniden çalıştırın.

## Vaka çalışması: eksik durum assertion'larını ortaya çıkarmak (Arkis DeFi protocol)

Arkis DeFi protocol denetimi sırasında yapılan bir mutation kampanyası şu hayatta kalanları gün yüzüne çıkardı:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Atamanın yorum satırı haline getirilmesi testleri kırmadı; bu, son-durum doğrulamalarının eksik olduğunu kanıtladı. Kök neden: kod, gerçek token transferlerini doğrulamak yerine kullanıcı kontrollü `_cmd.value` değerine güvendi. Bir saldırgan beklenen ile gerçek transferlerin eşleşmesini bozarak fonları boşaltabilir. Sonuç: protokolün ödenebilirliği için yüksek şiddette risk.

Rehber: değer transferlerini, muhasebeyi veya erişim kontrolünü etkileyen hayatta kalan mutantları (survivors), öldürülene kadar yüksek riskli olarak değerlendirin.

## Pratik kontrol listesi

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Hayatta kalan mutantları triage edip, mutasyona uğramış davranış altında başarısız olacak testler/invariantlar yazın.
- Bakiyeleri, arzı, yetkilendirmeleri ve olayları assert edin.
- Add boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Gerçekçi olmayan mocks'ları değiştirin; hata durumlarını simüle edin.
- Tüm mutantlar öldürülene veya yorumlar ve gerekçelerle haklı gösterilene kadar yineleyin.

## Referanslar

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
