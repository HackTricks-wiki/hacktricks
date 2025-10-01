# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" by systematically introducing small changes (mutants) into your Solidity code and re-running your test suite. If a test fails, the mutant is killed. If the tests still pass, the mutant survives, revealing a blind spot in your test suite that line/branch coverage cannot detect.

Key idea: Coverage shows code was executed; mutation testing shows whether behavior is actually asserted.

## Neden coverage aldatıcı olabilir

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
Birim testleri sadece eşik değerin altındaki ve üstündeki bir değeri kontrol ediyorsa, eşitlik sınırını (==) doğrulamadan %100 satır/branch kapsamına ulaşabilir. `deposit >= 2 ether` şeklinde yapılan bir refactor yine bu testleri geçer ve protokol mantığını sessizce bozabilir.

Mutasyon testi, koşulu değiştirerek ve testlerinizin başarısız olduğunu doğrulayarak bu boşluğu açığa çıkarır.

## Yaygın Solidity mutasyon operatörleri

Slither’s mutation engine birçok küçük, semantik değiştiren düzenleme uygular, örneğin:
- Operatör değiştirme: `+` ↔ `-`, `*` ↔ `/`, vb.
- Atama değiştirme: `+=` → `=`, `-=` → `=`
- Sabit değiştirme: sıfır olmayan → `0`, `true` ↔ `false`
- `if`/döngüler içinde koşulun tersine çevrilmesi/değiştirilmesi
- Tüm satırları yorum satırı haline getirme (CR: Comment Replacement)
- Bir satırı `revert()` ile değiştirme
- Veri tipi değişimleri: örn., `int128` → `int64`

Amaç: Oluşturulan mutantların %100'ünü etkisiz kılmak; hayatta kalanları ise açık gerekçelerle savunmak.

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
- Eğer Foundry kullanmıyorsanız, `--test-cmd` ile testleri çalıştırma komutunuzu değiştirin (ör. `npx hardhat test`, `npm test`).

Artefaktlar ve raporlar varsayılan olarak `./mutation_campaign` içinde saklanır. Yakalanmamış (hayatta kalan) mutantlar inceleme için oraya kopyalanır.

### Çıktıyı Anlama

Rapor satırları şu şekilde görünür:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Köşeli parantez içindeki etiket mutator takma adıdır (örn., `CR` = Comment Replacement).
- `UNCAUGHT` mutasyona uğramış davranış altında testlerin geçtiği anlamına gelir → eksik doğrulama.

## Çalışma süresini azaltma: etkili mutantlara öncelik verin

Mutasyon kampanyaları saatler veya günler sürebilir. Maliyeti azaltmak için ipuçları:
- Kapsam: Önce sadece kritik sözleşmeler/dizinlerle başlayın, sonra genişletin.
- Mutators'a öncelik verin: Bir satırdaki yüksek öncelikli bir mutant hayatta kalırsa (örn., tüm satır yorum satırı yapıldı), o satır için daha düşük öncelikli varyantları atlayabilirsiniz.
- Runner'ınız izin veriyorsa testleri paralelleştirin; bağımlılıkları/derlemeleri önbelleğe alın.
- Fail-fast: bir değişiklik açıkça bir doğrulama boşluğunu gösterdiğinde erken durun.

## Hayatta kalan mutantlar için triage iş akışı

1) Mutasyon uygulanmış satırı ve davranışı inceleyin.
- Mutasyonlu satırı uygulayıp odaklanmış bir test çalıştırarak yerelde yeniden üretin.

2) Testleri sadece dönüş değerlerini değil, durumu doğrulayacak şekilde güçlendirin.
- Eşitlik-sınır kontrolleri ekleyin (örn., eşik için `==` testi).
- Post-koşulları doğrulayın: bakiyeler, toplam arz, yetkilendirme etkileri ve yayılan olaylar.

3) Aşırı izin verici mock'ları gerçekçi davranışlarla değiştirin.
- Mock'ların on-chain gerçekleşen transferleri, hata yollarını ve olay yayınlarını zorunlu kıldığından emin olun.

4) Fuzz testleri için invariant'lar ekleyin.
- Örn., değer korunumu, negatif olmayan bakiyeler, yetkilendirme invariantları, uygulanabilir yerlerde monoton arz.

5) slither-mutate'i tekrar çalıştırın; hayatta kalanlar öldürülene kadar veya açıkça gerekçelendirene kadar.

## Vaka çalışması: eksik durum doğrulamalarını ortaya çıkarmak (Arkis DeFi protokolü)

Arkis DeFi protokolünün bir denetimi sırasında yürütülen bir mutasyon kampanyası şu tür hayatta kalanları ortaya çıkardı:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Atamanın yorum satırı haline getirilmesi testleri bozmadı; bu, son durum doğrulamalarının eksik olduğunu gösteriyor. Kök neden: kod, gerçek token transferlerini doğrulamak yerine kullanıcı kontrollü `_cmd.value`'ya güveniyordu. Bir saldırgan, beklenen ile gerçek transferleri senkronize etmeyerek fonları boşaltabilir. Sonuç: protokolün solventliği için yüksek risk.

Guidance: değer transferlerini, muhasebeyi veya erişim kontrolünü etkileyen survivors'ları killed edilene kadar yüksek risk olarak değerlendirin.

## Pratik kontrol listesi

- Hedefe yönelik bir kampanya yürütün:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Hayatta kalan mutantları sınıflandırın (triage) ve mutasyona uğramış davranışta başarısız olacak testler/invariant'lar yazın.
- Bakiyeleri, supply'ı, yetkilendirmeleri ve event'leri doğrulayın.
- Sınır testleri ekleyin (`==`, overflows/underflows, zero-address, zero-amount, boş diziler).
- Gerçekçi olmayan mock'ları değiştirin; hata modlarını simüle edin.
- Tüm mutantlar öldürülene (killed) veya yorumlar ve gerekçe ile haklı çıkarılana kadar yineleyin.

## Kaynaklar

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
