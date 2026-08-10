# Web3 Signing Workflow Compromise ve Safe Delegatecall Proxy Takeover

## Overview

Bir cold-wallet theft chain, **Safe{Wallet} web UI'ının supply-chain compromise edilmesi** ile **proxy'nin implementation pointer'ını (slot 0) overwrite eden on-chain bir delegatecall primitive'ini** bir araya getirdi. Temel çıkarımlar:

- Bir dApp signing path'e code inject edebiliyorsa, bir signer'a **attacker tarafından seçilen alanlar üzerinde geçerli bir EIP-712 signature** ürettirebilir ve diğer signer'ların durumdan haberdar olmaması için orijinal UI verilerini geri yükleyebilir.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxy'leri `masterCopy`'yi (implementation) **storage slot 0**'da saklar. Slot 0'a yazan bir contract'a yapılan delegatecall, Safe'i etkin şekilde attacker logic'e “upgrade” eder ve cüzdan üzerinde tam kontrol sağlar.<sup>[[3]](#references)</sup>

## Off-chain: Safe{Wallet} içinde hedefli signing mutation

Manipüle edilmiş bir Safe bundle'ı (`_app-*.js`), belirli Safe + signer adreslerini seçici olarak hedef aldı. Inject edilen logic, signing call'dan hemen önce çalıştı:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: kurban Safe'ler/signers için hard-coded allowlist'ler gürültüyü önledi ve tespiti zorlaştırdı.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: alanlar (`to`, `data`, `operation`, gas), `signTransaction` çağrısından hemen önce üzerine yazıldı, ardından geri alındı; böylece UI'daki proposal payload'ları zararsız görünürken signature'lar attacker payload'ıyla eşleşti.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallet'lar structured data gösterdi ancak nested calldata'yı decode etmedi veya `operation = delegatecall` değerini vurgulamadı; bu da mutated message'ın fiilen blind-signed olmasına yol açtı.<sup>[[3]](#references)[[4]](#references)</sup>

### Gateway validation relevance
Safe proposal'ları **Safe Client Gateway**'e gönderilir.<sup>[[5]](#references)</sup> Hardened check'lerden önce gateway, UI bunları signing sonrasında yeniden yazarsa `safeTxHash`/signature'ın JSON body'deki alanlardan farklı olduğu bir proposal'ı kabul edebiliyordu. Incident sonrasında gateway, hash/signature gönderilen transaction ile eşleşmeyen proposal'ları artık reddediyor.<sup>[[3]](#references)</sup> Benzer server-side hash verification, signing-orchestration API'lerinde zorunlu kılınmalıdır.

### 2025 Bybit/Safe incident highlights
- 21 Şubat 2025'teki Bybit cold-wallet drain'i (~401k ETH) aynı pattern'i yeniden kullandı: compromised Safe S3 bundle yalnızca Bybit signers için tetiklendi ve `operation=0` → `1` değiştirildi; `to`, slot 0'a yazan pre-deployed attacker contract'ını gösterecek şekilde ayarlandı.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js`, logic'in Bybit'in Safe'i (`0x1db9…cf4`) ve signer address'lerine göre çalıştığını, ardından execution'dan iki dakika sonra clean bundle'a geri döndüğünü gösteriyor; bu, “mutate → sign → restore” trick'ini yansıtıyor.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (ör. `0x9622…c7242`), basit `sweepETH/sweepERC20` function'larının yanı sıra implementation slot'ına yazan bir `transfer(address,uint256)` içeriyordu. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` execution'ı proxy implementation'ını değiştirdi ve full control sağladı.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Slot collision üzerinden Delegatecall proxy takeover

Safe proxy'leri **storage slot 0**'da `masterCopy`'yi tutar ve tüm logic'i buna delegate eder. Safe, **`operation = 1` (delegatecall)** desteklediği için imzalanmış herhangi bir transaction, arbitrary bir contract'ı hedefleyebilir ve onun code'unu proxy'nin storage context'inde çalıştırabilir.<sup>[[3]](#references)</sup>

Bir attacker contract, ERC-20 `transfer(address,uint256)` function'ını taklit etti ancak bunun yerine `_to` değerini slot 0'a yazdı:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Yürütme yolu:<sup>[[1]](#references)[[3]](#references)</sup>
1. Mağdurlar `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)` ile `execTransaction` imzalar.
2. Safe masterCopy, bu parametreler üzerindeki imzaları doğrular.
3. Proxy, `attackerContract` içine delegatecall yapar; `transfer` gövdesi slot 0'a yazar.
4. Slot 0 (`masterCopy`) artık saldırganın kontrolündeki logic'i gösterir → **tam wallet ele geçirme ve fonların boşaltılması**.

### Guard ve sürüm notları (olay sonrası hardening)
- Transaction guard'ları Safe v1.3.0'da kullanıma sunuldu ve yürütme öncesinde tüm `execTransaction` parametrelerini inceleyebilir; bir guard, `delegatecall`'ı reddedebilir veya hedef ve calldata üzerinde policy uygulayabilir. Bybit, bu hook'tan önceki v1.1.1 sürümünü kullanıyordu.<sup>[[2]](#references)[[6]](#references)</sup>

## Detection ve hardening checklist

- **UI integrity**: JS asset'lerini / SRI'yi sabitleyin; bundle farklarını izleyin; signing UI'ını trust boundary'nin bir parçası olarak değerlendirin.
- **Sign-time validation**: **EIP-712 clear-signing** destekli hardware wallet'lar kullanın; `operation` değerini açıkça gösterin ve iç içe calldata'yı decode edin. Policy izin vermedikçe `operation = 1` olduğunda imzalamayı reddedin.<sup>[[3]](#references)</sup>
- **Server-side hash checks**: proposal'ları relay eden gateway/service'ler `safeTxHash` değerini yeniden hesaplamalı ve imzaların gönderilen alanlarla eşleştiğini doğrulamalıdır.<sup>[[3]](#references)</sup>
- **Policy/allowlists**: `to`, selector'lar ve asset türleri için preflight kuralları kullanın; incelenmiş flow'lar dışında delegatecall'ı yasaklayın. Tam imzalı transaction'ları broadcast etmeden önce dahili bir policy service gerektirin.
- **Contract design**: Kesinlikle gerekli olmadıkça multisig/treasury wallet'larında arbitrary delegatecall açığa çıkarmaktan kaçının. Her implementation pointer'ını bir upgrade primitive olarak değerlendirin: açık access control ile koruyun ve delegatecall hedeflerini/selector'larını guard ile sınırlayın; pointer'ı tek başına başka bir slot'a taşımak eksiksiz bir defense değildir.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: Treasury fonlarını tutan wallet'lardan gerçekleştirilen delegatecall yürütmeleri ve `operation` değerini tipik `call` pattern'lerinden değiştiren proposal'lar için alert oluşturun.

## References

- [1] [Bybit Safe exploit'inin AnChain.AI forensic incelemesi](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise hakkında Zero Hour Technology analizi](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack'inin derinlemesine teknik analizi (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 değişiklik günlüğü (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
