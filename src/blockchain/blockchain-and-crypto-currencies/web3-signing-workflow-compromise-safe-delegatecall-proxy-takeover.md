# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Bir cold-wallet hırsızlık zinciri, Safe{Wallet} web UI'sinin bir **supply-chain compromise** ile ve proxy’nin implementation pointer’ını (slot 0) üzerine yazan bir **on-chain delegatecall primitive** ile birleşti. Öne çıkan noktalar:

- Eğer bir dApp imzalama yoluna kod enjekte edebiliyorsa, bir signer'ı saldırganın seçtiği alanlar üzerinde geçerli bir **EIP-712 signature** üretmeye zorlayabilir ve aynı zamanda orijinal UI verisini geri yükleyerek diğer signer'ların habersiz kalmasını sağlayabilir.
- Safe proxy'ları `masterCopy` (implementation) öğesini **storage slot 0**'da saklar. Slot 0'a yazan bir delegatecall, Safe'i etkin olarak saldırgan mantığına “upgrade” ederek cüzdanın tam kontrolünü verir.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Tahrif edilmiş bir Safe bundle'ı (`_app-*.js`) belirli Safe + signer adreslerini seçici olarak hedefledi. Enjekte edilen mantık imzalama çağrısından hemen önce çalıştırıldı:
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
- **Context-gated**: hedef Safe'ler/signers için sabitlenmiş allowlist'ler gürültüyü önledi ve tespiti azalttı.
- **Last-moment mutation**: alanlar (`to`, `data`, `operation`, gas) `signTransaction`'dan hemen önce üzerine yazıldı, sonra geri alındı; bu yüzden UI'daki proposal yükleri masum görünürken imzalar saldırgan payload ile eşleşiyordu.
- **EIP-712 opacity**: cüzdanlar yapılandırılmış veriyi gösteriyordu ama iç içe calldata'yı çözmüyor veya `operation = delegatecall`'ı vurgulamıyordu, bu da değiştirilen mesajın pratikte blind-signed olmasına neden oldu.

### Gateway validation relevance
Safe proposals **Safe Client Gateway**'e gönderilir. Sertleştirilmiş kontrollerden önce, gateway UI imzalamadan sonra alanları yeniden yazdıysa `safeTxHash`/signature'ın JSON gövdesindeki farklı alanlara karşılık geldiği bir proposal'ı kabul edebiliyordu. Olaydan sonra gateway artık hash/imza gönderilen transaction ile eşleşmeyen proposal'leri reddediyor. Benzer sunucu-tarafı hash doğrulaması herhangi bir signing-orchestration API'sinde zorunlu kılınmalıdır.

### 2025 Bybit/Safe incident highlights
- 21 Şubat 2025 Bybit cold-wallet boşaltması (~401k ETH) aynı deseni yeniden kullandı: ele geçirilmiş bir Safe S3 bundle yalnızca Bybit signers için tetiklendi ve `operation=0` → `1` olarak değiştirildi, `to` slot 0 yazan önceden deploy edilmiş saldırgan kontratına işaret etti.
- Wayback-cached `_app-52c9031bfa03da47.js` mantığın Bybit’in Safe (`0x1db9…cf4`) ve signer adreslerine göre anahtarlandığını gösteriyor ve yürütmeden iki dakika sonra hemen temiz bir bundle'a geri alındı; bu, “mutate → sign → restore” hilesini yansıtıyor.
- Kötü niyetli kontrat (ör. `0x9622…c7242`) basit `sweepETH/sweepERC20` fonksiyonlarının yanı sıra implementation slot'una yazan bir `transfer(address,uint256)` içeriyordu. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` yürütülmesi proxy implementation'ını kaydırdı ve tam kontrol sağladı.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxy'ları `masterCopy`'ı **storage slot 0**'da tutar ve tüm mantığı ona devreder. Safe **`operation = 1` (delegatecall)**'i desteklediği için, herhangi bir imzalı transaction rastgele bir kontrata işaret edebilir ve kodunu proxy’nin storage bağlamında çalıştırabilir.

Bir saldırgan kontrat ERC-20 `transfer(address,uint256)`'ini taklit etti fakat bunun yerine `_to`'yu slot 0'a yazdı:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
İcra yolu:
1. Kurbanlar `execTransaction`'ı `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)` ile imzalar.
2. Safe masterCopy bu parametreler üzerindeki imzaları doğrular.
3. Proxy, `attackerContract`'a delegatecall yapar; `transfer` gövdesi slot 0'a yazar.
4. Slot 0 (`masterCopy`) artık saldırgan kontrollü mantığa işaret eder → **tam cüzdan ele geçirme ve fon boşaltma**.

### Guard & sürüm notları (olay sonrası sertleştirme)
- Safes >= v1.3.0, `delegatecall`'ı veto etmek veya `to`/selectors üzerinde ACL uygulamak için bir **Guard** kurabilir; Bybit v1.1.1 çalıştırıyordu, bu yüzden Guard hook yoktu. Bu kontrol düzlemini kazanmak için sözleşmelerin yükseltilmesi (ve sahiplerin yeniden eklenmesi) gerekir.

## Tespit ve sertleştirme kontrol listesi

- **UI integrity**: JS varlıklarını pinleyin / SRI; bundle diff'lerini izleyin; imzalama UI'sını güven sınırının bir parçası olarak değerlendirin.
- **Sign-time validation**: donanım cüzdanları ile **EIP-712 clear-signing**; `operation`'ı açıkça render edin ve iç içe calldata'yı decode edin. Politika izin vermiyorsa `operation = 1` iken imzalamayı reddedin.
- **Server-side hash checks**: teklifleri ileten gateway/service'ler `safeTxHash`'i yeniden hesaplamalı ve imzaların gönderilen alanlarla eşleştiğini doğrulamalı.
- **Policy/allowlists**: `to`, selector'lar, varlık türleri için preflight kuralları uygulayın ve vetted flow'lar dışında delegatecall'ı yasaklayın. Tam imzalanmış işlemleri yayınlamadan önce dahili bir politika servisi gerektirin.
- **Contract design**: multisig/treasury cüzdanlarda keyfi delegatecall'ı gerekmedikçe açığa çıkarmayın. Yükseltme işaretçilerini slot 0'dan uzağa koyun veya açık yükseltme mantığı ve erişim kontrolü ile koruyun.
- **Monitoring**: hazinede fon tutan cüzdanlardan yapılan delegatecall yürütmeleri için uyarı verin ve `operation`'ı tipik `call` desenlerinden değiştiren teklifler için alarm kurun.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
