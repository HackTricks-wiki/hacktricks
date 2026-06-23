# ERC-4337 Smart Account Güvenlik Tuzakları

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction, cüzdanları programlanabilir sistemlere dönüştürür. Temel akış, tüm bundle boyunca **doğrula-sonra-yürüt** şeklindedir: `EntryPoint`, herhangi bir `UserOperation` yürütmeden önce her birini doğrular. Bu sıralama, validation permissive, stateful veya bundler simulation rules ile tutarsız olduğunda bariz olmayan bir attack surface oluşturur.

## 1) Privileged functions için direct-call bypass
`EntryPoint` ile (veya doğrulanmış bir executor module ile) sınırlandırılmamış herhangi bir externally callable `execute` (veya fund-moving) function, hesabı drain etmek için doğrudan çağrılabilir.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Güvenli desen: `EntryPoint` ile sınırlandırın ve admin/kendi kendini yönetme akışları (module install, validator değişiklikleri, upgrades) için `msg.sender == address(this)` kullanın.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) İmzalanmamış veya kontrol edilmemiş gas alanları -> fee drain
Eğer signature doğrulaması yalnızca intent’i (`callData`) kapsıyor ama gas ile ilgili alanları kapsamıyorsa, bir bundler veya frontrunner fee’leri şişirip ETH drain edebilir. İmzalanmış payload en az şunları bağlamalıdır:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint` tarafından sağlanan `userOpHash`’i kullanın (gas alanlarını içerir) ve/veya her alanı sıkı şekilde sınırlandırın.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
Tüm validation'lar herhangi bir execution'dan önce çalıştığı için, validation sonuçlarını contract state'inde saklamak güvensizdir. Aynı bundle içindeki başka bir op bunu overwrite edebilir ve execution'ınızın attacker-influenced state kullanmasına neden olabilir.

`validateUserOp` içinde storage yazmaktan kaçının. Kaçınılmazsa, geçici veriyi `userOpHash` ile key'leyin ve kullanımdan sonra deterministik olarak silin (tercihen stateless validation kullanın).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` imzaları **bu contract** ve **bu chain** ile bağlamalıdır. Raw bir hash üzerinde recovery yapmak, imzaların accounts veya chains arasında replay edilmesine izin verir.

EIP-712 typed data kullanın (domain içinde `verifyingContract` ve `chainId` yer alır) ve başarı durumunda tam ERC-1271 magic value olan `0x1626ba7e` döndürün.

## 5) Reverts do not refund after validation
`validateUserOp` başarılı olduktan sonra, execution daha sonra revert etse bile fees commit edilir. Attackers, başarısız olacak op'ları tekrar tekrar gönderip yine de account'tan fees toplayabilir.

Paymaster'lar için, `validateUserOp` içinde shared pool'dan ödeme yapmak ve kullanıcıları `postOp` içinde charge etmek kırılgandır çünkü `postOp` ödeme geri alınmadan revert edebilir. Validation sırasında fonları güvence altına alın (kullanıcı başına escrow/deposit), `postOp`'u minimal ve non-reverting tutun ve en kötü durum reimbursement yolu için `paymasterPostOpGasLimit` ayırın.

## 6) Counterfactual deployment / factory assumptions
İlk `UserOperation` çoğu zaman `initCode` taşır; bu da account'un validation sırasında bir **factory** üzerinden deploy edilmesine neden olur. Bu yolun audit'i kolayca eksik kalır çünkü yalnızca ilk kullanımda çalışır.

Yaygın hatalar:

- Factory/initializer, `msg.sender == entryPoint` varsayar; ancak ERC-4337 deployment path'i `initCode`'yu doğrudan `EntryPoint`'ten çağırmaz.
- Salt, owner, validator veya module configuration signed intent'e tam olarak bağlı değildir; bu yüzden bir frontrunner ilk deployment için yarışabilir ve attacker-controlled settings ile counterfactual address'i burn edebilir.
- Factory non-idempotent'tir; bu yüzden tekrarlanan ilk kullanım akışı, zaten oluşturulmuş address'i döndürmek yerine wallet'ı bozar.

Güvenli pattern: signed deployment parameters'tan beklenen sender'ı yeniden hesaplayın, deployment'ı deterministic yapın (genellikle `CREATE2`) ve initialization'ı one-shot hale getirin.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Bundler'ların reddettiği validation logic
Validation code local testlerde doğru olabilir ama gerçek bundler'larda kullanılamaz hale gelebilir. Public bundler'lar `validateUserOp()` / `validatePaymasterUserOp()` fonksiyonlarını off-chain simüle eder ve inclusion öncesinde yaygın olarak tam bir `debug_traceCall(handleOps)` çalıştırır.

Bu da validation içinde şu pattern'leri tehlikeli yapar:

- `TIMESTAMP`, `NUMBER` veya `BLOCKHASH` gibi block-dependent opcode'lar
- `SSTORE` gibi state write'lar
- storage üzerinde sınırsız iteration
- simulation ile inclusion arasında değişebilen keyfi external call'lar veya oracle read'leri

Kötü örnek:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Doğrulamayı deterministik, sınırları belli bir preflight fonksiyonu olarak ele alın. Gerçekten shared state veya external lookups gerekiyorsa, bu karmaşıklığı staked/reputation-tracked entity’lere taşıyın ve yalnızca unit tests değil, exact bundler simulation path’i test edin.

## 8) ERC-7702 initialization frontrun
ERC-7702, bir EOA’nın tek bir tx için smart-account code çalıştırmasına izin verir. Eğer initialization externally callable ise, bir frontrunner kendisini owner olarak ayarlayabilir.

Mitigation: initialization’a yalnızca **self-call** üzerinden ve sadece bir kez izin verin.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Hızlı pre-merge kontrolleri
- İmzaları `EntryPoint`'in `userOpHash`'i kullanarak doğrulayın (`gas` alanlarını bağlar).
- Ayrıcalıklı fonksiyonları uygun şekilde yalnızca `EntryPoint` ve/veya `address(this)` ile sınırlandırın.
- `validateUserOp`'i stateless, deterministic ve bundler simulation kurallarıyla uyumlu tutun.
- ERC-1271 için EIP-712 domain separation uygulayın ve başarı durumunda `0x1626ba7e` döndürün.
- `postOp`'u minimal, bounded ve non-reverting tutun; ücretleri validation sırasında güvence altına alın.
- İlk `initCode` yolunu ayrı test edin: deterministic deployment, idempotent factory davranışı ve one-shot initialization.
- Yayınlamadan önce tam bundler simulation (`simulateValidation` artı traced bir `handleOps`) çalıştırın.
- ERC-7702 için init'e yalnızca self-call üzerinde ve yalnızca bir kez izin verin.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
