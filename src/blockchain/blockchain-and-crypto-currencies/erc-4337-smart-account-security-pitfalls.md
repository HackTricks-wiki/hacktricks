# ERC-4337 Smart Account Güvenlik Tuzakları

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 hesap soyutlama, cüzdanları programlanabilir sistemlere dönüştürür. Temel akış, bütün bir bundle genelinde **validate-then-execute** şeklindedir: `EntryPoint`, herhangi bir `UserOperation` yürütülmeden önce tüm `UserOperation` nesnelerini doğrular. Bu sıralama, validation izin verici, stateful olduğunda veya bundler simulation kurallarıyla tutarsız olduğunda kolayca fark edilmeyen bir attack surface oluşturur.

## 1) Privileged function'ların direct-call ile bypass edilmesi
`EntryPoint` (veya incelenmiş bir executor module) ile sınırlandırılmamış, harici olarak çağrılabilen herhangi bir `execute` (veya fon taşıyan) function, hesabı boşaltmak için doğrudan çağrılabilir.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Güvenli desen: `EntryPoint` ile sınırlandırın ve yönetici/kendi kendini yönetme akışları (modül kurulumu, validator değişiklikleri, yükseltmeler) için `msg.sender == address(this)` kullanın.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) İmzalanmamış veya kontrol edilmeyen gas alanları -> fee drain
Signature validation yalnızca intent'i (`callData`) kapsıyorsa, bir bundler veya frontrunner ücretleri artırarak ETH tüketebilir. İmzalanan payload en azından şunları bağlamalıdır:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Savunma yöntemi: `EntryPoint` tarafından sağlanan (`gas fields`'ı içeren) `userOpHash` değerini kullanın ve/veya her alan için katı bir üst sınır belirleyin.<sup>[[1]](#references)</sup>
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
Tüm validation işlemleri execution'dan önce çalıştığından, validation sonuçlarını contract state içinde saklamak güvenli değildir. Aynı bundle içindeki başka bir op bunu overwrite edebilir ve execution işleminizin attacker-controlled state kullanmasına neden olabilir.<sup>[[1]](#references)</sup>

`validateUserOp` içinde storage'a yazmaktan kaçının. Kaçınılmazsa, geçici verileri `userOpHash` ile key'leyin ve kullanım sonrasında deterministik olarak silin (stateless validation tercih edilir).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`, signature'ları **bu contract'a** ve **bu chain'e** bağlamalıdır. Raw hash üzerinden recovery yapmak, signature'ların farklı account'lar veya chain'ler arasında replay edilmesine olanak tanır.<sup>[[1]](#references)</sup>

EIP-712 typed data kullanın (domain, `verifyingContract` ve `chainId` değerlerini içerir) ve başarılı durumda tam ERC-1271 magic value olan `0x1626ba7e` değerini döndürün.<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp` başarılı olduktan sonra execution daha sonra revert etse bile fee'ler kesinleşir. Attack'lar başarısız olacak op'leri tekrar tekrar submit ederek account'tan yine de fee tahsil edilmesini sağlayabilir.<sup>[[1]](#references)</sup>

Paymaster'lar açısından, `validateUserOp` içinde shared pool'dan ödeme yapmak ve kullanıcıları `postOp` içinde charge etmek, `postOp` işleminin ödemeyi geri almadan revert edebilmesi nedeniyle güvenilir değildir. Validation sırasında fonları güvenceye alın (kullanıcı başına escrow/deposit), `postOp` işlemini minimal ve revert etmeyecek şekilde tutun ve en kötü durumdaki reimbursement path için `paymasterPostOpGasLimit` bütçesi ayırın.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
İlk `UserOperation` çoğu zaman `initCode` taşır; bu da account'un validation sırasında bir **factory** üzerinden deploy edilmesine neden olur. Yalnızca ilk kullanımda çalıştığı için bu path'in yeterince audit edilmemesi kolaydır.<sup>[[2]](#references)</sup>

Yaygın hatalar:

- Factory/initializer, `msg.sender == entryPoint` koşuluna güvenir; ancak ERC-4337 deployment path'i `initCode`'u doğrudan `EntryPoint` üzerinden çağırmaz.
- Salt, owner, validator veya module configuration signed intent'e tamamen bağlanmamıştır; bu nedenle bir frontrunner ilk deployment için yarışabilir ve counterfactual address'i attacker-controlled ayarlarla kullanılamaz hale getirebilir.
- Factory non-idempotent'tır; bu nedenle tekrarlanan bir first-use flow, zaten oluşturulmuş address'i döndürmek yerine wallet'ı kullanılamaz hale getirir.

Güvenli pattern: expected sender'ı signed deployment parameters üzerinden yeniden hesaplayın, deployment'ı deterministik hale getirin (genellikle `CREATE2`) ve initialization işlemini tek seferlik yapın.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Bundler'ların reddettiği validation logic
Validation code'u local testlerde doğru çalışabilir, ancak gerçek bundler'larda yine de kullanılamaz olabilir. Public bundler'lar `validateUserOp()` / `validatePaymasterUserOp()` işlemlerini off-chain olarak simüle eder ve inclusion öncesinde genellikle tam bir `debug_traceCall(handleOps)` çalıştırır.<sup>[[3]](#references)</sup>

Bu nedenle aşağıdaki pattern'ler validation içinde tehlikelidir:

- `TIMESTAMP`, `NUMBER` veya `BLOCKHASH` gibi block'a bağlı opcode'lar
- `SSTORE` gibi state write işlemleri
- Storage üzerinde unbounded iteration
- Simulation ile inclusion arasında değişebilecek arbitrary external call'lar veya oracle read işlemleri

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
Validation'ı deterministik ve sınırlandırılmış bir preflight function olarak ele alın. Gerçekten paylaşılan state veya harici lookup'lara ihtiyacınız varsa bu karmaşıklığı stake edilmiş/reputation-tracked entity'lere taşıyın ve yalnızca unit test'leri değil, tam bundler simulation path'ini test edin.

## 8) ERC-7702 initialization frontrun
ERC-7702, bir EOA'nın tek bir tx için smart-account code çalıştırmasına olanak tanır. Initialization harici olarak çağrılabiliyorsa, bir frontrunner kendisini owner olarak ayarlayabilir.<sup>[[1]](#references)</sup>

Mitigation: initialization'a yalnızca **self-call** üzerinden ve yalnızca bir kez izin verin.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Merge öncesi hızlı kontroller
- Gas alanlarını bağlayan `EntryPoint`'in `userOpHash` değerini kullanarak imzaları doğrulayın.
- Ayrıcalıklı işlevlere erişimi uygun şekilde `EntryPoint` ve/veya `address(this)` ile kısıtlayın.
- `validateUserOp` işlevini stateless, deterministic ve bundler simülasyon kurallarıyla uyumlu tutun.
- ERC-1271 için EIP-712 domain separation uygulayın ve başarı durumunda `0x1626ba7e` döndürün.
- `postOp` işlevini minimal, sınırlandırılmış ve revert etmeyecek şekilde tutun; ücretleri validation sırasında güvenceye alın.
- İlk `initCode` yolunu ayrı olarak test edin: deterministic deployment, idempotent factory davranışı ve tek seferlik initialization.
- Yayına almadan önce tam bundler simülasyonu (`simulateValidation` ve trace edilmiş bir `handleOps`) çalıştırın.
- ERC-7702 için init işlemine yalnızca self-call üzerinden ve yalnızca bir kez izin verin.

## Referanslar

- [1] [ERC-4337 smart account'larında altı hata (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Alt Mempool Kullanarak Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
