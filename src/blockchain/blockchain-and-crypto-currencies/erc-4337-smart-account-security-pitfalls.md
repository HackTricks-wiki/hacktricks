# ERC-4337 Akıllı Hesap Güvenlik Tuzakları

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction, cüzdanları programlanabilir sistemlere dönüştürür. Temel akış, tüm bundle genelinde **validate-then-execute** şeklindedir: `EntryPoint`, herhangi birini execute etmeden önce her `UserOperation` öğesini validate eder. Bu sıralama, validation permissive, stateful olduğunda veya bundler simulation rules ile tutarsız olduğunda, bariz olmayan bir attack surface oluşturur.

## 1) Privileged functions için direct-call bypass
`EntryPoint` (veya incelenmiş bir executor module) ile kısıtlanmamış herhangi bir externally callable `execute` (veya fund-moving) function, hesabı drain etmek için doğrudan çağrılabilir.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Güvenli yaklaşım: `EntryPoint` ile kısıtlayın ve admin/kendi kendini yönetme akışları (modül kurulumu, validator değişiklikleri, yükseltmeler) için `msg.sender == address(this)` kullanın.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) İmzalanmamış veya kontrol edilmemiş gas alanları -> ücret tüketimi
Signature validation yalnızca intent'i (`callData`) kapsıyorsa, bir bundler veya frontrunner ücretleri artırarak ETH'yi tüketebilir. İmzalanan payload en azından şunları bağlamalıdır:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint` tarafından sağlanan ve gas alanlarını içeren `userOpHash` değerini kullanın ve/veya her alan için katı bir üst sınır belirleyin.<sup>[[1]](#references)</sup>
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
Tüm doğrulamalar herhangi bir execution işleminden önce çalıştığından, doğrulama sonuçlarını contract state içinde saklamak güvenli değildir. Aynı bundle içindeki başka bir op bu değerin üzerine yazabilir ve execution işleminizin attacker-controlled state kullanmasına neden olabilir.<sup>[[1]](#references)</sup>

`validateUserOp` içinde storage yazmaktan kaçının. Kaçınılmazsa geçici verileri `userOpHash` ile anahtarlayın ve kullanımdan sonra deterministik olarak silin (stateless validation tercih edilir).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`, imzaları **bu contract** ve **bu chain** ile ilişkilendirmelidir. Ham bir hash üzerinden recovery yapmak, imzaların farklı account'lar veya chain'ler arasında replay edilmesine olanak tanır.<sup>[[1]](#references)</sup>

EIP-712 typed data kullanın (domain içinde `verifyingContract` ve `chainId` bulunmalıdır) ve başarı durumunda tam ERC-1271 magic value olan `0x1626ba7e` değerini döndürün.<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp` başarılı olduktan sonra execution daha sonra revert etse bile ücretler taahhüt edilmiş olur. Attackers, başarısız olacak op'leri tekrar tekrar submit ederek yine de account'tan ücret tahsil edilmesini sağlayabilir.<sup>[[1]](#references)</sup>

Paymaster'lar için `validateUserOp` içinde shared pool'dan ödeme yapmak ve kullanıcıları `postOp` içinde ücretlendirmek, `postOp` işleminin ödemeyi geri almadan revert edebilmesi nedeniyle güvenilmezdir. Validation sırasında fonları güvence altına alın (kullanıcı başına escrow/deposit), `postOp` işlemini minimal ve revert etmeyecek şekilde tutun ve en kötü durumdaki reimbursement path için `paymasterPostOpGasLimit` bütçesini ayarlayın.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
İlk `UserOperation` çoğu zaman `initCode` taşır; bu da validation sırasında account'un bir **factory** aracılığıyla deploy edilmesine neden olur. Bu path yalnızca ilk kullanımda çalıştığından yeterince audit edilmemesi kolaydır.<sup>[[2]](#references)</sup>

Yaygın hatalar:

- Factory/initializer, `msg.sender == entryPoint` olduğunu varsayar; ancak ERC-4337 deployment path'i `initCode`'u doğrudan `EntryPoint` üzerinden çağırmaz.
- Salt, owner, validator veya module configuration signed intent'e tamamen bağlanmamıştır; bu nedenle bir frontrunner ilk deployment için yarışabilir ve counterfactual address'i attacker-controlled ayarlarla kullanılamaz hale getirebilir.
- Factory non-idempotent'tır; bu nedenle tekrarlanan ilk kullanım flow'u wallet'ı brick eder ve zaten oluşturulmuş address'i döndürmez.

Güvenli pattern: beklenen sender'ı signed deployment parameters üzerinden yeniden hesaplayın, deployment'ı deterministik hale getirin (genellikle `CREATE2`) ve initialization'ı tek seferlik olacak şekilde uygulayın.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Bundler'ların reddettiği validation mantığı
Validation kodu yerel testlerde doğru çalışabilir, ancak gerçek bundler'larda yine de kullanılamaz olabilir. Public bundler'lar `validateUserOp()` / `validatePaymasterUserOp()` işlemlerini off-chain olarak simüle eder ve inclusion öncesinde genellikle tam bir `debug_traceCall(handleOps)` çalıştırır.

Bu nedenle validation içinde aşağıdaki pattern'ler tehlikelidir:

- `TIMESTAMP`, `NUMBER` veya `BLOCKHASH` gibi block'a bağlı opcode'lar
- `SSTORE` gibi state yazma işlemleri
- Storage üzerinde sınırsız iteration
- Simulation ile inclusion arasında değişebilecek arbitrary external call'lar veya oracle okumaları

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
Doğrulamayı deterministik, sınırlandırılmış bir preflight function olarak ele alın. Gerçekten paylaşılan state veya harici lookup'lara ihtiyacınız varsa bu karmaşıklığı staked/reputation-tracked entity'lere taşıyın ve yalnızca unit test'lerini değil, tam bundler simulation path'ini test edin.

## 8) ERC-7702 initialization frontrun
ERC-7702, bir EOA'nın tek bir tx için smart-account kodu çalıştırmasına olanak tanır. Initialization harici olarak çağrılabiliyorsa, bir frontrunner kendisini owner olarak ayarlayabilir.<sup>[[1]](#references)</sup>

Mitigation: initialization'a yalnızca **self-call** üzerinden ve yalnızca bir kez izin verin.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Hızlı merge öncesi kontroller
- İmzaları `EntryPoint`'in `userOpHash` değeriyle doğrulayın (gas alanlarını bağlar).
- Ayrıcalıklı işlevleri uygun şekilde `EntryPoint` ve/veya `address(this)` ile sınırlandırın.
- `validateUserOp` işlevini stateless, deterministik ve bundler simülasyonu kurallarıyla uyumlu tutun.
- ERC-1271 için EIP-712 domain ayrımını zorunlu kılın ve başarı durumunda `0x1626ba7e` döndürün.
- `postOp` işlevini minimal, sınırlandırılmış ve revert etmeyecek şekilde tutun; ücretleri validation sırasında güvence altına alın.
- İlk `initCode` yolunu ayrı olarak test edin: deterministik deployment, idempotent factory davranışı ve tek seferlik initialization.
- Yayına almadan önce tam bundler simülasyonu (`simulateValidation` ve trace uygulanmış bir `handleOps`) çalıştırın.
- ERC-7702 için init işlemine yalnızca self-call üzerinden ve yalnızca bir kez izin verin.



## Referanslar

- [1] [ERC-4337 smart account'larındaki altı hata (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Alt Mempool Kullanarak Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
