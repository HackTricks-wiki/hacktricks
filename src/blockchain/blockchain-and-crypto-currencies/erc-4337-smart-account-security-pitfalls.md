# ERC-4337 Smart Account Güvenlik Tuzakları

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction, cüzdanları programlanabilir sistemlere dönüştürür. Temel akış, tüm bundle genelinde **validate-then-execute** şeklindedir: `EntryPoint`, herhangi birini çalıştırmadan önce her `UserOperation` öğesini doğrular.<sup>[[5]](#references)</sup> Bu sıralama, doğrulama izin verici, stateful olduğunda veya bundler simulation kurallarıyla tutarsız olduğunda fark edilmesi zor bir attack surface oluşturur.

## 1) Privileged functions için direct-call bypass
`EntryPoint` (veya güvenilirliği doğrulanmış bir executor module) ile kısıtlanmamış, dışarıdan çağrılabilen herhangi bir `execute` (veya fon taşıyan) function, hesabı boşaltmak için doğrudan çağrılabilir.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Güvenli pattern: `EntryPoint` ile sınırlandırın ve admin/self-management akışları (modül yükleme, validator değişiklikleri, upgrade'ler) için `msg.sender == address(this)` kullanın.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) İmzalanmamış veya doğrulanmamış gas alanları -> fee drain
Signature validation yalnızca intent'i (`callData`) kapsıyorsa, bir bundler veya frontrunner ücretleri artırarak ETH drain edebilir. İmzalanan payload en azından şunları bağlamalıdır:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: gas alanlarını da içeren `EntryPoint` tarafından sağlanan `userOpHash` değerini kullanın ve/veya her alan için kesin bir üst sınır belirleyin.<sup>[[2]](#references)[[5]](#references)</sup>
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
Tüm doğrulamalar herhangi bir execution işleminden önce çalıştığından, doğrulama sonuçlarını contract state içinde saklamak güvenli değildir. Aynı bundle içindeki başka bir op bunu üzerine yazarak execution işleminizin attacker-controlled state kullanmasına neden olabilir.<sup>[[2]](#references)</sup>

`validateUserOp` içinde storage'a yazmaktan kaçının. Kaçınılmazsa geçici verileri `userOpHash` ile anahtarlayın ve kullanım sonrasında deterministik olarak silin (stateless validation tercih edilir).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`, imzaları **bu contract** ve **bu chain** ile ilişkilendirmelidir. Ham bir hash üzerinden recovery yapmak, imzaların hesaplar veya chain'ler arasında replay edilmesine olanak tanır.<sup>[[1]](#references)[[4]](#references)</sup>

EIP-712 typed data kullanın (`verifyingContract` ve `chainId` alanlarını içeren domain) ve başarılı durumda tam ERC-1271 magic value olan `0x1626ba7e` değerini döndürün.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp` başarılı olduktan sonra execution daha sonra revert etse bile ücretler kesinleşmiş olur. Attackers, başarısız olacak op'leri tekrar tekrar submit ederek hesaptan ücret almaya devam edebilir.<sup>[[2]](#references)</sup>

Paymasters açısından, `validateUserOp` içinde ortak bir pool'dan ödeme yapmak ve kullanıcıları `postOp` içinde ücretlendirmek, `postOp` işleminin ödemeyi geri almadan revert edebilmesi nedeniyle güvenilir değildir. Fonları validation sırasında güvence altına alın (kullanıcı başına escrow/deposit), `postOp` işlemini minimal ve revert etmeyecek şekilde tutun ve en kötü durumdaki reimbursement path için `paymasterPostOpGasLimit` bütçesi ayırın.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
İlk `UserOperation` çoğu zaman `initCode` içerir; bu da validation sırasında hesabın bir **factory** aracılığıyla deploy edilmesine neden olur. Yalnızca ilk kullanımda çalıştığından bu path'in denetimi kolayca yetersiz kalabilir.<sup>[[5]](#references)</sup>

Yaygın hatalar şunlardır:<sup>[[5]](#references)</sup>

- Factory/initializer, `msg.sender == entryPoint` koşuluna güvenir; ancak ERC-4337 deployment path'i `initCode`'u doğrudan `EntryPoint` üzerinden çağırmaz.
- Salt, owner, validator veya module yapılandırması signed intent'e tamamen bağlanmamıştır; bu nedenle bir frontrunner ilk deployment için yarışabilir ve counterfactual address'i attacker-controlled ayarlarla kullanılamaz hale getirebilir.
- Factory non-idempotent'tır; bu nedenle tekrarlanan bir first-use flow, zaten oluşturulmuş adresi döndürmek yerine wallet'ı kullanılamaz hale getirir.

Güvenli pattern: beklenen sender'ı signed deployment parameters üzerinden yeniden hesaplayın, deployment'ı deterministik hale getirin (genellikle `CREATE2`) ve initialization işlemini one-shot yapın.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Bundlers'ın reddettiği validation mantığı
Validation kodu yerel testlerde doğru olabilir, ancak gerçek bundlers ortamında yine de kullanılamaz olabilir. Bundlers validation işlemini birden çok kez çalıştırır ve gönderimden önce traced full-bundle validation gerçekleştirmelidir.<sup>[[6]](#references)</sup>

Bu validation-scope kuralları kapsamında aşağıdaki kalıplar tehlikelidir:<sup>[[6]](#references)</sup>

- `TIMESTAMP`, `NUMBER` veya `BLOCKHASH` gibi block-dependent opcode'lar
- İzin verilen account/entity scope dışındaki storage erişimi veya storage üzerinde sınırlandırılmamış iteration
- İzin verilen validation scope dışındaki mutable state'e bağlı external call'lar veya oracle read'leri

Kötü örnek:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Validation'ı deterministik ve sınırlandırılmış bir preflight işlevi olarak ele alın. Paylaşılan state veya harici lookup'lar gerekli ise staked-entity kurallarını izleyin ve yalnızca unit test'leri değil, aynı çok geçişli bundler simulation path'ini de test edin.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702, bir EOA'ya smart-account koduna kalıcı delegation verir; delegation initialization'ı atomik olarak çalıştırmaz. Initialization harici olarak çağrılabiliyorsa bir gözlemci bunu front-run ederek kendisini owner olarak ayarlayabilir.<sup>[[7]](#references)</sup>

Mitigation: initialization calldata'nın EOA tarafından authorize edilmesini zorunlu kılın ve initialization'a yalnızca bir kez izin verin. ERC-4337 EIP-7702 flow'unda ayrıca caller'ı `EntryPoint.senderCreator()` ile sınırlandırın.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Hızlı merge öncesi kontroller
- `EntryPoint`'in `userOpHash` değerini kullanarak imzaları doğrulayın (gas alanlarını bağlar).
- Ayrıcalıklı işlevleri uygun şekilde `EntryPoint` ve/veya `address(this)` ile sınırlandırın.
- `validateUserOp` işlevini stateless, deterministik ve bundler simulation kurallarıyla uyumlu tutun.
- ERC-1271 için EIP-712 domain separation uygulayın ve başarılı durumda `0x1626ba7e` döndürün.
- `postOp` işlevini minimal, sınırlandırılmış ve revert etmeyecek şekilde tutun; validation sırasında ücretleri güvence altına alın.
- İlk `initCode` yolunu ayrı olarak test edin: deterministik deployment, idempotent factory davranışı ve tek seferlik initialization.
- Yayına almadan önce bundler'ın multi-pass validation işlemini ve trace edilmiş full-bundle kontrolünü çalıştırın.
- ERC-7702 için init işlemini EOA authorization'a bağlayın ve yalnızca bir kez çalışmasına izin verin; ERC-4337 akışlarında caller'ı `EntryPoint.senderCreator()` ile sınırlandırın.

## References

- [1] [ERC1271 Replay - 15+ Etkilenen Ekip (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [ERC-4337 smart account'larında altı hata (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Contract'lar için Standard Signature Validation Method](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Alt Mempool Kullanarak Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: EOA'lar için Code Ayarlama](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
