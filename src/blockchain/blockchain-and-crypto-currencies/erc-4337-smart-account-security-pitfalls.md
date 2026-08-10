# ERC-4337 Smart Account Güvenlik Tuzakları

ERC-4337 hesap soyutlama, cüzdanları programlanabilir sistemlere dönüştürür. Temel akış, tüm bundle genelinde **validate-then-execute** şeklindedir: `EntryPoint`, bunlardan herhangi birini çalıştırmadan önce her `UserOperation` işlemini doğrular.<sup>[[5]](#references)</sup> Bu sıralama, validation izin verici, stateful olduğunda veya bundler simulation kurallarıyla tutarsız olduğunda fark edilmesi zor bir attack surface oluşturur.

## 1) Ayrıcalıklı işlevlerin doğrudan çağrıyla bypass edilmesi
`EntryPoint` (veya incelenmiş bir executor module) ile sınırlandırılmamış, harici olarak çağrılabilen herhangi bir `execute` (veya fon transferi yapan) işlev, account'u drain etmek için doğrudan çağrılabilir.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Güvenli pattern: `EntryPoint` ile sınırlandırın ve admin/self-management akışları (module install, validator changes, upgrades) için `msg.sender == address(this)` kullanın.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) İmzalanmamış veya doğrulanmamış gas alanları -> ücret tüketimi
İmza doğrulaması yalnızca intent'i (`callData`) kapsıyor, ancak gas ile ilgili alanları kapsamıyorsa, bir bundler veya frontrunner ücretleri artırarak ETH tüketebilir. İmzalanan payload en azından şunları bağlamalıdır:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint` tarafından sağlanan (gas alanlarını içeren) `userOpHash` değerini kullanın ve/veya her alan için katı bir üst sınır belirleyin.<sup>[[2]](#references)[[5]](#references)</sup>
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
Tüm doğrulamalar herhangi bir execution işleminden önce çalıştığı için doğrulama sonuçlarını contract state içinde saklamak güvenli değildir. Aynı bundle içindeki başka bir op bunu üzerine yazabilir ve execution işleminizin attacker etkisindeki state'i kullanmasına neden olabilir.<sup>[[2]](#references)</sup>

`validateUserOp` içinde storage'a yazmaktan kaçının. Kaçınılmazsa geçici verileri `userOpHash` ile anahtarlayın ve kullanım sonrasında deterministik olarak silin (stateless validation tercih edilir).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)`, imzaları **bu contract'a** ve **bu chain'e** bağlamalıdır. Ham bir hash üzerinden recovery yapmak, imzaların hesaplar veya chain'ler arasında replay edilmesine olanak tanır.<sup>[[1]](#references)[[4]](#references)</sup>

EIP-712 typed data kullanın (`verifyingContract` ve `chainId` alanlarını içeren domain) ve başarı durumunda tam ERC-1271 magic value olan `0x1626ba7e` değerini döndürün.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
`validateUserOp` başarılı olduktan sonra execution işlemi daha sonra revert olsa bile ücretler kesinleşir. Attackers, başarısız olacak op'leri tekrar tekrar submit ederek yine de hesaptan ücret tahsil edebilir.<sup>[[2]](#references)</sup>

Paymaster'lar için `validateUserOp` içinde paylaşılan bir pool'dan ödeme yapmak ve kullanıcıları `postOp` içinde ücretlendirmek kırılgandır; çünkü `postOp`, ödemeyi geri almadan revert olabilir. Fonları validation sırasında güvenceye alın (kullanıcı başına escrow/deposit), `postOp` işlemini minimal ve revert etmeyecek şekilde tutun ve en kötü durumdaki reimbursement path için `paymasterPostOpGasLimit` bütçesi ayırın.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
İlk `UserOperation` çoğu zaman `initCode` taşır; bu da validation sırasında hesabın bir **factory** aracılığıyla deploy edilmesine neden olur. Yalnızca ilk kullanımda çalıştığı için bu path'in yeterince audit edilmemesi kolaydır.<sup>[[5]](#references)</sup>

Yaygın hatalar şunlardır:<sup>[[5]](#references)</sup>

- Factory/initializer, `msg.sender == entryPoint` koşuluna güvenir; ancak ERC-4337 deployment path'i `initCode`'u doğrudan `EntryPoint` üzerinden çağırmaz.
- Salt, owner, validator veya module configuration signed intent'e tamamen bağlanmamıştır; bu nedenle bir frontrunner ilk deployment için yarışabilir ve counterfactual address'i attacker-controlled ayarlarla kullanılamaz hale getirebilir.
- Factory idempotent değildir; bu nedenle tekrarlanan bir ilk kullanım flow'u, zaten oluşturulmuş address'i döndürmek yerine wallet'ı kullanılamaz hale getirir.

Güvenli pattern: beklenen sender'ı signed deployment parametrelerinden yeniden hesaplayın, deployment'ı deterministik hale getirin (genellikle `CREATE2`) ve initialization işlemini tek seferlik yapın.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Bundler'ların reddettiği validation mantığı
Validation code'u local testlerde doğru olabilir, ancak gerçek bundler'larda yine de kullanılamaz. Bundler'lar validation işlemini birden çok kez çalıştırır ve submission öncesinde traced full-bundle validation gerçekleştirmelidir.<sup>[[6]](#references)</sup>

Bu validation-scope kuralları kapsamında aşağıdaki pattern'ler tehlikelidir:<sup>[[6]](#references)</sup>

- `TIMESTAMP`, `NUMBER` veya `BLOCKHASH` gibi block-dependent opcode'lar
- İzin verilen account/entity scope dışındaki storage erişimi veya storage üzerinde sınırsız iteration
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
Doğrulamayı deterministik ve sınırlandırılmış bir preflight işlevi olarak ele alın. Paylaşılan durum veya harici sorgular gerekliyse, staked-entity kurallarını izleyin ve yalnızca unit testlerini değil, aynı çok geçişli bundler simulation yolunu da test edin.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702, bir EOA'ya smart-account koduna kalıcı bir delegation sağlar; delegation, initialization işlemini atomik olarak çalıştırmaz. Initialization harici olarak çağrılabiliyorsa, bir gözlemci işlemi front-run ederek kendisini owner olarak ayarlayabilir.<sup>[[7]](#references)</sup>

Mitigation: initialization calldata'sının EOA tarafından yetkilendirilmesini zorunlu kılın ve initialization işlemine yalnızca bir kez izin verin. Bir ERC-4337 EIP-7702 akışında, çağıranı ayrıca `EntryPoint.senderCreator()` ile sınırlandırın.<sup>[[5]](#references)[[7]](#references)</sup>
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
- Ayrıcalıklı işlevleri uygun şekilde `EntryPoint` ve/veya `address(this)` ile sınırlayın.
- `validateUserOp` işlevini stateless, deterministik ve bundler simulation kurallarıyla uyumlu tutun.
- ERC-1271 için EIP-712 domain separation uygulayın ve başarı durumunda `0x1626ba7e` döndürün.
- `postOp` işlevini minimal, sınırlandırılmış ve revert etmeyecek şekilde tutun; validation sırasında ücretleri güvence altına alın.
- İlk `initCode` yolunu ayrı olarak test edin: deterministik deployment, idempotent factory davranışı ve tek seferlik initialization.
- Yayına almadan önce bundler'ın multi-pass validation işlemini ve trace içeren full-bundle kontrolünü çalıştırın.
- ERC-7702 için init işlemini EOA authorization'a bağlayın ve yalnızca bir kez kullanılmasına izin verin; ERC-4337 akışlarında çağıranı `EntryPoint.senderCreator()` ile sınırlayın.

## References

- [1] [ERC1271 Replay - 15+ Teams Affected (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [ERC-4337 smart account'larında altı hata (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Contract'lar için Standard Signature Validation Method](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data hashing ve signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Alt Mempool Kullanarak Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: EOA'lar için Code Ayarlama](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
