# ERC-4337 Akıllı Hesap Güvenlik Tuzakları

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 hesap soyutlaması cüzdanları programlanabilir sistemlere dönüştürür. Temel akış tüm paket üzerinde **validate-then-execute** şeklindedir: `EntryPoint`, herhangi birini yürütmeden önce her `UserOperation`'u doğrular. Bu sıralama, doğrulama gevşek veya duruma bağlı olduğunda belirgin olmayan bir saldırı yüzeyi yaratır.

## 1) Doğrudan çağrıyla ayrıcalıklı fonksiyonların atlatılması
Dışarıdan çağrılabilir herhangi bir `execute` (veya fon taşıma) fonksiyonu `EntryPoint`'e (veya onaylı bir executor module'a) kısıtlanmamışsa, hesabı boşaltmak için doğrudan çağrılabilir.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Güvenli desen: `EntryPoint` ile sınırlandırın ve admin/self-management akışları (modül kurulumu, validator değişiklikleri, yükseltmeler) için `msg.sender == address(this)` kullanın.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Imzalanmamış veya kontrol edilmeyen gas alanları -> ücret boşaltma
Eğer imza doğrulaması yalnızca niyeti (`callData`) kapsıyor ancak gas ile ilgili alanları kapsamıyorsa, bir bundler veya frontrunner ücretleri şişirebilir ve ETH'yi boşaltabilir. İmzalanmış payload en az şunlara bağlanmalıdır:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Savunma deseni: `EntryPoint` tarafından sağlanan `userOpHash`'i kullanın (bu, gas alanlarını içerir) ve/veya her alanı sıkı şekilde sınırlandırın.
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
Çünkü tüm doğrulamalar herhangi bir yürütmeden önce çalışır, doğrulama sonuçlarını contract state'te saklamak güvenli değildir. Aynı bundle içindeki başka bir op bunu üzerine yazabilir ve yürütmenizin saldırgan tarafından etkilenmiş state'i kullanmasına yol açabilir.

`validateUserOp` içinde storage yazmaktan kaçının. Kaçınılmazsa, geçici veriyi `userOpHash` ile anahtarlayın ve kullanımdan sonra deterministik olarak silin (stateless validation tercih edin).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` imzaları **bu contract** ve **bu zincir** ile bağlamalıdır. Ham bir hash üzerinde recover yapmak imzaların hesaplar veya zincirler arasında replay olmasına izin verir.

EIP-712 typed data kullanın (domain `verifyingContract` ve `chainId`'i içerir) ve başarılı olduğunda tam ERC-1271 magic değeri `0x1626ba7e` döndürün.

## 5) Reverts do not refund after validation
`validateUserOp` başarılı olduktan sonra, yürütme daha sonra revert olsa bile ücretler taahhüt edilir. Saldırganlar başarısız olacak işlemleri tekrar tekrar gönderip yine de hesaptan ücret toplayabilir.

Paymasters için, `validateUserOp` içinde paylaşılan bir havuzdan ödeme yapıp `postOp` içinde kullanıcılardan ücret almak kırılgandır; çünkü `postOp` ödeme geri alınmadan revert olabilir. Doğrulama sırasında fonları güvence altına alın (kullanıcı başına escrow/deposit) ve `postOp`'u minimal ve revert etmeyecek şekilde tutun.

## 6) ERC-7702 initialization frontrun
ERC-7702, bir EOA'nın tek bir tx için smart-account kodunu çalıştırmasına izin verir. Eğer initialization dışarıdan çağrılabiliyorsa, bir frontrunner kendisini owner olarak ayarlayabilir.

Mitigation: initialization'a yalnızca **self-call** ile ve yalnızca bir kez izin verin.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Hızlı ön-merge kontrolleri
- İmzaları `EntryPoint`'in `userOpHash`'ini kullanarak doğrulayın (gas alanlarını bağlar).
- Ayrıcalıklı fonksiyonları uygun olduğu şekilde `EntryPoint` ve/veya `address(this)` ile sınırlandırın.
- `validateUserOp`'u durumsuz (stateless) tutun.
- ERC-1271 için EIP-712 domain ayrımını uygulayın ve başarı halinde `0x1626ba7e` döndürün.
- `postOp`'u minimal, sınırlı ve revert olmayan şekilde tutun; doğrulama sırasında ücretleri güvence altına alın.
- ERC-7702 için init'e yalnızca self-call üzerinde ve yalnızca bir kez izin verin.

## Referanslar

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
