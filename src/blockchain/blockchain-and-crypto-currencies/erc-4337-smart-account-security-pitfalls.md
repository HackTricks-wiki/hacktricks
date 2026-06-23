# ERC-4337 Bezbednosne zamke Smart Account-a

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction pretvara wallets u programabilne sisteme. Osnovni tok je **validate-then-execute** kroz ceo bundle: `EntryPoint` validira svaku `UserOperation` pre nego što izvrši bilo koju od njih. Ovaj redosled stvara neočiglednu attack surface kada je validacija permisivna, stateful, ili nedosledna sa bundler simulation pravilima.

## 1) Direct-call bypass privilegovanih funkcija
Svaka spolja poziva `execute` (ili fund-moving) funkcija koja nije ograničena na `EntryPoint` (ili provereni executor modul) može biti pozvana direktno da isprazni account.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Siguran obrazac: ograniči na `EntryPoint`, i koristi `msg.sender == address(this)` za admin/self-management tokove (instalacija modula, promene validatora, nadogradnje).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nepotpisana ili neproverena gas polja -> drain naknada
Ako validacija potpisa pokriva samo intent (`callData`), ali ne i gas-related polja, bundler ili frontrunner mogu da naduvaju fee-jeve i isisaju ETH. Potpisani payload mora da vezuje bar:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: koristi `EntryPoint`-provided `userOpHash` (koji uključuje gas polja) i/ili striktno ograniči svako polje.
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
Pošto se sve validacije izvršavaju pre bilo kakvog izvršavanja, čuvanje rezultata validacije u state-u ugovora nije bezbedno. Drugi op u istom bundle-u može da ga prepiše, uzrokujući da vaše izvršavanje koristi state pod uticajem napadača.

Izbegavajte upisivanje u storage u `validateUserOp`. Ako je neizbežno, privremene podatke ključirajte pomoću `userOpHash` i obrišite ih deterministički nakon upotrebe (po mogućstvu stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` mora da veže potpise za **ovaj contract** i **ovu chain**. Recovering nad sirovim hash-om omogućava replay potpisa preko accounts ili chain-ova.

Koristite EIP-712 typed data (domain uključuje `verifyingContract` i `chainId`) i vratite tačnu ERC-1271 magic vrednost `0x1626ba7e` pri uspehu.

## 5) Reverts do not refund after validation
Jednom kada `validateUserOp` uspe, fees su potvrđene čak i ako se izvršavanje kasnije revert-uje. Napadači mogu ponavljano da šalju ops koje će fail-ovati i i dalje naplaćivati fees sa account-a.

Za paymasters, plaćanje iz shared pool-a u `validateUserOp` i naplaćivanje korisnika u `postOp` je fragilno jer `postOp` može da revert-uje bez poništavanja plaćanja. Bezbedno obezbedite funds tokom validacije (po korisniku escrow/deposit), držite `postOp` minimalnim i non-reverting, i budget-ujte `paymasterPostOpGasLimit` za najgori slučaj reimbursement path-a.

## 6) Counterfactual deployment / factory assumptions
Prva `UserOperation` često nosi `initCode`, što uzrokuje da se account deploy-uje kroz **factory** tokom validacije. Ovaj path se lako nedovoljno audituje jer se izvršava samo pri prvoj upotrebi.

Uobičajeni fail-ovi:

- Factory/initializer veruje `msg.sender == entryPoint`, ali ERC-4337 deployment path ne poziva `initCode` direktno iz `EntryPoint`.
- Salt, owner, validator ili module konfiguracija nisu u potpunosti vezani za potpisanu nameru, pa frontrunner može da prestigne prvi deployment i burn-uje counterfactual address sa podešavanjima pod kontrolom napadača.
- Factory nije idempotentna, pa ponovljeni first-use flow brick-uje wallet umesto da vrati već kreiranu adresu.

Bezbedan pattern: ponovo izračunajte očekivanog sender-a iz potpisanih deployment parametara, učinite deployment determinističkim (tipično `CREATE2`), i učinite inicijalizaciju jednokratnom.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logika koju bundleri odbacuju
Kod za validaciju može biti ispravan u lokalnim testovima, a da i dalje bude neupotrebljiv u stvarnim bundlerima. Javni bundleri simuliraju `validateUserOp()` / `validatePaymasterUserOp()` off-chain i obično pokreću kompletan `debug_traceCall(handleOps)` pre uključivanja.

To čini ove obrasce opasnima unutar validacije:

- Opcode-ovi zavisni od bloka kao što su `TIMESTAMP`, `NUMBER`, ili `BLOCKHASH`
- Upisi u state kao što je `SSTORE`
- Neograničena iteracija preko storage-a
- Arbitrary external calls ili oracle reads koji mogu da se promene između simulacije i uključivanja

Loš primer:
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
Tretirajte validaciju kao determinističku, ograničenu preflight funkciju. Ako vam zaista treba deljeno stanje ili eksterni lookup-ovi, gurnite tu složenost u entitete sa stake/reputation tracking-om i testirajte tačnu bundler simulation putanju, ne samo unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 omogućava da EOA izvrši smart-account code za jednu tx. Ako je initialization eksterno pozivljiv, frontrunner može da postavi sebe za owner-a.

Mitigation: dozvolite initialization samo na **self-call** i samo jednom.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Brze provere pre merge
- Validiraj potpise koristeći `EntryPoint`-ov `userOpHash` (vezuje gas polja).
- Ograniči privilegovane funkcije na `EntryPoint` i/ili `address(this)` po potrebi.
- Drži `validateUserOp` stateless, deterministic, i kompatibilnim sa bundler simulation pravilima.
- Primeni EIP-712 domain separation za ERC-1271 i vrati `0x1626ba7e` pri uspehu.
- Drži `postOp` minimalnim, bounded, i non-reverting; obezbedi fee-jeve tokom validation.
- Testiraj prvi `initCode` path odvojeno: deterministic deployment, idempotent factory behavior, i one-shot initialization.
- Pokreni punu bundler simulation (`simulateValidation` plus traced `handleOps`) pre shipping-a.
- Za ERC-7702, dozvoli init samo na self-call i samo jednom.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
