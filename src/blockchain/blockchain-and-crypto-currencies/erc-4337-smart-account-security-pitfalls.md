# ERC-4337 Pułapki bezpieczeństwa Smart Account

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction zamienia wallets w programowalne systemy. Główny przepływ to **validate-then-execute** dla całego bundle: `EntryPoint` waliduje każdą `UserOperation` przed wykonaniem którejkolwiek z nich. Ta kolejność tworzy nieoczywistą powierzchnię ataku, gdy walidacja jest permissive, stateful lub niespójna z regułami symulacji bundler.

## 1) Ominięcie privileged functions przez direct-call
Każda funkcja `execute` (lub przenosząca funds), która może być wywołana z zewnątrz i nie jest ograniczona do `EntryPoint` (lub zweryfikowanego executor module), może zostać wywołana bezpośrednio, aby drainować account.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezpieczny wzorzec: ogranicz do `EntryPoint` i używaj `msg.sender == address(this)` dla przepływów admin/self-management (module install, zmiany validator, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Niepodpisane lub niezweryfikowane pola gas -> drenaż fee
Jeśli walidacja signature obejmuje tylko intent (`callData`), ale nie obejmuje pól związanych z gas, bundler lub frontrunner mogą zawyżyć fee i drenować ETH. Podpisany payload musi wiązać co najmniej:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Wzorzec obronny: użyj `userOpHash` dostarczanego przez `EntryPoint` (który zawiera pola gas) i/lub ściśle ogranicz każde pole.
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
Ponieważ wszystkie walidacje uruchamiają się przed jakimkolwiek wykonaniem, przechowywanie wyników walidacji w stanie kontraktu jest niebezpieczne. Inna op w tym samym bundle może to nadpisać, powodując, że wykonanie użyje stanu pod wpływem attacker.

Unikaj zapisu do storage w `validateUserOp`. Jeśli to nieuniknione, kluczuj dane tymczasowe przez `userOpHash` i usuwaj je deterministycznie po użyciu (preferuj stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` musi powiązać signatures z **tym kontraktem** i **tą chain**. Recovering na surowym hash pozwala na replay signatures między accountami lub chainami.

Używaj EIP-712 typed data (domain zawiera `verifyingContract` i `chainId`) i zwracaj dokładną ERC-1271 magic value `0x1626ba7e` przy sukcesie.

## 5) Reverts do not refund after validation
Gdy `validateUserOp` zakończy się sukcesem, fees są już committed, nawet jeśli execution później revertuje. Attackers mogą wielokrotnie wysyłać ops, które zakończą się fail i nadal pobierać fees z account.

Dla paymasters, płacenie z shared pool w `validateUserOp` i charge users w `postOp` jest kruche, ponieważ `postOp` może revert bez cofnięcia payment. Zabezpieczaj funds podczas validation (per-user escrow/deposit), utrzymuj `postOp` minimalne i non-reverting, oraz budżetuj `paymasterPostOpGasLimit` dla najgorszej ścieżki reimbursement.

## 6) Counterfactual deployment / factory assumptions
Pierwsze `UserOperation` często niesie `initCode`, które powoduje, że account jest deployed przez **factory** podczas validation. Tę ścieżkę łatwo niedostatecznie audytować, bo uruchamia się tylko przy pierwszym użyciu.

Typowe failures:

- Factory/initializer ufa `msg.sender == entryPoint`, ale ścieżka deployment ERC-4337 nie wywołuje `initCode` bezpośrednio z `EntryPoint`.
- Salt, owner, validator albo module configuration nie są w pełni powiązane ze signed intent, więc frontrunner może wygrać race o pierwszy deployment i spalić counterfactual address z ustawieniami kontrolowanymi przez attacker.
- Factory nie jest idempotentna, więc powtórzony first-use flow brickuje wallet zamiast zwrócić już utworzony address.

Safe pattern: przeliczaj expected sender z podpisanych deployment parameters, rób deployment deterministycznie (zwykle `CREATE2`) i spraw, aby initialization było one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika walidacji, którą bundlery odrzucają
Kod walidacji może być poprawny w lokalnych testach, a mimo to nie nadawać się do użycia w rzeczywistych bundlerach. Publiczne bundlery symulują `validateUserOp()` / `validatePaymasterUserOp()` off-chain i zwykle uruchamiają pełny `debug_traceCall(handleOps)` przed inclusion.

To sprawia, że następujące wzorce są niebezpieczne wewnątrz walidacji:

- Operandy zależne od bloku, takie jak `TIMESTAMP`, `NUMBER` lub `BLOCKHASH`
- Zapis stanu, taki jak `SSTORE`
- Nieograniczona iteracja po storage
- Dowolne zewnętrzne call lub odczyty oracle, które mogą się zmienić między symulacją a inclusion

Zły przykład:
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
Traktuj walidację jako deterministyczną, ograniczoną funkcję preflight. Jeśli naprawdę potrzebujesz współdzielonego stanu albo zewnętrznych lookupów, przenieś tę złożoność do jednostek ze stake/reputation-tracked i testuj dokładną ścieżkę symulacji bundler, a nie tylko testy jednostkowe.

## 8) ERC-7702 initialization frontrun
ERC-7702 pozwala EOA uruchomić kod smart-account dla pojedynczego tx. Jeśli initialization jest wywoływalna z zewnątrz, frontrunner może ustawić siebie jako owner.

Mitigation: zezwól na initialization tylko przy **self-call** i tylko raz.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Szybkie kontrole przed scaleniem
- Waliduj podpisy używając `userOpHash` z `EntryPoint` (wiąże pola gas).
- Ogranicz funkcje uprzywilejowane do `EntryPoint` i/lub `address(this)` zależnie od potrzeb.
- Utrzymuj `validateUserOp` bezstanowe, deterministyczne i zgodne z regułami symulacji bundlera.
- Wymuś separację domeny EIP-712 dla ERC-1271 i zwracaj `0x1626ba7e` przy sukcesie.
- Utrzymuj `postOp` minimalne, ograniczone i bez revertów; zabezpiecz opłaty podczas walidacji.
- Testuj osobno pierwszą ścieżkę `initCode`: deterministyczny deployment, idempotentne zachowanie factory i jednorazową inicjalizację.
- Uruchom pełną symulację bundlera (`simulateValidation` oraz śledzone `handleOps`) przed wdrożeniem.
- Dla ERC-7702, zezwalaj na init tylko przy self-call i tylko raz.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
