# ERC-4337 Pułapki bezpieczeństwa Smart Accountów

{{#include ../../banners/hacktricks-training.md}}

Abstrakcja kont ERC-4337 zamienia portfele w programowalne systemy. Główny przepływ to **validate-then-execute** dla całego pakietu: `EntryPoint` waliduje każdą `UserOperation` przed wykonaniem którejkolwiek z nich. Taki porządek tworzy nieoczywistą powierzchnię ataku, gdy walidacja jest zbyt liberalna lub zależna od stanu.

## 1) Omijanie uprzywilejowanych funkcji przez bezpośrednie wywołanie
Każda zewnętrznie wywoływalna funkcja `execute` (lub przenosząca środki), która nie jest ograniczona do `EntryPoint` (lub sprawdzonego modułu wykonawczego), może być wywołana bezpośrednio, aby opróżnić konto.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezpieczny wzorzec: ograniczyć do `EntryPoint` i używać `msg.sender == address(this)` dla przepływów administracyjnych i samodzielnego zarządzania (instalacja modułu, zmiany walidatora, aktualizacje).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Niepodpisane lub niezweryfikowane pola gas -> wyciek opłat
Jeśli walidacja podpisu obejmuje tylko intencję (`callData`), ale nie pola związane z gas, bundler lub frontrunner mogą zawyżyć opłaty i wypompować ETH. Podpisany payload musi obejmować co najmniej:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Wzorzec obronny: użyj dostarczonego przez `EntryPoint` `userOpHash` (który zawiera pola gas) i/lub nałóż ścisłe limity na każde z tych pól.
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
Ponieważ wszystkie walidacje wykonywane są przed jakąkolwiek egzekucją, zapisywanie wyników walidacji w stanie kontraktu jest niebezpieczne. Inna op w tym samym bundle może to nadpisać, powodując, że Twoje wykonanie użyje stanu zmanipulowanego przez atakującego.

Unikaj zapisywania do storage w `validateUserOp`. Jeśli nie da się tego uniknąć, indeksuj dane tymczasowe według `userOpHash` i usuń je deterministycznie po użyciu (preferuj walidację bezstanową).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` musi powiązać sygnatury z **tym kontraktem** i **tą siecią**. Użycie recover na surowym hashie umożliwia replay sygnatur pomiędzy kontami lub łańcuchami.

Użyj EIP-712 typed data (domena powinna zawierać `verifyingContract` i `chainId`) i zwracaj dokładną magiczną wartość ERC-1271 `0x1626ba7e` po powodzeniu.

## 5) Reverts do not refund after validation
Gdy `validateUserOp` powiedzie się, opłaty są zobowiązane nawet jeśli wykonanie później revertuje. Atakujący mogą wielokrotnie wysyłać opy, które się nie powiodą, a mimo to pobierać opłaty z konta.

Dla paymasterów, opłacanie ze wspólnej puli w `validateUserOp` i obciążanie użytkowników w `postOp` jest kruche, ponieważ `postOp` może revertować bez cofnięcia płatności. Zabezpiecz środki podczas walidacji (depozyt/escrow przypisany do użytkownika) i utrzymuj `postOp` minimalnym oraz nie-revertującym.

## 6) ERC-7702 initialization frontrun
ERC-7702 pozwala EOA uruchomić kod smart-account dla pojedynczego tx. Jeśli inicjalizacja jest wywoływalna z zewnątrz, frontrunner może ustawić siebie jako właściciela.

Środki zaradcze: zezwól na inicjalizację tylko przy **self-call** i tylko raz.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Szybkie kontrole przed scaleniem
- Weryfikuj podpisy za pomocą `userOpHash` z `EntryPoint` (wiąże pola gazu).
- Ogranicz funkcje uprzywilejowane do `EntryPoint` i/lub `address(this)`, w zależności od potrzeby.
- Utrzymuj `validateUserOp` bezstanową.
- Wymuś separację domen EIP-712 dla ERC-1271 i zwróć `0x1626ba7e` przy powodzeniu.
- Utrzymuj `postOp` minimalne, ograniczone i nie wywołujące revertu; zabezpiecz opłaty podczas walidacji.
- Dla ERC-7702, zezwól na init tylko przy self-call (wywołaniu własnym) i tylko raz.

## Referencje

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
