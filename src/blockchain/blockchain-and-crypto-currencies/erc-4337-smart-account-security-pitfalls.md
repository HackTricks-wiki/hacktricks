# Pułapki bezpieczeństwa Smart Account w ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Abstrakcja kont w ERC-4337 zmienia wallets w programowalne systemy. Główny przepływ to **validate-then-execute** w ramach całego bundle: `EntryPoint` weryfikuje każdą `UserOperation` przed wykonaniem którejkolwiek z nich. Taka kolejność tworzy nieoczywistą powierzchnię ataku, gdy walidacja jest zbyt liberalna, stanowa lub niespójna z zasadami symulacji bundlera.

## 1) Ominięcie zabezpieczeń uprzywilejowanych funkcji przez bezpośrednie wywołanie
Każda publicznie wywoływalna funkcja `execute` (lub funkcja przenosząca środki), która nie jest ograniczona do `EntryPoint` (lub sprawdzonego modułu executora), może zostać wywołana bezpośrednio w celu opróżnienia konta.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezpieczny wzorzec: ogranicz do `EntryPoint` i używaj `msg.sender == address(this)` w przepływach administracyjnych/samozarządzania (instalowanie modułów, zmiany validatorów, aktualizacje).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Niepodpisane lub niesprawdzane pola gas -> drenaż opłat
Jeśli walidacja podpisu obejmuje wyłącznie intent (`callData`), ale nie pola związane z gas, bundler lub frontrunner może zawyżyć opłaty i opróżnić saldo ETH. Podpisany payload musi wiązać co najmniej:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Wzorzec ochronny: używaj dostarczanego przez `EntryPoint` `userOpHash` (który zawiera pola gas) i/lub ściśle ograniczaj każde pole.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Nadpisywanie walidacji ze stanem (semantyka bundle)
Ponieważ wszystkie walidacje są wykonywane przed jakimkolwiek wykonaniem, zapisywanie wyników walidacji w stanie kontraktu jest niebezpieczne. Inna operacja w tym samym bundle może je nadpisać, powodując, że wykonanie użyje stanu kontrolowanego przez attackera.<sup>[[1]](#references)</sup>

Unikaj zapisywania danych w storage w `validateUserOp`. Jeśli jest to nieuniknione, przypisuj dane tymczasowe do `userOpHash` i deterministycznie usuwaj je po użyciu (preferowana jest stateless validation).<sup>[[1]](#references)</sup>

## 4) Replay ERC-1271 między kontami i chainami (brak separacji domen)
`isValidSignature(bytes32 hash, bytes sig)` musi wiązać podpis z **tym kontraktem** i **tym chainem**. Odzyskiwanie klucza na podstawie surowego hasha pozwala na replay podpisów między kontami lub chainami.<sup>[[1]](#references)</sup>

Używaj typed data EIP-712 (domena zawiera `verifyingContract` i `chainId`) oraz zwracaj dokładną magiczną wartość ERC-1271 `0x1626ba7e` w przypadku sukcesu.<sup>[[1]](#references)</sup>

## 5) Rewerty nie zwracają opłat po walidacji
Po pomyślnym zakończeniu `validateUserOp` opłaty są już naliczone, nawet jeśli wykonanie później zakończy się rewertem. Attackers mogą wielokrotnie przesyłać operacje, które zakończą się niepowodzeniem, a mimo to pobierać opłaty z konta.<sup>[[1]](#references)</sup>

W przypadku paymasterów pobieranie środków ze wspólnej puli w `validateUserOp` i obciążanie użytkowników w `postOp` jest podatne na błędy, ponieważ `postOp` może zakończyć się rewertem bez cofnięcia płatności. Zabezpieczaj środki podczas walidacji (escrow/deposit per użytkownik), utrzymuj `postOp` jako minimalne i niegenerujące rewertów oraz uwzględnij w budżecie `paymasterPostOpGasLimit` najgorszy przypadek ścieżki zwrotu kosztów.<sup>[[1]](#references)</sup>

## 6) Założenia dotyczące wdrażania counterfactual / factory
Pierwsza `UserOperation` często zawiera `initCode`, co powoduje wdrożenie konta przez **factory** podczas walidacji. Ta ścieżka jest łatwa do niewystarczającego przeaudytowania, ponieważ jest uruchamiana tylko przy pierwszym użyciu.<sup>[[2]](#references)</sup>

Typowe błędy:

- Factory/initializer ufa, że `msg.sender == entryPoint`, ale ścieżka wdrażania ERC-4337 **nie** wywołuje `initCode` bezpośrednio z `EntryPoint`.
- Salt, owner, validator lub konfiguracja modułów nie są w pełni powiązane z podpisaną intencją, więc frontrunner może wyprzedzić pierwsze wdrożenie i zająć adres counterfactual ustawieniami kontrolowanymi przez attackera.
- Factory nie jest idempotentne, więc powtórzenie przepływu pierwszego użycia blokuje wallet zamiast zwrócić już utworzony adres.

Bezpieczny wzorzec: ponownie oblicz oczekiwanego sendera na podstawie podpisanych parametrów wdrożenia, zapewnij deterministyczne wdrożenie (zwykle za pomocą `CREATE2`) i spraw, aby inicjalizacja mogła zostać wykonana tylko raz.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika walidacji odrzucana przez bundlers

Kod walidacji może być poprawny w testach lokalnych, a mimo to nie nadawać się do użycia przez rzeczywiste bundlers. Publiczne bundlers symulują `validateUserOp()` / `validatePaymasterUserOp()` off-chain i często wykonują pełne `debug_traceCall(handleOps)` przed uwzględnieniem operacji.<sup>[[3]](#references)</sup>

To sprawia, że poniższe wzorce są niebezpieczne w walidacji:

- Opkody zależne od bloku, takie jak `TIMESTAMP`, `NUMBER` lub `BLOCKHASH`
- Zapisy do stanu, takie jak `SSTORE`
- Nieograniczone iterowanie po storage
- Dowolne wywołania zewnętrzne lub odczyty z oracle, które mogą zmienić się między symulacją a uwzględnieniem operacji

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
Traktuj walidację jako deterministyczną, ograniczoną funkcję preflight. Jeśli rzeczywiście potrzebujesz współdzielonego stanu lub zewnętrznych odwołań, przenieś tę złożoność do encji ze stakiem i śledzoną reputacją oraz testuj dokładną ścieżkę symulacji bundlera, a nie tylko testy jednostkowe.

## 8) Frontrun inicjalizacji ERC-7702
ERC-7702 pozwala EOA wykonywać kod smart accountu w ramach pojedynczego tx. Jeśli inicjalizacja jest dostępna z zewnątrz, frontrunner może ustawić siebie jako właściciela.<sup>[[1]](#references)</sup>

Mitigacja: zezwalaj na inicjalizację wyłącznie za pomocą **self-call** i tylko raz.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Szybkie kontrole przed scaleniem
- Weryfikuj podpisy za pomocą `userOpHash` obiektu `EntryPoint` (wiąże pola dotyczące gasu).
- Ogranicz funkcje uprzywilejowane do `EntryPoint` i/lub `address(this)`, zależnie od sytuacji.
- Zachowaj bezstanowość i determinizm `validateUserOp`, zapewniając zgodność z regułami symulacji bundlera.
- Wymuś separację domeny EIP-712 dla ERC-1271 i zwracaj `0x1626ba7e` w przypadku powodzenia.
- Zachowaj `postOp` jako minimalną, ograniczoną i niepowodującą revertu funkcję; zabezpiecz opłaty podczas walidacji.
- Przetestuj osobno pierwszą ścieżkę `initCode`: deterministyczne wdrażanie, idempotentne działanie factory oraz jednorazową inicjalizację.
- Przed wdrożeniem uruchom pełną symulację bundlera (`simulateValidation` oraz śledzone `handleOps`).
- W przypadku ERC-7702 zezwalaj na init wyłącznie podczas self-call i tylko raz.

## References

- [1] [Six mistakes in ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
