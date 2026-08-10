# Pułapki bezpieczeństwa Smart Account w ERC-4337

Abstrakcja kont ERC-4337 zmienia portfele w programowalne systemy. Główny przepływ to **validate-then-execute** w ramach całego bundle: `EntryPoint` weryfikuje każdą `UserOperation` przed wykonaniem którejkolwiek z nich.<sup>[[5]](#references)</sup> Ta kolejność tworzy nieoczywistą attack surface, gdy walidacja jest liberalna, stanowa lub niespójna z regułami symulacji bundlera.

## 1) Obejście przez bezpośrednie wywołanie funkcji uprzywilejowanych
Każda publicznie wywoływalna funkcja `execute` (lub funkcja przenosząca środki), która nie jest ograniczona do `EntryPoint` (lub sprawdzonego modułu executora), może zostać wywołana bezpośrednio w celu opróżnienia konta.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezpieczny wzorzec: ogranicz do `EntryPoint` i używaj `msg.sender == address(this)` dla przepływów administracyjnych i zarządzania sobą (instalowanie modułów, zmiany validatorów, upgrades).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Niepodpisane lub niesprawdzane pola gas -> drenaż opłat
Jeśli walidacja podpisu obejmuje tylko zamiar (`callData`), ale nie pola związane z gas, bundler lub frontrunner może zawyżyć opłaty i opróżnić ETH. Podpisany payload musi wiązać co najmniej:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Wzorzec obronny: używaj dostarczanego przez `EntryPoint` `userOpHash` (który obejmuje pola gas) i/lub ściśle ograniczaj każde pole.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering walidacji stanowej (semantyka bundla)
Ponieważ wszystkie walidacje są wykonywane przed jakimkolwiek wykonaniem, przechowywanie wyników walidacji w stanie kontraktu jest niebezpieczne. Inna operacja w tym samym bundlu może je nadpisać, powodując, że wykonanie użyje stanu kontrolowanego przez attackera.<sup>[[2]](#references)</sup>

Unikaj zapisu do storage w `validateUserOp`. Jeśli jest to nieuniknione, kluczuj dane tymczasowe za pomocą `userOpHash` i usuwaj je deterministycznie po użyciu (preferowana jest walidacja bezstanowa).<sup>[[2]](#references)</sup>

## 4) Replay ERC-1271 między kontami i chainami (brak separacji domen)
`isValidSignature(bytes32 hash, bytes sig)` musi wiązać podpis z **tym kontraktem** i **tym chainem**. Odzyskiwanie podpisującego na podstawie surowego hasha pozwala na replay podpisów między kontami lub chainami.<sup>[[1]](#references)[[4]](#references)</sup>

Używaj typed data EIP-712 (domena zawiera `verifyingContract` i `chainId`) oraz zwracaj dokładną wartość magiczną ERC-1271 `0x1626ba7e` w przypadku powodzenia.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Revert nie powoduje zwrotu środków po walidacji
Gdy `validateUserOp` zakończy się powodzeniem, opłaty są już zatwierdzone, nawet jeśli wykonanie później zakończy się revert. Attackers mogą wielokrotnie przesyłać operacje, które zakończą się niepowodzeniem, a mimo to pobierać opłaty z konta.<sup>[[2]](#references)</sup>

W przypadku paymasterów pobieranie środków ze współdzielonej puli w `validateUserOp` i obciążanie użytkowników w `postOp` jest podatne na problemy, ponieważ `postOp` może zakończyć się revert bez cofnięcia płatności. Zabezpieczaj środki podczas walidacji (osobny escrow/deposit dla użytkownika), utrzymuj `postOp` jako minimalny i niepowodujący revertów oraz rezerwuj `paymasterPostOpGasLimit` na najgorszy przypadek ścieżki refundacji.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Założenia dotyczące wdrożenia kontrfaktycznego / factory
Pierwsza `UserOperation` często zawiera `initCode`, co powoduje wdrożenie konta przez **factory** podczas walidacji. Ta ścieżka jest często niedostatecznie audytowana, ponieważ jest uruchamiana tylko przy pierwszym użyciu.<sup>[[5]](#references)</sup>

Typowe błędy obejmują:<sup>[[5]](#references)</sup>

- Factory/initializer ufa, że `msg.sender == entryPoint`, ale ścieżka wdrażania ERC-4337 **nie** wywołuje `initCode` bezpośrednio z `EntryPoint`.
- Salt, owner, validator lub konfiguracja modułu nie są w pełni powiązane z podpisaną intencją, więc frontrunner może wyprzedzić pierwsze wdrożenie i zająć adres kontrfaktyczny ustawieniami kontrolowanymi przez attackera.
- Factory nie jest idempotentne, więc powtórzenie ścieżki pierwszego użycia blokuje wallet zamiast zwrócić już utworzony adres.

Bezpieczny wzorzec: ponownie obliczaj oczekiwanego sendera na podstawie podpisanych parametrów wdrożenia, zapewnij deterministyczne wdrażanie (zwykle za pomocą `CREATE2`) i spraw, aby inicjalizacja mogła zostać wykonana tylko raz.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika walidacji odrzucana przez bundlers

Kod walidacji może działać poprawnie w lokalnych testach, a mimo to być bezużyteczny w prawdziwych bundlers. Bundlers uruchamiają walidację wielokrotnie i przed przesłaniem powinny wykonać pełną walidację bundle'a z tracingiem.<sup>[[6]](#references)</sup>

Zgodnie z zasadami zakresu walidacji niebezpieczne są następujące wzorce:<sup>[[6]](#references)</sup>

- OpCode zależne od bloku, takie jak `TIMESTAMP`, `NUMBER` lub `BLOCKHASH`
- Dostęp do storage poza dozwolonym zakresem account/entity lub nieograniczone iterowanie po storage
- Wywołania zewnętrzne lub odczyty z oracle zależne od zmiennego stanu poza dozwolonym zakresem walidacji

Zły przykład:
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
Traktuj walidację jako deterministyczną, ograniczoną funkcję preflight. Jeśli wymagany jest współdzielony stan lub zewnętrzne zapytania, stosuj zasady dotyczące staked entity i testuj tę samą ścieżkę wieloprzebiegowej symulacji bundlera, a nie tylko testy jednostkowe.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 zapewnia EOA trwałą delegację do kodu smart account; delegacja nie uruchamia inicjalizacji atomowo. Jeśli inicjalizacja jest dostępna z zewnątrz, obserwator może wykonać frontrun i ustawić siebie jako właściciela.<sup>[[7]](#references)</sup>

Mitigacja: wymagaj, aby calldata inicjalizacji była autoryzowana przez EOA, i zezwalaj na inicjalizację tylko raz. W przepływie ERC-4337 EIP-7702 ogranicz również caller do `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Szybkie kontrole przed scaleniem
- Weryfikuj sygnatury za pomocą `userOpHash` obiektu `EntryPoint` (wiąże pola gasu).
- Ograniczaj funkcje uprzywilejowane do `EntryPoint` i/lub `address(this)`, zależnie od potrzeb.
- Utrzymuj `validateUserOp` jako bezstanową, deterministyczną i zgodną z zasadami symulacji bundlera.
- Wymuszaj separację domeny EIP-712 dla ERC-1271 i zwracaj `0x1626ba7e` w przypadku powodzenia.
- Utrzymuj `postOp` jako minimalną, ograniczoną i niepowodującą revertu; zabezpieczaj opłaty podczas walidacji.
- Testuj osobno pierwszą ścieżkę `initCode`: deterministyczne wdrażanie, idempotentne działanie factory oraz jednorazową inicjalizację.
- Przed wdrożeniem uruchom wieloprzebiegową walidację bundlera oraz pełną kontrolę bundle z trace'owaniem.
- W przypadku ERC-7702 powiąż init z autoryzacją EOA i zezwalaj na nie tylko raz; w przepływach ERC-4337 ogranicz caller do `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 - dotkniętych ponad 15 zespołów (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Sześć błędów w smart accountach ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standardowa metoda walidacji sygnatur dla kontraktów](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashowanie i podpisywanie typowanych danych strukturalnych](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Abstrakcja kont z użyciem Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Reguły zakresu walidacji abstrakcji kont](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Ustawianie kodu dla EOA](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
