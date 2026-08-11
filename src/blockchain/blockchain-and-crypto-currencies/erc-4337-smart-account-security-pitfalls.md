# Pułapki bezpieczeństwa smart accountów

{{#include ../../banners/hacktricks-training.md}}

Abstrakcja kont ERC-4337 przekształca portfele w programowalne systemy. Główny przepływ to **validate-then-execute** w ramach całego pakietu: `EntryPoint` weryfikuje każdą `UserOperation` przed wykonaniem którejkolwiek z nich.<sup>[[5]](#references)</sup> Ta kolejność tworzy nieoczywistą powierzchnię ataku, gdy walidacja jest zbyt liberalna, stanowa lub niespójna z regułami symulacji bundlera.

## 1) Ominięcie przez bezpośrednie wywołanie uprzywilejowanych funkcji
Każda zewnętrznie wywoływalna funkcja `execute` (lub funkcja przenosząca środki), która nie jest ograniczona do `EntryPoint` (lub zweryfikowanego modułu executora), może zostać wywołana bezpośrednio w celu opróżnienia konta.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezpieczny wzorzec: ogranicz do `EntryPoint` i używaj `msg.sender == address(this)` w przepływach administracyjnych i zarządzania własnym kontem (instalowanie modułów, zmiany validatorów, aktualizacje).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Niezainicjalizowane lub niesprawdzane pola gas -> wyczerpanie opłat
Jeśli walidacja podpisu obejmuje wyłącznie intencję (`callData`), ale nie pola związane z gas, bundler lub frontrunner może zawyżyć opłaty i wyczerpać ETH. Podpisany payload musi obejmować co najmniej:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Wzorzec defensywny: używaj dostarczanego przez `EntryPoint` `userOpHash` (który obejmuje pola gas) i/lub ściśle ograniczaj każde pole.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Nadpisywanie walidacji stanowej (semantyka bundle)
Ponieważ wszystkie walidacje są wykonywane przed jakimkolwiek wykonaniem, zapisywanie wyników walidacji w stanie kontraktu jest niebezpieczne. Inna operacja w tym samym bundle może je nadpisać, powodując, że wykonanie użyje stanu kontrolowanego przez attackera.<sup>[[2]](#references)</sup>

Unikaj zapisywania danych w storage w `validateUserOp`. Jeśli jest to nieuniknione, oznaczaj dane tymczasowe za pomocą `userOpHash` i deterministycznie usuwaj je po użyciu (preferowana jest stateless validation).<sup>[[2]](#references)</sup>

## 4) Replay ERC-1271 między kontami i chainami (brak separacji domen)
`isValidSignature(bytes32 hash, bytes sig)` musi wiązać podpis z **tym kontraktem** i **tym chainem**. Odzyskiwanie podpisującego na podstawie surowego hasha pozwala na replay podpisów między kontami lub chainami.<sup>[[1]](#references)[[4]](#references)</sup>

Używaj typed data EIP-712 (domena zawiera `verifyingContract` i `chainId`) oraz zwracaj dokładną wartość magiczną ERC-1271 `0x1626ba7e` w przypadku powodzenia.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts nie powodują zwrotu środków po walidacji
Po pomyślnym wykonaniu `validateUserOp` opłaty są naliczane nawet wtedy, gdy wykonanie później zakończy się revertem. Attackers mogą wielokrotnie przesyłać operacje, które zakończą się niepowodzeniem, a mimo to pobierać opłaty z konta.<sup>[[2]](#references)</sup>

W przypadku paymasterów płacenie ze wspólnego poola w `validateUserOp` i obciążanie użytkowników w `postOp` jest podatne na problemy, ponieważ `postOp` może zakończyć się revertem bez cofnięcia płatności. Zabezpieczaj środki podczas walidacji (per-user escrow/deposit), utrzymuj `postOp` w minimalnej formie i bez możliwości revertu oraz rezerwuj `paymasterPostOpGasLimit` na najgorszy przypadek ścieżki refundacji.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Deployment kontrfaktyczny / założenia dotyczące factory
Pierwsza `UserOperation` często zawiera `initCode`, który powoduje wdrożenie konta za pośrednictwem **factory** podczas walidacji. Ta ścieżka jest łatwa do pominięcia w audycie, ponieważ jest wykonywana tylko przy pierwszym użyciu.<sup>[[5]](#references)</sup>

Typowe błędy obejmują:<sup>[[5]](#references)</sup>

- Factory/initializer ufa, że `msg.sender == entryPoint`, ale ścieżka deploymentu ERC-4337 **nie** wywołuje `initCode` bezpośrednio z `EntryPoint`.
- Salt, owner, validator lub konfiguracja modułu nie są w pełni powiązane z podpisaną intencją, więc frontrunner może wyścignąć pierwszy deployment i zająć adres kontrfaktyczny ustawieniami kontrolowanymi przez attackera.
- Factory nie jest idempotentna, więc powtórzona ścieżka pierwszego użycia blokuje wallet zamiast zwrócić już utworzony adres.

Bezpieczny wzorzec: ponownie obliczaj oczekiwanego sendera na podstawie podpisanych parametrów deploymentu, zapewnij deterministyczny deployment (zwykle za pomocą `CREATE2`) i spraw, aby inicjalizacja mogła zostać wykonana tylko raz.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika walidacji odrzucana przez bundlers

Kod walidacji może działać poprawnie w lokalnych testach, a mimo to być niemożliwy do użycia przez rzeczywiste bundlers. Bundlers uruchamiają walidację wielokrotnie i przed wysłaniem powinny przeprowadzić prześledzoną, pełną walidację całego bundla.<sup>[[6]](#references)</sup>

Zgodnie z zasadami zakresu walidacji następujące wzorce są niebezpieczne:<sup>[[6]](#references)</sup>

- Opcode zależne od bloku, takie jak `TIMESTAMP`, `NUMBER` lub `BLOCKHASH`
- Dostęp do storage poza dozwolonym zakresem konta/encji lub nieograniczone iterowanie po storage
- Zewnętrzne wywołania lub odczyty oracle zależne od zmiennego stanu poza dozwolonym zakresem walidacji

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
Traktuj walidację jako deterministyczną, ograniczoną funkcję preflight. Jeśli wymagany jest współdzielony stan lub zewnętrzne zapytania, przestrzegaj zasad dotyczących staked entities i testuj tę samą wieloetapową ścieżkę symulacji bundlera, a nie tylko testy jednostkowe.<sup>[[6]](#references)</sup>

## 8) ERC-7702 frontrun inicjalizacji
ERC-7702 zapewnia EOA trwałą delegację do kodu smart account; delegacja nie wykonuje inicjalizacji atomowo. Jeśli inicjalizacja jest dostępna z zewnątrz, obserwator może wykonać front-run i ustawić siebie jako właściciela.<sup>[[7]](#references)</sup>

Mitigacja: wymagaj, aby calldata inicjalizacji była autoryzowana przez EOA, i zezwalaj na inicjalizację tylko raz. W przepływie ERC-4337 EIP-7702 dodatkowo ogranicz wywołującego do `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Szybkie kontrole przed scaleniem
- Weryfikuj signatures za pomocą `userOpHash` obiektu `EntryPoint` (wiąże pola gas).
- Ogranicz uprzywilejowane funkcje do `EntryPoint` i/lub `address(this)` odpowiednio do potrzeb.
- Zachowaj bezstanowość i deterministyczność `validateUserOp` oraz zgodność z regułami symulacji bundlera.
- Wymuś separację domeny EIP-712 dla ERC-1271 i zwracaj `0x1626ba7e` w przypadku powodzenia.
- Zachowaj `postOp` jako minimalne, ograniczone i niepowodujące revertu; zabezpiecz opłaty podczas walidacji.
- Testuj oddzielnie pierwszą ścieżkę `initCode`: deterministyczne wdrażanie, idempotentne działanie factory oraz jednorazową inicjalizację.
- Przed wdrożeniem uruchom wieloprzebiegową walidację bundlera oraz sprawdzenie całego bundle z tracingiem.
- W przypadku ERC-7702 powiąż init z autoryzacją EOA i zezwalaj na nie tylko raz; w przepływach ERC-4337 ogranicz caller do `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 - dotyczy ponad 15 zespołów (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Sześć błędów w smart accountach ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standardowa metoda walidacji signatures dla kontraktów](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashowanie i podpisywanie typowanych danych strukturalnych](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Abstrakcja kont z użyciem Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Reguły zakresu walidacji abstrakcji kont](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Ustawianie kodu dla EOA](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
