# Pułapki bezpieczeństwa Smart Account w ERC-4337

{{#include ../../banners/hacktricks-training.md}}

Abstrakcja kont w ERC-4337 przekształca portfele w programowalne systemy. Główny przepływ opiera się na **validate-then-execute** dla całego bundla: `EntryPoint` weryfikuje każdą `UserOperation` przed wykonaniem którejkolwiek z nich. Taka kolejność tworzy nieoczywistą powierzchnię ataku, gdy walidacja jest zbyt liberalna, stanowa lub niespójna z regułami symulacji bundlera.

## 1) Obejście uprawnień przez bezpośrednie wywołanie
Każdą publicznie wywoływalną funkcję `execute` (lub funkcję przenoszącą środki), która nie jest ograniczona do `EntryPoint` (lub zweryfikowanego modułu executora), można wywołać bezpośrednio w celu opróżnienia konta.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezpieczny wzorzec: ogranicz do `EntryPoint` i używaj `msg.sender == address(this)` w przepływach administracyjnych i samozarządzania (instalowanie modułów, zmiany validatorów, aktualizacje).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Niepodpisane lub niesprawdzane pola gasu -> drenaż opłat
Jeśli walidacja podpisu obejmuje tylko zamiar (`callData`), ale nie pola związane z gasem, bundler lub frontrunner może zawyżyć opłaty i opróżnić saldo ETH. Podpisany payload musi wiązać co najmniej:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Wzorzec ochronny: używaj dostarczanego przez `EntryPoint` `userOpHash` (który zawiera pola gasu) i/lub ściśle ograniczaj każde pole.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Nadpisywanie wyników walidacji ze stanem (semantyka bundla)
Ponieważ wszystkie walidacje są wykonywane przed jakimkolwiek wykonaniem, przechowywanie wyników walidacji w stanie kontraktu jest niebezpieczne. Inna operacja w tym samym bundlu może je nadpisać, powodując wykonanie operacji z użyciem stanu kontrolowanego przez atakującego.<sup>[[1]](#references)</sup>

Unikaj zapisywania danych w storage w `validateUserOp`. Jeśli jest to nieuniknione, kluczuj dane tymczasowe za pomocą `userOpHash` i usuwaj je deterministycznie po użyciu (preferuj stateless validation).<sup>[[1]](#references)</sup>

## 4) Replay ERC-1271 między kontami i chainami (brak separacji domen)
`isValidSignature(bytes32 hash, bytes sig)` musi wiązać podpis z **tym kontraktem** i **tym chainem**. Odzyskiwanie podpisującego na podstawie surowego hasha umożliwia replay podpisów między kontami lub chainami.<sup>[[1]](#references)</sup>

Używaj typed data EIP-712 (domena zawiera `verifyingContract` i `chainId`) oraz zwracaj dokładną magiczną wartość ERC-1271 `0x1626ba7e` w przypadku powodzenia.<sup>[[1]](#references)</sup>

## 5) Revert nie zwraca opłat po walidacji
Po pomyślnym wykonaniu `validateUserOp` opłaty zostają naliczone, nawet jeśli wykonanie później zakończy się revert. Atakujący mogą wielokrotnie przesyłać operacje, które zakończą się niepowodzeniem, a mimo to pobierać opłaty z konta.<sup>[[1]](#references)</sup>

W przypadku paymasterów płacenie ze wspólnej puli w `validateUserOp` i obciążanie użytkowników w `postOp` jest ryzykowne, ponieważ `postOp` może zakończyć się revert bez cofnięcia płatności. Zabezpiecz środki podczas walidacji (per-user escrow/deposit), zachowaj `postOp` jako minimalne i niewywołujące revert, a `paymasterPostOpGasLimit` ustaw z uwzględnieniem najgorszego przypadku ścieżki refundacji.<sup>[[1]](#references)</sup>

## 6) Deployment kontrfaktyczny / założenia dotyczące factory
Pierwsza `UserOperation` często zawiera `initCode`, co powoduje deployment konta przez **factory** podczas walidacji. Ta ścieżka jest łatwa do niedostatecznego audytu, ponieważ jest wykonywana tylko przy pierwszym użyciu.<sup>[[2]](#references)</sup>

Typowe błędy:

- Factory/initializer ufa, że `msg.sender == entryPoint`, ale ścieżka deploymentu ERC-4337 **nie** wywołuje `initCode` bezpośrednio z `EntryPoint`.
- Salt, owner, validator lub konfiguracja modułu nie są w pełni powiązane z podpisaną intencją, więc frontrunner może przejąć wyścig o pierwszy deployment i zająć adres kontrfaktyczny ustawieniami kontrolowanymi przez atakującego.
- Factory nie jest idempotentne, więc powtórzony proces pierwszego użycia blokuje wallet zamiast zwrócić już utworzony adres.

Bezpieczny wzorzec: ponownie oblicz oczekiwanego sendera na podstawie podpisanych parametrów deploymentu, zapewnij deterministyczny deployment (zwykle `CREATE2`) i spraw, aby inicjalizacja mogła zostać wykonana tylko raz.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika walidacji odrzucana przez bundlers
Kod walidacji może być poprawny w lokalnych testach, a mimo to nie nadawać się do użycia przez rzeczywiste bundlers. Publiczne bundlers symulują `validateUserOp()` / `validatePaymasterUserOp()` off-chain i często wykonują pełne `debug_traceCall(handleOps)` przed uwzględnieniem operacji.

To sprawia, że poniższe wzorce w walidacji są niebezpieczne:

- Opkody zależne od bloku, takie jak `TIMESTAMP`, `NUMBER` lub `BLOCKHASH`
- Zapisy stanu, takie jak `SSTORE`
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
Traktuj walidację jako deterministyczną, ograniczoną funkcję preflight. Jeśli naprawdę potrzebujesz współdzielonego stanu lub zewnętrznych odwołań, przenieś tę złożoność do encji objętych stakingiem i śledzeniem reputacji oraz testuj dokładną ścieżkę symulacji bundlera, a nie tylko testy jednostkowe.

## 8) Frontrun inicjalizacji ERC-7702
ERC-7702 pozwala EOA uruchamiać kod smart-account przez pojedynczy tx. Jeśli inicjalizacja jest dostępna z zewnątrz, frontrunner może ustawić siebie jako owner.<sup>[[1]](#references)</sup>

Mitigacja: zezwalaj na inicjalizację wyłącznie w ramach **self-call** i tylko raz.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Szybkie kontrole przed scaleniem
- Weryfikuj signatures za pomocą `userOpHash` obiektu `EntryPoint` (wiąże pola gas).
- Ogranicz uprzywilejowane funkcje do `EntryPoint` i/lub `address(this)`, odpowiednio do sytuacji.
- Zachowaj `validateUserOp` jako bezstanową i deterministyczną oraz zgodną z zasadami symulacji bundlera.
- Wymuś separację domeny EIP-712 dla ERC-1271 i zwracaj `0x1626ba7e` w przypadku powodzenia.
- Zachowaj `postOp` jako minimalną, ograniczoną i niepowodującą revertów; zabezpiecz opłaty podczas walidacji.
- Testuj osobno pierwszą ścieżkę `initCode`: deterministyczne wdrażanie, idempotentne działanie factory oraz jednorazową inicjalizację.
- Przed wdrożeniem uruchom pełną symulację bundlera (`simulateValidation` oraz śledzone `handleOps`).
- W przypadku ERC-7702 zezwalaj na init wyłącznie podczas self-call i tylko raz.



## Referencje

- [1] [Sześć błędów w smart accountach ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Abstrakcja kont z użyciem alternatywnego mempoola](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
