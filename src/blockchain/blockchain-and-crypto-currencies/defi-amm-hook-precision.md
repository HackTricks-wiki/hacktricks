# Eksploatacja DeFi/AMM: nadużycie precyzji/zaokrąglania w Hookach Uniswap v4

Ta strona dokumentuje klasę technik eksploatacji DeFi/AMM wymierzonych w giełdy DEX w stylu Uniswap v4, które rozszerzają podstawową matematykę za pomocą niestandardowych hooków. Incydent Bunni V2 ilustruje powiązaną awarię: błąd kierunku zaokrąglania w księgowaniu wypłat zaniżał aktywną płynność, a późniejszy swap ujawnił to zaniżenie w rentownym sandwichu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Kluczowa idea: jeśli hook implementuje dodatkowe księgowanie zależne od matematyki fixed-point, zaokrąglania ticków i logiki progowej, atakujący może tworzyć swapy exact-input, które przekraczają określone progi, powodując kumulowanie się rozbieżności zaokrągleń na jego korzyść. Powtarzanie tego wzorca, a następnie wypłata zawyżonego salda, realizuje zysk, często finansowany za pomocą flash loan.

## Tło: hooki Uniswap v4 i przebieg swapu

- Hooki to kontrakty, które PoolManager wywołuje w określonych punktach cyklu życia (np. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pule są inicjalizowane za pomocą PoolKey zawierającego kontrakt hooka. Niezerowy adres hooka włącza callbacki wybrane dla danej puli.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooki mogą zwracać **custom deltas**, które modyfikują końcowe zmiany salda swapu lub operacji płynności (custom accounting). Te delty są rozliczane jako salda netto na końcu wywołania, więc każdy błąd zaokrągleń w matematyce hooka kumuluje się przed rozliczeniem.<sup>[[4]](#references)</sup>
- Matematyka bazowa używa formatów fixed-point, takich jak Q64.96 dla sqrtPriceX96, oraz arytmetyki ticków z wykorzystaniem 1.0001^tick. Każda niestandardowa matematyka nałożona na tę warstwę musi dokładnie zachowywać semantykę zaokrągleń, aby uniknąć dryfu inwariantów.<sup>[[12]](#references)[[13]](#references)</sup>
- Swapy mogą być exactInput lub exactOutput. W v3/v4 cena porusza się wzdłuż ticków; przekroczenie granicy ticka może aktywować/dezaktywować płynność zakresu. Hooki mogą implementować dodatkową logikę przy przekraczaniu progów/ticków.<sup>[[9]](#references)[[11]](#references)</sup>

## Archetyp podatności: dryf precyzji/zaokrągleń przy przekraczaniu progów

Typowy podatny wzorzec w niestandardowych hookach:

1. Hook oblicza delty płynności lub salda dla każdego swapu za pomocą dzielenia całkowitoliczbowego, mulDiv albo konwersji fixed-point (np. token ↔ płynność z użyciem sqrtPrice i zakresów ticków).
2. Logika progowa (np. rebalancing, stopniowa redystrybucja lub aktywacja poszczególnych zakresów) jest uruchamiana, gdy rozmiar swapu lub ruch ceny przekroczy wewnętrzną granicę.
3. Zaokrąglanie jest stosowane niespójnie (np. obcięcie w kierunku zera, floor zamiast ceil) między obliczeniem w przód a ścieżką rozliczenia. Małe rozbieżności nie znoszą się, lecz zamiast tego uznają środki na rzecz wywołującego.
4. Swapy exact-input, precyzyjnie dobrane tak, aby przekraczać te granice, wielokrotnie wykorzystują dodatnią resztę zaokrąglenia. Atakujący później wypłaca skumulowany credit.

Warunki wstępne ataku
- Pula korzystająca z niestandardowego hooka v4, który wykonuje dodatkowe obliczenia przy każdym swapie (np. LDF/rebalancer).
- Co najmniej jedna ścieżka wykonania, na której zaokrąglanie działa na korzyść inicjatora swapu przy przekraczaniu progów.
- Możliwość atomowego powtarzania wielu swapów (flash loan idealnie nadaje się do zapewnienia tymczasowego kapitału i zamortyzowania gas).

## Praktyczna metodyka ataku

1) Zidentyfikuj pule będące kandydatami i posiadające hooki
- Wylicz pule v4 i sprawdź, czy PoolKey.hooks != address(0).
- Przeanalizuj bytecode/ABI hooka pod kątem callbacków: beforeSwap/afterSwap oraz wszelkich niestandardowych metod rebalancingu.
- Szukaj matematyki, która: dzieli przez płynność, konwertuje między ilościami tokenów a płynnością lub agreguje BalanceDelta z zaokrągleniami.

2) Zamodeluj matematykę hooka i progi
- Odtwórz wzór płynności/redystrybucji hooka: dane wejściowe zazwyczaj obejmują sqrtPriceX96, tickLower/Upper, currentTick, fee tier oraz płynność netto.
- Zmapuj funkcje progowe/stopniowe: ticki, granice bucketów lub breakpointy LDF. Ustal, po której stronie każdej granicy zaokrąglana jest delta.
- Zidentyfikuj miejsca, w których konwersje rzutują między uint256/int256, używają SafeCast lub polegają na mulDiv z niejawnym floor.

3) Skalibruj swapy exact-input tak, aby przekraczały granice
- Użyj symulacji Foundry/Hardhat do obliczenia minimalnego Δin potrzebnego do przesunięcia ceny tuż za granicę i uruchomienia gałęzi hooka.
- Zweryfikuj, czy rozliczenie afterSwap uznaje na rzecz wywołującego więcej niż wynosi koszt, pozostawiając dodatnią BalanceDelta lub credit w księgowaniu hooka.
- Powtarzaj swapy, aby kumulować credit; następnie wywołaj ścieżkę wypłaty/rozliczenia hooka.

W v4 pętla swapu musi być uruchomiona z callbacku unlock PoolManager; ujemne `amountSpecified` oznacza exact input, a `sqrtPriceLimitX96` musi znajdować się ściśle wewnątrz prawidłowego zakresu. Zerowy limit ceny powoduje revert, dlatego poniższy pseudocode używa dolnej granicy dla swapu zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Przykładowy harness testowy w stylu Foundry (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: IHooks(address(bunniHook))
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
// This loop runs inside the PoolManager unlockCallback.
for (uint i; i < N; ++i) {
pm.swap(
key,
SwapParams({
zeroForOne: true,
amountSpecified: -int256(exactIn), // exactInput
sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Kalibracja exactInput
- Oblicz wartość docelową za pomocą rdzenia TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) w ujęciu wartości rzeczywistych; wynik Q64.96 jest zaokrąglany przez TickMath.<sup>[[13]](#references)</sup>
- Przybliż ilość wejściową token0 (zero-for-one), używając formuły uwzględniającej Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Dopasuj kierunek zaokrąglania do procedury core.<sup>[[12]](#references)</sup>
- Dostosuj Δin o ±1 wei wokół granicy, aby znaleźć branch, w którym hook zaokrągla na Twoją korzyść.

4) Zwiększ skalę za pomocą flash loans
- Pożycz dużą wartość nominalną (np. 3M USDT lub 2000 WETH), aby atomowo wykonać wiele iteracji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Wykonaj skalibrowaną pętlę swapów, a następnie wypłać środki i spłać pożyczkę w ramach callbacku flash loan.

Szkielet flash loan dla Aave V3
```solidity
function executeOperation(
address[] calldata assets,
uint256[] calldata amounts,
uint256[] calldata premiums,
address initiator,
bytes calldata params
) external returns (bool) {
// run threshold‑crossing swap loop here
for (uint i; i < N; ++i) {
_exactInBoundaryCrossingSwap();
}
// realize credits / withdraw inflated balances
bunniHook.withdrawCredits(address(this));
// repay
for (uint j; j < assets.length; ++j) {
IERC20(assets[j]).approve(address(POOL), amounts[j] + premiums[j]);
}
return true;
}
```
5) Wyjście i replikacja cross-chain
- Jeśli hooks są wdrożone na wielu chainach, powtórz tę samą kalibrację dla każdego chaina.
- W incydencie Bunni płynność flash-loanów i ścieżki bridge różniły się między chainami, dlatego podczas odtwarzania analizy uwzględnij ograniczenia specyficzne dla danego chaina.<sup>[[1]](#references)[[2]](#references)</sup>

## Typowe przyczyny źródłowe w matematyce hooków

- Mieszane zasady zaokrąglania: mulDiv zaokrągla w dół, podczas gdy późniejsze ścieżki efektywnie zaokrąglają w górę; albo konwersje między tokenami a liquidity stosują różne zasady zaokrąglania.
- Błędy wyrównania ticków: używanie niezaokrąglonych ticków w jednej ścieżce i zaokrąglania zgodnego z odstępem ticków w innej.
- Problemy ze znakiem lub przepełnieniem BalanceDelta podczas konwersji między int256 i uint256 w trakcie settlement.
- Utrata precyzji w konwersjach Q64.96 (sqrtPriceX96), której nie odwzorowuje mapowanie odwrotne.
- Ścieżki akumulacji: reszty z poszczególnych swapów są śledzone jako credits, które może wypłacić caller, zamiast zostać spalane lub wyzerowane w ramach bilansu.

## Custom accounting i amplifikacja delta

- Uniswap v4 custom accounting pozwala hooks zwracać deltas, które bezpośrednio korygują kwotę należną od callera lub otrzymywaną przez callera. Jeśli hook wewnętrznie śledzi credits, reszta wynikająca z zaokrągleń może akumulować się w wielu małych operacjach **przed** finalnym settlement.<sup>[[4]](#references)</sup>
- Jeśli hook udostępnia zgodną ścieżkę withdrawal, attacker może naprzemiennie wykonywać `swap → withdraw → swap` w ramach tego samego callbacku PoolManager unlock, zmuszając hook do ponownego obliczania delta na nieco innym stanie, podczas gdy balances pozostają oczekujące do czasu zakończenia unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Podczas przeglądu hooks zawsze prześledź, jak BalanceDelta/HookDelta jest tworzone i rozliczane. Pojedyncze stronnicze zaokrąglenie w jednej gałęzi może stać się narastającym credit, gdy deltas są wielokrotnie obliczane ponownie.

## Wskazówki dotyczące obrony

- Differential testing: porównuj matematykę hooka z implementacją referencyjną wykorzystującą arithmetic na liczbach wymiernych o wysokiej precyzji i sprawdzaj równość lub ograniczony błąd, który zawsze działa na niekorzyść użytkownika (nigdy na korzyść callera).
- Testy invariant/property:
- Suma delta (tokenów, liquidity) w ścieżkach swapów i korektach hooka musi zachowywać wartość z uwzględnieniem fees.
- Żadna ścieżka nie powinna tworzyć dodatniego net credit dla inicjatora swapa podczas wielokrotnych iteracji exactInput.
- Testy progów i granic ticków wokół wartości wejściowych ±1 wei dla exactInput/exactOutput.
- Zasady zaokrąglania: scentralizuj helpery zaokrąglania, które zawsze zaokrąglają na niekorzyść użytkownika; wyeliminuj niespójne casty i niejawne zaokrąglanie w dół.
- Settlement sinks: kieruj nieuniknioną resztę z zaokrągleń do treasury protokołu lub ją spalaj; nigdy nie przypisuj jej do msg.sender.
- Rate-limits/guardrails: minimalne rozmiary swapów dla triggerów rebalancingu; wyłączaj rebalancing, jeśli deltas są mniejsze niż wei; sprawdzaj poprawność delta względem oczekiwanych zakresów.
- Przeglądaj callbacki hooka całościowo: beforeSwap/afterSwap oraz before/after zmiany liquidity powinny stosować zgodne wyrównanie ticków i zaokrąglanie delta.

## Studium przypadku: Bunni V2 (2025-09-02)

- Protokół: Bunni V2, hook Uniswap v4 wykorzystujący Liquidity Density Function (LDF) do obliczania gęstości tokenów i szacunków total-liquidity.<sup>[[1]](#references)[[2]](#references)</sup>
- Dotknięte poole: USDC/USDT na Ethereum oraz weETH/ETH na Unichain, łącznie około 8,4 mln USD.<sup>[[1]](#references)</sup>
- Krok 1 (price push): attacker pożyczył flashowo około 3 mln USDT i wykonał swap, aby przesunąć tick do około 5000, zmniejszając **aktywny** balance USDC do około 28 wei.<sup>[[1]](#references)</sup>
- Krok 2 (rounding drain): 44 niewielkie withdrawals wykorzystały zaokrąglanie w dół wewnątrz `BunniHubLogic::withdraw()`, zmniejszając aktywny balance USDC z 28 wei do 4 wei (-85,7%), podczas gdy spalono jedynie niewielką część udziałów LP. Total liquidity zmniejszyła się o około 84,4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Krok 3 (liquidity rebound sandwich): duży swap przesunął tick do około 839 189 (1 USDC ≈ 2,77e36 USDT). Szacunki liquidity odwróciły się i wzrosły o około 16,8%, umożliwiając sandwich, w którym attacker wykonał swap powrotny po zawyżonej cenie i zakończył operację z zyskiem.<sup>[[1]](#references)</sup>
- Zidentyfikowana poprawka w post-mortem: zmiana aktualizacji idle-balance tak, aby zaokrąglała **w górę**, dzięki czemu powtarzające się micro-withdrawals nie będą już stopniowo zmniejszać aktywnego balance poola.<sup>[[1]](#references)</sup>

Uproszczona podatna linia (oraz poprawka z post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Lista kontrolna

- Czy pool używa niezerowego adresu hooks? Które callbacks są włączone?
- Czy przy każdym swapie wykonywane są redystrybucje/rebalance z użyciem custom math? Czy występuje logika tick/threshold?
- Gdzie używane są dzielenia, mulDiv, konwersje Q64.96 lub SafeCast? Czy semantyka zaokrągleń jest spójna globalnie?
- Czy można skonstruować Δin, które ledwo przekracza granicę i uruchamia korzystną gałąź zaokrąglenia? Przetestuj oba kierunki oraz zarówno exactInput, jak i exactOutput.
- Czy hook śledzi credits lub deltas przypisane do poszczególnych callerów, które można wypłacić później? Upewnij się, że residue zostaje zneutralizowany.

## References

- [1] [Raport pośmiertny exploita Bunni (wrzesień 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit Bunni V2: pełna analiza hacku](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit Bunni V2: 8,3 mln USD wyprowadzonych przez lukę w liquidity (podsumowanie)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Tło Uniswap v4 (badania QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mechanika liquidity w Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mechanika swapów w Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks Uniswap v4 i kwestie bezpieczeństwa](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol w Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol w Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams w Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol w Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol w Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey w Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
