# Eksploatacja DeFi/AMM: nadużycie precyzji/zaokrągleń w Hookach Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje klasę technik eksploatacji DeFi/AMM przeciwko DEX-om w stylu Uniswap v4, które rozszerzają podstawową matematykę za pomocą custom hooks. Niedawny incydent w Bunni V2 wykorzystywał błąd zaokrągleń/precyzji w Liquidity Distribution Function (LDF) wykonywanej przy każdym swapie, umożliwiając atakującemu gromadzenie dodatnich kredytów i drenaż płynności.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Kluczowa idea: jeśli hook implementuje dodatkowe księgowanie zależne od fixed-point math, zaokrągleń ticków i logiki progowej, atakujący może tworzyć exact-input swapy przekraczające określone progi, tak aby rozbieżności zaokrągleń kumulowały się na jego korzyść. Powtarzanie tego wzorca, a następnie wypłata zawyżonego salda, realizuje zysk, często finansowany za pomocą flash loan.

## Tło: hooki Uniswap v4 i przebieg swapu

- Hooki to kontrakty, które PoolManager wywołuje w określonych punktach cyklu życia (np. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Pula jest inicjalizowana za pomocą PoolKey zawierającego adres hooka. Jeśli jest różny od zera, PoolManager wykonuje callbacki przy każdej odpowiedniej operacji.<sup>[[6]](#references)</sup>
- Hooki mogą zwracać **custom deltas**, które modyfikują końcowe zmiany salda w swapie lub operacji płynności (custom accounting). Te delty są rozliczane jako salda netto na końcu wywołania, dlatego każdy błąd zaokrągleń wewnątrz matematyki hooka kumuluje się przed rozliczeniem.<sup>[[5]](#references)</sup>
- Core math korzysta z formatów fixed-point, takich jak Q64.96 dla sqrtPriceX96, oraz z arytmetyki ticków opartej na 1.0001^tick. Każda custom math nałożona na tę logikę musi dokładnie odpowiadać semantyce zaokrągleń, aby uniknąć dryfu inwariantu.<sup>[[4]](#references)[[8]](#references)</sup>
- Swapy mogą być typu exactInput lub exactOutput. W v3/v4 cena porusza się wzdłuż ticków; przekroczenie granicy ticka może aktywować/dezaktywować płynność zakresu. Hooki mogą implementować dodatkową logikę przy przekraczaniu progów/ticków.<sup>[[5]](#references)</sup>

## Archetyp podatności: dryf precyzji/zaokrągleń przy przekraczaniu progów

Typowy podatny wzorzec w custom hooks:

1. Hook oblicza delty płynności lub salda dla każdego swapu za pomocą dzielenia całkowitoliczbowego, mulDiv albo konwersji fixed-point (np. token ↔ płynność z użyciem sqrtPrice i zakresów ticków).
2. Logika progowa (np. rebalancing, stepwise redistribution lub aktywacja poszczególnych zakresów) jest uruchamiana, gdy rozmiar swapu lub ruch ceny przekracza wewnętrzną granicę.
3. Zaokrąglenia są stosowane niespójnie (np. truncation toward zero, floor zamiast ceil) między obliczeniem w przód a ścieżką rozliczenia. Małe rozbieżności nie znoszą się, lecz zamiast tego uznają kredyt na rzecz wywołującego.
4. Swapy exact-input, precyzyjnie dobrane tak, aby przechodziły przez te granice, wielokrotnie wykorzystują dodatnią resztę z zaokrągleń. Atakujący później wypłaca zgromadzony kredyt.

Warunki wstępne ataku
- Pula korzystająca z custom v4 hooka, który wykonuje dodatkowe obliczenia przy każdym swapie (np. LDF/rebalancer).
- Co najmniej jedna ścieżka wykonania, w której zaokrąglenia działają na korzyść inicjatora swapu przy przekraczaniu progów.
- Możliwość atomowego powtarzania wielu swapów (flash loans są idealne do zapewnienia tymczasowego kapitału operacyjnego i zamortyzowania gas).

## Praktyczna metodologia ataku

1) Identyfikacja kandydujących pul z hookami
- Wyszukaj pule v4 i sprawdź, czy PoolKey.hooks != address(0).
- Przeanalizuj bytecode/ABI hooka pod kątem callbacków: beforeSwap/afterSwap oraz niestandardowych metod rebalancingu.
- Poszukaj matematyki, która: dzieli przez płynność, konwertuje kwoty tokenów na płynność lub agreguje BalanceDelta z zaokrągleniami.

2) Modelowanie matematyki hooka i progów
- Odtwórz formułę płynności/redistribution hooka: dane wejściowe zazwyczaj obejmują sqrtPriceX96, tickLower/Upper, currentTick, fee tier oraz net liquidity.
- Zmapuj funkcje progowe/step functions: ticki, granice bucketów lub breakpointy LDF. Ustal, po której stronie każdej granicy delta jest zaokrąglana.
- Zidentyfikuj miejsca, w których wykonywane są casty między uint256/int256, używany jest SafeCast lub stosowany jest mulDiv z niejawnym floor.

3) Kalibracja swapów exact-input w celu przekraczania granic
- Użyj symulacji Foundry/Hardhat, aby obliczyć minimalne Δin wymagane do przesunięcia ceny tuż za granicę i uruchomienia gałęzi hooka.
- Zweryfikuj, czy rozliczenie afterSwap przyznaje wywołującemu więcej niż wynosi koszt, pozostawiając dodatni BalanceDelta lub kredyt w księgowości hooka.
- Powtarzaj swapy, aby gromadzić kredyt, a następnie wywołaj ścieżkę wypłaty/rozliczenia hooka.

Przykładowy harness testowy w stylu Foundry (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: address(bunniHook)
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
for (uint i; i < N; ++i) {
pm.swap(
key,
IPoolManager.SwapParams({
zeroForOne: true,
amountSpecified: int256(exactIn), // exactInput
sqrtPriceLimitX96: 0 // allow tick crossing
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Kalibracja exactInput
- Oblicz ΔsqrtP dla kroku ticka: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Przybliż Δin za pomocą formuł v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Upewnij się, że kierunek zaokrąglania odpowiada obliczeniom core.
- Dostosuj Δin o ±1 wei wokół granicy, aby znaleźć branch, w którym hook zaokrągla na Twoją korzyść.

4) Wzmocnij atak za pomocą flash loans
- Pożycz dużą wartość nominalną (np. 3M USDT lub 2000 WETH), aby atomowo wykonać wiele iteracji.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Wykonaj skalibrowaną pętlę swapów, a następnie wypłać środki i spłać pożyczkę w callbacku flash loan.

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
- Przenieś środki z powrotem na docelowy chain i opcjonalnie przeprowadź je przez protokoły lending, aby utrudnić śledzenie przepływów.<sup>[[2]](#references)</sup>

## Typowe przyczyny źródłowe problemów w matematyce hooków

- Niejednolite zasady zaokrąglania: mulDiv zaokrągla w dół, podczas gdy kolejne ścieżki efektywnie zaokrąglają w górę; albo konwersje między tokenami i płynnością stosują różne zasady zaokrąglania.
- Błędy wyrównania ticków: używanie niezaokrąglonych ticków w jednej ścieżce i zaokrąglania zgodnego z odstępem ticków w innej.
- Problemy ze znakiem/przepełnieniem BalanceDelta podczas konwersji między int256 i uint256 w trakcie settlement.
- Utrata precyzji w konwersjach Q64.96 (sqrtPriceX96), której nie odwzorowano w mapowaniu odwrotnym.
- Ścieżki akumulacji: reszty po każdym swapie są śledzone jako credits, które caller może wypłacić, zamiast zostać spalonymi lub rozliczonymi w modelu zero-sum.

## Custom accounting i amplifikacja delta

- Custom accounting w Uniswap v4 pozwala hookom zwracać deltas, które bezpośrednio korygują kwotę należną od callera lub otrzymywaną przez callera. Jeśli hook wewnętrznie śledzi credits, reszty wynikające z zaokrągleń mogą kumulować się podczas wielu małych operacji **zanim** nastąpi final settlement.<sup>[[5]](#references)</sup>
- Wzmacnia to ataki na granice/progi: attacker może wykonywać naprzemiennie `swap → withdraw → swap` w tej samej tx, zmuszając hook do ponownego obliczania deltas na nieco innym stanie, podczas gdy wszystkie salda nadal oczekują na settlement.
- Podczas przeglądu hooków zawsze prześledź, w jaki sposób BalanceDelta/HookDelta jest tworzony i rozliczany. Pojedyncze stronnicze zaokrąglenie w jednej gałęzi może stać się narastającym credit, gdy deltas są wielokrotnie przeliczane.

## Wskazówki obronne

- Differential testing: porównuj matematykę hooka z implementacją referencyjną wykorzystującą arytmetykę wymierną o wysokiej precyzji i wymagaj równości albo ograniczonego błędu, który zawsze działa na niekorzyść callera.
- Testy invariant/property:
- Suma deltas (tokenów, płynności) na wszystkich ścieżkach swapów i korektach hooka musi zachowywać wartość z uwzględnieniem fees.
- Żadna ścieżka nie powinna tworzyć dodatniego salda netto credit dla inicjatora swapa podczas powtarzanych iteracji exactInput.
- Testy granic progów/ticków wokół wejść ±1 wei zarówno dla exactInput, jak i exactOutput.
- Polityka zaokrąglania: scentralizuj helpery zaokrąglania, które zawsze zaokrąglają na niekorzyść użytkownika; wyeliminuj niespójne casts i niejawne zaokrąglanie w dół.
- Settlement sinks: kieruj nieuniknione reszty z zaokrągleń do treasury protokołu albo je spalaj; nigdy nie przypisuj ich do msg.sender.
- Rate-limits/guardrails: ustaw minimalne rozmiary swapów dla triggerów rebalancingu; wyłączaj rebalancing, jeśli deltas są mniejsze niż wei; sprawdzaj poprawność deltas względem oczekiwanych zakresów.
- Przeglądaj callbacki hooka całościowo: beforeSwap/afterSwap oraz before/after zmiany płynności powinny stosować to samo wyrównanie ticków i zaokrąglanie delta.

## Studium przypadku: Bunni V2 (2025-09-02)

- Protokół: Bunni V2 (hook Uniswap v4) z LDF stosowanym przy każdym swapie w celu rebalancingu.<sup>[[7]](#references)</sup>
- Dotknięte poole: USDC/USDT na Ethereum oraz weETH/ETH na Unichain, o łącznej wartości około $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Krok 1 (wypchnięcie ceny): attacker pożyczył flashowo około 3M USDT i wykonał swap, aby przesunąć tick do około 5000, zmniejszając **aktywne** saldo USDC do około 28 wei.<sup>[[7]](#references)</sup>
- Krok 2 (drenaż przez zaokrąglanie): 44 małe wypłaty wykorzystały zaokrąglanie w dół w `BunniHubLogic::withdraw()`, aby zmniejszyć aktywne saldo USDC z 28 wei do 4 wei (-85.7%), podczas gdy spalono jedynie niewielką część udziałów LP. Łączna płynność została zaniżona o około 84.4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Krok 3 (sandwich po odbiciu płynności): duży swap przesunął tick do około 839,189 (1 USDC ≈ 2.77e36 USDT). Szacunki płynności odwróciły się i wzrosły o około 16.8%, umożliwiając sandwich, w którym attacker wykonał swap wstecz po zawyżonej cenie i wyszedł z zyskiem.<sup>[[7]](#references)</sup>
- Zidentyfikowana poprawka w post-mortem: zmiana aktualizacji idle-balance tak, aby zaokrąglała **w górę**, dzięki czemu powtarzane mikrowypłaty nie mogą stopniowo obniżać aktywnego salda poola.<sup>[[7]](#references)</sup>

Uproszczona podatna linia (oraz poprawka z post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Lista kontrolna analizy

- Czy pula używa niezerowego adresu hooks? Które callbacki są włączone?
- Czy podczas każdego swapu wykonywane są redystrybucje/rebalansowania z użyciem niestandardowej matematyki? Czy występuje logika ticków/progów?
- Gdzie używane są dzielenia/mulDiv, konwersje Q64.96 lub SafeCast? Czy semantyka zaokrąglania jest spójna globalnie?
- Czy można skonstruować Δin, które ledwo przekracza granicę i powoduje korzystną gałąź zaokrąglania? Przetestuj oba kierunki oraz zarówno exactInput, jak i exactOutput.
- Czy hook śledzi kredyty lub delty przypisane do poszczególnych callerów, które można wypłacić później? Upewnij się, że pozostałości są neutralizowane.

## Referencje

- [1] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
