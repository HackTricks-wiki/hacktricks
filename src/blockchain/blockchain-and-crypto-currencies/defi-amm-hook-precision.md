# DeFi/AMM Eksploatacja: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Ta strona dokumentuje klasę technik eksploatacji DeFi/AMM wymierzonych w DEXy w stylu Uniswap v4, które rozszerzają core math o custom hooks. Niedawny incydent w Bunni V2 wykorzystał błąd zaokrąglania/precyzji w Liquidity Distribution Function (LDF) wywoływanym przy każdej swapie, co pozwoliło atakującemu na narastanie pozytywnych kredytów i wypompowanie płynności.

Kluczowa idea: jeśli hook implementuje dodatkowe rozliczenia zależne od fixed‑point math, tick rounding i logiki progowej, atakujący może skonstruować exact‑input swaps, które przechodzą przez konkretne progi tak, że rozbieżności zaokrągleń kumulują się na jego korzyść. Powtarzanie wzorca i późniejsza wypłata zawyżonego salda realizuje zysk, często finansowany flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks to kontrakty, które PoolManager wywołuje w określonych punktach cyklu życia (np. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools są inicjalizowane z PoolKey zawierającym adres hooks. Jeśli różny od zero, PoolManager wykonuje callbacks przy każdej istotnej operacji.
- Hooks mogą zwracać **custom deltas**, które modyfikują końcowe zmiany bilansów swapu lub akcji liquidity (custom accounting). Te delty są rozliczane jako netto na końcu wywołania, więc każdy błąd zaokrąglenia wewnątrz hook math kumuluje się przed settlement.
- Core math korzysta z fixed‑point formats takich jak Q64.96 dla sqrtPriceX96 oraz arytmetyki tick z 1.0001^tick. Każda custom math na wierzchu musi dokładnie dopasować semantykę zaokrąglania, by uniknąć dryfu invariantu.
- Swapy mogą być exactInput lub exactOutput. W v3/v4 price przesuwa się wzdłuż ticków; przekroczenie granicy tick może aktywować/dezaktywować range liquidity. Hooks mogą implementować dodatkową logikę przy przekraczaniu progów/ticków.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Typowy wzorzec podatności w custom hooks:

1. Hook oblicza per‑swap liquidity lub balance delty używając integer division, mulDiv, lub konwersji fixed‑point (np. token ↔ liquidity używając sqrtPrice i zakresów tick).
2. Logika progowa (np. rebalancing, stepwise redistribution, lub per‑range activation) jest wyzwalana, gdy rozmiar swapu lub ruch price przekracza wewnętrzną granicę.
3. Zaokrąglanie jest stosowane niespójnie (np. truncation toward zero, floor versus ceil) między ścieżką forward a ścieżką settlement. Małe rozbieżności się nie znoszą i zamiast tego kredytują caller.
4. Exact‑input swaps, precyzyjnie dobrane, by zahaczyć o te granice, wielokrotnie zżerają dodatni remainder z zaokrąglania. Atakujący później wypłaca nagromadzony credit.

Warunki wstępne ataku
- Pool używający custom v4 hook, który wykonuje dodatkowe obliczenia przy każdym swapie (np. LDF/rebalancer).
- Przynajmniej jedna ścieżka wykonania, gdzie zaokrąglenie faworyzuje inicjatora swapu przy przekraczaniu progów.
- Możliwość powtarzania wielu swapów atomowo (flash loans są idealne do zapewnienia tymczasowego float i amortyzacji gas).

## Practical attack methodology

1) Zidentyfikuj kandydackie pule z hookami
- Enumeruj v4 pools i sprawdź PoolKey.hooks != address(0).
- Zbadaj hook bytecode/ABI pod kątem callbacks: beforeSwap/afterSwap i wszelkich custom rebalancing methods.
- Szukaj matematyki, która: dzieli przez liquidity, konwertuje między token amounts a liquidity, lub agreguje BalanceDelta z zaokrąglaniem.

2) Zamodeluj hook’s math i progi
- Odtwórz formułę hook’s liquidity/redistribution: inputy zwykle obejmują sqrtPriceX96, tickLower/Upper, currentTick, fee tier i net liquidity.
- Zmapuj threshold/step functions: ticki, granice bucketów, lub LDF breakpoints. Określ, po której stronie każdej granicy delta jest zaokrąglana.
- Zidentyfikuj miejsca, gdzie konwersje rzutują między uint256/int256, używają SafeCast, lub polegają na mulDiv z implicit floor.

3) Skalibruj exact‑input swaps, by przekraczały granice
- Użyj Foundry/Hardhat simulations, by policzyć minimalne Δin potrzebne do przesunięcia price tuż poza granicę i wywołania branch hooka.
- Zweryfikuj, że afterSwap settlement kredytuje caller więcej niż koszt, pozostawiając pozytywny BalanceDelta lub credit w księgowości hooka.
- Powtarzaj swapy, by akumulować credit; potem wywołaj ścieżkę wypłaty/settlement hooka.

Example Foundry‑style test harness (pseudocode)
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
- Oblicz ΔsqrtP dla kroku tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Przybliż Δin przy użyciu wzorów v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Upewnij się, że kierunek zaokrąglania odpowiada core math.
- Dostosuj Δin o ±1 wei wokół granicy, aby znaleźć gałąź, w której hook zaokrągla na twoją korzyść.

4) Zwiększ skalę za pomocą flash loanów
- Pożycz dużą kwotę nominalną (np. 3M USDT lub 2000 WETH), aby uruchomić wiele iteracji atomowo.
- Wykonaj skalibrowaną pętlę swapów, następnie wycofaj i spłać w ramach callbacka flash loanu.

Szkielet flash loanu Aave V3
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
5) Exit i replikacja między‑łańcuchowa
- Jeśli hooks są wdrożone na wielu łańcuchach, powtórz tę samą kalibrację dla każdego łańcucha.
- Bridge proceeds back to the target chain i opcjonalnie cykl przez lending protocols aby zacierać przepływy.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv zaokrągla w dół, podczas gdy późniejsze ścieżki skutecznie zaokrąglają w górę; albo konwersje między token/liquidity stosują różne zaokrąglenia.
- Tick alignment errors: używanie niezaokrąglonych ticków w jednej ścieżce i tick‑spaced rounding w innej.
- BalanceDelta sign/overflow issues przy konwersji między int256 a uint256 podczas settlementu.
- Utrata precyzji w konwersjach Q64.96 (sqrtPriceX96) nieodzwierciedlona w odwrotnym mapowaniu.
- Ścieżki akumulacji: reszty per‑swap śledzone jako kredyty, które mogą być wypłacone przez wywołującego zamiast być spalane/zero‑sum.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting pozwala hookom zwracać delty, które bezpośrednio korygują to, co caller jest winien/otrzymuje. Jeśli hook śledzi wewnętrznie kredyty, resztki zaokrągleń mogą kumulować się przez wiele małych operacji **zanim** nastąpi ostateczne settlement.
- To wzmacnia nadużycia na granicach/progu: atakujący może naprzemiennie wykonywać `swap → withdraw → swap` w tym samym tx, zmuszając hook do przeliczenia deltas na nieco innym stanie, podczas gdy wszystkie salda są nadal w stanie oczekującym.
- Przy przeglądzie hooków zawsze śledź, jak BalanceDelta/HookDelta jest generowane i rozliczane. Pojedyncze stronnicze zaokrąglenie w jednej gałęzi może stać się kumulującym kredytem, gdy delty są wielokrotnie ponownie przeliczane.

## Defensive guidance

- Differential testing: odwzoruj matematykę hooka względem referencyjnej implementacji używając arytmetyki wymiernej wysokiej precyzji i asercji równości lub ograniczonego błędu, który zawsze musi być niekorzystny dla użytkownika (nigdy korzystny dla caller).
- Invariant/property tests:
- Suma deltas (tokeny, liquidity) wzdłuż ścieżek swap i korekt hooka musi zachowywać wartość modulo fees.
- Żadna ścieżka nie powinna tworzyć dodatniego netto kredytu dla inicjatora swapu przy powtarzanych exactInput iteracjach.
- Testy progów/granic ticków wokół ±1 wei dla obu exactInput/exactOutput.
- Polityka zaokrąglania: centralizuj helpery do zaokrąglania, które zawsze zaokrąglają przeciwko użytkownikowi; wyeliminuj niespójne rzutowania i implicit floors.
- Settlement sinks: akumuluj nieuniknione resztki zaokrągleń do skarbca protokołu lub spal je; nigdy nie przypisuj ich do msg.sender.
- Rate‑limits/guardrails: minimalne rozmiary swapów dla triggerów rebalansowania; wyłącz rebalanse jeśli deltas są sub‑wei; sanity‑checkuj deltas względem oczekiwanych zakresów.
- Przeglądaj callbacki hooków holistycznie: beforeSwap/afterSwap i before/after liquidity changes powinny zgadzać się co do wyrównania ticków i zaokrąglania deltas.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) z LDF stosowanym per swap do rebalansowania.
- Affected pools: USDC/USDT na Ethereum oraz weETH/ETH na Unichain, łącznie około $8.4M.
- Step 1 (price push): atakujący flash‑borrowed ~3M USDT i swapped, aby wypchnąć tick do ~5000, zmniejszając **active** balans USDC do ~28 wei.
- Step 2 (rounding drain): 44 drobne withdrawals wykorzystały floor rounding w BunniHubLogic::withdraw() aby zredukować active balans USDC z 28 wei do 4 wei (‑85.7%) przy spaleniu tylko małej frakcji LP shares. Całkowita płynność została niedoszacowana o ~84.4%.
- Step 3 (liquidity rebound sandwich): duży swap przesunął tick do ~839,189 (1 USDC ≈ 2.77e36 USDT). Estymaty płynności odwróciły się i wzrosły o ~16.8%, umożliwiając sandwich, w którym atakujący wymienił z powrotem po zawyżonej cenie i wyszedł z zyskiem.
- Fix zidentyfikowany w post‑mortem: zmienić aktualizację idle‑balance tak, aby zaokrąglała **up**, żeby powtarzające się mikro‑wypłaty nie mogły zszarpnąć active salda puli w dół.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Lista kontrolna poszukiwań

- Czy pula używa nie‑zerowego adresu hooks? Które callbacki są włączone?
- Czy dla każdego swapu występują redystrybucje/reequilibrowania wykorzystujące custom math? Czy istnieje logika tick/threshold?
- Gdzie stosowane są divisions/mulDiv, konwersje Q64.96 lub SafeCast? Czy semantyka zaokrągleń jest spójna globalnie?
- Czy możesz skonstruować Δin, które ledwie przekracza granicę i skutkuje korzystną gałęzią zaokrągleń? Przetestuj oba kierunki oraz exactInput i exactOutput.
- Czy hook śledzi kredyty lub delty dla poszczególnych callerów, które można później wypłacić? Upewnij się, że pozostałość jest zneutralizowana.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
