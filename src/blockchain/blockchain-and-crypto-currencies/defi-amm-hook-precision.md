# Wykorzystania DeFi/AMM: Uniswap v4 — nadużycie precyzji/zaokrąglania w hookach

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje klasę technik eksploitacji DeFi/AMM przeciwko DEX‑om w stylu Uniswap v4, które rozszerzają core math o niestandardowe hooki. Ostatni incydent w Bunni V2 wykorzystał błąd zaokrąglania/precyzji w Liquidity Distribution Function (LDF) wykonywanym przy każdej wymianie, co pozwoliło atakującemu na narastanie dodatnich kredytów i spuszczenie płynności.

Główna idea: jeśli hook implementuje dodatkowe księgowanie zależne od fixed‑point math, tick rounding i logiki progów, atakujący może skonstruować exact‑input swaps, które przekraczają konkretne progi tak, że różnice zaokrągleń kumulują się na jego korzyść. Powtarzanie wzorca i następne wypłacenie zawyżonego salda realizuje zysk, często finansowany flash loan.

## Tło: Uniswap v4 hooks i przebieg swapu

- Hooki to kontrakty, które PoolManager wywołuje w określonych punktach cyklu życia (np. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools są inicjalizowane z PoolKey zawierającym adres hooks. Jeśli różny od zero, PoolManager wykonuje callbacki przy każdej istotnej operacji.
- Core math używa formatów fixed‑point takich jak Q64.96 dla sqrtPriceX96 oraz tick arithmetic z 1.0001^tick. Każda niestandardowa matematyka nakładana na to musi dokładnie dopasować semantykę zaokrągleń, by uniknąć dryfu invariant.
- Swaps mogą być exactInput lub exactOutput. W v3/v4 price przesuwa się wzdłuż ticków; przekroczenie granicy tick może aktywować/dezaktywować range liquidity. Hooki mogą implementować dodatkową logikę przy przekraczaniu progów/ticków.

## Archetyp podatności: dryf precyzji/zaokrąglania przy przekraczaniu progów

Typowy wzorzec podatny w niestandardowych hookach:

1. Hook oblicza delty płynności lub sald per‑swap używając integer division, mulDiv lub konwersji fixed‑point (np. token ↔ liquidity używając sqrtPrice i zakresów ticków).
2. Logika progów (np. rebalancing, stepwise redistribution lub aktywacja per‑range) jest uruchamiana, gdy rozmiar swapu lub ruch ceny przekroczy wewnętrzną granicę.
3. Zaokrąglanie jest stosowane niespójnie (np. obcinanie w kierunku zera, różnica floor vs ceil) między obliczeniami „forward” a ścieżką settlement. Małe rozbieżności nie znoszą się i zamiast tego kredytują callera.
4. Exact‑input swaps, precyzyjnie dobrane tak, by leżeć na obu stronach tych granic, wielokrotnie eksploatują dodatni remainder zaokrąglenia. Atakujący później wypłaca zgromadzony kredyt.

Warunki wstępne ataku
- Pool używający niestandardowego v4 hooka, który wykonuje dodatkową matematykę przy każdej wymianie (np. LDF/rebalancer).
- Przynajmniej jedna ścieżka wykonania, gdzie zaokrąglenie faworyzuje inicjatora swapu przy przekraczaniu progów.
- Możliwość powtarzania wielu swapów atomowo (flash loans idealne do dostarczenia tymczasowego float i amortyzacji kosztów gazu).

## Praktyczna metodologia ataku

1) Zidentyfikuj kandydackie pule z hookami
- Enumerate v4 pools i sprawdź PoolKey.hooks != address(0).
- Inspect hook bytecode/ABI pod kątem callbacków: beforeSwap/afterSwap i dowolnych niestandardowych metod rebalansujących.
- Szukaj matematyki, która: dzieli przez liquidity, konwertuje między token amounts a liquidity, lub agreguje BalanceDelta z zaokrąglaniem.

2) Zamodeluj matematykę hooka i progi
- Odtwórz formułę liquidity/redistribution hooka: wejścia typowo obejmują sqrtPriceX96, tickLower/Upper, currentTick, fee tier i net liquidity.
- Mapuj funkcje progów/stopni: ticki, bucket boundaries lub LDF breakpoints. Określ, po której stronie każdej granicy delta jest zaokrąglana.
- Zidentyfikuj miejsca, gdzie konwersje rzutują między uint256/int256, używają SafeCast lub polegają na mulDiv z implicit floor.

3) Skalibruj exact‑input swaps by przekraczały granice
- Użyj Foundry/Hardhat do symulacji i wyliczenia minimalnego Δin potrzebnego, by price przesunęła się tuż za granicę i uruchomiła branch hooka.
- Zweryfikuj, że afterSwap settlement kredytuje callera więcej niż koszt, pozostawiając dodatni BalanceDelta lub kredit w księgowości hooka.
- Powtarzaj swapy, żeby skumulować kredyt; potem wywołaj ścieżkę wypłaty/settlement hooka.

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
Kalibrowanie exactInput
- Oblicz ΔsqrtP dla kroku tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Zaproksymuj Δin korzystając ze wzorów v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Upewnij się, że kierunek zaokrąglenia zgadza się z matematyką core.
- Dostosuj Δin o ±1 wei wokół granicy, aby znaleźć branch, w której hook zaokrągla na twoją korzyść.

4) Zwiększ skalę za pomocą flash loans
- Pożycz dużą wartość nominalną (np. 3M USDT lub 2000 WETH), aby wykonać wiele iteracji atomowo.
- Wykonaj skalibrowaną pętlę swapów, następnie wycofaj i spłać w ramach callbacku flash loan.

Aave V3 flash loan skeleton
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
5) Wyjście i replikacja między‑łańcuchowa
- Jeśli hooks są wdrożone na wielu łańcuchach, powtórz tę samą kalibrację dla każdego łańcucha.
- Mostuj środki z powrotem na docelowy łańcuch i opcjonalnie przepuść je przez protokoły pożyczkowe, aby zaciemnić przepływy.

## Typowe przyczyny błędów w obliczeniach hooków

- Mieszane semantyki zaokrągleń: mulDiv stosuje floor, podczas gdy dalsze ścieżki efektywnie zaokrąglają w górę; albo konwersje między token/liquidity stosują różne zaokrąglenia.
- Błędy wyrównania ticków: użycie niezaokrąglonych ticków w jednej ścieżce i zaokrągleń do najbliższego ticku w innej.
- Problemy ze znakiem/przepełnieniem BalanceDelta przy konwersji między int256 a uint256 podczas rozliczania.
- Utrata precyzji przy konwersjach Q64.96 (sqrtPriceX96) nieodzwierciedlona w mapowaniu odwrotnym.
- Ścieżki akumulacji: per‑swap pozostałości śledzone jako kredyty wypłacalne przez callera zamiast być spalane/zero‑sum.

## Wytyczne obronne

- Testowanie różnicowe: odwzoruj obliczenia hooka względem implementacji referencyjnej używając wysokoprecyzyjnej arytmetyki wymiernej i zapewnij równość lub ograniczony błąd nastawiony przeciw użytkownikowi (nigdy na jego korzyść).
- Testy inwariantów/własności:
- Suma delt (tokeny, liquidity) w różnych ścieżkach swap i korektach hooka musi zachowywać wartość modulo opłat.
- Żadna ścieżka nie powinna tworzyć dodatniego netto kredytu dla inicjatora swapu przy powtarzanych iteracjach exactInput.
- Testy progów/granic ticków wokół ±1 wei wejść zarówno dla exactInput, jak i exactOutput.
- Polityka zaokrągleń: scentralizuj helpery zaokrągleń, które zawsze zaokrąglają na niekorzyść użytkownika; usuń niespójne rzutowania i ukryte operacje floor.
- Miejsca rozliczeń: akumuluj nieuniknione resztki zaokrągleń w skarbcu protokołu albo spalaj je; nigdy nie przypisuj ich do msg.sender.
- Limity/ograniczenia: minimalne rozmiary swapów do triggerów rebalansowania; wyłącz rebalans jeśli delty są poniżej 1 wei; sanity‑check delt względem oczekiwanych zakresów.
- Przejrzyj callbacki hooków holistycznie: beforeSwap/afterSwap oraz before/after zmian liquidity powinny zgadzać się w kwestii wyrównania ticków i zaokrągleń delt.

## Studium przypadku: Bunni V2 (2025‑09‑02)

- Protokół: Bunni V2 (Uniswap v4 hook) z LDF stosowanym per swap do rebalansowania.
- Przyczyna: błąd zaokrągleń/precyzji w rozliczeniach liquidity LDF podczas swapów przekraczających progi; per‑swap rozbieżności kumulowały się jako dodatnie kredyty dla callera.
- Leg Ethereum: attacker wziął ~3M USDT flash loan, wykonał skalibrowane exact‑input swapy na USDC/USDT, aby zbudować kredyty, wypłacił zawyżone salda, spłacił i skierował środki przez Aave.
- Leg UniChain: powtórzył exploit z 2000 WETH flash loan, wyprowadził ~1366 WETH i mostował na Ethereum.
- Skutki: ~USD 8.3M wypompowane między łańcuchami. Nie wymagało interakcji użytkownika; w całości on‑chain.

## Lista kontrolna do wykrywania

- Czy pool używa nie‑zerowego adresu hooks? Które callbacki są włączone?
- Czy występują per‑swap redystrybucje/rebalansowania używające niestandardowej matematyki? Jakaś logika ticków/progów?
- Gdzie używane są dzielenia/mulDiv, konwersje Q64.96 lub SafeCast? Czy semantyka zaokrągleń jest globalnie spójna?
- Czy możesz skonstruować Δin, które ledwo przekracza granicę i daje korzystną gałąź zaokrągleń? Przetestuj oba kierunki oraz exactInput i exactOutput.
- Czy hook śledzi per‑caller kredyty lub delty, które mogą być później wypłacone? Upewnij się, że resztki są zneutralizowane.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
