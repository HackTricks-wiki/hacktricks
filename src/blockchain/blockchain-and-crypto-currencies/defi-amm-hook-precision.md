# Eksploatacja DeFi/AMM: nadużycie precyzji/zaokrągleń w hookach Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje klasę technik eksploatacji DeFi/AMM wymierzonych w DEX-y w stylu Uniswap v4, które rozszerzają podstawową matematykę za pomocą niestandardowych hooków. Incydent Bunni V2 ilustruje powiązany błąd: błąd kierunku zaokrąglania w rozliczaniu wypłat zaniżał aktywną płynność, a późniejszy swap ujawnił to zaniżenie w zyskownym sandwichu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Kluczowa idea: jeśli hook wykonuje dodatkowe rozliczenia zależne od matematyki fixed-point, zaokrąglania ticków i logiki progowej, atakujący może spreparować swapy exact-input przekraczające określone progi, tak aby rozbieżności zaokrągleń kumulowały się na jego korzyść. Powtarzanie tego schematu, a następnie wypłacenie zawyżonego salda, pozwala zrealizować zysk, często finansowany flash loanem.

## Wprowadzenie: hooki Uniswap v4 i przebieg swapu

- Hooki to kontrakty, które PoolManager wywołuje w określonych punktach cyklu życia (np. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pule są inicjalizowane za pomocą PoolKey zawierającego kontrakt hooka. Niezerowy adres hooka aktywuje callbacki wybrane dla danej puli.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooki mogą zwracać **niestandardowe delty**, które modyfikują końcowe zmiany salda swapu lub operacji na płynności (custom accounting). Te delty są rozliczane jako salda netto na końcu wywołania, więc każdy błąd zaokrąglania w obliczeniach hooka kumuluje się przed rozliczeniem.<sup>[[4]](#references)</sup>
- Podstawowe obliczenia wykorzystują formaty fixed-point, takie jak Q64.96 dla sqrtPriceX96, oraz arytmetykę ticków z 1.0001^tick. Każda niestandardowa matematyka nałożona na te obliczenia musi dokładnie odwzorowywać semantykę zaokrąglania, aby uniknąć rozbieżności niezmiennika.<sup>[[12]](#references)[[13]](#references)</sup>
- Swapy mogą być exactInput lub exactOutput. W v3/v4 cena zmienia się wzdłuż ticków; przekroczenie granicy ticka może aktywować/dezaktywować płynność zakresu. Hooki mogą implementować dodatkową logikę uruchamianą przy przekroczeniu progów/ticków.<sup>[[9]](#references)[[11]](#references)</sup>

## Klasa podatności: dryf precyzji/zaokrągleń przy przekraczaniu progów

Typowy podatny wzorzec w niestandardowych hookach:

1. Hook oblicza delty płynności lub salda dla każdego swapu za pomocą dzielenia na liczbach całkowitych, mulDiv lub konwersji fixed-point (np. token ↔ płynność przy użyciu sqrtPrice i zakresów ticków).
2. Logika progowa (np. rebalansowanie, stopniowa redystrybucja lub aktywacja zakresów) uruchamia się, gdy wielkość swapu lub ruch ceny przekracza wewnętrzną granicę.
3. Zaokrąglanie jest stosowane niespójnie (np. obcięcie do zera, floor zamiast ceil) w obliczeniach w przód i ścieżce rozliczenia. Małe rozbieżności nie znoszą się, lecz zamiast tego zasilają konto wywołującego.
4. Swapy exact-input o precyzyjnie dobranym rozmiarze, które przekraczają te granice, wielokrotnie zbierają dodatnią resztę z zaokrągleń. Atakujący później wypłaca zgromadzony kredyt.

Warunki wstępne ataku
- Pula korzystająca z niestandardowego hooka v4, który wykonuje dodatkowe obliczenia przy każdym swapie (np. LDF/rebalancer).
- Co najmniej jedna ścieżka wykonania, w której zaokrąglanie przy przekraczaniu progów działa na korzyść inicjatora swapu.
- Możliwość atomowego powtarzania wielu swapów (flash loan idealnie zapewnia tymczasowy kapitał i rozkłada koszt gasu). 

## Praktyczna metodologia ataku

1) Identyfikacja potencjalnych pul z hookami
- Wyszukaj pule v4 i sprawdź, czy PoolKey.hooks != address(0).
- Sprawdź bytecode/ABI hooka pod kątem callbacków: beforeSwap/afterSwap oraz wszelkich niestandardowych metod rebalansowania.
- Szukaj obliczeń, które: dzielą przez płynność, konwertują między ilościami tokenów a płynnością albo agregują BalanceDelta z zaokrąglaniem.

2) Modelowanie obliczeń i progów hooka
- Odtwórz wzór płynności/redystrybucji hooka: dane wejściowe zwykle obejmują sqrtPriceX96, tickLower/Upper, currentTick, poziom opłaty i płynność netto.
- Zmapuj funkcje progowe/stopniowe: ticki, granice kubełków lub punkty podziału LDF. Ustal, po której stronie każdej granicy zaokrąglana jest delta.
- Zidentyfikuj miejsca konwersji między uint256/int256, użycia SafeCast lub wywołania mulDiv z niejawnym zaokrąglaniem w dół.

3) Dostosowanie swapów exact-input do przekraczania granic
- Użyj symulacji Foundry/Hardhat, aby obliczyć minimalną Δin potrzebną do przesunięcia ceny tuż za granicę i uruchomienia gałęzi kodu hooka.
- Sprawdź, czy rozliczenie afterSwap przyznaje wywołującemu więcej, niż wyniósł koszt, pozostawiając dodatnie BalanceDelta lub kredyt w rozliczeniach hooka.
- Powtarzaj swapy, aby zgromadzić kredyt; następnie wywołaj ścieżkę wypłaty/rozliczenia hooka.

W v4 pętla swapu musi być uruchomiona z callbacka odblokowania PoolManager; ujemne `amountSpecified` oznacza exact input, a `sqrtPriceLimitX96` musi znajdować się ściśle wewnątrz prawidłowego zakresu. Zerowy limit ceny powoduje revert, dlatego poniższy pseudokod używa dolnej granicy dla swapu zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Przykładowy harness testowy w stylu Foundry (pseudokod)
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
- Oblicz wartość docelową za pomocą core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) w wartościach rzeczywistych; wynik Q64.96 jest zaokrąglany przez TickMath.<sup>[[13]](#references)</sup>
- Przybliż wartość wejściową token0 (zero-for-one) za pomocą wzoru uwzględniającego Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Zastosuj zaokrąglanie zgodne z kierunkiem w core routine.<sup>[[12]](#references)</sup>
- Skoryguj Δin o ±1 wei w pobliżu granicy, aby znaleźć gałąź, w której hook zaokrągla na twoją korzyść.

4) Zwiększenie skali za pomocą flash loans
- Pożycz dużą kwotę nominalną (np. 3M USDT lub 2000 WETH), aby wykonać wiele iteracji atomowo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Wykonaj skalibrowaną pętlę swapów, a następnie wypłać środki i spłać pożyczkę w ramach callbacku flash loan.

Szkielet flash loan w Aave V3
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

5) Wyjście i replikacja między łańcuchami
- Jeśli hooki wdrożono na wielu łańcuchach, powtórz tę samą kalibrację dla każdego łańcucha.
- W incydencie Bunni płynność flash-loanów i trasy bridge różniły się w zależności od łańcucha, dlatego podczas odtwarzania analizy uwzględnij ograniczenia specyficzne dla danego łańcucha.<sup>[[1]](#references)[[2]](#references)</sup>

## Częste przyczyny źródłowe błędów w obliczeniach hooków

- Niespójne zasady zaokrąglania: mulDiv zaokrągla w dół, podczas gdy późniejsze ścieżki efektywnie zaokrąglają w górę; albo konwersje między tokenami a płynnością stosują różne zasady zaokrąglania.
- Błędy wyrównania ticków: używanie niezaokrąglonych ticków w jednej ścieżce, a zaokrąglania do wielokrotności tick-spacing w innej.
- Problemy ze znakiem lub przepełnieniem BalanceDelta podczas konwersji między int256 a uint256 przy rozliczaniu.
- Utrata precyzji przy konwersjach Q64.96 (sqrtPriceX96), której nie uwzględnia mapowanie odwrotne.
- Ścieżki akumulacji: reszty z poszczególnych swapów są zapisywane jako kredyty, które caller może wypłacić, zamiast zostać spalone lub wyzerowane.

## Niestandardowe księgowanie i wzmacnianie delt

- Niestandardowe księgowanie w Uniswap v4 pozwala hookom zwracać delty, które bezpośrednio zmieniają kwoty należne od callera lub otrzymywane przez niego. Jeśli hook wewnętrznie śledzi kredyty, reszty z zaokrągleń mogą się kumulować podczas wielu małych operacji, **zanim** dojdzie do końcowego rozliczenia.<sup>[[4]](#references)</sup>
- Jeśli hook udostępnia zgodną ścieżkę wypłaty, attacker może naprzemiennie wykonywać `swap → withdraw → swap` w ramach tego samego callbacku odblokowania PoolManager, wymuszając ponowne obliczanie delt przez hook przy nieznacznie zmienionym stanie, podczas gdy salda pozostają nierozliczone do chwili zakończenia odblokowania.<sup>[[4]](#references)[[10]](#references)</sup>
- Podczas przeglądu hooków zawsze prześledź sposób wyznaczania i rozliczania BalanceDelta/HookDelta. Pojedyncze stronnicze zaokrąglenie w jednej gałęzi może stać się kumulującym się kredytem, gdy delty są wielokrotnie przeliczane.

## Wskazówki dotyczące zabezpieczeń

- Testowanie różnicowe: porównuj obliczenia hooka z implementacją referencyjną wykorzystującą precyzyjną arytmetykę wymierną i sprawdzaj równość lub ograniczony błąd, który zawsze działa na niekorzyść użytkownika (nigdy na korzyść callera).
- Testy niezmienników/właściwości:
  - Suma delt (tokenów, płynności) w ścieżkach swapów i korektach hooka musi zachowywać wartość z uwzględnieniem opłat.
  - Żadna ścieżka nie powinna tworzyć dodatniego salda netto na rzecz inicjatora swapa podczas wielokrotnych iteracji exactInput.
  - Testy progów/granic ticków dla wartości wejściowych ±1 wei zarówno dla exactInput, jak i exactOutput.
- Zasady zaokrąglania: scentralizuj funkcje pomocnicze do zaokrąglania, które zawsze zaokrąglają na niekorzyść użytkownika; wyeliminuj niespójne rzutowania i niejawne zaokrąglanie w dół.
- Miejsca przekazywania rozliczeń: gromadź nieuniknione reszty z zaokrągleń w skarbcu protokołu lub je spalaj; nigdy nie przypisuj ich do msg.sender.
- Limity szybkości/zabezpieczenia: minimalne rozmiary swapów dla wyzwalaczy rebalansowania; wyłączaj rebalansowanie, jeśli delty są mniejsze niż wei; sprawdzaj, czy delty mieszczą się w oczekiwanych zakresach.
- Przeglądaj callbacki hooka całościowo: beforeSwap/afterSwap oraz before/after zmiany płynności powinny stosować zgodne zasady wyrównywania ticków i zaokrąglania delt.

## Studium przypadku: Bunni V2 (2025‑09‑02)

- Protokół: Bunni V2, hook Uniswap v4 wykorzystujący Liquidity Density Function (LDF) do obliczania gęstości tokenów i szacunków całkowitej płynności.<sup>[[1]](#references)[[2]](#references)</sup>
- Dotknięte pule: USDC/USDT na Ethereum oraz weETH/ETH na Unichain, o łącznej wartości około 8,4 mln USD.<sup>[[1]](#references)</sup>
- Krok 1 (zmiana ceny): attacker pożyczył w ramach flash-loana około 3 mln USDT i wykonał swap, aby przesunąć tick do około 5000, zmniejszając **aktywny** stan USDC do około 28 wei.<sup>[[1]](#references)</sup>
- Krok 2 (drenaż przez zaokrąglanie): 44 niewielkie wypłaty wykorzystały zaokrąglanie w dół w `BunniHubLogic::withdraw()`, zmniejszając aktywny stan USDC z 28 wei do 4 wei (-85,7%), podczas gdy spalono jedynie niewielką część udziałów LP. Całkowita płynność spadła o około 84,4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Krok 3 (kanapka ze wzrostem płynności): duży swap przesunął tick do około 839 189 (1 USDC ≈ 2.77e36 USDT). Szacunki płynności uległy odwróceniu i wzrosły o około 16,8%, umożliwiając wykonanie kanapki, w ramach której attacker wykonał swap powrotny po zawyżonej cenie i osiągnął zysk.<sup>[[1]](#references)</sup>
- Poprawka wskazana w analizie post-mortem: zmiana aktualizacji nieaktywnego salda tak, by zaokrąglała **w górę**, dzięki czemu powtarzane mikrowypłaty nie będą już stopniowo obniżać aktywnego salda puli.<sup>[[1]](#references)</sup>

Uproszczona podatna linia kodu (i poprawka z analizy post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Lista kontrolna

- Czy pula używa niezerowego adresu hooks? Które callbacki są włączone?
- Czy przy każdym swapie następują redystrybucje/rebalansowanie z użyciem niestandardowej matematyki? Czy występuje logika ticków/progów?
- Gdzie używane są dzielenia/mulDiv, konwersje Q64.96 lub SafeCast? Czy zasady zaokrąglania są spójne w całym systemie?
- Czy możesz skonstruować Δin, które ledwo przekracza granicę i powoduje korzystną gałąź zaokrąglania? Testuj oba kierunki oraz exactInput i exactOutput.
- Czy hook śledzi środki lub delty przypisane do poszczególnych callerów, które można później wypłacić? Upewnij się, że pozostałości są neutralizowane.

## References

- [1] [Analiza powłamaniowa exploita Bunni (wrzesień 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit Bunni V2: pełna analiza ataku](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit Bunni V2: odpływ 8,3 mln USD przez błąd płynności (podsumowanie)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Biała księga Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Wprowadzenie do Uniswap v4 (badania QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mechanika płynności w Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mechanika swapów w Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks w Uniswap v4 i kwestie bezpieczeństwa](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 Core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 Core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams w Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 Core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 Core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey w Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
