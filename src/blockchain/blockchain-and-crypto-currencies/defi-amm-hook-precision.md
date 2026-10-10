# DeFi/AMM Exploitation: Nadużycie precyzji/zaokrągleń w hookach Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje klasę technik DeFi/AMM exploitation wymierzonych w DEX-y w stylu Uniswap v4, które rozszerzają podstawowe obliczenia za pomocą niestandardowych hooków. Incydent Bunni V2 ilustruje podobny błąd: nieprawidłowy kierunek zaokrąglania w księgowaniu wypłat zaniżał aktywną płynność, a późniejszy swap ujawnił to niedoszacowanie w zyskownym sandwichu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Główna idea: jeśli hook implementuje dodatkowe księgowanie oparte na matematyce stałoprzecinkowej, zaokrąglaniu ticków i logice progowej, atakujący może przygotować swapy exact-input przekraczające określone progi, tak by rozbieżności wynikające z zaokrągleń kumulowały się na jego korzyść. Powtarzanie tego schematu, a następnie wypłata zawyżonego salda, pozwala zrealizować zysk, często finansowany flash loanem.

## Wprowadzenie: hooki Uniswap v4 i przebieg swapu

- Hooki to kontrakty, które PoolManager wywołuje w określonych punktach cyklu życia (np. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pule inicjalizuje się z PoolKey zawierającym kontrakt hooka. Niezerowy adres hooka włącza wybrane callbacki dla danej puli.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooki mogą zwracać **custom deltas**, które modyfikują końcowe zmiany salda wynikające ze swapu lub operacji na płynności (custom accounting). Te delty są rozliczane jako salda netto na końcu wywołania, więc każdy błąd zaokrąglenia w obliczeniach hooka kumuluje się przed rozliczeniem.<sup>[[4]](#references)</sup>
- Podstawowe obliczenia używają formatów stałoprzecinkowych, takich jak Q64.96 dla sqrtPriceX96, oraz arytmetyki ticków opartej na 1.0001^tick. Każde niestandardowe obliczenia oparte na tych mechanizmach muszą dokładnie odwzorowywać reguły zaokrąglania, aby uniknąć dryfu niezmiennika.<sup>[[12]](#references)[[13]](#references)</sup>
- Swapy mogą być typu exactInput lub exactOutput. W v3/v4 cena zmienia się wzdłuż ticków; przekroczenie granicy ticka może aktywować/dezaktywować płynność w danym zakresie. Hooki mogą implementować dodatkową logikę uruchamianą przy przekraczaniu progów/ticków.<sup>[[9]](#references)[[11]](#references)</sup>

## Typ podatności: dryf precyzji/zaokrągleń przy przekraczaniu progów

Typowy podatny schemat w niestandardowych hookach:

1. Hook oblicza delty płynności lub salda dla każdego swapu przy użyciu dzielenia całkowitoliczbowego, mulDiv lub konwersji stałoprzecinkowych (np. konwersji tokenów na płynność z użyciem sqrtPrice i zakresów ticków).
2. Logika progowa (np. rebalancing, stopniowa redystrybucja lub aktywacja poszczególnych zakresów) uruchamia się, gdy rozmiar swapu lub zmiana ceny przekracza wewnętrzną granicę.
3. Zaokrąglanie jest stosowane niespójnie (np. obcięcie do zera, floor zamiast ceil) między obliczeniem początkowym a ścieżką rozliczenia. Małe rozbieżności nie znoszą się, lecz przynoszą korzyść wywołującemu.
4. Swapy exact-input o precyzyjnie dobranych rozmiarach, które przekraczają te granice, wielokrotnie zbierają dodatnią resztę z zaokrągleń. Następnie atakujący wypłaca zgromadzony kredyt.

Warunki wstępne ataku
- Pula korzysta z niestandardowego hooka v4, który wykonuje dodatkowe obliczenia przy każdym swapie (np. LDF/rebalancer).
- Istnieje co najmniej jedna ścieżka wykonania, w której zaokrąglenia działają na korzyść inicjatora swapu przy przekraczaniu progów.
- Możliwość atomowego powtarzania wielu swapów (flash loan idealnie zapewnia tymczasowy kapitał i pozwala rozłożyć koszt gasu). 

## Praktyczna metodyka ataku

1) Wyszukaj potencjalne pule z hookami
- Wylicz pule v4 i sprawdź, czy PoolKey.hooks != address(0).
- Przeanalizuj bytecode/ABI hooka pod kątem callbacków: beforeSwap/afterSwap oraz niestandardowych metod rebalancingu.
- Szukaj obliczeń, które: dzielą przez płynność, konwertują między ilościami tokenów a płynnością lub agregują BalanceDelta z zaokrąglaniem.

2) Zamodeluj obliczenia i progi hooka
- Odtwórz wzór na płynność/redystrybucję używany przez hook: dane wejściowe zazwyczaj obejmują sqrtPriceX96, tickLower/Upper, currentTick, poziom opłat i płynność netto.
- Zmapuj funkcje progowe/krokowe: ticki, granice przedziałów lub punkty podziału LDF. Ustal, po której stronie każdej granicy delta jest zaokrąglana.
- Ustal, gdzie konwersje rzutują między uint256/int256, używają SafeCast lub polegają na mulDiv z niejawnym zaokrąglaniem w dół.

3) Dostosuj swapy exact-input tak, by przekraczały granice
- Użyj symulacji w Foundry/Hardhat, aby obliczyć minimalne Δin potrzebne do przesunięcia ceny tuż za granicę i uruchomienia odpowiedniej gałęzi hooka.
- Zweryfikuj, czy rozliczenie afterSwap przyznaje wywołującemu więcej, niż wyniósł koszt, pozostawiając dodatnie BalanceDelta lub kredyt w księgowości hooka.
- Powtarzaj swapy, aby zgromadzić kredyt, a następnie wywołaj ścieżkę wypłaty/rozliczenia hooka.

W v4 pętla swapu musi działać w callbacku odblokowania PoolManager; ujemne `amountSpecified` oznacza exact input, a `sqrtPriceLimitX96` musi znajdować się ściśle wewnątrz prawidłowego zakresu. Zerowy limit ceny powoduje revert, dlatego poniższy pseudokod używa dolnej granicy dla swapu zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Przybliż wartość wejściową token0 (zero-for-one) za pomocą wzoru uwzględniającego Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Dopasuj kierunek zaokrąglania do procedury core.<sup>[[12]](#references)</sup>
- Zmień Δin o ±1 wei przy granicy, aby znaleźć gałąź, w której hook zaokrągla na Twoją korzyść.

4) Zwiększ skalę za pomocą flash loans
- Pożycz dużą kwotę (np. 3M USDT lub 2000 WETH), aby wykonać wiele iteracji atomowo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Wykonaj skalibrowaną pętlę swapów, a następnie wypłać środki i spłać pożyczkę w callbacku flash loan.

Szkielet flash loan Aave V3
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
- Jeśli hooki są wdrożone na wielu łańcuchach, powtórz tę samą kalibrację dla każdego z nich.
- W przypadku incydentu Bunni płynność z flash loanów i trasy bridge różniły się w zależności od łańcucha, dlatego podczas odtwarzania analizy uwzględnij ograniczenia specyficzne dla każdego łańcucha.<sup>[[1]](#references)[[2]](#references)</sup>

## Częste pierwotne przyczyny błędów w matematyce hooków

- Niejednolite zasady zaokrąglania: mulDiv zaokrągla w dół, a późniejsze ścieżki efektywnie zaokrąglają w górę; albo konwersje między tokenami a płynnością stosują różne zasady zaokrąglania.
- Błędy wyrównania ticków: użycie niezaokrąglonych ticków w jednej ścieżce i zaokrąglania do wielokrotności odstępu ticków w innej.
- Problemy ze znakiem lub przepełnieniem BalanceDelta podczas konwersji między int256 a uint256 w trakcie rozliczenia.
- Utrata precyzji przy konwersjach Q64.96 (sqrtPriceX96), której nie uwzględnia odwzorowanie w przeciwnym kierunku.
- Ścieżki akumulacji: reszty z poszczególnych swapów są rejestrowane jako środki do wypłaty przez wywołującego, zamiast być spalane lub zerować się netto.

## Własna księgowość i wzmacnianie delt

- Własna księgowość Uniswap v4 pozwala hookom zwracać delty, które bezpośrednio korygują kwoty należne od wywołującego lub mu przysługujące. Jeśli hook wewnętrznie rejestruje środki, reszty z zaokrągleń mogą się kumulować podczas wielu małych operacji **przed** końcowym rozliczeniem.<sup>[[4]](#references)</sup>
- Jeśli hook udostępnia zgodną ścieżkę wypłaty, atakujący może naprzemiennie wykonywać `swap → withdraw → swap` w ramach tego samego callbacku odblokowania PoolManagera, zmuszając hook do ponownego obliczania delt na nieco innym stanie, podczas gdy salda pozostają nierozliczone do czasu zakończenia odblokowania.<sup>[[4]](#references)[[10]](#references)</sup>
- Podczas analizy hooków zawsze prześledź sposób obliczania i rozliczania BalanceDelta/HookDelta. Pojedyncze niekorzystne zaokrąglenie w jednej gałęzi może stać się narastającym kredytem, gdy delty są wielokrotnie przeliczane.

## Zalecenia dotyczące zabezpieczeń

- Testowanie różnicowe: porównuj matematykę hooka z implementacją referencyjną wykorzystującą precyzyjną arytmetykę wymierną i wymagaj równości albo ograniczonego błędu, który zawsze działa na niekorzyść użytkownika (nigdy na korzyść wywołującego).
- Testy niezmienników/właściwości:
  - Suma delt (tokenów, płynności) we wszystkich ścieżkach swapów i korektach hooka musi zachowywać wartość z uwzględnieniem opłat.
  - Żadna ścieżka nie powinna tworzyć dodatniego kredytu netto dla inicjatora swapu podczas kolejnych iteracji exactInput.
  - Testy granic progów/ticków dla danych wejściowych ±1 wei dla exactInput/exactOutput.
- Zasady zaokrąglania: scentralizuj funkcje pomocnicze zaokrąglające zawsze na niekorzyść użytkownika; wyeliminuj niespójne rzutowania i niejawne zaokrąglanie w dół.
- Miejsca docelowe rozliczeń: gromadź nieuniknione reszty z zaokrągleń w skarbcu protokołu albo je spalaj; nigdy nie przypisuj ich do msg.sender.
- Limity/ograniczenia: ustal minimalne rozmiary swapów dla wyzwalaczy równoważenia; wyłączaj równoważenie, gdy delty są mniejsze niż wei; sprawdzaj, czy delty mieszczą się w oczekiwanych zakresach.
- Analizuj całościowo callbacki hooka: beforeSwap/afterSwap oraz before/after zmian płynności powinny stosować te same zasady wyrównania ticków i zaokrąglania delt.

## Studium przypadku: Bunni V2 (2025‑09‑02)

- Protokół: Bunni V2, hook Uniswap v4 wykorzystujący Liquidity Density Function (LDF) do obliczania gęstości tokenów i szacunkowej całkowitej płynności.<sup>[[1]](#references)[[2]](#references)</sup>
- Dotknięte pule: USDC/USDT na Ethereum oraz weETH/ETH na Unichain, o łącznej wartości około 8,4 mln USD.<sup>[[1]](#references)</sup>
- Krok 1 (wypchnięcie ceny): atakujący pożyczył około 3 mln USDT w ramach flash loanu i wykonał swap, aby przesunąć tick do około 5000, zmniejszając **aktywny** stan USDC do około 28 wei.<sup>[[1]](#references)</sup>
- Krok 2 (wyczerpanie przez zaokrąglanie): 44 niewielkie wypłaty wykorzystały zaokrąglanie w dół w `BunniHubLogic::withdraw()`, zmniejszając aktywny stan USDC z 28 wei do 4 wei (-85,7%), podczas gdy spalono tylko niewielką część udziałów LP. Całkowita płynność zmniejszyła się o około 84,4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Krok 3 (sandwich odbicia płynności): duży swap przesunął tick do około 839 189 (1 USDC ≈ 2.77e36 USDT). Szacunki płynności uległy zmianie i wzrosły o około 16,8%, umożliwiając sandwich, w którym atakujący wykonał swap w przeciwnym kierunku po zawyżonej cenie i osiągnął zysk.<sup>[[1]](#references)</sup>
- Poprawka wskazana w analizie po incydencie: zmienić aktualizację salda nieaktywnego tak, aby zaokrąglała **w górę**. Dzięki temu kolejne mikrowypłaty nie będą już stopniowo obniżać aktywnego salda puli.<sup>[[1]](#references)</sup>

Uproszczony podatny fragment (i poprawka z analizy po incydencie).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Lista kontrolna poszukiwań

- Czy pula używa niezerowego adresu hooks? Które callbacks są włączone?
- Czy przy każdym swapie następuje redystrybucja lub rebalansowanie z użyciem niestandardowej matematyki? Czy występuje logika ticków lub progów?
- Gdzie używane są dzielenia, mulDiv, konwersje Q64.96 lub SafeCast? Czy zasady zaokrąglania są spójne w całym systemie?
- Czy możesz skonstruować Δin, które ledwo przekracza granicę i prowadzi do korzystnej gałęzi zaokrąglania? Przetestuj oba kierunki oraz exactInput i exactOutput.
- Czy hook śledzi salda lub delty poszczególnych callerów, które można później wypłacić? Upewnij się, że reszta jest neutralizowana.

## References

- [1] [Analiza pośmiertna exploita Bunni (wrzesień 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit Bunni V2: pełna analiza hacka](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit Bunni V2: 8,3 mln USD wyprowadzonych z powodu błędu płynności (podsumowanie)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Wprowadzenie do Uniswap v4 (badania QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mechanika płynności w Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mechanika swapów w Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks w Uniswap v4 i kwestie bezpieczeństwa](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
