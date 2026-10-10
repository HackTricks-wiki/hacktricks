# DeFi/AMM-Exploitation: Präzisions-/Rundungsmanipulation bei Uniswap-v4-Hooks

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert eine Klasse von DeFi/AMM-Exploitation-Techniken gegen DEXes im Stil von Uniswap v4, die die Kernmathematik durch benutzerdefinierte Hooks erweitern. Ein Vorfall mit Bunni V2 veranschaulicht einen verwandten Fehler: Ein Rundungsrichtungsfehler bei der Auszahlungsabrechnung führte dazu, dass die aktive Liquidität zu niedrig angesetzt wurde. Ein späterer Swap deckte diese Unterschätzung in einem profitablen Sandwich auf.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Grundidee: Wenn ein Hook zusätzliche Abrechnungen implementiert, die von Fixed-Point-Mathematik, Tick-Rundung und Schwellenwertlogik abhängen, kann ein Angreifer Exact-Input-Swaps so gestalten, dass sie bestimmte Schwellenwerte überschreiten und Rundungsabweichungen zu seinen Gunsten aufsummieren. Durch Wiederholung des Musters und anschließende Auszahlung des überhöhten Guthabens wird der Gewinn realisiert, oft finanziert durch einen Flash Loan.

## Hintergrund: Uniswap-v4-Hooks und Swap-Ablauf

- Hooks sind Contracts, die der PoolManager an bestimmten Punkten im Lebenszyklus aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools werden mit einem PoolKey initialisiert, der den Hook-Contract enthält. Eine Hook-Adresse ungleich null aktiviert die für diesen Pool ausgewählten Callbacks.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks können **custom deltas** zurückgeben, die die endgültigen Bilanzänderungen eines Swaps oder einer Liquiditätsaktion modifizieren (custom accounting). Diese Deltas werden am Ende des Aufrufs als Nettosalden ausgeglichen. Daher summieren sich Rundungsfehler innerhalb der Hook-Mathematik vor dem Ausgleich.<sup>[[4]](#references)</sup>
- Die Kernmathematik verwendet Fixed-Point-Formate wie Q64.96 für sqrtPriceX96 sowie Tick-Arithmetik mit 1.0001^tick. Benutzerdefinierte Mathematik, die darauf aufbaut, muss die Rundungssemantik genau beachten, um eine Abweichung von den Invarianten zu vermeiden.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps können exactInput oder exactOutput sein. In v3/v4 bewegt sich der Preis entlang der Ticks; beim Überschreiten einer Tick-Grenze kann Bereichsliquidität aktiviert oder deaktiviert werden. Hooks können zusätzliche Logik für das Überschreiten von Schwellenwerten oder Ticks implementieren.<sup>[[9]](#references)[[11]](#references)</sup>

## Verwundbarkeitsmuster: Präzisions-/Rundungsabweichung beim Überschreiten von Schwellenwerten

Ein typisches verwundbares Muster in benutzerdefinierten Hooks:

1. Der Hook berechnet Liquiditäts- oder Bilanzdeltas pro Swap mithilfe von Ganzzahldivision, mulDiv oder Fixed-Point-Konvertierungen (z. B. Umrechnung zwischen Token und Liquidität anhand von sqrtPrice und Tick-Bereichen).
2. Schwellenwertlogik (z. B. Rebalancing, schrittweise Umverteilung oder Aktivierung pro Bereich) wird ausgelöst, wenn Swap-Größe oder Preisbewegung eine interne Grenze überschreiten.
3. Die Rundung wird uneinheitlich angewendet (z. B. Abschneiden gegen null, Abrunden statt Aufrunden) zwischen Vorwärtsberechnung und Abrechnungspfad. Kleine Abweichungen gleichen sich nicht aus, sondern schreiben dem Aufrufer stattdessen einen Vorteil gut.
4. Exakt bemessene Exact-Input-Swaps, die diese Grenzen überschreiten, schöpfen wiederholt den positiven Rundungsrest ab. Der Angreifer hebt das angesammelte Guthaben später ab.

Angriffsvoraussetzungen
- Ein Pool mit einem benutzerdefinierten v4-Hook, der bei jedem Swap zusätzliche Berechnungen durchführt (z. B. ein LDF/Rebalancer).
- Mindestens ein Ausführungspfad, bei dem Rundung dem Swap-Initiator beim Überschreiten von Schwellenwerten zugutekommt.
- Die Möglichkeit, viele Swaps atomar zu wiederholen (Flash Loans eignen sich ideal, um vorübergehend Kapital bereitzustellen und die Gas-Kosten zu amortisieren).

## Praktische Angriffsmethodik

1) Pools mit Hooks identifizieren
- Alle v4-Pools auflisten und prüfen, ob PoolKey.hooks != address(0) gilt.
- Hook-Bytecode/ABI auf Callbacks prüfen: beforeSwap/afterSwap und benutzerdefinierte Rebalancing-Methoden.
- Nach Mathematik suchen, die durch Liquidität dividiert, Tokenbeträge in Liquidität umrechnet oder BalanceDelta mit Rundung aggregiert.

2) Die Mathematik und Schwellenwerte des Hooks modellieren
- Die Liquiditäts-/Umverteilungsformel des Hooks nachbilden: Zu den Eingaben gehören typischerweise sqrtPriceX96, tickLower/Upper, currentTick, die Gebührenstufe und die Nettoliquidität.
- Schwellenwert-/Stufenfunktionen abbilden: Ticks, Bucket-Grenzen oder LDF-Knickpunkte. Bestimmen, auf welcher Seite jeder Grenze das Delta gerundet wird.
- Ermitteln, wo Konvertierungen zwischen uint256/int256 stattfinden, SafeCast verwendet wird oder mulDiv mit implizitem Abrunden zum Einsatz kommt.

3) Exact-Input-Swaps auf das Überschreiten von Grenzen abstimmen
- Foundry-/Hardhat-Simulationen verwenden, um das minimale Δin zu berechnen, das nötig ist, um den Preis knapp über eine Grenze zu bewegen und den entsprechenden Zweig im Hook auszulösen.
- Prüfen, ob die afterSwap-Abrechnung dem Aufrufer mehr gutschreibt als die Kosten betragen, sodass ein positives BalanceDelta oder ein Guthaben in der Abrechnung des Hooks verbleibt.
- Swaps wiederholen, um Guthaben anzusammeln; anschließend den Auszahlungs-/Abrechnungspfad des Hooks aufrufen.

In v4 muss die Swap-Schleife über einen PoolManager-Unlock-Callback ausgeführt werden; ein negatives `amountSpecified` kennzeichnet Exact Input, und `sqrtPriceLimitX96` muss strikt innerhalb des gültigen Bereichs liegen. Ein Preislimit von null führt zu einem Revert. Deshalb verwendet der folgende Pseudocode für einen Zero-for-One-Swap die Untergrenze.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Beispiel für ein Foundry-artiges Test-Harness (Pseudocode)
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

Kalibrierung von exactInput
- Berechne das Ziel mit der Core-TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in reellen Werten; das Q64.96-Ergebnis wird von TickMath gerundet.<sup>[[13]](#references)</sup>
- Näherungsweise die Token0-Eingabe (zero-for-one) mit der Q64.96-bewussten Formel berechnen: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Die richtungsspezifische Rundung der Core-Routine muss dabei berücksichtigt werden.<sup>[[12]](#references)</sup>
- Δin an der Grenze um ±1 wei anpassen, um den Zweig zu finden, bei dem der Hook zu deinen Gunsten rundet.

4) Mit Flash Loans verstärken
- Einen hohen Nominalbetrag leihen (z. B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Die kalibrierte Swap-Schleife ausführen und anschließend innerhalb des Flash-Loan-Callbacks abheben und zurückzahlen.

Flash-Loan-Grundgerüst für Aave V3
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

5) Exit und Cross-Chain-Replikation
- Wenn Hooks auf mehreren Chains bereitgestellt werden, dieselbe Kalibrierung für jede Chain wiederholen.
- Beim Bunni-Vorfall unterschieden sich Flash-Loan-Liquidität und Bridge-Routen je nach Chain. Diese chainspezifischen Einschränkungen daher bei der Reproduktion der Analyse berücksichtigen.<sup>[[1]](#references)[[2]](#references)</sup>

## Häufige Ursachen von Fehlern in der Hook-Arithmetik

- Gemischte Rundungsregeln: `mulDiv` rundet ab, während spätere Pfade effektiv aufrunden; oder Umrechnungen zwischen Token und Liquidität wenden unterschiedliche Rundungsregeln an.
- Fehler bei der Tick-Ausrichtung: In einem Pfad werden nicht gerundete Ticks verwendet, in einem anderen eine Rundung auf Tick-Abstände.
- Vorzeichen-/Überlaufprobleme bei `BalanceDelta` beim Umwandeln zwischen `int256` und `uint256` während der Abrechnung.
- Präzisionsverlust bei `Q64.96`-Umrechnungen (`sqrtPriceX96`), der bei der Rückumwandlung nicht berücksichtigt wird.
- Akkumulationspfade: Pro Swap erfasste Reste werden als Gutschriften verbucht, die der Aufrufer abheben kann, statt sie zu verbrennen oder auszugleichen.

## Benutzerdefinierte Abrechnung und Delta-Verstärkung

- Die benutzerdefinierte Abrechnung von Uniswap v4 ermöglicht Hooks, Deltas zurückzugeben, die direkt anpassen, was der Aufrufer schuldet oder erhält. Wenn der Hook Gutschriften intern erfasst, können sich Rundungsreste über viele kleine Vorgänge ansammeln, **bevor** die endgültige Abrechnung erfolgt.<sup>[[4]](#references)</sup>
- Wenn der Hook einen kompatiblen Abhebungspfad bereitstellt, kann ein Angreifer innerhalb desselben PoolManager-Unlock-Callbacks zwischen `swap → withdraw → swap` wechseln. Dadurch muss der Hook Deltas anhand eines leicht veränderten Zustands neu berechnen, während die Guthaben bis zur Abrechnung beim Unlock noch ausstehen.<sup>[[4]](#references)[[10]](#references)</sup>
- Bei der Prüfung von Hooks immer nachvollziehen, wie `BalanceDelta`/`HookDelta` erzeugt und abgerechnet werden. Eine einzige verzerrte Rundung in einem Zweig kann zu einer sich vervielfachenden Gutschrift führen, wenn Deltas wiederholt neu berechnet werden.

## Sicherheitsempfehlungen

- Differentialtests: Die Mathematik des Hooks mit einer Referenzimplementierung unter Verwendung hochpräziser rationaler Arithmetik abgleichen und Gleichheit oder einen begrenzten Fehler sicherstellen, der stets zum Nachteil des Angreifers ausfällt (niemals zugunsten des Aufrufers).
- Invarianten-/Eigenschaftstests:
  - Die Summe der Deltas (Token, Liquidität) über Swap-Pfade und Hook-Anpassungen muss den Wert abzüglich Gebühren erhalten.
  - Kein Pfad darf dem Swap-Initiator bei wiederholten `exactInput`-Iterationen eine positive Nettogutschrift verschaffen.
  - Tests an Schwellenwerten und Tick-Grenzen mit Eingaben von ±1 wei für `exactInput` und `exactOutput`.
- Rundungsrichtlinie: Rundungsfunktionen zentralisieren, die stets zum Nachteil des Nutzers runden; inkonsistente Casts und implizites Abrunden beseitigen.
- Abrechnungssenken: Unvermeidbare Rundungsreste der Protokollkasse zuführen oder verbrennen; niemals `msg.sender` gutschreiben.
- Rate-Limits/Schutzmaßnahmen: Mindest-Swap-Größen für Rebalancing-Auslöser festlegen; Rebalancing deaktivieren, wenn Deltas kleiner als ein wei sind; Deltas anhand erwarteter Bereiche plausibilisieren.
- Hook-Callbacks ganzheitlich prüfen: `beforeSwap`/`afterSwap` und Änderungen an Liquidität vor/nachher müssen bei Tick-Ausrichtung und Delta-Rundung übereinstimmen.

## Fallstudie: Bunni V2 (2025‑09‑02)

- Protokoll: Bunni V2, ein Uniswap-v4-Hook, der eine Liquidity Density Function (LDF) zur Berechnung der Token-Dichte und der Gesamtl Liquiditätsschätzungen verwendet.<sup>[[1]](#references)[[2]](#references)</sup>
- Betroffene Pools: USDC/USDT auf Ethereum und weETH/ETH auf Unichain, insgesamt etwa 8,4 Mio. $.<sup>[[1]](#references)</sup>
- Schritt 1 (Preisverschiebung): Der Angreifer lieh sich per Flash Loan etwa 3 Mio. USDT und tauschte sie, um den Tick auf etwa 5000 zu verschieben. Dadurch sank der **aktive** USDC-Bestand auf etwa 28 wei.<sup>[[1]](#references)</sup>
- Schritt 2 (Abfluss durch Rundung): 44 kleine Abhebungen nutzten die Abrundung in `BunniHubLogic::withdraw()` aus und senkten den aktiven USDC-Bestand von 28 wei auf 4 wei (-85,7 %), während nur ein winziger Anteil der LP-Anteile verbrannt wurde. Die Gesamtliquidität sank um etwa 84,4 %.<sup>[[1]](#references)[[2]](#references)</sup>
- Schritt 3 (Sandwich mit Liquiditätssprung): Ein großer Swap verschob den Tick auf etwa 839.189 (1 USDC ≈ 2,77e36 USDT). Die Liquiditätsschätzungen kehrten sich um und stiegen um etwa 16,8 %. Dadurch wurde ein Sandwich ermöglicht, bei dem der Angreifer zum überhöhten Preis zurücktauschte und mit Gewinn ausstieg.<sup>[[1]](#references)</sup>
- Im Post-Mortem identifizierte Korrektur: Die Aktualisierung des ungenutzten Guthabens so ändern, dass aufgerundet wird. Dadurch können wiederholte Mikro-Abhebungen den aktiven Bestand des Pools nicht mehr schrittweise senken.<sup>[[1]](#references)</sup>

Vereinfachte verwundbare Zeile (und Korrektur aus dem Post-Mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Checkliste für die Suche

- Verwendet der Pool eine von null verschiedene hooks-Adresse? Welche Callbacks sind aktiviert?
- Gibt es pro Swap Umverteilungen/Rebalances mit benutzerdefinierter Mathematik? Gibt es Tick-/Schwellenwertlogik?
- Wo werden Divisionen/mulDiv, Q64.96-Konvertierungen oder SafeCast verwendet? Sind die Rundungsregeln überall konsistent?
- Kannst du ein Δin konstruieren, das eine Grenze gerade so überschreitet und dadurch einen vorteilhaften Rundungszweig auslöst? Teste beide Richtungen sowie exactInput und exactOutput.
- Erfasst der Hook Credits oder Deltas pro Aufrufer, die später abgehoben werden können? Stelle sicher, dass Restbeträge neutralisiert werden.

## References

- [1] [Bunni-Exploit: Bericht nach dem Vorfall (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni-V2-Exploit: Vollständige Hack-Analyse](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni-V2-Exploit: 8,3 Mio. $ durch Liquiditätsfehler abgezogen (Zusammenfassung)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap-v4-Core-Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Hintergrund zu Uniswap v4 (QuillAudits-Recherche)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Liquiditätsmechanismen im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Swap-Mechanismen im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap-v4-Hooks und Sicherheitsaspekte](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap-v4-Core-Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap-v4-Core-PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap-v4-SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap-v4-Core-SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap-v4-Core-TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap-v4-PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
