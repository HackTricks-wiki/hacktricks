# DeFi/AMM-Exploitation: Uniswap v4 Hook-Präzisions-/Rundungs-Missbrauch

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert eine Klasse von DeFi/AMM-Exploitation-Techniken gegen DEXes im Stil von Uniswap v4, die die Kernmathematik durch benutzerdefinierte Hooks erweitern. Ein Vorfall bei Bunni V2 veranschaulicht einen verwandten Fehler: Ein Fehler bei der Rundungsrichtung in der Auszahlungsbuchhaltung unterschätzte die aktive Liquidität. Ein späterer Swap machte diese Unterschätzung in einem profitablen Sandwich sichtbar.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Grundidee: Wenn ein Hook zusätzliche Buchhaltung implementiert, die von Fixed-Point-Mathematik, Tick-Rundung und Schwellenwertlogik abhängt, kann ein Angreifer Exact-Input-Swaps so gestalten, dass sie bestimmte Schwellenwerte überschreiten und Rundungsabweichungen zu seinem Vorteil aufsummieren. Durch Wiederholung des Musters und anschließende Auszahlung des überhöhten Guthabens wird der Gewinn realisiert, oft finanziert durch einen Flash Loan.

## Hintergrund: Uniswap-v4-Hooks und Swap-Ablauf

- Hooks sind Contracts, die der PoolManager an bestimmten Punkten im Lebenszyklus aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools werden mit einem PoolKey initialisiert, der den Hook-Contract enthält. Eine Hook-Adresse ungleich null aktiviert die für diesen Pool ausgewählten Callbacks.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks können **benutzerdefinierte Deltas** zurückgeben, die die endgültigen Bilanzänderungen eines Swaps oder einer Liquiditätsaktion modifizieren (benutzerdefinierte Buchhaltung). Diese Deltas werden am Ende des Aufrufs als Nettosalden ausgeglichen, sodass sich Rundungsfehler innerhalb der Hook-Mathematik vor dem Ausgleich aufsummieren.<sup>[[4]](#references)</sup>
- Die Kernmathematik verwendet Fixed-Point-Formate wie Q64.96 für sqrtPriceX96 und Tick-Arithmetik mit 1.0001^tick. Jede darauf aufbauende benutzerdefinierte Mathematik muss die Rundungssemantik sorgfältig berücksichtigen, um eine Verschiebung der Invariante zu vermeiden.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps können exactInput oder exactOutput sein. In v3/v4 bewegt sich der Preis entlang von Ticks; beim Überschreiten einer Tick-Grenze kann Liquidität eines Bereichs aktiviert oder deaktiviert werden. Hooks können zusätzliche Logik für Schwellenwert- oder Tick-Überschreitungen implementieren.<sup>[[9]](#references)[[11]](#references)</sup>

## Schwachstellenmuster: Präzisions-/Rundungsabweichungen beim Überschreiten von Schwellenwerten

Ein typisches anfälliges Muster in benutzerdefinierten Hooks:

1. Der Hook berechnet Liquiditäts- oder Bilanzdeltas pro Swap mithilfe ganzzahliger Division, mulDiv oder Fixed-Point-Konvertierungen (z. B. Token ↔ Liquidität unter Verwendung von sqrtPrice und Tick-Bereichen).
2. Schwellenwertlogik (z. B. Rebalancing, schrittweise Umverteilung oder Aktivierung pro Bereich) wird ausgelöst, wenn die Swap-Größe oder Preisbewegung eine interne Grenze überschreitet.
3. Die Rundung wird uneinheitlich angewendet (z. B. Abschneiden gegen null, Abrunden gegenüber Aufrunden) zwischen der Vorwärtsberechnung und dem Ausgleichspfad. Kleine Abweichungen heben sich nicht auf, sondern schreiben dem Aufrufer stattdessen einen Vorteil gut.
4. Genau bemessene Exact-Input-Swaps, die diese Grenzen überschreiten, schöpfen wiederholt den positiven Rundungsrest ab. Der Angreifer hebt später das angesammelte Guthaben ab.

Angriffsvoraussetzungen
- Ein Pool mit einem benutzerdefinierten v4-Hook, der bei jedem Swap zusätzliche Berechnungen durchführt (z. B. einen LDF/Rebalancer).
- Mindestens ein Ausführungspfad, bei dem die Rundung den Initiator des Swaps beim Überschreiten von Schwellenwerten begünstigt.
- Die Möglichkeit, viele Swaps atomar zu wiederholen (Flash Loans eignen sich ideal, um vorübergehend Liquidität bereitzustellen und Gas zu amortisieren).

## Praktische Angriffsmethodik

1) Kandidaten-Pools mit Hooks identifizieren
- v4-Pools auflisten und prüfen, ob PoolKey.hooks != address(0) gilt.
- Hook-Bytecode/ABI auf Callbacks untersuchen: beforeSwap/afterSwap und alle benutzerdefinierten Rebalancing-Methoden.
- Nach Mathematik suchen, die durch Liquidität dividiert, zwischen Token-Beträgen und Liquidität umrechnet oder BalanceDelta mit Rundung aggregiert.

2) Die Mathematik und Schwellenwerte des Hooks modellieren
- Die Liquiditäts-/Umverteilungsformel des Hooks nachbilden: Zu den Eingaben gehören typischerweise sqrtPriceX96, tickLower/Upper, currentTick, die Fee-Stufe und die Nettoliquidität.
- Schwellenwert-/Schrittfunktionen abbilden: Ticks, Bucket-Grenzen oder LDF-Knickpunkte. Bestimmen, auf welcher Seite jeder Grenze das Delta gerundet wird.
- Stellen identifizieren, an denen Konvertierungen zwischen uint256/int256 stattfinden, SafeCast verwendet wird oder mulDiv implizit abgerundet wird.

3) Exact-Input-Swaps so abstimmen, dass sie Grenzen überschreiten
- Foundry-/Hardhat-Simulationen verwenden, um das minimale Δin zu berechnen, das nötig ist, um den Preis knapp über eine Grenze zu bewegen und den Zweig des Hooks auszulösen.
- Prüfen, ob der afterSwap-Ausgleich dem Aufrufer mehr gutschreibt, als der Swap kostet, sodass ein positives BalanceDelta oder ein Guthaben in der Buchhaltung des Hooks verbleibt.
- Swaps wiederholen, um Guthaben anzusammeln; anschließend den Auszahlungs-/Ausgleichspfad des Hooks aufrufen.

In v4 muss die Swap-Schleife über einen PoolManager-Unlock-Callback ausgeführt werden; ein negatives `amountSpecified` kennzeichnet Exact Input, und `sqrtPriceLimitX96` muss strikt innerhalb des gültigen Bereichs liegen. Ein Preislimit von null führt zu einem Revert, daher verwendet der Pseudocode unten bei einem Zero-for-One-Swap die untere Grenze.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Beispiel für ein Foundry-ähnliches Test-Harness (Pseudocode)
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
- Berechne das Ziel mit der core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in realen Werten; das Q64.96-Ergebnis wird von TickMath gerundet.<sup>[[13]](#references)</sup>
- Nähere einen token0-Input (zero-for-one) mit der Q64.96-bewussten Formel an: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Beachte die richtungsspezifische Rundung der core-Routine.<sup>[[12]](#references)</sup>
- Passe Δin an der Grenze um ±1 wei an, um den Zweig zu finden, in dem der Hook zu deinen Gunsten rundet.

4) Mit Flash Loans verstärken
- Leihe dir einen hohen Nominalbetrag (z. B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Führe die kalibrierte Swap-Schleife aus und hebe dann innerhalb des Flash-Loan-Callbacks ab und zahle den Kredit zurück.

Grundgerüst für einen Aave-V3-Flash-Loan
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
- Wenn Hooks auf mehreren Chains eingesetzt werden, wiederholen Sie dieselbe Kalibrierung für jede Chain.
- Beim Bunni-Vorfall unterschieden sich Flash-Loan-Liquidität und Bridge-Routen je nach Chain. Berücksichtigen Sie daher bei der Reproduktion der Analyse die jeweiligen Chain-spezifischen Einschränkungen.<sup>[[1]](#references)[[2]](#references)</sup>

## Häufige Ursachen für Fehler in der Hook-Arithmetik

- Gemischte Rundungssemantik: `mulDiv` rundet ab, während spätere Pfade effektiv aufrunden; oder Umrechnungen zwischen Token und Liquidität verwenden unterschiedliche Rundungsverfahren.
- Fehler bei der Tick-Ausrichtung: In einem Pfad werden nicht gerundete Ticks verwendet, in einem anderen eine Rundung auf Tick-Abstände.
- Vorzeichen-/Overflow-Probleme bei BalanceDelta, wenn während des Settlements zwischen int256 und uint256 konvertiert wird.
- Präzisionsverlust bei Q64.96-Konvertierungen (`sqrtPriceX96`), der bei der Rückabbildung nicht berücksichtigt wird.
- Akkumulationspfade: Pro Swap werden Reste als Credits verbucht, die der Aufrufer abheben kann, statt sie zu verbrennen oder eine Nullsumme sicherzustellen.

## Benutzerdefinierte Abrechnung und Delta-Verstärkung

- Die benutzerdefinierte Abrechnung in Uniswap v4 ermöglicht Hooks, Deltas zurückzugeben, die direkt anpassen, was der Aufrufer schuldet oder erhält. Wenn der Hook intern Credits erfasst, können sich Rundungsreste über viele kleine Vorgänge ansammeln, **bevor** das endgültige Settlement erfolgt.<sup>[[4]](#references)</sup>
- Wenn der Hook einen kompatiblen Auszahlungsweg bereitstellt, kann ein Angreifer innerhalb desselben PoolManager-Unlock-Callbacks zwischen `swap → withdraw → swap` wechseln. Dadurch wird der Hook gezwungen, Deltas anhand eines leicht veränderten Zustands neu zu berechnen, während die Salden bis zum Abschluss des Unlocks ausstehen.<sup>[[4]](#references)[[10]](#references)</sup>
- Verfolgen Sie beim Prüfen von Hooks immer, wie BalanceDelta/HookDelta erzeugt und abgerechnet wird. Eine einzige verzerrte Rundung in einem Zweig kann zu einem anwachsenden Credit werden, wenn Deltas wiederholt neu berechnet werden.

## Empfehlungen zur Abwehr

- Differenzialtests: Vergleichen Sie die Arithmetik des Hooks mit einer Referenzimplementierung, die hochpräzise rationale Arithmetik verwendet, und fordern Sie Gleichheit oder einen begrenzten Fehler, der immer zulasten des Aufrufers geht.
- Invarianten-/Property-Tests:
  - Die Summe der Deltas (Token, Liquidität) über Swap-Pfade und Hook-Anpassungen muss den Wert abzüglich Gebühren erhalten.
  - Kein Pfad sollte dem Swap-Initiator bei wiederholten `exactInput`-Iterationen einen positiven Nettocredit verschaffen.
  - Tests für Schwellenwerte und Tick-Grenzen mit ±1-wei-Eingaben für `exactInput` und `exactOutput`.
- Rundungsregeln: Zentralisieren Sie Rundungshelfer, die immer zulasten des Nutzers runden; beseitigen Sie inkonsistente Casts und implizites Abrunden.
- Settlement-Senken: Leiten Sie unvermeidbare Rundungsreste an die Treasury des Protokolls weiter oder verbrennen Sie sie; schreiben Sie sie niemals `msg.sender` gut.
- Rate-Limits/Schutzmaßnahmen: Legen Sie Mindestgrößen für Swaps fest, die Rebalancing auslösen; deaktivieren Sie Rebalancing, wenn Deltas kleiner als ein Wei sind; prüfen Sie Deltas auf plausible Wertebereiche.
- Prüfen Sie Hook-Callbacks ganzheitlich: `beforeSwap`/`afterSwap` und Änderungen vor/nach der Liquidität müssen bei Tick-Ausrichtung und Delta-Rundung übereinstimmen.

## Fallstudie: Bunni V2 (2025‑09‑02)

- Protokoll: Bunni V2, ein Uniswap-v4-Hook, der eine Liquidity Density Function (LDF) zur Berechnung der Token-Dichte und von Schätzungen der Gesamtliquidität verwendet.<sup>[[1]](#references)[[2]](#references)</sup>
- Betroffene Pools: USDC/USDT auf Ethereum und weETH/ETH auf Unichain, mit einem Gesamtwert von etwa 8,4 Mio. US-Dollar.<sup>[[1]](#references)</sup>
- Schritt 1 (Preisbewegung): Der Angreifer lieh sich per Flash Loan etwa 3 Mio. USDT und tauschte sie, um den Tick auf etwa 5000 zu treiben. Dadurch schrumpfte der **aktive** USDC-Saldo auf etwa 28 Wei.<sup>[[1]](#references)</sup>
- Schritt 2 (Abzug durch Rundung): 44 kleine Abhebungen nutzten die Abrundung in `BunniHubLogic::withdraw()` aus, um den aktiven USDC-Saldo von 28 Wei auf 4 Wei zu senken (-85,7 %), während nur ein winziger Anteil der LP-Anteile verbrannt wurde. Die Gesamtliquidität sank um etwa 84,4 %.<sup>[[1]](#references)[[2]](#references)</sup>
- Schritt 3 (Sandwich mit Liquiditätsanstieg): Ein großer Swap verschob den Tick auf etwa 839.189 (1 USDC ≈ 2.77e36 USDT). Die Liquiditätsschätzungen kehrten sich um und stiegen um etwa 16,8 %. Dadurch wurde ein Sandwich möglich, bei dem der Angreifer zum überhöhten Preis zurücktauschte und mit Gewinn ausstieg.<sup>[[1]](#references)</sup>
- Im Nachbericht identifizierte Korrektur: Die Aktualisierung des ungenutzten Saldos soll aufgerundet werden, damit wiederholte Mikroabhebungen den aktiven Saldo des Pools nicht weiter schrittweise senken können.<sup>[[1]](#references)</sup>

Vereinfachte verwundbare Codezeile (und Korrektur aus dem Nachbericht).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Hunting-Checkliste

- Verwendet der Pool eine Hooks-Adresse ungleich null? Welche Callbacks sind aktiviert?
- Gibt es pro Swap Umverteilungen/Rebalances mit benutzerdefinierter Mathematik? Gibt es Tick-/Schwellenwertlogik?
- Wo werden Divisionsoperationen/mulDiv, Q64.96-Konvertierungen oder SafeCast verwendet? Sind die Rundungsregeln überall konsistent?
- Kannst du ein Δin konstruieren, das eine Grenze gerade eben überschreitet und einen vorteilhaften Rundungszweig auslöst? Teste beide Richtungen sowie exactInput und exactOutput.
- Verfolgt der Hook Guthaben oder Deltas pro Aufrufer, die später abgehoben werden können? Stelle sicher, dass Restbeträge neutralisiert werden.

## References

- [1] [Bunni-Exploit: Analyse nach dem Vorfall (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2-Exploit: vollständige Hack-Analyse](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2-Exploit: 8,3 Mio. $ durch Liquiditätsfehler abgezogen (Zusammenfassung)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap-v4-Core-Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Hintergrund zu Uniswap v4 (QuillAudits-Recherche)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Liquiditätsmechanismen im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Swap-Mechanismen im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks und Sicherheitsaspekte](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap-v4-Core-Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap-v4-Core-PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap-v4-SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap-v4-Core-SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap-v4-Core-TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap-v4-PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
