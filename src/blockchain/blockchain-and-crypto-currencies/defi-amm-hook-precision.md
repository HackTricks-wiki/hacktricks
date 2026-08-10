# DeFi/AMM-Exploitation: Uniswap-v4-Hook-Precision/Rounding-Abuse

Diese Seite dokumentiert eine Klasse von DeFi/AMM-Exploitation-Techniken gegen DEXes im Stil von Uniswap v4, die die Kernmathematik mit benutzerdefinierten Hooks erweitern. Ein Bunni-V2-Vorfall veranschaulicht einen verwandten Fehler: Ein Bug bei der Rundungsrichtung in der Abrechnungslogik von Abhebungen unterschätzte die aktive Liquidität, und ein späterer Swap machte diese Unterschätzung in einem profitablen Sandwich ausnutzbar.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Die zentrale Idee: Wenn ein Hook zusätzliche Abrechnungen implementiert, die von Fixed-Point-Mathematik, Tick-Rundung und Schwellenwertlogik abhängen, kann ein Angreifer exact-input-Swaps so gestalten, dass bestimmte Schwellenwerte überschritten werden und sich Rundungsabweichungen zu seinen Gunsten aufsummieren. Durch Wiederholung dieses Musters und anschließende Abhebung des aufgeblähten Guthabens wird der Profit realisiert, häufig finanziert durch einen Flash Loan.

## Hintergrund: Uniswap-v4-Hooks und Swap-Ablauf

- Hooks sind Contracts, die der PoolManager an bestimmten Lifecycle-Punkten aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools werden mit einem PoolKey initialisiert, der den Hook-Contract enthält. Eine Hook-Adresse ungleich null aktiviert die für diesen Pool ausgewählten Callbacks.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks können **custom deltas** zurückgeben, die die endgültigen Balance-Änderungen eines Swaps oder einer Liquiditätsaktion verändern (custom accounting). Diese Deltas werden am Ende des Calls als Nettoguthaben abgerechnet, sodass sich jeder Rundungsfehler innerhalb der Hook-Mathematik vor der Abrechnung aufsummiert.<sup>[[4]](#references)</sup>
- Die Kernmathematik verwendet Fixed-Point-Formate wie Q64.96 für sqrtPriceX96 sowie Tick-Arithmetik mit 1.0001^tick. Jede darauf aufbauende benutzerdefinierte Mathematik muss die Rundungssemantik sorgfältig abgleichen, um eine Verschiebung der Invariante zu vermeiden.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps können exactInput oder exactOutput sein. In v3/v4 bewegt sich der Preis entlang von Ticks; das Überschreiten einer Tick-Grenze kann Range-Liquidität aktivieren oder deaktivieren. Hooks können zusätzliche Logik für das Überschreiten von Schwellenwerten oder Ticks implementieren.<sup>[[9]](#references)[[11]](#references)</sup>

## Schwachstellen-Archetyp: Präzisions-/Rundungsdrift beim Überschreiten von Schwellenwerten

Ein typisches verwundbares Muster in benutzerdefinierten Hooks:

1. Der Hook berechnet Liquiditäts- oder Balance-Deltas pro Swap mithilfe von Integer-Division, mulDiv oder Fixed-Point-Konvertierungen (z. B. Token ↔ Liquidität anhand von sqrtPrice und Tick-Ranges).
2. Die Schwellenwertlogik (z. B. Rebalancing, schrittweise Umverteilung oder Aktivierung pro Range) wird ausgelöst, wenn eine Swap-Größe oder Preisbewegung eine interne Grenze überschreitet.
3. Die Rundung wird zwischen der Vorwärtsberechnung und dem Settlement-Pfad inkonsistent angewendet (z. B. Abschneiden gegen null, Abrunden statt Aufrunden). Kleine Abweichungen heben sich nicht auf, sondern schreiben stattdessen dem Aufrufer ein Guthaben gut.
4. Exact-input-Swaps, die präzise so bemessen sind, dass sie diese Grenzen überschreiten, schöpfen wiederholt den positiven Rundungsrest ab. Der Angreifer hebt anschließend das angesammelte Guthaben ab.

Voraussetzungen für den Angriff
- Ein Pool mit einem benutzerdefinierten v4-Hook, der bei jedem Swap zusätzliche Mathematik ausführt (z. B. ein LDF/Rebalancer).
- Mindestens ein Ausführungspfad, bei dem die Rundung den Swap-Initiator beim Überschreiten von Schwellenwerten begünstigt.
- Die Möglichkeit, viele Swaps atomar zu wiederholen (Flash Loans sind ideal, um vorübergehend Liquidität bereitzustellen und Gas-Kosten zu amortisieren).

## Praktische Angriffsmethodik

1) Geeignete Pools mit Hooks identifizieren
- v4-Pools auflisten und prüfen, ob PoolKey.hooks != address(0) ist.
- Den Bytecode/die ABI des Hooks auf Callbacks prüfen: beforeSwap/afterSwap sowie benutzerdefinierte Rebalancing-Methoden.
- Nach Mathematik suchen, die: durch Liquidität dividiert, zwischen Token-Beträgen und Liquidität konvertiert oder BalanceDelta mit Rundung aggregiert.

2) Die Mathematik und Schwellenwerte des Hooks modellieren
- Die Liquiditäts-/Umverteilungsformel des Hooks nachbilden: Zu den Eingaben gehören typischerweise sqrtPriceX96, tickLower/Upper, currentTick, die Fee-Tier und die Netto-Liquidität.
- Schwellenwert-/Step-Funktionen abbilden: Ticks, Bucket-Grenzen oder LDF-Breakpoints. Bestimmen, auf welcher Seite jeder Grenze das Delta gerundet wird.
- Identifizieren, wo zwischen uint256/int256 gecastet wird, SafeCast verwendet wird oder mulDiv mit implizitem Abrunden zum Einsatz kommt.

3) Exact-input-Swaps zum Überschreiten der Grenzen kalibrieren
- Foundry/Hardhat-Simulationen verwenden, um das minimale Δin zu berechnen, das erforderlich ist, um den Preis gerade über eine Grenze zu bewegen und den Branch des Hooks auszulösen.
- Überprüfen, dass das afterSwap-Settlement dem Aufrufer mehr gutschreibt als die Kosten betragen, sodass ein positives BalanceDelta oder Guthaben in der Abrechnung des Hooks verbleibt.
- Swaps wiederholen, um Guthaben anzusammeln; anschließend den Withdrawal-/Settlement-Pfad des Hooks aufrufen.

In v4 muss die Swap-Schleife über einen PoolManager-Unlock-Callback ausgeführt werden; ein negatives `amountSpecified` bezeichnet exact input, und `sqrtPriceLimitX96` muss strikt innerhalb des gültigen Bereichs liegen. Ein Preislimit von null führt zu einem Revert, daher verwendet der folgende Pseudocode bei einem zero-for-one-Swap die untere Grenze.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Beispiel für einen Foundry-ähnlichen Test-Harness (Pseudocode)
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
- Berechne das Ziel mit der core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in real-value terms; das Q64.96-Ergebnis wird von TickMath gerundet.<sup>[[13]](#references)</sup>
- Nähere einen token0- (zero-for-one-)Input mit der Q64.96-aware formula an: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Gleiche das richtungsspezifische Rounding der core routine ab.<sup>[[12]](#references)</sup>
- Passe Δin um ±1 wei an der Grenze an, um den Branch zu finden, in dem der Hook zu deinen Gunsten rundet.

4) Mit flash loans verstärken
- Leihe einen großen Notionalbetrag (z. B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Führe die kalibrierte Swap-Schleife aus, ziehe anschließend die Mittel ab und zahle sie innerhalb des flash-loan-Callbacks zurück.

Aave V3 flash-loan skeleton
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
- Wenn Hooks auf mehreren Chains deployed sind, wiederhole die gleiche Kalibrierung pro Chain.
- Im Bunni-Incident unterschieden sich Flash-Loan-Liquidität und Bridge-Routen je nach Chain. Berücksichtige daher bei der Reproduktion der Analyse die jeweiligen chain-spezifischen Einschränkungen.<sup>[[1]](#references)[[2]](#references)</sup>

## Häufige Hauptursachen in der Hook-Mathematik

- Gemischte Rundungssemantik: `mulDiv` rundet ab, während spätere Pfade effektiv aufrunden; oder Konvertierungen zwischen Token/Liquidität verwenden unterschiedliche Rundungen.
- Fehler bei der Tick-Ausrichtung: In einem Pfad werden nicht gerundete Ticks verwendet, in einem anderen Tick-Spacing-basiertes Rounding.
- Vorzeichen-/Overflow-Probleme bei `BalanceDelta`, wenn während des Settlements zwischen `int256` und `uint256` konvertiert wird.
- Präzisionsverlust bei Q64.96-Konvertierungen (`sqrtPriceX96`), der bei der Rückwärtszuordnung nicht gespiegelt wird.
- Akkumulationspfade: Pro-Swap-Reste werden als Credits erfasst, die vom Caller abgehoben werden können, anstatt verbrannt zu werden oder in einer Nullsummenrechnung zu verbleiben.

## Custom Accounting und Delta-Verstärkung

- Uniswap-v4-Custom-Accounting ermöglicht es Hooks, Deltas zurückzugeben, die direkt anpassen, was der Caller schuldet oder erhält. Wenn der Hook intern Credits erfasst, können sich Rundungsreste über viele kleine Operationen **bevor** das finale Settlement erfolgt, akkumulieren.<sup>[[4]](#references)</sup>
- Wenn der Hook einen kompatiblen Withdrawal-Pfad bereitstellt, kann ein Angreifer innerhalb desselben PoolManager-Unlock-Callbacks zwischen `swap → withdraw → swap` wechseln. Dadurch wird der Hook gezwungen, Deltas anhand eines leicht veränderten Zustands neu zu berechnen, während die Salden bis zum Settlement des Unlocks ausstehen.<sup>[[4]](#references)[[10]](#references)</sup>
- Bei der Prüfung von Hooks muss immer nachvollzogen werden, wie `BalanceDelta`/`HookDelta` erzeugt und settled werden. Eine einzige verzerrte Rundung in einem Zweig kann zu einem anwachsenden Credit werden, wenn Deltas wiederholt neu berechnet werden.

## Defensive Leitlinien

- Differential Testing: Spiegle die Mathematik des Hooks gegenüber einer Referenzimplementierung mit hochpräziser rationaler Arithmetik und prüfe auf Gleichheit oder einen begrenzten Fehler, der immer adversarial ist (niemals zugunsten des Callers).
- Invariant-/Property-Tests:
- Die Summe der Deltas (Token, Liquidität) über Swap-Pfade und Hook-Anpassungen muss den Wert abzüglich der Gebühren erhalten.
- Kein Pfad darf dem Initiator des Swaps über wiederholte `exactInput`-Iterationen einen positiven Netto-Credit erzeugen.
- Threshold-/Tick-Grenztests für Eingaben von ±1 Wei sowohl für `exactInput` als auch für `exactOutput`.
- Rundungspolitik: Zentralisiere Rundungshelfer, die immer zulasten des Users runden; beseitige inkonsistente Casts und implizite Abrundungen.
- Settlement-Senken: Akkumuliere unvermeidbare Rundungsreste in der Protocol Treasury oder verbrenne sie; ordne sie niemals `msg.sender` zu.
- Rate-Limits/Guardrails: Mindestgröße von Swaps für Rebalancing-Trigger; deaktiviere Rebalancing, wenn Deltas kleiner als ein Wei sind; prüfe Deltas auf Plausibilität anhand erwarteter Wertebereiche.
- Prüfe Hook-Callbacks ganzheitlich: `beforeSwap`/`afterSwap` sowie Änderungen der Liquidität vor und nach der Änderung müssen bei Tick-Ausrichtung und Delta-Rundung übereinstimmen.

## Fallstudie: Bunni V2 (2025-09-02)

- Protocol: Bunni V2, ein Uniswap-v4-Hook, der eine Liquidity Density Function (LDF) verwendet, um Token-Dichte und Schätzungen der Gesamtliquidität zu berechnen.<sup>[[1]](#references)[[2]](#references)</sup>
- Betroffene Pools: USDC/USDT auf Ethereum und weETH/ETH auf Unichain, insgesamt etwa 8,4 Mio. US-Dollar.<sup>[[1]](#references)</sup>
- Schritt 1 (Price Push): Der Angreifer lieh sich per Flash-Loan etwa 3 Mio. USDT und führte einen Swap durch, um den Tick auf etwa 5000 zu verschieben. Dadurch sank der **aktive** USDC-Saldo auf etwa 28 Wei.<sup>[[1]](#references)</sup>
- Schritt 2 (Rounding Drain): 44 winzige Withdrawals nutzten die Abrundung in `BunniHubLogic::withdraw()` aus, um den aktiven USDC-Saldo von 28 Wei auf 4 Wei zu reduzieren (-85,7 %), während nur ein winziger Bruchteil der LP-Shares verbrannt wurde. Die Gesamtliquidität sank um etwa 84,4 %.<sup>[[1]](#references)[[2]](#references)</sup>
- Schritt 3 (Liquidity Rebound Sandwich): Ein großer Swap verschob den Tick auf etwa 839.189 (1 USDC ≈ 2,77e36 USDT). Die Liquiditätsschätzungen kehrten sich um und stiegen um etwa 16,8 %, wodurch ein Sandwich ermöglicht wurde, bei dem der Angreifer zum überhöhten Preis zurückswappte und mit Gewinn ausstieg.<sup>[[1]](#references)</sup>
- Im Post-Mortem identifizierter Fix: Die Aktualisierung des Idle-Saldos soll aufrunden, damit wiederholte Micro-Withdrawals den aktiven Pool-Saldo nicht weiter nach unten korrigieren.<sup>[[1]](#references)</sup>

Vereinfachte verwundbare Zeile (und Fix aus dem Post-Mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting-Checkliste

- Verwendet der Pool eine Adresse für non-zero Hooks? Welche callbacks sind aktiviert?
- Gibt es pro Swap Redistribuierungen/Rebalancing mit benutzerdefinierter Mathematik? Gibt es eine Tick-/Schwellenwertlogik?
- Wo werden divisions/mulDiv, Q64.96-Konvertierungen oder SafeCast verwendet? Sind die Rundungssemantiken global konsistent?
- Kannst du ein Δin konstruieren, das eine Grenze gerade überschreitet und einen vorteilhaften Rundungspfad auslöst? Teste beide Richtungen sowie exactInput und exactOutput.
- Verfolgt der Hook caller-spezifische Gutschriften oder deltas, die später abgehoben werden können? Stelle sicher, dass der Restbetrag neutralisiert wird.

## References

- [1] [Bunni-Exploit-Analyse nach dem Vorfall (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni-V2-Exploit: Vollständige Hack-Analyse](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni-V2-Exploit: 8,3 Mio. USD durch Liquiditätsfehler abgezogen (Zusammenfassung)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap-v4-Core-Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Hintergrund zu Uniswap v4 (QuillAudits-Recherche)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Liquiditätsmechanik im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Swap-Mechanik im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks und Sicherheitsüberlegungen](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap-v4-Core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap-v4-Core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap-v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap-v4-Core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap-v4-Core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap-v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
