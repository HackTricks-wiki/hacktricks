# DeFi/AMM-Exploitation: Missbrauch von Hook-Präzision/Rundung bei Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert eine Klasse von DeFi/AMM-Exploitation-Techniken gegen DEXes im Stil von Uniswap v4, die die Kernmathematik durch benutzerdefinierte Hooks erweitern. Ein Vorfall bei Bunni V2 veranschaulicht einen verwandten Fehler: Ein Fehler bei der Rundungsrichtung in der Abhebungsabrechnung unterschätzte die aktive Liquidität, und ein späterer Swap legte diese Unterschätzung in einem profitablen Sandwich offen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Die zentrale Idee: Wenn ein Hook zusätzliche Abrechnungen implementiert, die von Fixed-Point-Mathematik, Tick-Rundung und Schwellenwertlogik abhängen, kann ein Angreifer Exact-Input-Swaps so gestalten, dass sie bestimmte Schwellenwerte überschreiten und sich Rundungsabweichungen zugunsten des Angreifers ansammeln. Durch Wiederholen des Musters und anschließendes Abheben des aufgeblähten Guthabens wird der Profit realisiert, häufig finanziert durch ein Flash Loan.

## Hintergrund: Uniswap v4-Hooks und Swap-Ablauf

- Hooks sind Contracts, die der PoolManager an bestimmten Lifecycle-Punkten aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools werden mit einem PoolKey initialisiert, der den Hook-Contract enthält. Eine Hook-Adresse ungleich null aktiviert die für diesen Pool ausgewählten Callbacks.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks können **custom deltas** zurückgeben, die die endgültigen Bilanzänderungen eines Swaps oder einer Liquiditätsaktion modifizieren (custom accounting). Diese Deltas werden am Ende des Calls als Nettosalden abgerechnet, sodass sich jeder Rundungsfehler innerhalb der Hook-Mathematik vor der Abrechnung ansammelt.<sup>[[4]](#references)</sup>
- Die Kernmathematik verwendet Fixed-Point-Formate wie Q64.96 für sqrtPriceX96 sowie Tick-Arithmetik mit 1.0001^tick. Jede darauf aufbauende benutzerdefinierte Mathematik muss die Rundungssemantik sorgfältig einhalten, um eine Verschiebung der Invariante zu vermeiden.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps können ExactInput oder ExactOutput sein. In v3/v4 bewegt sich der Preis entlang von Ticks; das Überschreiten einer Tick-Grenze kann Range-Liquidität aktivieren oder deaktivieren. Hooks können zusätzliche Logik bei Schwellenwert- oder Tick-Überschreitungen implementieren.<sup>[[9]](#references)[[11]](#references)</sup>

## Schwachstellen-Archetyp: Präzisions-/Rundungsdrift beim Überschreiten von Schwellenwerten

Ein typisches verwundbares Muster in benutzerdefinierten Hooks:

1. Der Hook berechnet Liquiditäts- oder Bilanzdeltas pro Swap mithilfe von Integer-Division, mulDiv oder Fixed-Point-Konvertierungen (z. B. Token ↔ Liquidität unter Verwendung von sqrtPrice und Tick-Ranges).
2. Die Schwellenwertlogik (z. B. Rebalancing, schrittweise Umverteilung oder Aktivierung pro Range) wird ausgelöst, wenn eine Swap-Größe oder Preisbewegung eine interne Grenze überschreitet.
3. Die Rundung wird zwischen der Vorwärtsberechnung und dem Abrechnungspfad inkonsistent angewendet (z. B. Abschneiden gegen null, Abrunden gegenüber Aufrunden). Kleine Abweichungen heben sich nicht auf, sondern schreiben dem Caller stattdessen Guthaben gut.
4. Exact-Input-Swaps, die genau so bemessen sind, dass sie diese Grenzen überschreiten, schöpfen den positiven Rundungsrest wiederholt ab. Der Angreifer hebt das angesammelte Guthaben später ab.

Angriffsvoraussetzungen
- Ein Pool mit einem benutzerdefinierten v4-Hook, der bei jedem Swap zusätzliche Mathematik ausführt (z. B. ein LDF/Rebalancer).
- Mindestens ein Ausführungspfad, bei dem die Rundung den Swap-Initiator beim Überschreiten von Schwellenwerten begünstigt.
- Die Möglichkeit, viele Swaps atomar zu wiederholen (Flash Loans sind ideal, um vorübergehendes Kapital bereitzustellen und Gas zu amortisieren).

## Praktische Angriffsmethodik

1) Geeignete Pools mit Hooks identifizieren
- v4-Pools enumerieren und prüfen, ob PoolKey.hooks != address(0) ist.
- Den Bytecode/die ABI des Hooks auf Callbacks prüfen: beforeSwap/afterSwap sowie benutzerdefinierte Rebalancing-Methoden.
- Nach Mathematik suchen, die: durch Liquidität dividiert, zwischen Token-Beträgen und Liquidität konvertiert oder BalanceDelta mit Rundung aggregiert.

2) Die Mathematik und Schwellenwerte des Hooks modellieren
- Die Liquiditäts-/Umverteilungsformel des Hooks nachbilden: Zu den Eingaben gehören typischerweise sqrtPriceX96, tickLower/Upper, currentTick, die Fee-Tier und die Nettoliquidität.
- Schwellenwert-/Schrittfunktionen abbilden: Ticks, Bucket-Grenzen oder LDF-Breakpoints. Bestimmen, auf welcher Seite jeder Grenze das Delta gerundet wird.
- Identifizieren, wo zwischen uint256/int256 konvertiert wird, SafeCast verwendet wird oder mulDiv mit implizitem Abrunden zum Einsatz kommt.

3) Exact-Input-Swaps zum Überschreiten von Grenzen kalibrieren
- Foundry/Hardhat-Simulationen verwenden, um das minimale Δin zu berechnen, das erforderlich ist, um den Preis gerade über eine Grenze zu bewegen und den Branch des Hooks auszulösen.
- Überprüfen, ob die afterSwap-Abrechnung dem Caller mehr gutschreibt als die Kosten betragen, sodass ein positives BalanceDelta oder Guthaben in der Abrechnung des Hooks verbleibt.
- Swaps wiederholen, um Guthaben anzusammeln; anschließend den Withdrawal-/Settlement-Pfad des Hooks aufrufen.

In v4 muss die Swap-Schleife innerhalb eines PoolManager-Unlock-Callbacks ausgeführt werden; ein negatives `amountSpecified` bezeichnet Exact Input, und `sqrtPriceLimitX96` muss strikt innerhalb des gültigen Bereichs liegen. Ein Preislimit von null führt zu einem Revert, daher verwendet der folgende Pseudocode für einen Zero-for-One-Swap die untere Grenze.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Berechne das Ziel mit der core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) in reellen Werten; das Q64.96-Ergebnis wird von TickMath gerundet.<sup>[[13]](#references)</sup>
- Näherung für ein token0- (zero-for-one-)Input unter Verwendung der Q64.96-aware-Formel: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Stimme die richtungsspezifische Rundung der core-Routine ab.<sup>[[12]](#references)</sup>
- Passe Δin an der Grenze um ±1 Wei an, um den Zweig zu finden, in dem der Hook zu deinen Gunsten rundet.

4) Mit flash loans verstärken
- Leihe einen hohen Nominalbetrag (z. B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Führe die kalibrierte Swap-Schleife aus und zahle anschließend innerhalb des flash loan callbacks aus und zurück.

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
5) Exit und Cross-Chain-Replikation
- Wenn Hooks auf mehreren Chains deployed werden, die gleiche Kalibrierung pro Chain wiederholen.
- Im Bunni-Incident unterschieden sich Flash-Loan-Liquidität und Bridge-Routen je nach Chain. Daher müssen diese Chain-spezifischen Einschränkungen bei der Reproduktion der Analyse berücksichtigt werden.<sup>[[1]](#references)[[2]](#references)</sup>

## Häufige Grundursachen in der Hook-Mathematik

- Gemischte Rundungssemantik: `mulDiv` rundet ab, während spätere Pfade effektiv aufrunden; oder Konvertierungen zwischen Token/Liquidität verwenden unterschiedliche Rundungen.
- Fehler bei der Tick-Ausrichtung: In einem Pfad werden nicht gerundete Ticks verwendet, in einem anderen eine Tick-Spacing-Rundung.
- Vorzeichen-/Overflow-Probleme bei `BalanceDelta`, wenn während der Abwicklung zwischen `int256` und `uint256` konvertiert wird.
- Präzisionsverlust bei `Q64.96`-Konvertierungen (`sqrtPriceX96`), der bei der Rückwärtsabbildung nicht gespiegelt wird.
- Akkumulationspfade: Pro-Swap-Reste werden als Credits erfasst, die vom Caller abgehoben werden können, anstatt verbrannt zu werden oder in einer Nullsummenbilanz zu enden.

## Benutzerdefinierte Abrechnung und Delta-Verstärkung

- Uniswap-v4-Custom-Accounting ermöglicht es Hooks, Deltas zurückzugeben, die direkt anpassen, was der Caller schuldet bzw. erhält. Wenn der Hook intern Credits erfasst, können sich Rundungsreste über viele kleine Operationen **vor** der finalen Abrechnung akkumulieren.<sup>[[4]](#references)</sup>
- Wenn der Hook einen kompatiblen Withdrawal-Pfad bereitstellt, kann ein Angreifer innerhalb desselben PoolManager-Unlock-Callbacks zwischen `swap → withdraw → swap` wechseln. Dadurch wird der Hook gezwungen, Deltas anhand eines leicht veränderten Zustands neu zu berechnen, während die Bilanzen bis zum Abschluss des Unlocks ausstehend bleiben.<sup>[[4]](#references)[[10]](#references)</sup>
- Bei der Prüfung von Hooks immer nachvollziehen, wie `BalanceDelta`/`HookDelta` erzeugt und abgewickelt werden. Eine einzelne verzerrte Rundung in einem Zweig kann zu einem anwachsenden Credit werden, wenn Deltas wiederholt neu berechnet werden.

## Defensive Hinweise

- Differential Testing: Die Mathematik des Hooks mit einer Referenzimplementierung unter Verwendung hochpräziser rationaler Arithmetik vergleichen und Gleichheit oder einen begrenzten Fehler erzwingen, der immer adversarial ist (niemals zugunsten des Callers).
- Invarianten-/Property-Tests:
- Die Summe der Deltas (Token, Liquidität) über Swap-Pfade und Hook-Anpassungen muss den Wert abzüglich der Gebühren erhalten.
- Kein Pfad darf dem Swap-Initiator über wiederholte `exactInput`-Iterationen einen positiven Nettocredit erzeugen.
- Threshold-/Tick-Grenztests für Eingaben um ±1 Wei sowohl bei `exactInput` als auch bei `exactOutput`.
- Rundungspolitik: Rundungshelfer zentralisieren, die immer gegen den User runden; inkonsistente Casts und implizite Abrundungen beseitigen.
- Settlement-Sinks: Unvermeidbare Rundungsreste im Protocol-Treasury akkumulieren oder verbrennen; niemals `msg.sender` zuordnen.
- Rate-Limits/Guardrails: Mindestgrößen für Swaps bei Rebalancing-Triggern; Rebalances deaktivieren, wenn Deltas unter einem Wei liegen; Deltas gegen erwartete Wertebereiche plausibilisieren.
- Hook-Callbacks ganzheitlich prüfen: `beforeSwap`/`afterSwap` sowie Änderungen an Liquidität vor und nach der Änderung müssen bei Tick-Ausrichtung und Delta-Rundung übereinstimmen.

## Fallstudie: Bunni V2 (2025-09-02)

- Protocol: Bunni V2, ein Uniswap-v4-Hook, der eine Liquidity Density Function (LDF) verwendet, um Token-Dichte und Schätzungen der Gesamtliquidität zu berechnen.<sup>[[1]](#references)[[2]](#references)</sup>
- Betroffene Pools: USDC/USDT auf Ethereum und weETH/ETH auf Unichain, insgesamt etwa 8,4 Mio. USD.<sup>[[1]](#references)</sup>
- Schritt 1 (Price Push): Der Angreifer lieh sich per Flash-Loan etwa 3 Mio. USDT und tauschte sie, um den Tick auf etwa 5000 zu verschieben, wodurch der **aktive** USDC-Saldo auf etwa 28 Wei schrumpfte.<sup>[[1]](#references)</sup>
- Schritt 2 (Rounding Drain): 44 kleine Withdrawals nutzten die Abrundung in `BunniHubLogic::withdraw()` aus, um den aktiven USDC-Saldo von 28 Wei auf 4 Wei zu reduzieren (-85,7 %), während nur ein winziger Anteil der LP-Shares verbrannt wurde. Die Gesamtliquidität sank um etwa 84,4 %.<sup>[[1]](#references)[[2]](#references)</sup>
- Schritt 3 (Liquidity-Rebound-Sandwich): Ein großer Swap verschob den Tick auf etwa 839.189 (1 USDC ≈ 2,77e36 USDT). Die Liquiditätsschätzungen kippten und stiegen um etwa 16,8 %, wodurch ein Sandwich ermöglicht wurde, bei dem der Angreifer zum überhöhten Preis zurückswappte und mit Gewinn ausstieg.<sup>[[1]](#references)</sup>
- Im Post-Mortem identifizierter Fix: Das Update des Idle-Saldos so ändern, dass aufgerundet wird, damit wiederholte Micro-Withdrawals den aktiven Pool-Saldo nicht weiter nach unten korrigieren.<sup>[[1]](#references)</sup>

Vereinfachte verwundbare Zeile (und Fix aus dem Post-Mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checkliste für die Suche

- Verwendet der Pool eine Adresse ungleich null für Hooks? Welche Callbacks sind aktiviert?
- Gibt es Redistribuierungen/Rebalancing pro Swap mit eigener Mathematik? Gibt es eine Tick-/Schwellenwertlogik?
- Wo werden Divisionen/mulDiv, Q64.96-Konvertierungen oder SafeCast verwendet? Sind die Rundungssemantiken global konsistent?
- Kannst du ein Δin konstruieren, das eine Grenze nur knapp überschreitet und einen vorteilhaften Rundungszweig ergibt? Teste beide Richtungen sowie sowohl exactInput als auch exactOutput.
- Verfolgt der Hook Credits oder Deltas pro Aufrufer, die später abgehoben werden können? Stelle sicher, dass der Restbetrag neutralisiert wird.

## References

- [1] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
