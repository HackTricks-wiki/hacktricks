# DeFi/AMM-Ausnutzung: Uniswap v4 Hook — Präzisions-/Rundungs‑Missbrauch

{{#include ../../banners/hacktricks-training.md}}



Diese Seite dokumentiert eine Klasse von DeFi/AMM‑Ausnutzungen gegen Uniswap v4‑artige DEXes, die die Core‑Mathematik mit custom hooks erweitern. Ein kürzlicher Vorfall in Bunni V2 nutzte einen Rundungs/Präzisionsfehler in einer Liquidity Distribution Function (LDF) aus, die bei jedem Swap ausgeführt wurde, wodurch der Angreifer positive Guthaben anhäufen und Liquidität abziehen konnte.

Kernidee: implementiert ein Hook zusätzliche Buchhaltung, die von Fixed‑Point‑Math, Tick‑Rundung und Schwellenlogik abhängt, kann ein Angreifer exact‑input Swaps so konstruieren, dass sie bestimmte Schwellen überschreiten und Rundungsdifferenzen sich zu seinen Gunsten aufsummieren. Das Muster zu wiederholen und anschließend das aufgeblähte Guthaben abzuheben realisiert Gewinn, oft finanziert mit einem flash loan.

## Hintergrund: Uniswap v4 Hooks und Swap‑Ablauf

- Hooks sind Verträge, die der PoolManager an bestimmten Lebenszyklus‑Punkten aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools werden mit einem PoolKey initialisiert, der die hooks‑Adresse enthält. Ist diese ungleich address(0), führt der PoolManager bei jeder relevanten Operation Callbacks aus.
- Hooks können **custom deltas** zurückgeben, die die finalen Bilanzänderungen eines Swaps oder einer Liquidity‑Aktion verändern (custom accounting). Diese Deltas werden am Ende des Aufrufs als Netto‑Salden verrechnet, sodass Rundungsfehler innerhalb der Hook‑Mathematik sich vor der Verrechnung aufsummieren.
- Die Core‑Mathematik verwendet Fixed‑Point‑Formate wie Q64.96 für sqrtPriceX96 und Tick‑Arithmetik mit 1.0001^tick. Jede darauf aufbauende custom math muss die Rundungssemantik genau abgleichen, um Invariant‑Drift zu vermeiden.
- Swaps können exactInput oder exactOutput sein. In v3/v4 bewegt sich der Preis entlang der Ticks; das Überschreiten einer Tick‑Grenze kann Range‑Liquidity aktivieren/deaktivieren. Hooks können zusätzliche Logik bei Schwellen-/Tick‑Überschreitungen implementieren.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Ein typisches verwundbares Muster in custom hooks:

1. Der Hook berechnet pro Swap Liquidity‑ oder Balance‑Deltas unter Verwendung von Integer‑Division, mulDiv oder Fixed‑Point‑Konversionen (z. B. token ↔ liquidity mittels sqrtPrice und Tick‑Bereichen).
2. Schwellen‑Logik (z. B. rebalancing, stufenweise Umverteilung oder per‑Range Aktivierung) wird ausgelöst, wenn die Swap‑Größe oder Preisbewegung eine interne Grenze überschreitet.
3. Rundung wird inkonsistent angewendet (z. B. Trunkierung Richtung Null, floor versus ceil) zwischen Vorwärtsberechnung und Verrechnungsweg. Kleine Diskrepanzen heben sich nicht auf, sondern werden dem Aufrufer gutgeschrieben.
4. Exact‑input swaps, präzise bemessen, um diese Grenzen zu überspannen, ernten wiederholt den positiven Rundungsrest. Der Angreifer hebt später das angesammelte Guthaben ab.

Voraussetzungen für den Angriff
- Ein Pool, der einen custom v4 Hook verwendet, der bei jedem Swap zusätzliche Mathematik ausführt (z. B. eine LDF/rebalancer).
- Mindestens ein Ausführungspfad, bei dem Rundung bei Schwellenüberschreitungen dem Swap‑Initiator zugutekommt.
- Fähigkeit, viele Swaps atomar zu wiederholen (flash loans sind ideal, um temporäre Mittel bereitzustellen und Gas zu amortisieren).

## Praktische Angriffsmethodik

1) Identify candidate pools with hooks
- Enumerate v4 pools and check PoolKey.hooks != address(0).
- Inspect hook bytecode/ABI for callbacks: beforeSwap/afterSwap and any custom rebalancing methods.
- Look for math that: divides by liquidity, converts between token amounts and liquidity, or aggregates BalanceDelta with rounding.

2) Model the hook’s math and thresholds
- Recreate the hook’s liquidity/redistribution formula: inputs typically include sqrtPriceX96, tickLower/Upper, currentTick, fee tier, and net liquidity.
- Map threshold/step functions: ticks, bucket boundaries, or LDF breakpoints. Determine which side of each boundary the delta is rounded on.
- Identify where conversions cast between uint256/int256, use SafeCast, or rely on mulDiv with implicit floor.

3) Calibrate exact‑input swaps to cross boundaries
- Use Foundry/Hardhat simulations to compute the minimal Δin needed to move price just across a boundary and trigger the hook’s branch.
- Verify that afterSwap settlement credits the caller more than the cost, leaving a positive BalanceDelta or credit in the hook’s accounting.
- Repeat swaps to accumulate credit; then call the hook’s withdrawal/settlement path.

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
Calibrating the exactInput
- Berechne ΔsqrtP für einen Tick-Schritt: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Schätze Δin mithilfe der v3/v4-Formeln: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Stelle sicher, dass die Rundungsrichtung mit der Core-Math übereinstimmt.
- Passe Δin um ±1 wei an der Grenze an, um den Zweig zu finden, in dem der hook zu deinen Gunsten rundet.

4) Verstärken mit flash loans
- Leihe ein großes Notional (z. B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.
- Führe die kalibrierte Swap-Schleife aus, dann withdraw und repay innerhalb des flash loan callback.

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
5) Exit und Cross‑Chain‑Replikation
- Wenn Hooks auf mehreren Chains deployed sind, die gleiche Kalibrierung pro Chain wiederholen.
- Die Bridge transferiert die Erlöse zurück zur Zielchain und kann optional zyklisch über Lending‑Protokolle laufen, um Flüsse zu verschleiern.

## Häufige Ursachen in Hook‑Berechnungen

- Gemischte Rundungssemantik: mulDiv floort, während spätere Pfade effektiv aufrunden; oder Konversionen zwischen Token/Liquidität verwenden unterschiedliche Rundungen.
- Tick‑Ausrichtungsfehler: ungerundete ticks in einem Pfad verwenden und tick‑spacing‑Rundung in einem anderen.
- BalanceDelta Vorzeichen/Overflow‑Probleme beim Konvertieren zwischen int256 und uint256 während der Settlement‑Phase.
- Präzisionsverlust bei Q64.96‑Konversionen (sqrtPriceX96), der in der Rückabbildung nicht gespiegelt wird.
- Akkumulationspfade: pro‑swap Reste, die als Credits verfolgt werden und vom Caller abhebbar sind, anstatt verbrannt/zero‑sum zu sein.

## Benutzerdefinierte Buchführung & Delta‑Verstärkung

- Uniswap v4 custom accounting erlaubt es Hooks, Deltas zurückzugeben, die direkt anpassen, was der Caller schuldet/erhält. Wenn der Hook intern Credits verfolgt, kann Rundungs‑Residuum sich über viele kleine Operationen **vor** der endgültigen Settlement‑Phase anhäufen.
- Das stärkt Boundary/Threshold‑Missbrauch: der Angreifer kann `swap → withdraw → swap` in derselben tx alternieren und den Hook zwingen, Deltas auf leicht unterschiedlichem State neu zu berechnen, während alle Salden noch pending sind.
- Beim Review von Hooks immer nachverfolgen, wie BalanceDelta/HookDelta erzeugt und abgerechnet werden. Eine einzelne verzerrte Rundung in einem Zweig kann zu einem sich verstärkenden Credit werden, wenn Deltas wiederholt neu berechnet werden.

## Defensive Hinweise

- Differential testing: die Hook‑Berechnungen gegen eine Referenzimplementierung mit hochpräziser rationaler Arithmetik spiegeln und Gleichheit oder eine begrenzte Fehlergrenze prüfen, die stets adversarial ist (niemals zugunsten des Callers).
- Invariant/Property‑Tests:
  - Summe der Deltas (Token, Liquidität) über Swap‑Pfade und Hook‑Anpassungen muss Wert modulo Fees konservieren.
  - Kein Pfad darf bei wiederholten exactInput‑Iterationen einen positiven Nettokredit für den Swap‑Initiator erzeugen.
  - Threshold/Tick‑Boundary‑Tests um ±1 wei Inputs für sowohl exactInput als auch exactOutput.
- Rundungspolicy: Rundungs‑Hilfsfunktionen zentralisieren, die immer gegen den Nutzer runden; inkonsistente Casts und implizite Floors eliminieren.
- Settlement‑Sinks: unvermeidbares Rundungsresiduum an die Protocol‑Treasury akkumulieren oder verbrennen; niemals dem msg.sender zurechnen.
- Rate‑Limits/Guardrails: Mindest‑Swap‑Größen für Rebalancing‑Trigger; Rebalances deaktivieren, wenn Deltas sub‑wei sind; Deltas gegen erwartete Bereiche sanity‑checken.
- Hooks‑Callbacks ganzheitlich prüfen: beforeSwap/afterSwap und before/after Liquidity‑Änderungen sollten sich bei Tick‑Ausrichtung und Delta‑Rundung einig sein.

## Fallstudie: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) mit einem LDF, das pro Swap zum Rebalancen angewendet wurde.
- Betroffene Pools: USDC/USDT auf Ethereum und weETH/ETH auf Unichain, insgesamt ca. $8.4M.
- Step 1 (price push): der Angreifer flash‑borrowed ~3M USDT und swapped, um den Tick auf ~5000 zu treiben, wodurch der **aktive** USDC‑Saldo auf ~28 wei schrumpfte.
- Step 2 (rounding drain): 44 winzige Withdrawals nutzten Floor‑Rundung in `BunniHubLogic::withdraw()` aus, um den aktiven USDC‑Saldo von 28 wei auf 4 wei (‑85.7%) zu reduzieren, während nur ein winziger Bruchteil der LP‑Shares verbrannt wurde. Die Gesamtliquidität wurde um ~84.4% unterschätzt.
- Step 3 (liquidity rebound sandwich): ein großer Swap verschob den Tick auf ~839,189 (1 USDC ≈ 2.77e36 USDT). Die Liquiditäts‑Schätzungen kippten und stiegen um ~16.8%, wodurch ein Sandwich möglich wurde, bei dem der Angreifer zurück zum aufgeblähten Preis swapped und mit Profit exitierte.
- Fix, der im Post‑Mortem identifiziert wurde: das Idle‑Balance‑Update so ändern, dass es **aufrundet**, damit wiederholte Mikro‑Withdrawals den aktiven Pool‑Saldo nicht nach unten ratchet.

Vereinfachte verwundbare Zeile (und Post‑Mortem‑Fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting-Checkliste

- Verwendet der Pool eine non‑zero hooks‑Adresse? Welche callbacks sind aktiviert?
- Gibt es per‑swap Umverteilungen/Rebalances mit benutzerdefinierter Mathematik? Irgendwelche tick-/Threshold‑Logiken?
- Wo werden divisions/mulDiv, Q64.96‑Konversionen oder SafeCast verwendet? Sind die Rundungssemantiken global konsistent?
- Kannst du Δin konstruieren, das gerade eine Grenze überschreitet und einen vorteilhaften Rundungszweig erzeugt? Teste beide Richtungen sowie exactInput und exactOutput.
- Verfolgt der hook per‑caller Credits oder Deltas, die später abgehoben werden können? Stelle sicher, dass Restbeträge neutralisiert werden.

## References

- [Bunni V2 Exploit: $8.3M durch Liquidity‑Fehler abgeflossen (Zusammenfassung)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Vollständige Hack‑Analyse](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 Hintergrund (QuillAudits‑Forschung)](https://www.quillaudits.com/research/uniswap-development)
- [Liquiditätsmechanik im Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap‑Mechanik im Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks und Sicherheitsüberlegungen](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post‑Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
