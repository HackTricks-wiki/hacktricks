# DeFi/AMM-Ausnutzung: Uniswap v4 Hook Präzisions-/Rundungs‑Missbrauch

{{#include ../../banners/hacktricks-training.md}}



Diese Seite dokumentiert eine Klasse von DeFi/AMM‑Ausnutzungen gegen Uniswap v4–artige DEXes, die die Core‑Math um benutzerdefinierte Hooks erweitern. Ein kürzliches Incident in Bunni V2 nutzte einen Rundungs-/Präzisionsfehler in einer Liquiditätsverteilungsfunktion (LDF), die bei jedem Swap ausgeführt wird, und ermöglichte dem Angreifer, positive Gutschriften anzusammeln und Liquidität abzuziehen.

Kernidee: Wenn ein hook zusätzliche Buchhaltung implementiert, die von fixed‑point Math, Tick‑Rundung und Schwellenlogik abhängt, kann ein Angreifer exact‑input swaps konstruieren, die bestimmte Schwellen überschreiten, sodass Rundungsabweichungen zu seinen Gunsten akkumulieren. Wiederholt man das Muster und zieht anschließend den aufgeblähten Saldo ab, wird Gewinn realisiert, oft finanziert durch einen flash loan.

## Hintergrund: Uniswap v4 hooks und Swap‑Ablauf

- Hooks sind Contracts, die der PoolManager zu bestimmten Lebenszyklus‑Zeitpunkten aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools werden mit einem PoolKey initialisiert, der die hooks‑Adresse enthält. Ist diese ungleich null, führt der PoolManager bei jeder relevanten Operation Callbacks aus.
- Hooks können **custom deltas** zurückgeben, die die endgültigen Bilanzänderungen eines Swaps oder einer Liquidity‑Aktion modifizieren (custom accounting). Diese Deltas werden am Ende des Aufrufs als Nettobalance verrechnet, weshalb sich jede Rundungsfehlersumme innerhalb der Hook‑Math vor der Abrechnung akkumuliert.
- Die Core‑Math verwendet fixed‑point Formate wie Q64.96 für sqrtPriceX96 und Tick‑Arithmetik mit 1.0001^tick. Jegliche zusätzliche Math‑Schicht obenauf muss die Rundungssemantik sorgfältig angleichen, um Invariant‑Drift zu vermeiden.
- Swaps können exactInput oder exactOutput sein. In v3/v4 bewegt sich der Preis entlang von ticks; das Überschreiten einer Tick‑Grenze kann Range‑Liquidity aktivieren/deaktivieren. Hooks können zusätzliche Logik bei Schwellen‑/Tick‑Überschreitungen implementieren.

## Vulnerability‑Archetyp: Schwellen‑Überschreitungs‑Präzisions-/Rundungs‑Drift

Ein typisches verwundbares Muster in custom hooks:

1. Der hook berechnet pro Swap Liquidity‑ oder Balance‑Deltas unter Verwendung von integer division, mulDiv oder fixed‑point Konversionen (z. B. token ↔ liquidity mittels sqrtPrice und Tick‑Bereichen).
2. Schwellenlogik (z. B. Rebalancing, stufenweise Redistribution oder per‑Range Activation) wird ausgelöst, wenn eine Swap‑Größe oder Preisbewegung eine interne Grenze überschreitet.
3. Rundung wird inkonsistent angewandt (z. B. Trunkierung Richtung Null, floor versus ceil) zwischen der Vorwärtsberechnung und dem Abrechnungspfad. Kleine Abweichungen heben sich nicht auf, sondern schreiben dem Caller gut.
4. Exact‑input swaps, präzise dimensioniert, um diese Grenzen zu überqueren, ernten wiederholt den positiven Rundungsrest. Der Angreifer zieht später die akkumulierte Gutschrift ab.

Voraussetzungen für den Angriff
- Ein Pool, der einen custom v4 hook verwendet, der bei jedem Swap zusätzliche Math ausführt (z. B. ein LDF/rebalancer).
- Mindestens ein Ausführungspfad, in dem die Rundung dem Swap‑Initiator beim Überschreiten von Schwellen zugutekommt.
- Fähigkeit, viele Swaps atomar zu wiederholen (flash loans sind ideal, um temporäre Mittel bereitzustellen und Gas zu amortisieren).

## Praktische Angriffs‑Methodik

1) Kandidatenpools mit hooks identifizieren
- Enumeriere v4 Pools und prüfe PoolKey.hooks != address(0).
- Inspecte Hook‑Bytecode/ABI auf Callbacks: beforeSwap/afterSwap und jegliche custom rebalancing‑Methoden.
- Suche nach Math, die: durch Liquidity dividiert, zwischen Token‑Beträgen und Liquidity konvertiert oder BalanceDelta mit Rundung aggregiert.

2) Die Hook‑Math und Schwellen modellieren
- Rekonstruiere die Liquidity/Redistribution‑Formel des Hooks: Inputs sind typischerweise sqrtPriceX96, tickLower/Upper, currentTick, fee tier und net liquidity.
- Mappe Schwellen-/Stufenfunktionen: ticks, Bucket‑Grenzen oder LDF‑Breakpoints. Bestimme, auf welcher Seite jeder Grenze das Delta gerundet wird.
- Identifiziere Stellen, an denen Konversionen zwischen uint256/int256 casten, SafeCast verwenden oder mulDiv mit implizitem floor vertrauen.

3) Exact‑input swaps kalibrieren, um Grenzen zu überqueren
- Nutze Foundry/Hardhat Simulationen, um das minimale Δin zu berechnen, das nötig ist, um den Preis gerade über eine Grenze zu bewegen und den Hook‑Branch zu triggern.
- Verifiziere, dass nach der Abrechnung (afterSwap settlement) dem Caller mehr gutgeschrieben wird als die Kosten, sodass ein positiver BalanceDelta oder eine Gutschrift in der Hook‑Buchhaltung verbleibt.
- Wiederhole Swaps, um Gutschriften anzusammeln; rufe dann den Withdrawal/Settlement‑Pfad des Hooks auf.

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
Kalibrierung des exactInput
- Berechne ΔsqrtP für einen Tick-Schritt: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximiere Δin mit v3/v4-Formeln: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Stelle sicher, dass die Rundungsrichtung mit der Kernmathematik übereinstimmt.
- Passe Δin um ±1 wei um die Grenze an, um den Zweig zu finden, in dem der hook zu deinen Gunsten rundet.

4) Mit flash loans verstärken
- Leihe einen großen Notionalbetrag (z.B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.
- Führe die kalibrierte Swap-Schleife aus, hebe dann ab und zahle innerhalb des flash loan callbacks zurück.

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
5) Exit und cross‑chain replication
- Wenn hooks auf mehreren Chains deployed sind, wiederhole dieselbe Kalibrierung pro Chain.
- Bridge proceeds back to the target chain und optional zyklisch über lending protocols, um Flows zu verschleiern.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floort, während spätere Pfade effektiv aufrunden; oder Konversionen zwischen token/liquidity verwenden unterschiedliche Rundungen.
- Tick alignment errors: Verwendung ungerundeter ticks in einem Pfad und tick‑spaced rounding in einem anderen.
- BalanceDelta sign/overflow Probleme beim Konvertieren zwischen int256 und uint256 während der Settlement‑Phase.
- Precision loss in Q64.96 conversions (sqrtPriceX96), die nicht in der Rückabbildung gespiegelt wird.
- Accumulation pathways: Pro‑swap Reste werden als Credits getrackt, die vom Caller withdrawable sind, anstatt verbrannt/zero‑sum zu werden.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting erlaubt Hooks, Deltas zurückzugeben, die direkt anpassen, was der Caller schuldet/erhält. Wenn der Hook intern Credits tracked, kann Rundungsresiduum über viele kleine Operationen hinweg akkumulieren, und zwar bevor die finale Settlement‑Operation stattfindet.
- Das verstärkt Boundary/Threshold‑Abuse: Der Angreifer kann innerhalb derselben tx `swap → withdraw → swap` alternieren und den Hook zwingen, Deltas auf leicht unterschiedlichem State neu zu berechnen, während alle Balances noch pending sind.
- Beim Review von Hooks immer nachverfolgen, wie BalanceDelta/HookDelta erzeugt und settled werden. Eine einzige verzerrte Rundung in einem Branch kann zu einem sich aufschaukelnden Credit werden, wenn Deltas wiederholt neu berechnet werden.

## Defensive guidance

- Differential testing: Spiegel die Hook‑Math gegenüber einer Referenzimplementation mit hochpräziser rationaler Arithmetik und assertiere Gleichheit oder einen begrenzten Fehler, der immer adversarial ist (niemals zugunsten des Callers).
- Invariant-/Property‑Tests:
  - Summe der Deltas (tokens, liquidity) über Swap‑Pfade und Hook‑Anpassungen muss Wert konservieren modulo fees.
  - Kein Pfad darf über wiederholte exactInput‑Iterationen einen positiven Nettocredit für den Swap‑Initiator erzeugen.
  - Threshold/tick‑Boundary‑Tests um ±1 wei Inputs für sowohl exactInput/exactOutput.
- Rounding policy: Zentralisiere Rounding‑Helper, die immer gegen den User runden; eliminiere inkonsistente Casts und implizite Floors.
- Settlement sinks: Sammle unvermeidbare Rundungsresiduen in der protocol treasury oder burne sie; weise sie niemals msg.sender zu.
- Rate‑limits/Guardrails: Mindest‑Swap‑Größen für Rebalancing‑Triggers; deaktiviere Rebalances, wenn Deltas sub‑wei sind; sanity‑checke Deltas gegen erwartete Bereiche.
- Review Hook‑Callbacks ganzheitlich: beforeSwap/afterSwap und before/after liquidity changes sollten sich über Tick‑Ausrichtung und Delta‑Rundung einig sein.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) mit einem LDF, das pro Swap angewendet wurde, um zu rebalancen.
- Affected pools: USDC/USDT auf Ethereum und weETH/ETH auf Unichain, insgesamt etwa $8.4M.
- Step 1 (price push): Der Angreifer flash‑borrowed ~3M USDT und swapped, um den Tick auf ~5000 zu schieben, wodurch der aktive USDC‑Balance auf ~28 wei schrumpfte.
- Step 2 (rounding drain): 44 winzige Withdrawals nutzten Floor‑Rounding in `BunniHubLogic::withdraw()` aus, um den aktiven USDC‑Balance von 28 wei auf 4 wei (‑85.7%) zu reduzieren, während nur ein winziger Bruchteil der LP‑Shares burned wurde. Die totale Liquidity wurde um ~84.4% unterschätzt.
- Step 3 (liquidity rebound sandwich): Ein großer Swap verschob den Tick auf ~839,189 (1 USDC ≈ 2.77e36 USDT). Liquidity‑Schätzungen flippten und stiegen um ~16.8%, wodurch ein Sandwich möglich wurde, in dem der Angreifer beim aufgeblasenen Preis zurückswapte und mit Profit exitierte.
- Fix, im Post‑Mortem identifiziert: Aktualisiere das idle‑balance Update so, dass aufgerundet wird, damit wiederholte Mikro‑Withdrawals den aktiven Pool‑Balance nicht nach unten ratcheten.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting-Checkliste

- Verwendet der Pool eine von null verschiedene hooks-Adresse? Welche Callbacks sind aktiviert?
- Gibt es pro‑Swap Redistribuierungen/Rebalances mit benutzerdefinierter Mathematik? Irgendwelche tick/threshold-Logiken?
- Wo werden Divisionen/mulDiv, Q64.96-Konversionen oder SafeCast verwendet? Sind die Rundungssemantiken global konsistent?
- Kannst du ein Δin konstruieren, das gerade eine Grenze überschreitet und einen vorteilhaften Rundungszweig erzeugt? Teste beide Richtungen sowie exactInput und exactOutput.
- Verfolgt der Hook pro‑Caller Credits oder Deltas, die später abgehoben werden können? Stelle sicher, dass Restguthaben neutralisiert werden.

## Referenzen

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
