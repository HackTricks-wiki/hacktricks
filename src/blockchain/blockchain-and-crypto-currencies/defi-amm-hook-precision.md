# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert eine Klasse von DeFi/AMM-Exploitation-Techniken gegen Uniswap v4–artige DEXes, die die Core-Mathematik mit benutzerdefinierten hooks erweitern. Ein aktueller Vorfall in Bunni V2 nutzte einen Rundungs-/Präzisionsfehler in einer Liquidity Distribution Function (LDF), die bei jedem Swap ausgeführt wurde, und ermöglichte dem Angreifer, positive Credits anzusammeln und Liquidität abzuziehen.

Kernaussage: Wenn ein hook zusätzliche Buchführung implementiert, die von Fixed‑Point‑Math, Tick‑Rundung und Schwellenwertlogik abhängt, kann ein Angreifer exact‑input Swaps so gestalten, dass sie bestimmte Schwellen überschreiten und Rundungsdifferenzen sich zu seinen Gunsten akkumulieren. Das Muster zu wiederholen und anschließend das aufgeblähte Guthaben abzuheben realisiert Gewinn, oft finanziert durch einen flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks sind Verträge, die der PoolManager zu bestimmten Lifecycle‑Punkten aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools werden mit einem PoolKey initialisiert, der die hooks-Adresse enthält. Ist diese nicht null, führt der PoolManager Callback-Aufrufe bei jeder relevanten Operation aus.
- Die Core‑Mathematik benutzt Fixed‑Point‑Formate wie Q64.96 für sqrtPriceX96 und Tick‑Arithmetik mit 1.0001^tick. Jede zusätzliche benutzerdefinierte Mathematik darüber muss die Rundungssemantik exakt nachbilden, um ein Drift der Invarianten zu vermeiden.
- Swaps können exactInput oder exactOutput sein. In v3/v4 bewegt sich der Preis entlang der ticks; das Überschreiten einer Tick‑Grenze kann Range‑Liquidity aktivieren/deaktivieren. Hooks können zusätzliche Logik bei Schwellen-/Tick‑Überschreitungen implementieren.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Ein typisches anfälliges Muster in benutzerdefinierten hooks:

1. Der hook berechnet pro Swap Liquidity‑ oder Balance‑Deltas unter Verwendung von Integer‑Division, mulDiv oder Fixed‑Point‑Konversionen (z. B. token ↔ liquidity mittels sqrtPrice und Tick‑Ranges).
2. Schwellenwertlogik (z. B. Rebalancing, stufenweise Redistribution oder per‑Range Aktivierung) wird ausgelöst, wenn eine Swap‑Größe oder Preisbewegung eine interne Grenze überschreitet.
3. Rundung wird inkonsistent angewendet (z. B. Trunkierung Richtung Null, floor versus ceil) zwischen der Vorwärtsberechnung und dem Settlement‑Pfad. Kleine Abweichungen heben sich nicht auf, sondern schreiben dem Caller Guthaben gut.
4. Exact‑input Swaps, präzise dimensioniert, um diese Grenzen zu überqueren, ernten wiederholt die positive Rundungsremainder. Der Angreifer hebt anschließend das akkumulierte Credit ab.

Voraussetzungen des Angriffs
- Ein Pool, der einen benutzerdefinierten v4 hook verwendet, der bei jedem Swap zusätzliche Mathematik ausführt (z. B. eine LDF/rebalancer).
- Mindestens ein Ausführungspfad, bei dem Rundung den Swap‑Initiator über Schwellenübertritte begünstigt.
- Möglichkeit, viele Swaps atomar zu wiederholen (flash loans eignen sich gut, um temporäre Liquidität bereitzustellen und Gas zu amortisieren).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumeriere v4 Pools und prüfe PoolKey.hooks != address(0).
- Inspektiere hook‑Bytecode/ABI auf Callbacks: beforeSwap/afterSwap und alle benutzerdefinierten Rebalancing‑Methoden.
- Suche nach Mathematik, die: durch liquidity teilt, zwischen token‑Beträgen und liquidity konvertiert, oder BalanceDelta mit Rundung aggregiert.

2) Model the hook’s math and thresholds
- Rekonstruiere die Liquidity/Redistribution‑Formel des hooks: Inputs sind typischerweise sqrtPriceX96, tickLower/Upper, currentTick, fee tier und net liquidity.
- Mappe Schwellen-/Stufenfunktionen: ticks, Bucket‑Grenzen oder LDF‑Breakpoints. Bestimme, auf welcher Seite jeder Grenze der Delta gerundet wird.
- Identifiziere Stellen, an denen Konversionen zwischen uint256/int256 erfolgen, SafeCast verwendet wird oder mulDiv mit implizitem floor arbeitet.

3) Calibrate exact‑input swaps to cross boundaries
- Nutze Foundry/Hardhat‑Simulationen, um das minimale Δin zu berechnen, das nötig ist, um den Preis gerade über eine Grenze zu bewegen und den Hook‑Branch auszulösen.
- Verifiziere, dass nach dem afterSwap‑Settlement dem Caller mehr gutgeschrieben wird als die Kosten, sodass ein positives BalanceDelta oder Kredit in der Hook‑Buchführung verbleibt.
- Wiederhole Swaps, um Kredit anzusammeln; rufe dann den Entnahme/Settlement‑Pfad des Hooks auf.

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
- Approximiere Δin mithilfe der v3/v4-Formeln: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Stelle sicher, dass die Rundungsrichtung mit der Core-Mathematik übereinstimmt.
- Passe Δin um ±1 wei um die Grenze herum an, um den Branch zu finden, in dem der Hook zugunsten deiner Rundung rundet.

4) Verstärken mit flash loans
- Leihe einen großen Nominalbetrag (z. B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.
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
- If hooks are deployed on multiple chains, repeat the same calibration per chain.
- Bridge proceeds back to the target chain and optionally cycle via lending protocols to obfuscate flows.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Defensive guidance

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
- Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
- No path should create positive net credit for the swap initiator over repeated exactInput iterations.
- Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and bridging to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## Hunting checklist

- Does the pool use a non‑zero hooks address? Which callbacks are enabled?
- Are there per‑swap redistributions/rebalances using custom math? Any tick/threshold logic?
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- Can you construct Δin that barely crosses a boundary and yields a favorable rounding branch? Test both directions and both exactInput and exactOutput.
- Does the hook track per‑caller credits or deltas that can be withdrawn later? Ensure residue is neutralized.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
