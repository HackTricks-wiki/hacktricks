# DeFi/AMM-Exploitation: Uniswap-v4-Hook-Precision/Rounding-Abuse

{{#include ../../banners/hacktricks-training.md}}

Diese Seite dokumentiert eine Klasse von DeFi/AMM-Exploitation-Techniken gegen DEXes im Stil von Uniswap v4, die die Core-Mathematik durch benutzerdefinierte Hooks erweitern. Bei einem kürzlichen Vorfall in Bunni V2 wurde ein Precision/Rounding-Fehler in einer Liquidity Distribution Function (LDF) ausgenutzt, die bei jedem Swap ausgeführt wurde. Dadurch konnte der Angreifer positive Gutschriften ansammeln und Liquidität abziehen.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Die zentrale Idee: Wenn ein Hook zusätzliche Buchungen implementiert, die von Fixed-Point-Mathematik, Tick-Rundung und Threshold-Logik abhängen, kann ein Angreifer Exact-Input-Swaps so gestalten, dass bestimmte Thresholds überschritten werden und sich Rundungsabweichungen zu seinen Gunsten akkumulieren. Durch Wiederholung dieses Musters und anschließende Auszahlung des erhöhten Guthabens wird der Gewinn realisiert, häufig finanziert durch einen Flash Loan.

## Hintergrund: Uniswap-v4-Hooks und Swap-Ablauf

- Hooks sind Contracts, die der PoolManager an bestimmten Lifecycle-Punkten aufruft (z. B. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Pools werden mit einem PoolKey einschließlich der Hook-Adresse initialisiert. Wenn diese ungleich null ist, führt der PoolManager bei jeder relevanten Operation Callbacks aus.<sup>[[6]](#references)</sup>
- Hooks können **custom deltas** zurückgeben, die die finalen Balance-Änderungen eines Swaps oder einer Liquiditätsaktion modifizieren (custom accounting). Diese Deltas werden am Ende des Calls als Nettosalden beglichen, sodass sich Rundungsfehler innerhalb der Hook-Mathematik vor der Begleichung akkumulieren.<sup>[[5]](#references)</sup>
- Die Core-Mathematik verwendet Fixed-Point-Formate wie Q64.96 für sqrtPriceX96 sowie Tick-Arithmetik mit 1.0001^tick. Jede darauf aufbauende benutzerdefinierte Mathematik muss die Rundungssemantik sorgfältig übernehmen, um eine Abweichung von der Invariante zu vermeiden.<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps können ExactInput oder ExactOutput sein. In v3/v4 bewegt sich der Preis entlang von Ticks; das Überschreiten einer Tick-Grenze kann Range-Liquidität aktivieren/deaktivieren. Hooks können zusätzliche Logik beim Überschreiten von Thresholds/Ticks implementieren.<sup>[[5]](#references)</sup>

## Schwachstellen-Archetyp: Precision/Rounding-Drift beim Überschreiten von Thresholds

Ein typisches verwundbares Muster in benutzerdefinierten Hooks:

1. Der Hook berechnet Liquidity- oder Balance-Deltas pro Swap mithilfe von Integer-Division, mulDiv oder Fixed-Point-Konvertierungen (z. B. Token ↔ Liquidity unter Verwendung von sqrtPrice und Tick-Ranges).
2. Die Threshold-Logik (z. B. Rebalancing, schrittweise Umverteilung oder Aktivierung pro Range) wird ausgelöst, wenn eine Swap-Größe oder Preisbewegung eine interne Grenze überschreitet.
3. Die Rundung wird zwischen der Vorwärtsberechnung und dem Settlement-Pfad inkonsistent angewendet (z. B. Abschneiden gegen null, Floor statt Ceil). Kleine Abweichungen heben sich nicht auf, sondern schreiben dem Aufrufer stattdessen einen Betrag gut.
4. Exakt bemessene Exact-Input-Swaps, die diese Grenzen überschreiten, schöpfen wiederholt den positiven Rundungsrest ab. Der Angreifer zahlt das angesammelte Guthaben später aus.

Voraussetzungen für den Angriff
- Ein Pool mit einem benutzerdefinierten v4-Hook, der bei jedem Swap zusätzliche Mathematik ausführt (z. B. ein LDF/Rebalancer).
- Mindestens ein Ausführungspfad, auf dem die Rundung den Swap-Initiator beim Überschreiten von Thresholds begünstigt.
- Die Möglichkeit, viele Swaps atomar zu wiederholen (Flash Loans sind ideal, um vorübergehendes Float bereitzustellen und Gas zu amortisieren).

## Praktische Angriffsmethodik

1) Geeignete Pools mit Hooks identifizieren
- v4-Pools enumerieren und prüfen, ob PoolKey.hooks != address(0) ist.
- Hook-Bytecode/ABI auf Callbacks prüfen: beforeSwap/afterSwap sowie benutzerdefinierte Rebalancing-Methoden.
- Nach Mathematik suchen, die: durch Liquidity teilt, zwischen Token-Beträgen und Liquidity konvertiert oder BalanceDelta mit Rundung aggregiert.

2) Die Mathematik und Thresholds des Hooks modellieren
- Die Liquidity-/Redistribution-Formel des Hooks nachbilden: Zu den Eingaben gehören typischerweise sqrtPriceX96, tickLower/Upper, currentTick, die Fee-Tier und die Net-Liquidity.
- Threshold-/Step-Funktionen abbilden: Ticks, Bucket-Grenzen oder LDF-Breakpoints. Bestimmen, auf welcher Seite jeder Grenze das Delta gerundet wird.
- Identifizieren, wo zwischen uint256/int256 gecastet wird, SafeCast verwendet wird oder mulDiv mit implizitem Floor eingesetzt wird.

3) Exact-Input-Swaps zum Überschreiten von Grenzen kalibrieren
- Foundry/Hardhat-Simulationen verwenden, um das minimale Δin zu berechnen, das erforderlich ist, um den Preis knapp über eine Grenze zu bewegen und den Branch des Hooks auszulösen.
- Überprüfen, dass das afterSwap-Settlement dem Aufrufer mehr gutschreibt als die Kosten betragen, sodass ein positives BalanceDelta oder Guthaben in der Buchhaltung des Hooks verbleibt.
- Swaps wiederholen, um Guthaben anzusammeln, und anschließend den Withdrawal-/Settlement-Pfad des Hooks aufrufen.

Beispiel für ein Foundry-ähnliches Test-Harness (Pseudocode)
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
Kalibrieren von exactInput
- Berechne ΔsqrtP für einen Tick-Schritt: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Nähere Δin mit den v3/v4-Formeln an: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Stelle sicher, dass die Rundungsrichtung mit der Core-Mathematik übereinstimmt.
- Passe Δin an der Grenze um ±1 Wei an, um den Branch zu finden, bei dem der Hook zu deinen Gunsten rundet.

4) Mit flash loans verstärken
- Leihe einen großen Nominalbetrag (z. B. 3M USDT oder 2000 WETH), um viele Iterationen atomar auszuführen.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Führe die kalibrierte Swap-Schleife aus, und zahle anschließend innerhalb des flash loan callbacks aus und zurück.

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
- Proceeds zurück zur Ziel-Chain bridgen und optional über Lending-Protokolle zyklisieren, um die Flows zu verschleiern.<sup>[[2]](#references)</sup>

## Häufige Grundursachen in der Hook-Mathematik

- Gemischte Rundungssemantik: `mulDiv` rundet ab, während spätere Pfade effektiv aufrunden; oder Konvertierungen zwischen Token/Liquidität verwenden unterschiedliche Rundungen.
- Tick-Alignment-Fehler: In einem Pfad werden nicht gerundete Ticks verwendet, in einem anderen eine Tick-Spacing-Rundung.
- Vorzeichen-/Overflow-Probleme bei `BalanceDelta`, wenn während des Settlements zwischen `int256` und `uint256` konvertiert wird.
- Präzisionsverlust bei Q64.96-Konvertierungen (`sqrtPriceX96`), der beim Reverse-Mapping nicht gespiegelt wird.
- Akkumulationspfade: Pro-Swap-Reste werden als Credits erfasst, die vom Caller abgehoben werden können, anstatt verbrannt zu werden oder in einer Zero-Sum-Bilanz zu verbleiben.

## Custom Accounting und Delta-Verstärkung

- Uniswap v4 Custom Accounting ermöglicht es Hooks, Deltas zurückzugeben, die direkt anpassen, was der Caller schuldet oder erhält. Wenn der Hook Credits intern erfasst, können sich Rundungsreste über viele kleine Operationen **bevor** das finale Settlement erfolgt ansammeln.<sup>[[5]](#references)</sup>
- Dadurch wird Boundary-/Threshold-Missbrauch verstärkt: Der Angreifer kann im selben Tx `swap → withdraw → swap` abwechseln und den Hook zwingen, Deltas auf leicht unterschiedlichen Zuständen neu zu berechnen, während alle Bilanzen noch ausstehen.
- Bei der Prüfung von Hooks immer nachvollziehen, wie `BalanceDelta`/`HookDelta` erzeugt und settled werden. Eine einzelne verzerrte Rundung in einem Branch kann zu einem sich aufaddierenden Credit werden, wenn Deltas wiederholt neu berechnet werden.

## Defensive Hinweise

- Differential Testing: Die Mathematik des Hooks mit einer Referenzimplementierung unter Verwendung hochpräziser rationaler Arithmetik spiegeln und Gleichheit oder einen begrenzten Fehler erzwingen, der immer adversarial ist (niemals zugunsten des Callers).
- Invariant-/Property-Tests:
- Die Summe der Deltas (Token, Liquidität) über Swap-Pfade und Hook-Anpassungen muss den Wert abzüglich Fees erhalten.
- Kein Pfad darf dem Swap-Initiator bei wiederholten `exactInput`-Iterationen ein positives Netto-Credit erzeugen.
- Threshold-/Tick-Boundary-Tests rund um ±1-Wei-Inputs für sowohl `exactInput` als auch `exactOutput`.
- Rundungspolitik: Rundungs-Helper zentralisieren, die immer zugunsten des Users abrunden; inkonsistente Casts und implizite Abrundungen eliminieren.
- Settlement-Sinks: Unvermeidbare Rundungsreste im Protocol-Treasury akkumulieren oder verbrennen; niemals `msg.sender` zuordnen.
- Rate-Limits/Guardrails: Mindest-Swap-Größen für Rebalancing-Trigger; Rebalances deaktivieren, wenn Deltas unter einem Wei liegen; Deltas gegen erwartete Wertebereiche plausibilisieren.
- Hook-Callbacks ganzheitlich prüfen: `beforeSwap`/`afterSwap` sowie Änderungen der Liquidität vor und nach der Änderung sollten beim Tick-Alignment und bei der Delta-Rundung übereinstimmen.

## Fallstudie: Bunni V2 (2025-09-02)

- Protocol: Bunni V2 (Uniswap-v4-Hook) mit einem pro Swap angewendeten LDF zum Rebalancing.<sup>[[7]](#references)</sup>
- Betroffene Pools: USDC/USDT auf Ethereum und weETH/ETH auf Unichain, insgesamt etwa 8,4 Mio. USD.<sup>[[1]](#references)[[2]](#references)</sup>
- Schritt 1 (Price Push): Der Angreifer nahm per Flash-Borrow etwa 3 Mio. USDT auf und führte einen Swap aus, um den Tick auf etwa 5000 zu verschieben, wodurch das **aktive** USDC-Guthaben auf etwa 28 Wei sank.<sup>[[7]](#references)</sup>
- Schritt 2 (Rundungs-Drain): 44 kleine Withdrawals nutzten die Abrundung in `BunniHubLogic::withdraw()` aus, um das aktive USDC-Guthaben von 28 Wei auf 4 Wei zu reduzieren (-85,7 %), während nur ein winziger Anteil der LP-Shares verbrannt wurde. Die Gesamtliquidität wurde um etwa 84,4 % unterschätzt.<sup>[[2]](#references)[[7]](#references)</sup>
- Schritt 3 (Liquidity-Rebound-Sandwich): Ein großer Swap verschob den Tick auf etwa 839.189 (1 USDC ≈ 2,77e36 USDT). Die Liquiditätsschätzungen kippten und stiegen um etwa 16,8 %, wodurch ein Sandwich ermöglicht wurde, bei dem der Angreifer zum aufgeblähten Preis zurückswappte und mit Profit ausstieg.<sup>[[7]](#references)</sup>
- Im Post-Mortem identifizierter Fix: Das Update des Idle-Balances so ändern, dass aufgerundet wird, damit wiederholte Micro-Withdrawals das aktive Guthaben des Pools nicht schrittweise nach unten korrigieren können.<sup>[[7]](#references)</sup>

Vereinfachte verwundbare Zeile (und Fix aus dem Post-Mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting-Checkliste

- Verwendet der Pool eine Hooks-Adresse ungleich null? Welche Callbacks sind aktiviert?
- Gibt es Redistribuierungen/Rebalances pro Swap mit benutzerdefinierter Mathematik? Gibt es eine Tick-/Threshold-Logik?
- Wo werden divisions/mulDiv, Q64.96-Konvertierungen oder SafeCast verwendet? Sind die Rundungssemantiken global konsistent?
- Kannst du ein Δin konstruieren, das eine Grenze gerade überschreitet und einen vorteilhaften Rundungszweig auslöst? Teste beide Richtungen sowie exactInput und exactOutput.
- Verfolgt der Hook Credits oder Deltas pro Caller, die später abgehoben werden können? Stelle sicher, dass der Restbetrag neutralisiert wird.

## Referenzen

- [1] [Bunni V2 Exploit: $8.3M durch einen Liquidity-Fehler abgezogen (Zusammenfassung)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Vollständige Hack-Analyse](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap-v4-Hintergrund (QuillAudits-Forschung)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Liquidity-Mechanik im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Swap-Mechanik im Uniswap-v4-Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap-v4-Hooks und Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap-v4-Core-Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
