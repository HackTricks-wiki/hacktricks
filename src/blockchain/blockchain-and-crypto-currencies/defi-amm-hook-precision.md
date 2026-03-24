# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Questa pagina documenta una classe di tecniche di exploit DeFi/AMM contro DEX in stile Uniswap v4 che estendono la matematica core con hook personalizzati. Un incidente recente in Bunni V2 ha sfruttato un difetto di arrotondamento/precisione in una Liquidity Distribution Function (LDF) eseguita ad ogni swap, permettendo all'attaccante di accumulare crediti positivi e drenare la liquidità.

Idea chiave: se un hook implementa una contabilità aggiuntiva che dipende da matematica a punto fisso, arrotondamento dei tick e logica a soglia, un attaccante può costruire swap exact‑input che attraversano soglie specifiche in modo che le discrepanze di arrotondamento si accumulino a suo favore. Ripetendo il pattern e poi ritirando il saldo gonfiato si realizza il profitto, spesso finanziato con un flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks sono contratti che il PoolManager chiama in punti specifici del ciclo di vita (es. beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- I pool sono inizializzati con un PoolKey che include l'indirizzo hooks. Se non‑zero, il PoolManager esegue callback ad ogni operazione pertinente.
- Gli hook possono restituire **custom deltas** che modificano i cambiamenti di bilancio finali di uno swap o di un'azione di liquidity (custom accounting). Quei delta vengono compensati come saldi netti alla fine della chiamata, quindi qualsiasi errore di arrotondamento nella matematica dell'hook si accumula prima della liquidazione.
- La matematica core usa formati a punto fisso come Q64.96 per sqrtPriceX96 e aritmetica dei tick con 1.0001^tick. Qualsiasi matematica personalizzata stratificata sopra deve attentamente corrispondere alle semantiche di arrotondamento per evitare drift invarianti.
- Gli swap possono essere exactInput o exactOutput. In v3/v4, il prezzo si muove lungo i tick; attraversare un confine di tick può attivare/disattivare liquidity di range. Gli hook possono implementare logiche aggiuntive su crossing di soglie/tick.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Un pattern tipico vulnerabile in hook personalizzati:

1. L'hook calcola delta di liquidity o del bilancio per swap usando divisione intera, mulDiv, o conversioni a punto fisso (es. token ↔ liquidity usando sqrtPrice e range di tick).
2. La logica a soglia (es. rebalancing, redistribuzione a step, o attivazione per range) viene attivata quando la dimensione dello swap o lo spostamento di prezzo supera un bordo interno.
3. L'arrotondamento viene applicato in modo incoerente (es. troncamento verso zero, floor vs ceil) tra il calcolo forward e il percorso di settlement. Piccole discrepanze non si annullano e invece accreditano il caller.
4. Swap exact‑input, dimensionati con precisione per barcamenarsi su quei confini, raccolgono ripetutamente il resto positivo dell'arrotondamento. L'attaccante poi ritira il credito accumulato.

Prerequisiti dell'attacco
- Un pool che usa un hook v4 personalizzato che esegue matematica aggiuntiva ad ogni swap (es. un LDF/rebalancer).
- Almeno un percorso di esecuzione dove l'arrotondamento avvantaggia lo initiator dello swap attraverso crossing di soglie.
- Capacità di ripetere molti swap in modo atomico (i flash loan sono ideali per fornire float temporaneo e ammortizzare il gas).

## Metodologia pratica dell'attacco

1) Identificare pool candidati con hooks
- Enumerare i pool v4 e controllare PoolKey.hooks != address(0).
- Ispezionare hook bytecode/ABI per callback: beforeSwap/afterSwap e qualsiasi metodo custom di rebalancing.
- Cercare matematica che: divide per liquidity, converte tra token amounts e liquidity, o aggrega BalanceDelta con arrotondamento.

2) Modellare la matematica e le soglie dell'hook
- Ricreare la formula di liquidity/redistribuzione dell'hook: gli input tipici includono sqrtPriceX96, tickLower/Upper, currentTick, fee tier, e net liquidity.
- Mappare funzioni a soglia/step: tick, confini di bucket, o breakpoints LDF. Determinare su quale lato di ogni confine il delta viene arrotondato.
- Identificare dove le conversioni castano tra uint256/int256, usano SafeCast, o si basano su mulDiv con floor implicito.

3) Calibrare swap exact‑input per attraversare i confini
- Usare Foundry/Hardhat simulations per calcolare il Δin minimo necessario a muovere il prezzo appena oltre un confine e triggerare il branch dell'hook.
- Verificare che dopo la settlement dello swap il caller venga accreditato più del costo, lasciando un BalanceDelta positivo o un credito nella contabilità dell'hook.
- Ripetere gli swap per accumulare credito; poi chiamare il percorso di withdrawal/settlement dell'hook.

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
Calibrazione dell'exactInput
- Calcolare ΔsqrtP per un passo di tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approssimare Δin usando le formule v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Assicurarsi che la direzione dell'arrotondamento corrisponda alla matematica del core.
- Regolare Δin di ±1 wei attorno al limite per trovare il ramo in cui l'hook arrotonda a tuo favore.

4) Amplificare con flash loans
- Prendere in prestito un importo nozionale elevato (es., 3M USDT o 2000 WETH) per eseguire molte iterazioni in modo atomico.
- Eseguire il loop di swap calibrato, quindi ritirare e rimborsare all'interno della callback del flash loan.

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
5) Exit e replica cross‑chain
- Se gli hook sono deployati su più chain, ripetere la stessa calibrazione per ogni chain.
- I proventi vengono bridgeati indietro verso la chain di destinazione e opzionalmente girati tramite lending protocol per offuscare i flussi.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting lets hooks return deltas that directly adjust what the caller owes/receives. If the hook tracks credits internally, rounding residue can accumulate across many small operations **before** the final settlement happens.
- This makes boundary/threshold abuse stronger: the attacker can alternate `swap → withdraw → swap` in the same tx, forcing the hook to recompute deltas on slightly different state while all balances are still pending.
- When reviewing hooks, always trace how BalanceDelta/HookDelta is produced and settled. A single biased rounding in one branch can become a compounding credit when deltas are repeatedly re‑computed.

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
- Affected pools: USDC/USDT on Ethereum and weETH/ETH on Unichain, totaling about $8.4M.
- Step 1 (price push): l'attaccante ha flash‑borrowed ~3M USDT e ha swapped per spingere il tick a ~5000, riducendo il **active** USDC balance a ~28 wei.
- Step 2 (rounding drain): 44 tiny withdrawals hanno sfruttato il floor rounding in `BunniHubLogic::withdraw()` per ridurre il active USDC balance da 28 wei a 4 wei (‑85.7%) mentre solo una frazione minima di LP shares è stata burned. La liquidità totale è stata sottostimata di ~84.4%.
- Step 3 (liquidity rebound sandwich): un grande swap ha spostato il tick a ~839,189 (1 USDC ≈ 2.77e36 USDT). Le stime di liquidity sono invertite e aumentate di ~16.8%, permettendo un sandwich dove l'attaccante ha swapped indietro al prezzo gonfiato ed è uscito con profitto.
- Fix identified in the post‑mortem: change the idle‑balance update to round **up** so repeated micro‑withdrawals can’t ratchet the pool’s active balance downward.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklist di hunting

- Il pool usa un non‑zero hooks address? Quali callbacks sono abilitati?
- Ci sono redistribuzioni/ribilanciamenti per‑swap che usano matematica custom? Qualche logica di tick/threshold?
- Dove vengono usate divisions/mulDiv, conversioni Q64.96, o SafeCast? Le semantiche di arrotondamento sono coerenti a livello globale?
- È possibile costruire una Δin che appena oltrepassa un confine e produce un ramo di arrotondamento favorevole? Testa entrambe le direzioni e sia exactInput che exactOutput.
- L'hook traccia credits o deltas per‑caller che possono essere ritirati in seguito? Assicurati che i residui siano neutralizzati.

## Riferimenti

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
