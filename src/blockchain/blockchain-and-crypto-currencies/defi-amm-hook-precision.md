# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Esta página documenta uma classe de técnicas de exploração DeFi/AMM contra DEXes no estilo Uniswap v4 que estendem a matemática core com custom hooks. Um incidente recente no Bunni V2 explorou uma falha de arredondamento/precisão em uma Liquidity Distribution Function (LDF) executada a cada swap, permitindo que o attacker acumulasse créditos positivos e drenasse liquidez.

Key idea: if a hook implements additional accounting that depends on fixed‑point math, tick rounding, and threshold logic, an attacker can craft exact‑input swaps that cross specific thresholds so that rounding discrepancies accumulate in their favor. Repeating the pattern and then withdrawing the inflated balance realizes profit, often financed with a flash loan.

## Contexto: Uniswap v4 hooks e fluxo de swap

- Hooks são contratos que o PoolManager chama em pontos específicos do ciclo de vida (e.g., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools são inicializados com um PoolKey incluindo hooks address. Se non‑zero, PoolManager performs callbacks on every relevant operation.
- Hooks can return **custom deltas** that modify the final balance changes of a swap or liquidity action (custom accounting). Those deltas are settled as net balances at the end of the call, so any rounding error inside hook math accumulates before settlement.
- Core math uses fixed‑point formats such as Q64.96 for sqrtPriceX96 and tick arithmetic with 1.0001^tick. Any custom math layered on top must carefully match rounding semantics to avoid invariant drift.
- Swaps can be exactInput or exactOutput. In v3/v4, price moves along ticks; crossing a tick boundary may activate/deactivate range liquidity. Hooks may implement extra logic on threshold/tick crossings.

## Arquétipo de vulnerabilidade: deriva de precisão/arredondamento ao cruzar limiares

Um padrão típico vulnerável em custom hooks:

1. O hook calcula deltas de liquidez ou de saldo por swap usando integer division, mulDiv, ou fixed‑point conversions (e.g., token ↔ liquidity usando sqrtPrice e tick ranges).
2. Threshold logic (e.g., rebalancing, stepwise redistribution, or per‑range activation) é disparada quando o tamanho do swap ou o movimento de preço cruzam um boundary interno.
3. O arredondamento é aplicado de forma inconsistente (e.g., truncation toward zero, floor versus ceil) entre o cálculo forward e o caminho de settlement. Pequenas discrepâncias não se cancelam e, ao invés disso, creditam o caller.
4. Exact‑input swaps, precisamente dimensionados para atravessar esses limites, colhem repetidamente o resto positivo do arredondamento. O attacker depois retira o crédito acumulado.

Precondições do ataque
- Um pool usando um custom v4 hook que realiza matemática adicional a cada swap (e.g., um LDF/rebalancer).
- Pelo menos um caminho de execução onde o arredondamento beneficia o swap initiator ao cruzar limiares.
- Capacidade de repetir muitos swaps atomicamente (flash loans são ideais para fornecer float temporário e amortizar gas).

## Metodologia prática de ataque

1) Identificar pools candidatas com hooks
- Enumerar v4 pools e checar PoolKey.hooks != address(0).
- Inspecionar hook bytecode/ABI por callbacks: beforeSwap/afterSwap e quaisquer métodos custom de rebalancing.
- Procurar por matemática que: divide por liquidity, converte entre token amounts e liquidity, ou agrega BalanceDelta com arredondamento.

2) Modelar a matemática e os limiares do hook
- Recriar a fórmula de liquidez/redistribuição do hook: inputs tipicamente incluem sqrtPriceX96, tickLower/Upper, currentTick, fee tier, e net liquidity.
- Mapear funções de threshold/step: ticks, bucket boundaries, ou LDF breakpoints. Determinar de que lado de cada boundary o delta é arredondado.
- Identificar onde conversões fazem cast entre uint256/int256, usam SafeCast, ou dependem de mulDiv com implicit floor.

3) Calibrar exact‑input swaps para cruzar limites
- Usar simulações Foundry/Hardhat para computar o Δin mínimo necessário para mover o preço pouco além de um boundary e disparar o branch do hook.
- Verificar que afterSwap settlement credits the caller mais do que o custo, deixando um BalanceDelta positivo ou crédito na contabilidade do hook.
- Repetir swaps para acumular crédito; então chamar o caminho de withdrawal/settlement do hook.

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
Calibrando o exactInput
- Calcule ΔsqrtP para um passo de tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Aproxime Δin usando as fórmulas v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Garanta que a direção de arredondamento corresponda à matemática do core.
- Ajuste Δin em ±1 wei ao redor do limite para encontrar o ramo onde o hook arredonda a seu favor.

4) Amplifique com flash loans
- Tome emprestado um notional grande (por exemplo, 3M USDT ou 2000 WETH) para executar muitas iterações de forma atômica.
- Execute o loop de swap calibrado, então withdraw e repay dentro do callback do flash loan.

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
5) Saída e replicação cross‑chain
- If hooks are deployed on multiple chains, repeat the same calibration per chain.
- Bridge proceeds back to the target chain and optionally cycle via lending protocols to obfuscate flows.

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
- Step 1 (price push): the attacker flash‑borrowed ~3M USDT and swapped to push the tick to ~5000, shrinking the **active** USDC balance down to ~28 wei.
- Step 2 (rounding drain): 44 tiny withdrawals exploited floor rounding in `BunniHubLogic::withdraw()` to reduce the active USDC balance from 28 wei to 4 wei (‑85.7%) while only a tiny fraction of LP shares was burned. Total liquidity was underestimated by ~84.4%.
- Step 3 (liquidity rebound sandwich): a large swap moved the tick to ~839,189 (1 USDC ≈ 2.77e36 USDT). Liquidity estimates flipped and increased by ~16.8%, enabling a sandwich where the attacker swapped back at the inflated price and exited with profit.
- Fix identified in the post‑mortem: change the idle‑balance update to round **up** so repeated micro‑withdrawals can’t ratchet the pool’s active balance downward.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- O pool usa um hooks address não‑zero? Quais callbacks estão habilitados?
- Existem redistribuições/rebalances por‑swap usando custom math? Alguma lógica de tick/threshold?
- Onde são usadas divisions/mulDiv, conversões Q64.96, ou SafeCast? A semântica de arredondamento é consistente globalmente?
- Você consegue construir Δin que mal atravessa um limite e produz um branch de arredondamento favorável? Teste ambas as direções e tanto exactInput quanto exactOutput.
- O hook rastreia per‑caller credits ou deltas que podem ser sacados depois? Garanta que o resíduo seja neutralizado.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
