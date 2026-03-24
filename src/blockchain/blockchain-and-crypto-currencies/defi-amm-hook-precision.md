# Exploração DeFi/AMM: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma classe de técnicas de exploração DeFi/AMM contra DEXes no estilo Uniswap v4 que estendem a matemática central com hooks personalizados. Um incidente recente no Bunni V2 aproveitou uma falha de arredondamento/precisão em uma Liquidity Distribution Function (LDF) executada a cada swap, permitindo que o atacante acumulasse créditos positivos e drenasse liquidez.

Ideia chave: se um hook implementa contabilidade adicional que depende de matemática de ponto fixo, arredondamento de tick e lógica de limiares, um atacante pode construir swaps exact‑input que cruzem limiares específicos de modo que discrepâncias de arredondamento se acumulem a seu favor. Repetir o padrão e depois retirar o saldo inflado realiza o lucro, frequentemente financiado com um flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks são contracts que o PoolManager chama em pontos específicos do ciclo de vida (por exemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools são inicializados com um PoolKey incluindo hooks address. Se não‑zero, o PoolManager executa callbacks em cada operação relevante.
- Hooks podem retornar **custom deltas** que modificam as mudanças finais de saldo de um swap ou ação de liquidez (custom accounting). Esses deltas são liquidados como saldos líquidos ao fim da chamada, então qualquer erro de arredondamento dentro da matemática do hook se acumula antes da liquidação.
- A matemática core usa formatos de ponto fixo como Q64.96 para sqrtPriceX96 e aritmética de tick com 1.0001^tick. Qualquer matemática custom sobreposta deve casar cuidadosamente a semântica de arredondamento para evitar drift do invariante.
- Swaps podem ser exactInput ou exactOutput. Em v3/v4, o preço se move ao longo de ticks; cruzar uma boundary de tick pode ativar/desativar range liquidity. Hooks podem implementar lógica extra em crossings de limiar/tick.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Um padrão típico vulnerável em hooks customizados:

1. O hook calcula deltas por‑swap de liquidez ou saldo usando integer division, mulDiv, ou conversões de ponto fixo (por exemplo, token ↔ liquidity usando sqrtPrice e tick ranges).
2. Lógica de limiar (por exemplo, rebalancing, redistribuição em passos, ou ativação por faixa) é disparada quando um tamanho de swap ou movimento de preço cruza uma boundary interna.
3. O arredondamento é aplicado de forma inconsistente (por exemplo, truncamento toward zero, floor versus ceil) entre o cálculo forward e o caminho de settlement. Pequenas discrepâncias não se cancelam e em vez disso credenciam o caller.
4. Swaps exact‑input, precisamente dimensionados para pairar esses limites, colhem repetidamente o resto positivo do arredondamento. O atacante depois retira o crédito acumulado.

Precondições do ataque
- Um pool usando um hook v4 custom que realiza matemática adicional a cada swap (por exemplo, um LDF/rebalancer).
- Pelo menos um caminho de execução onde o arredondamento beneficie o swap initiator ao cruzar limiares.
- Capacidade de repetir muitos swaps atomicamente (flash loans são ideais para fornecer float temporário e amortizar gas).

## Practical attack methodology

1) Identificar pools candidatas com hooks
- Enumerar v4 pools e checar PoolKey.hooks != address(0).
- Inspecionar hook bytecode/ABI para callbacks: beforeSwap/afterSwap e quaisquer métodos custom de rebalancing.
- Procurar matemática que: divide por liquidity, converte entre token amounts e liquidity, ou agrega BalanceDelta com arredondamento.

2) Modelar a matemática do hook e os limiares
- Recriar a fórmula de liquidity/redistribution do hook: inputs tipicamente incluem sqrtPriceX96, tickLower/Upper, currentTick, fee tier, e net liquidity.
- Mapear funções de limiar/step: ticks, bucket boundaries, ou LDF breakpoints. Determinar de que lado de cada boundary o delta é arredondado.
- Identificar onde conversões fazem cast entre uint256/int256, usam SafeCast, ou dependem de mulDiv com floor implícito.

3) Calibrar swaps exact‑input para cruzar boundaries
- Usar Foundry/Hardhat simulations para computar o Δin mínimo necessário para mover o preço justo além de um boundary e disparar o branch do hook.
- Verificar que a liquidação afterSwap credencia o caller mais do que o custo, deixando um BalanceDelta ou crédito positivo na contabilidade do hook.
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
- Compute ΔsqrtP for a tick step: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Approximate Δin using v3/v4 formulas: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Ensure rounding direction matches core math.
- Adjust Δin by ±1 wei around the boundary to find the branch where the hook rounds in your favor.

4) Amplifique com flash loans
- Borrow a large notional (por exemplo, 3M USDT ou 2000 WETH) para executar muitas iterações de forma atômica.
- Execute the calibrated swap loop, then withdraw and repay within the flash loan callback.

Esqueleto de flash loan do Aave V3
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
- Se hooks forem implantados em múltiplas chains, repita a mesma calibração por chain.
- Os fundos atravessam o bridge de volta para a chain alvo e opcionalmente circulam via lending protocols para ofuscar os fluxos.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting lets hooks return deltas that directly adjust what the caller owes/receives. If the hook tracks credits internally, rounding residue can accumulate across many small operations **before** the final settlement happens.
- Isso torna o abuso de limites/thresholds mais forte: o atacante pode alternar `swap → withdraw → swap` na mesma tx, forçando o hook a recalcular deltas em um estado ligeiramente diferente enquanto todos os saldos ainda estão pendentes.
- Ao revisar hooks, sempre trace como BalanceDelta/HookDelta é produzido e liquidado. Um único arredondamento tendencioso em um ramo pode tornar‑se um crédito composto quando deltas são recomputados repetidamente.

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
## Checklist de Hunting

- O pool usa um endereço hooks diferente de zero? Quais callbacks estão habilitados?
- Existem redistribuições/rebalances por swap usando matemática customizada? Alguma lógica de tick/threshold?
- Onde são usadas divisions/mulDiv, conversões Q64.96, ou SafeCast? A semântica de arredondamento é consistente globalmente?
- Você consegue construir Δin que cruza por pouco um limite e produz um branch de arredondamento favorável? Teste ambas as direções e tanto exactInput quanto exactOutput.
- O hook rastreia créditos por chamador ou deltas que podem ser sacados depois? Garanta que resíduos sejam neutralizados.

## Referências

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
