# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Esta página documenta una clase de técnicas de explotación DeFi/AMM contra DEXes estilo Uniswap v4 que extienden la matemática central con hooks personalizados. Un incidente reciente en Bunni V2 aprovechó un fallo de redondeo/precisión en una Liquidity Distribution Function (LDF) ejecutada en cada swap, permitiendo al atacante acumular créditos positivos y drenar liquidez.

Idea clave: si un hook implementa contabilidad adicional que depende de math de punto fijo, redondeo de ticks y lógica de umbrales, un atacante puede confeccionar swaps exact‑input que crucen umbrales específicos de modo que las discrepancias de redondeo se acumulen a su favor. Repetir el patrón y luego retirar el saldo inflado realiza la ganancia, a menudo financiada con un flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks son contratos que el PoolManager llama en puntos específicos del ciclo de vida (por ejemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Los pools se inicializan con un PoolKey que incluye la dirección de hooks. Si es distinta de cero, PoolManager realiza callbacks en cada operación relevante.
- Los hooks pueden devolver **custom deltas** que modifican los cambios finales de balance de un swap o acción de liquidez (custom accounting). Esos deltas se saldan como balances netos al final de la llamada, por lo que cualquier error de redondeo dentro de la matemática del hook se acumula antes del settlement.
- La matemática core usa formatos de punto fijo como Q64.96 para sqrtPriceX96 y aritmética de tick con 1.0001^tick. Cualquier matemática personalizada sobrepuesta debe casar cuidadosamente las semánticas de redondeo para evitar drift del invariante.
- Los swaps pueden ser exactInput o exactOutput. En v3/v4, el precio se mueve a lo largo de ticks; cruzar un boundary de tick puede activar/desactivar liquidity de rango. Los hooks pueden implementar lógica extra en cruces de umbrales/ticks.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Un patrón típico vulnerable en hooks personalizados:

1. El hook calcula deltas por swap de liquidez o balance usando integer division, mulDiv, o conversiones de punto fijo (por ejemplo, token ↔ liquidity usando sqrtPrice y rangos de tick).
2. La lógica de umbral (por ejemplo, rebalancing, redistribución escalonada, o activación por rango) se dispara cuando el tamaño del swap o el movimiento del precio cruza una frontera interna.
3. El redondeo se aplica de forma inconsistente (por ejemplo, truncamiento hacia cero, floor versus ceil) entre el cálculo hacia adelante y la ruta de settlement. Pequeñas discrepancias no se cancelan y en su lugar acreditan al caller.
4. Swaps exact‑input, dimensionados precisamente para lindar esos boundaries, cosechan repetidamente el resto positivo del redondeo. El atacante luego retira el crédito acumulado.

Precondiciones del ataque
- Un pool que use un hook v4 personalizado que realice matemática adicional en cada swap (por ejemplo, un LDF/rebalancer).
- Al menos un camino de ejecución donde el redondeo beneficie al swap initiator durante cruces de umbrales.
- Capacidad de repetir muchos swaps de forma atómica (flash loans son ideales para suministrar float temporal y amortizar gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerar pools v4 y comprobar PoolKey.hooks != address(0).
- Inspeccionar hook bytecode/ABI para callbacks: beforeSwap/afterSwap y cualquier método personalizado de rebalancing.
- Buscar matemática que: divida por liquidity, convierta entre cantidades de token y liquidity, o agregue BalanceDelta con redondeo.

2) Model the hook’s math and thresholds
- Recrear la fórmula de liquidity/redistribution del hook: las entradas típicas incluyen sqrtPriceX96, tickLower/Upper, currentTick, fee tier, y net liquidity.
- Mapear funciones de umbral/paso: ticks, bucket boundaries, o breakpoints de LDF. Determinar en qué lado de cada boundary se redondea el delta.
- Identificar dónde las conversiones castean entre uint256/int256, usan SafeCast, o dependen de mulDiv con floor implícito.

3) Calibrate exact‑input swaps to cross boundaries
- Usar Foundry/Hardhat simulations para calcular el Δin mínimo necesario para mover el precio justo a través de un boundary y disparar la rama del hook.
- Verificar que el settlement afterSwap acredite al caller más de lo que cuesta, dejando un BalanceDelta positivo o crédito en la contabilidad del hook.
- Repetir swaps para acumular crédito; luego llamar a la ruta de withdrawal/settlement del hook.

Example Foundry‑style test harness (pseudocódigo)
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
Calibrando el exactInput
- Calcula ΔsqrtP para un paso de tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Aproxima Δin usando las fórmulas v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Asegúrate de que la dirección de redondeo coincida con las matemáticas centrales.
- Ajusta Δin en ±1 wei alrededor del límite para encontrar la rama donde el hook redondea a tu favor.

4) Amplifica con flash loans
- Pide prestado un notional grande (p. ej., 3M USDT o 2000 WETH) para ejecutar muchas iteraciones de forma atómica.
- Ejecuta el bucle de swap calibrado, luego retira y reembolsa dentro del callback del flash loan.

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
5) Exit and cross‑chain replication
- Si los hooks están desplegados en múltiples cadenas, repetir la misma calibración por cadena.
- Puentea los fondos de vuelta a la cadena objetivo y opcionalmente cicla vía protocolos de préstamo para ofuscar los flujos.

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
- Step 1 (price push): el atacante tomó prestado en flash ~3M USDT y los swapped para empujar el tick a ~5000, reduciendo el balance **activo** de USDC hasta ~28 wei.
- Step 2 (rounding drain): 44 retiros diminutos explotaron el floor rounding en `BunniHubLogic::withdraw()` para reducir el balance activo de USDC de 28 wei a 4 wei (‑85.7%) mientras solo una fracción ínfima de LP shares fue quemada. La liquidez total se subestimó en ~84.4%.
- Step 3 (liquidity rebound sandwich): un swap grande movió el tick a ~839,189 (1 USDC ≈ 2.77e36 USDT). Las estimaciones de liquidez se invirtieron e incrementaron ~16.8%, permitiendo un sandwich donde el atacante swapped de vuelta al precio inflado y salió con beneficio.
- Fix identified in the post‑mortem: change the idle‑balance update to round **up** so repeated micro‑withdrawals can’t ratchet the pool’s active balance downward.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Lista de comprobación de hunting

- ¿El pool usa una dirección de hooks distinta de cero? ¿Qué callbacks están habilitados?
- ¿Hay redistribuciones/reequilibrios per‑swap usando matemáticas personalizadas? ¿Alguna lógica de tick/threshold?
- ¿Dónde se usan divisiones/mulDiv, conversiones Q64.96 o SafeCast? ¿Son las semánticas de redondeo globalmente consistentes?
- ¿Puedes construir Δin que apenas cruce un límite y provoque una rama de redondeo favorable? Prueba ambas direcciones y tanto exactInput como exactOutput.
- ¿El hook rastrea créditos per‑caller o deltas que pueden retirarse posteriormente? Asegúrate de neutralizar cualquier residuo.

## Referencias

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
