# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



Esta página documenta una clase de técnicas de explotación DeFi/AMM contra DEXes estilo Uniswap v4 que extienden la matemática central con hooks personalizados. Un incidente reciente en Bunni V2 aprovechó un fallo de redondeo/precisión en una Liquidity Distribution Function (LDF) ejecutada en cada swap, permitiendo al atacante acumular créditos positivos y drenar liquidez.

Key idea: si un hook implementa contabilidad adicional que depende de fixed‑point math, tick rounding y lógica de umbrales, un atacante puede diseñar swaps exact‑input que crucen umbrales específicos de forma que las discrepancias de redondeo se acumulen a su favor. Repetir el patrón y luego retirar el saldo inflado realiza la ganancia, frecuentemente financiada con un flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks son contratos que el PoolManager llama en puntos específicos del ciclo de vida (por ejemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools se inicializan con un PoolKey que incluye hooks address. Si no es address(0), PoolManager realiza callbacks en cada operación relevante.
- Hooks pueden devolver **custom deltas** que modifican los cambios finales de balance de un swap o acción de liquidez (custom accounting). Esos deltas se liquidan como saldos netos al final de la llamada, por lo que cualquier error de redondeo dentro de la matemática del hook se acumula antes de la liquidación.
- La matemática central usa formatos fixed‑point como Q64.96 para sqrtPriceX96 y aritmética de ticks con 1.0001^tick. Cualquier matemática personalizada superpuesta debe casar cuidadosamente las semánticas de redondeo para evitar deriva del invariante.
- Los swaps pueden ser exactInput o exactOutput. En v3/v4, el precio se mueve a lo largo de ticks; cruzar una frontera de tick puede activar/desactivar liquidity por rango. Los hooks pueden implementar lógica extra en cruces de umbrales/ticks.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Un patrón típico vulnerable en hooks personalizados:

1. El hook calcula deltas de liquidez o de balance por swap usando división de enteros, mulDiv, o conversiones fixed‑point (por ejemplo, token ↔ liquidity usando sqrtPrice y rangos de tick).
2. La lógica de umbral (por ejemplo, rebalancing, redistribución por pasos, o activación por rango) se dispara cuando un tamaño de swap o movimiento de precio cruza una frontera interna.
3. El redondeo se aplica de forma inconsistente (por ejemplo, truncamiento hacia cero, floor versus ceil) entre el cálculo hacia adelante y la ruta de liquidación. Las pequeñas discrepancias no se cancelan y en su lugar acreditan al caller.
4. Swaps exact‑input, dimensionados con precisión para atravesar esos límites, cosechan repetidamente el resto positivo del redondeo. El atacante luego retira el crédito acumulado.

Attack preconditions
- Un pool que use un hook v4 que realice matemática adicional en cada swap (por ejemplo, un LDF/rebalancer).
- Al menos una ruta de ejecución donde el redondeo beneficie al swap initiator al cruzar umbrales.
- Capacidad para repetir muchos swaps atómicamente (flash loans son ideales para suministrar float temporal y amortizar gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerar pools v4 y comprobar PoolKey.hooks != address(0).
- Inspeccionar hook bytecode/ABI para callbacks: beforeSwap/afterSwap y cualquier método de rebalancing personalizado.
- Buscar matemática que: divida por liquidity, convierta entre token amounts y liquidity, o agregue BalanceDelta con redondeo.

2) Model the hook’s math and thresholds
- Recrear la fórmula de liquidez/redistribución del hook: las entradas típicas incluyen sqrtPriceX96, tickLower/Upper, currentTick, fee tier y net liquidity.
- Mapear funciones de umbral/paso: ticks, límites de buckets, o breakpoints del LDF. Determinar en qué lado de cada frontera el delta se redondea a favor.
- Identificar dónde las conversiones castean entre uint256/int256, usan SafeCast, o dependen de mulDiv con floor implícito.

3) Calibrate exact‑input swaps to cross boundaries
- Usar simulaciones Foundry/Hardhat para calcular el Δin mínimo necesario para mover el precio justo al otro lado de una frontera y disparar la rama del hook.
- Verificar que la liquidación afterSwap acredite al caller más de lo que cuesta, dejando un BalanceDelta positivo o un crédito en la contabilidad del hook.
- Repetir swaps para acumular crédito; luego llamar a la ruta de retiro/liquidación del hook.

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
- Aproxima Δin usando las fórmulas de v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Asegúrate de que la dirección de redondeo coincida con la matemática central.
- Ajusta Δin en ±1 wei alrededor del límite para encontrar la rama donde el hook redondea a tu favor.

4) Amplifica con flash loans
- Pide prestado un notional grande (p. ej., 3M USDT o 2000 WETH) para ejecutar muchas iteraciones de forma atómica.
- Ejecuta el bucle de swap calibrado, luego retira y reembolsa dentro del callback del flash loan.

Esqueleto de flash loan de Aave V3
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
5) Salida y replicación cross‑chain
- Si los hooks están desplegados en múltiples cadenas, repetir la misma calibración por cadena.
- El puente reenvía los fondos de vuelta a la cadena objetivo y opcionalmente hace ciclos vía protocolos de lending para ofuscar los flujos.

## Causas raíz comunes en la matemática de hooks

- Semánticas de redondeo mixtas: mulDiv trunca mientras que rutas posteriores efectivamente redondean hacia arriba; o las conversiones entre token/liquidez aplican redondeos distintos.
- Errores de alineación de ticks: usar ticks sin redondear en una ruta y redondeo espaciado por tick en otra.
- Problemas de signo/desbordamiento en BalanceDelta al convertir entre int256 y uint256 durante el settlement.
- Pérdida de precisión en conversiones Q64.96 (sqrtPriceX96) no reflejada en el mapeo inverso.
- Vías de acumulación: restos por swap rastreados como créditos que pueden retirarse por el caller en lugar de quemarse/ser suma cero.

## Contabilidad personalizada y amplificación de deltas

- La contabilidad personalizada de Uniswap v4 permite que los hooks devuelvan deltas que ajustan directamente lo que el caller debe/recibe. Si el hook rastrea créditos internamente, el residuo de redondeo puede acumularse a través de muchas operaciones pequeñas antes de que ocurra el settlement final.
- Esto fortalece el abuso de límites/umbrales: el atacante puede alternar `swap → withdraw → swap` en la misma tx, forzando al hook a recomputar deltas sobre un estado ligeramente distinto mientras todos los balances aún están pendientes.
- Al revisar hooks, siempre traza cómo se produce y liquida BalanceDelta/HookDelta. Un único redondeo sesgado en una rama puede convertirse en un crédito que se acumula cuando los deltas se recomputan repetidamente.

## Guía defensiva

- Pruebas diferenciales: contrapone la matemática del hook con una implementación de referencia usando aritmética racional de alta precisión y afirma igualdad o un error acotado que siempre sea adversarial (nunca favorable al caller).
- Tests de invariantes/propiedades:
  - La suma de deltas (tokens, liquidez) a través de rutas de swap y ajustes del hook debe conservar valor módulo fees.
  - Ninguna ruta debe crear crédito neto positivo para el iniciador del swap tras iteraciones repetidas de exactInput.
  - Tests de umbrales/límites de tick alrededor de entradas de ±1 wei tanto para exactInput como para exactOutput.
- Política de redondeo: centralizar los helpers de redondeo que siempre redondeen en contra del usuario; eliminar casts inconsistentes y floors implícitos.
- Sinks de settlement: acumular el residuo de redondeo inevitable en el treasury del protocolo o quemarlo; nunca atribuirlo a msg.sender.
- Límites/guardarraíles: tamaños mínimos de swap para triggers de reequilibrio; deshabilitar rebalances si los deltas son sub‑wei; validar que los deltas estén dentro de rangos esperados.
- Revisar los callbacks del hook de forma holística: beforeSwap/afterSwap y antes/después de cambios de liquidez deben coincidir en alineación de ticks y redondeo de deltas.

## Estudio de caso: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) con un LDF aplicado por swap para reequilibrar.
- Affected pools: USDC/USDT en Ethereum y weETH/ETH en Unichain, totalizando aproximadamente $8.4M.
- Step 1 (price push): el atacante tomó prestado en flash ~3M USDT y los intercambió para empujar el tick a ~5000, reduciendo el balance USDC **activo** a ~28 wei.
- Step 2 (rounding drain): 44 retiradas diminutas explotaron el redondeo hacia abajo en `BunniHubLogic::withdraw()` para reducir el balance USDC activo de 28 wei a 4 wei (‑85.7%) mientras que solo se quemó una fracción ínfima de las LP shares. La liquidez total fue subestimada en ~84.4%.
- Step 3 (liquidity rebound sandwich): un swap grande movió el tick a ~839,189 (1 USDC ≈ 2.77e36 USDT). Las estimaciones de liquidez se invirtieron y aumentaron ~16.8%, permitiendo un sandwich donde el atacante volvió a swapear al precio inflado y salió con beneficio.
- Fix identified in the post‑mortem: cambiar la actualización del idle‑balance para redondear hacia arriba de modo que las micro‑retiradas repetidas no puedan rebajar de forma escalonada el balance activo del pool.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Hunting checklist

- ¿El pool usa una hooks address distinta de cero? ¿Qué callbacks están habilitados?
- ¿Se realizan per‑swap redistributions/rebalances usando custom math? ¿Alguna lógica de tick/threshold?
- ¿Dónde se usan divisions/mulDiv, conversiones Q64.96 o SafeCast? ¿Son las semánticas de redondeo consistentes a nivel global?
- ¿Puedes construir Δin que apenas cruce una frontera y produzca una rama de redondeo favorable? Prueba ambas direcciones y tanto exactInput como exactOutput.
- ¿El hook rastrea per‑caller credits o deltas que puedan retirarse más tarde? Asegúrate de neutralizar el residuo.

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
