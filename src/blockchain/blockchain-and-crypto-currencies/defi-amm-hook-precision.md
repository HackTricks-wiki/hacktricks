# Exploitation de DeFi/AMM: abuso de precisión/redondeo en hooks de Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una clase de técnicas de explotación de DeFi/AMM contra DEXes de estilo Uniswap v4 que amplían las matemáticas del core mediante hooks personalizados. Un incidente reciente en Bunni V2 aprovechó un fallo de redondeo/precisión en una Liquidity Distribution Function (LDF) ejecutada en cada swap, lo que permitió al atacante acumular créditos positivos y drenar liquidez.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

La idea clave es que, si un hook implementa accounting adicional que depende de matemáticas de punto fijo, redondeo de ticks y lógica basada en umbrales, un atacante puede crear swaps exact-input que crucen umbrales específicos, haciendo que las discrepancias de redondeo se acumulen a su favor. Al repetir el patrón y retirar posteriormente el balance inflado, se obtiene el profit, normalmente financiado mediante un flash loan.

## Contexto: hooks de Uniswap v4 y flujo de los swaps

- Los hooks son contratos que PoolManager llama en puntos específicos del ciclo de vida (por ejemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Los pools se inicializan con un PoolKey que incluye la dirección del hook. Si no es cero, PoolManager ejecuta callbacks en cada operación relevante.<sup>[[6]](#references)</sup>
- Los hooks pueden devolver **custom deltas** que modifican los cambios finales de balance de un swap o una acción de liquidez (custom accounting). Esos deltas se liquidan como balances netos al final de la llamada, por lo que cualquier error de redondeo dentro de las matemáticas del hook se acumula antes de la liquidación.<sup>[[5]](#references)</sup>
- Las matemáticas del core utilizan formatos de punto fijo como Q64.96 para sqrtPriceX96 y aritmética de ticks con 1.0001^tick. Cualquier matemática personalizada superpuesta debe coincidir cuidadosamente con la semántica de redondeo para evitar el drift del invariant.<sup>[[4]](#references)[[8]](#references)</sup>
- Los swaps pueden ser exactInput o exactOutput. En v3/v4, el precio se mueve a lo largo de los ticks; cruzar el límite de un tick puede activar/desactivar la liquidez de un rango. Los hooks pueden implementar lógica adicional al cruzar umbrales/ticks.<sup>[[5]](#references)</sup>

## Arquetipo de vulnerabilidad: drift de precisión/redondeo al cruzar umbrales

Un patrón vulnerable típico en hooks personalizados:

1. El hook calcula deltas de liquidez o balance por swap mediante división entera, mulDiv o conversiones de punto fijo (por ejemplo, entre tokens y liquidez usando sqrtPrice y rangos de ticks).
2. La lógica de umbrales (por ejemplo, rebalancing, redistribución por pasos o activación por rango) se activa cuando el tamaño del swap o el movimiento del precio cruza un límite interno.
3. El redondeo se aplica de forma inconsistente (por ejemplo, truncamiento hacia cero, floor frente a ceil) entre el cálculo directo y la ruta de liquidación. Las pequeñas discrepancias no se cancelan y, en su lugar, acreditan al caller.
4. Los swaps exact-input, dimensionados con precisión para atravesar esos límites, cosechan repetidamente el resto positivo del redondeo. Posteriormente, el atacante retira el crédito acumulado.

Precondiciones del ataque
- Un pool que utilice un hook v4 personalizado que realice matemáticas adicionales en cada swap (por ejemplo, un LDF/rebalancer).
- Al menos una ruta de ejecución en la que el redondeo beneficie al iniciador del swap al cruzar umbrales.
- Capacidad para repetir muchos swaps de forma atómica (los flash loans son ideales para proporcionar float temporal y amortizar el gas).

## Metodología práctica del ataque

1) Identificar pools candidatos con hooks
- Enumerar los pools v4 y comprobar que PoolKey.hooks != address(0).
- Inspeccionar el bytecode/ABI del hook en busca de callbacks: beforeSwap/afterSwap y cualquier método de rebalancing personalizado.
- Buscar matemáticas que: dividan por la liquidez, conviertan entre cantidades de tokens y liquidez, o agreguen BalanceDelta con redondeo.

2) Modelar las matemáticas y los umbrales del hook
- Reproducir la fórmula de liquidez/redistribución del hook: las entradas normalmente incluyen sqrtPriceX96, tickLower/Upper, currentTick, fee tier y liquidez neta.
- Mapear las funciones de umbral/pasos: ticks, límites de buckets o breakpoints del LDF. Determinar en qué lado de cada límite se redondea el delta.
- Identificar dónde se realizan conversiones entre uint256/int256, se utiliza SafeCast o se depende de mulDiv con floor implícito.

3) Calibrar swaps exact-input para cruzar los límites
- Utilizar simulaciones con Foundry/Hardhat para calcular el Δin mínimo necesario para mover el precio justo más allá de un límite y activar la rama del hook.
- Verificar que la liquidación de afterSwap acredita al caller más que el coste, dejando un BalanceDelta o crédito positivo en el accounting del hook.
- Repetir los swaps para acumular crédito; después, llamar a la ruta de withdrawal/settlement del hook.

Ejemplo de harness de pruebas al estilo Foundry (pseudocódigo)
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
- Aproxima Δin usando las fórmulas de v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Asegúrate de que la dirección del redondeo coincida con las matemáticas del core.
- Ajusta Δin en ±1 wei alrededor del límite para encontrar la rama en la que el hook redondee a tu favor.

4) Amplificar con préstamos flash
- Pide prestado un valor nominal grande (por ejemplo, 3M USDT o 2000 WETH) para ejecutar muchas iteraciones de forma atómica.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Ejecuta el bucle de swap calibrado, y después retira los fondos y devuelve el préstamo dentro del callback del préstamo flash.

Esqueleto de préstamo flash de Aave V3
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
5) Salida y replicación cross-chain
- Si los hooks se despliegan en múltiples chains, repite la misma calibración por chain.
- Puentea los proceeds de vuelta a la chain objetivo y, opcionalmente, hazlos pasar por protocolos de lending para ofuscar los flujos.<sup>[[2]](#references)</sup>

## Causas raíz comunes en las matemáticas de los hooks

- Semántica de redondeo mixta: mulDiv redondea hacia abajo, mientras que las rutas posteriores redondean efectivamente hacia arriba; o las conversiones entre tokens/liquidez aplican distintos redondeos.
- Errores de alineación de ticks: usar ticks sin redondear en una ruta y redondeo según el espaciado de ticks en otra.
- Problemas de signo/overflow de BalanceDelta al convertir entre int256 y uint256 durante la liquidación.
- Pérdida de precisión en las conversiones Q64.96 (sqrtPriceX96) que no se replica en el mapeo inverso.
- Vías de acumulación: los residuos por swap se registran como créditos que el caller puede retirar en lugar de quemarse o compensarse en suma cero.

## Contabilidad personalizada y amplificación de deltas

- La contabilidad personalizada de Uniswap v4 permite que los hooks devuelvan deltas que ajustan directamente lo que el caller debe o recibe. Si el hook registra créditos internamente, el residuo de redondeo puede acumularse a través de muchas operaciones pequeñas **antes** de que ocurra la liquidación final.<sup>[[5]](#references)</sup>
- Esto hace más fuerte el abuso de límites/umbrales: el atacante puede alternar `swap → withdraw → swap` en la misma tx, obligando al hook a recalcular los deltas sobre un estado ligeramente distinto mientras todos los balances siguen pendientes.
- Al revisar hooks, sigue siempre cómo se produce y liquida BalanceDelta/HookDelta. Un único redondeo sesgado en una rama puede convertirse en un crédito acumulativo cuando los deltas se recalculan repetidamente.

## Guía defensiva

- Differential testing: compara las matemáticas del hook con una implementación de referencia usando aritmética racional de alta precisión y comprueba que la igualdad o el error acotado siempre sean adversariales (nunca favorables al caller).
- Pruebas de invariantes/propiedades:
- La suma de los deltas (tokens, liquidez) en las rutas de swap y los ajustes del hook debe conservar el valor, salvo las fees.
- Ninguna ruta debe crear un crédito neto positivo para el iniciador del swap después de iteraciones repetidas de exactInput.
- Pruebas de límites de umbral/tick alrededor de entradas de ±1 wei tanto para exactInput como para exactOutput.
- Política de redondeo: centraliza los helpers de redondeo para que siempre redondeen en contra del usuario; elimina los casts inconsistentes y los floors implícitos.
- Destinos de liquidación: acumula el residuo inevitable de redondeo en la treasury del protocolo o quémalo; nunca lo atribuyas a msg.sender.
- Límites/guardrails de tasa: tamaños mínimos de swap para activar rebalances; desactiva los rebalances si los deltas son inferiores a un wei; comprueba la coherencia de los deltas con los rangos esperados.
- Revisa los callbacks del hook de forma integral: beforeSwap/afterSwap y los cambios de liquidez before/after deben coincidir en la alineación de ticks y el redondeo de deltas.

## Caso de estudio: Bunni V2 (2025-09-02)

- Protocolo: Bunni V2 (hook de Uniswap v4) con un LDF aplicado por swap para realizar un rebalance.<sup>[[7]](#references)</sup>
- Pools afectados: USDC/USDT en Ethereum y weETH/ETH en Unichain, con un total aproximado de $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Paso 1 (price push): el atacante tomó prestados mediante flash loan ~3M USDT y ejecutó un swap para llevar el tick hasta ~5000, reduciendo el balance **activo** de USDC a ~28 wei.<sup>[[7]](#references)</sup>
- Paso 2 (rounding drain): 44 withdrawals pequeños explotaron el redondeo hacia abajo en `BunniHubLogic::withdraw()` para reducir el balance activo de USDC de 28 wei a 4 wei (-85.7%), mientras solo se quemaba una fracción mínima de las LP shares. La liquidez total se subestimó en ~84.4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Paso 3 (liquidity rebound sandwich): un swap grande movió el tick hasta ~839,189 (1 USDC ≈ 2.77e36 USDT). Las estimaciones de liquidez cambiaron y aumentaron ~16.8%, lo que permitió un sandwich en el que el atacante ejecutó el swap inverso al precio inflado y salió con beneficio.<sup>[[7]](#references)</sup>
- Corrección identificada en el post-mortem: cambiar la actualización del balance idle para que redondee **hacia arriba**, de modo que los micro-withdrawals repetidos no puedan reducir progresivamente el balance activo del pool.<sup>[[7]](#references)</sup>

Línea vulnerable simplificada (y corrección del post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Lista de comprobación de hunting

- ¿El pool utiliza una dirección de hooks distinta de cero? ¿Qué callbacks están habilitados?
- ¿Existen redistribuciones/rebalances por swap que utilicen math personalizada? ¿Hay alguna lógica de ticks/umbrales?
- ¿Dónde se utilizan divisiones/mulDiv, conversiones Q64.96 o SafeCast? ¿Son coherentes globalmente las semánticas de redondeo?
- ¿Puedes construir un Δin que apenas cruce un límite y produzca una rama de redondeo favorable? Prueba ambas direcciones y tanto exactInput como exactOutput.
- ¿El hook realiza un seguimiento de créditos o deltas por caller que puedan retirarse posteriormente? Asegúrate de neutralizar el residuo.

## Referencias

- [1] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (resumen)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: análisis completo del hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 background (investigación de QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Mecánica de liquidez en el core de Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Mecánica de swaps en el core de Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Hooks de Uniswap v4 y consideraciones de seguridad](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Post Mortem del exploit de Bunni (sep. de 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Whitepaper del core de Uniswap v4](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
