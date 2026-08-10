# Explotación de DeFi/AMM: abuso de precisión/redondeo en hooks de Uniswap v4

Esta página documenta una clase de técnicas de explotación de DeFi/AMM contra DEXes de estilo Uniswap v4 que amplían las matemáticas principales con hooks personalizados. Un incidente de Bunni V2 ilustra un fallo relacionado: un bug en la dirección del redondeo en la contabilidad de retiros subestimó la liquidez activa, y un swap posterior expuso esa subestimación en un sandwich rentable.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idea clave: si un hook implementa contabilidad adicional que depende de matemáticas de punto fijo, redondeo de ticks y lógica de umbrales, un atacante puede crear swaps exact-input que crucen umbrales específicos para que las discrepancias de redondeo se acumulen a su favor. Al repetir el patrón y retirar después el balance inflado, se obtiene el profit, a menudo financiado con un flash loan.

## Contexto: hooks de Uniswap v4 y flujo de los swaps

- Los hooks son contratos que el PoolManager llama en puntos específicos del ciclo de vida (por ejemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Los pools se inicializan con un PoolKey que incluye el contrato del hook. Una dirección de hook distinta de cero habilita los callbacks seleccionados para ese pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Los hooks pueden devolver **custom deltas** que modifican los cambios finales de balance de un swap o una acción de liquidez (custom accounting). Esos deltas se liquidan como balances netos al final de la llamada, por lo que cualquier error de redondeo dentro de las matemáticas del hook se acumula antes de la liquidación.<sup>[[4]](#references)</sup>
- Las matemáticas principales usan formatos de punto fijo como Q64.96 para sqrtPriceX96 y aritmética de ticks con 1.0001^tick. Cualquier matemática personalizada construida sobre ellas debe coincidir cuidadosamente con las semánticas de redondeo para evitar desviaciones del invariant.<sup>[[12]](#references)[[13]](#references)</sup>
- Los swaps pueden ser exactInput o exactOutput. En v3/v4, el precio se mueve a lo largo de los ticks; cruzar el límite de un tick puede activar/desactivar la liquidez del rango. Los hooks pueden implementar lógica adicional al cruzar umbrales/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Arquetipo de vulnerabilidad: desviación de precisión/redondeo al cruzar umbrales

Un patrón vulnerable típico en hooks personalizados:

1. El hook calcula deltas de liquidez o balance por swap usando división entera, mulDiv o conversiones de punto fijo (por ejemplo, token ↔ liquidez usando sqrtPrice y rangos de ticks).
2. La lógica de umbrales (por ejemplo, rebalanceo, redistribución escalonada o activación por rango) se activa cuando el tamaño de un swap o el movimiento del precio cruza un límite interno.
3. El redondeo se aplica de forma inconsistente (por ejemplo, truncamiento hacia cero, floor frente a ceil) entre el cálculo directo y la ruta de liquidación. Las pequeñas discrepancias no se cancelan, sino que acreditan al caller.
4. Los swaps exact-input, dimensionados con precisión para atravesar esos límites, cosechan repetidamente el remainder positivo del redondeo. Después, el atacante retira el crédito acumulado.

Precondiciones del ataque
- Un pool que use un hook personalizado de v4 que realice matemáticas adicionales en cada swap (por ejemplo, un LDF/rebalancer).
- Al menos una ruta de ejecución en la que el redondeo beneficie al iniciador del swap al cruzar umbrales.
- Capacidad para repetir muchos swaps de forma atómica (los flash loans son ideales para proporcionar float temporal y amortizar el gas).

## Metodología práctica del ataque

1) Identificar pools candidatos con hooks
- Enumerar los pools de v4 y comprobar que PoolKey.hooks != address(0).
- Inspeccionar el bytecode/ABI del hook en busca de callbacks: beforeSwap/afterSwap y cualquier método de rebalanceo personalizado.
- Buscar matemáticas que: dividan por la liquidez, conviertan entre cantidades de tokens y liquidez, o agreguen BalanceDelta con redondeo.

2) Modelar las matemáticas y los umbrales del hook
- Recrear la fórmula de liquidez/redistribución del hook: las entradas normalmente incluyen sqrtPriceX96, tickLower/Upper, currentTick, fee tier y liquidez neta.
- Mapear las funciones de umbral/step: ticks, límites de buckets o breakpoints del LDF. Determinar en qué lado de cada límite se redondea el delta.
- Identificar dónde se realizan casts entre uint256/int256, se usa SafeCast o se depende de mulDiv con floor implícito.

3) Calibrar swaps exact-input para cruzar límites
- Usar simulaciones de Foundry/Hardhat para calcular el Δin mínimo necesario para mover el precio justo más allá de un límite y activar la rama del hook.
- Verificar que la liquidación de afterSwap acredite al caller más que el coste, dejando un BalanceDelta positivo o un crédito en la contabilidad del hook.
- Repetir los swaps para acumular crédito; después, llamar a la ruta de withdrawal/settlement del hook.

En v4, el bucle del swap debe ejecutarse desde un callback de unlock del PoolManager; `amountSpecified` negativo indica exact input, y `sqrtPriceLimitX96` debe estar estrictamente dentro del rango válido. Un límite de precio cero revierte, por lo que el pseudocódigo siguiente usa el límite inferior para un swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Ejemplo de test harness al estilo de Foundry (pseudocódigo)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: IHooks(address(bunniHook))
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
// This loop runs inside the PoolManager unlockCallback.
for (uint i; i < N; ++i) {
pm.swap(
key,
SwapParams({
zeroForOne: true,
amountSpecified: -int256(exactIn), // exactInput
sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Calibración de exactInput
- Calcula el objetivo con TickMath del core: sqrtP_next = sqrtP_current × 1.0001^(Δtick) en términos de valores reales; el resultado Q64.96 se redondea mediante TickMath.<sup>[[13]](#references)</sup>
- Aproxima una entrada de token0 (zero-for-one) usando la fórmula compatible con Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Reproduce el redondeo específico de la dirección de la rutina del core.<sup>[[12]](#references)</sup>
- Ajusta Δin en ±1 wei alrededor del límite para encontrar la rama en la que el hook redondea a tu favor.

4) Amplificar con flash loans
- Pide prestado un notional grande (por ejemplo, 3M USDT o 2000 WETH) para ejecutar muchas iteraciones de forma atómica.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Ejecuta el bucle de swaps calibrado y, después, retira y devuelve el préstamo dentro del callback del flash loan.

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
5) Salida y replicación cross-chain
- Si los hooks se despliegan en varias chains, repite la misma calibración en cada chain.
- En el incidente de Bunni, la liquidez de flash-loan y las rutas de bridge diferían según la chain, así que ten en cuenta esas restricciones específicas de cada chain al reproducir el análisis.<sup>[[1]](#references)[[2]](#references)</sup>

## Causas raíz comunes en las matemáticas de los hooks

- Semánticas de redondeo mixtas: `mulDiv` redondea hacia abajo, mientras que las rutas posteriores redondean efectivamente hacia arriba; o las conversiones entre tokens/liquidez aplican distintos redondeos.
- Errores de alineación de ticks: usar ticks sin redondear en una ruta y redondeo basado en el espaciado de ticks en otra.
- Problemas de signo/overflow de `BalanceDelta` al convertir entre `int256` y `uint256` durante la liquidación.
- Pérdida de precisión en las conversiones Q64.96 (`sqrtPriceX96`) que no se refleja en el mapeo inverso.
- Vías de acumulación: los residuos por swap se registran como créditos que el caller puede retirar, en lugar de quemarse o compensarse en suma cero.

## Contabilidad personalizada y amplificación de deltas

- La contabilidad personalizada de Uniswap v4 permite que los hooks devuelvan deltas que ajustan directamente lo que el caller debe o recibe. Si el hook registra créditos internamente, el residuo del redondeo puede acumularse a través de muchas operaciones pequeñas **antes** de que ocurra la liquidación final.<sup>[[4]](#references)</sup>
- Si el hook expone una ruta de retiro compatible, un atacante puede alternar `swap → withdraw → swap` dentro del mismo callback de unlock de `PoolManager`, obligando al hook a recalcular los deltas sobre un estado ligeramente diferente, mientras los balances permanecen pendientes hasta que se liquida el unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Al revisar hooks, rastrea siempre cómo se produce y liquida `BalanceDelta`/`HookDelta`. Un único redondeo sesgado en una rama puede convertirse en un crédito acumulativo cuando los deltas se recalculan repetidamente.

## Guía defensiva

- Testing diferencial: compara las matemáticas del hook con una implementación de referencia usando aritmética racional de alta precisión y verifica la igualdad o un error acotado que siempre sea adversarial (nunca favorable al caller).
- Tests de invariantes/propiedades:
- La suma de los deltas (tokens, liquidez) en las rutas de swap y los ajustes del hook debe conservar el valor, salvo las fees.
- Ninguna ruta debe crear un crédito neto positivo para el iniciador del swap tras iteraciones repetidas de `exactInput`.
- Tests de umbrales/límites de ticks alrededor de entradas de ±1 wei, tanto para `exactInput` como para `exactOutput`.
- Política de redondeo: centraliza helpers de redondeo que siempre redondeen en contra del usuario; elimina los casts inconsistentes y los floors implícitos.
- Destinos de liquidación: acumula los residuos inevitables del redondeo en la treasury del protocolo o quémalos; nunca los atribuyas a `msg.sender`.
- Rate-limits/guardrails: tamaños mínimos de swap para los triggers de rebalanceo; desactiva los rebalanceos si los deltas son inferiores a un wei; valida los deltas frente a los rangos esperados.
- Revisa los callbacks del hook de forma integral: `beforeSwap`/`afterSwap` y los cambios de liquidez `before`/`after` deben coincidir en la alineación de ticks y el redondeo de deltas.

## Caso de estudio: Bunni V2 (2025-09-02)

- Protocolo: Bunni V2, un hook de Uniswap v4 que utiliza una Liquidity Density Function (LDF) para calcular la densidad de tokens y las estimaciones de liquidez total.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools afectados: USDC/USDT en Ethereum y weETH/ETH en Unichain, con un total aproximado de $8.4M.<sup>[[1]](#references)</sup>
- Paso 1 (price push): el atacante tomó prestados ~3M USDT mediante flash-loan e hizo swap para llevar el tick hasta ~5000, reduciendo el balance **activo** de USDC a ~28 wei.<sup>[[1]](#references)</sup>
- Paso 2 (drain por redondeo): 44 retiros pequeños explotaron el redondeo hacia abajo en `BunniHubLogic::withdraw()` para reducir el balance activo de USDC de 28 wei a 4 wei (-85.7%), mientras solo se quemaba una fracción mínima de las shares de LP. La liquidez total disminuyó ~84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Paso 3 (sandwich por recuperación de liquidez): un swap grande movió el tick hasta ~839,189 (1 USDC ≈ 2.77e36 USDT). Las estimaciones de liquidez cambiaron y aumentaron ~16.8%, lo que permitió un sandwich en el que el atacante hizo swap de vuelta al precio inflado y salió con ganancias.<sup>[[1]](#references)</sup>
- Corrección identificada en el post-mortem: modificar la actualización del balance idle para que redondee **hacia arriba**, de modo que los micro-retiros repetidos ya no reduzcan gradualmente el balance activo del pool.<sup>[[1]](#references)</sup>

Línea vulnerable simplificada (y corrección del post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Lista de comprobación de hunting

- ¿El pool utiliza una dirección de hooks distinta de cero? ¿Qué callbacks están habilitados?
- ¿Existen redistribuciones/rebalances por swap que utilicen custom math? ¿Alguna lógica de tick/threshold?
- ¿Dónde se utilizan divisiones/mulDiv, conversiones Q64.96 o SafeCast? ¿Son coherentes globalmente las semánticas de redondeo?
- ¿Puedes construir un Δin que apenas cruce un límite y produzca una rama de redondeo favorable? Prueba ambas direcciones y tanto exactInput como exactOutput.
- ¿El hook realiza un seguimiento de créditos o deltas por caller que puedan retirarse posteriormente? Asegúrate de neutralizar el residue.

## References

- [1] [Autopsia del exploit de Bunni (sep. de 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit de Bunni V2: análisis completo del hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit de Bunni V2: $8.3M drenados mediante un fallo de liquidez (resumen)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper de Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contexto de Uniswap v4 (investigación de QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mecánica de liquidez en Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mecánica de los swaps en Uniswap v4 Core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks de Uniswap v4 y consideraciones de seguridad](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol de Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol de Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams de Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol de Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol de Uniswap v4 Core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey de Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
