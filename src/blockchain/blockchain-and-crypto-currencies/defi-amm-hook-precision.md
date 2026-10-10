# Explotación de DeFi/AMM: abuso de precisión/redondeo de hooks de Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una clase de técnicas de explotación de DeFi/AMM contra DEXes de estilo Uniswap v4 que amplían las matemáticas del núcleo con hooks personalizados. Un incidente de Bunni V2 ilustra un fallo relacionado: un error en la dirección del redondeo al contabilizar retiros subestimó la liquidez activa, y un swap posterior expuso esa subestimación mediante un sandwich rentable.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Idea clave: si un hook implementa contabilidad adicional que depende de matemáticas de punto fijo, redondeo de ticks y lógica de umbrales, un atacante puede crear swaps de entrada exacta que crucen umbrales específicos para que las discrepancias de redondeo se acumulen a su favor. Al repetir el patrón y retirar después el saldo inflado, obtiene ganancias, a menudo financiadas con un flash loan.

## Antecedentes: hooks de Uniswap v4 y flujo de swaps

- Los hooks son contratos a los que PoolManager llama en puntos específicos del ciclo de vida (p. ej., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Los pools se inicializan con un PoolKey que incluye el contrato del hook. Una dirección de hook distinta de cero habilita las callbacks seleccionadas para ese pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Los hooks pueden devolver **deltas personalizados** que modifican los cambios finales de saldo de un swap o una acción de liquidez (contabilidad personalizada). Esos deltas se liquidan como saldos netos al final de la llamada, por lo que cualquier error de redondeo dentro de las matemáticas del hook se acumula antes de la liquidación.<sup>[[4]](#references)</sup>
- Las matemáticas del núcleo usan formatos de punto fijo como Q64.96 para sqrtPriceX96 y aritmética de ticks con 1.0001^tick. Cualquier matemática personalizada que se añada debe coincidir cuidadosamente con la semántica de redondeo para evitar desviaciones del invariante.<sup>[[12]](#references)[[13]](#references)</sup>
- Los swaps pueden ser de exactInput o exactOutput. En v3/v4, el precio se mueve a lo largo de los ticks; cruzar el límite de un tick puede activar/desactivar la liquidez del rango. Los hooks pueden implementar lógica adicional al cruzar umbrales/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Arquetipo de vulnerabilidad: desviación de precisión/redondeo al cruzar umbrales

Un patrón vulnerable típico en hooks personalizados:

1. El hook calcula deltas de liquidez o saldo por swap mediante división entera, mulDiv o conversiones de punto fijo (p. ej., de tokens a liquidez usando sqrtPrice y rangos de ticks).
2. La lógica de umbrales (p. ej., reequilibrio, redistribución escalonada o activación por rango) se ejecuta cuando el tamaño de un swap o el movimiento del precio cruza un límite interno.
3. El redondeo se aplica de forma inconsistente (p. ej., truncamiento hacia cero, floor frente a ceil) entre el cálculo directo y la ruta de liquidación. Las pequeñas discrepancias no se cancelan, sino que acreditan al usuario que ejecuta la llamada.
4. Los swaps de entrada exacta, dimensionados con precisión para atravesar esos límites, extraen repetidamente el residuo positivo del redondeo. Después, el atacante retira el crédito acumulado.

Requisitos previos del ataque
- Un pool que use un hook personalizado de v4 que realice cálculos adicionales en cada swap (p. ej., un LDF/rebalancer).
- Al menos una ruta de ejecución en la que el redondeo favorezca a quien inicia el swap al cruzar umbrales.
- Capacidad de repetir muchos swaps de forma atómica (los flash loans son ideales para aportar fondos temporales y amortizar el gas).

## Metodología práctica del ataque

1) Identificar pools candidatos con hooks
- Enumerar los pools de v4 y comprobar que PoolKey.hooks != address(0).
- Inspeccionar el bytecode/ABI del hook en busca de callbacks: beforeSwap/afterSwap y cualquier método de reequilibrio personalizado.
- Buscar matemáticas que: dividan por la liquidez, conviertan entre cantidades de tokens y liquidez, o agreguen BalanceDelta con redondeo.

2) Modelar las matemáticas y los umbrales del hook
- Recrear la fórmula de liquidez/redistribución del hook: las entradas suelen incluir sqrtPriceX96, tickLower/Upper, currentTick, el nivel de comisión y la liquidez neta.
- Mapear las funciones de umbral/escalonamiento: ticks, límites de buckets o puntos de ruptura de LDF. Determinar hacia qué lado de cada límite se redondea el delta.
- Identificar dónde las conversiones hacen casts entre uint256/int256, usan SafeCast o dependen de mulDiv con floor implícito.

3) Ajustar swaps de entrada exacta para cruzar límites
- Usar simulaciones con Foundry/Hardhat para calcular el Δin mínimo necesario para mover el precio justo más allá de un límite y activar la rama del hook.
- Verificar que la liquidación de afterSwap acredite al usuario que ejecuta la llamada más de lo que cuesta, dejando un BalanceDelta positivo o crédito en la contabilidad del hook.
- Repetir los swaps para acumular crédito y, luego, llamar a la ruta de retiro/liquidación del hook.

En v4, el bucle del swap debe ejecutarse desde un callback de desbloqueo de PoolManager; un `amountSpecified` negativo indica entrada exacta, y `sqrtPriceLimitX96` debe estar estrictamente dentro del rango válido. Un límite de precio igual a cero provoca un revert, por lo que el pseudocódigo siguiente usa el límite inferior para un swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Ejemplo de harness de pruebas al estilo Foundry (pseudocódigo)
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

Calibrar el exactInput
- Calcula el objetivo con el TickMath del core: sqrtP_next = sqrtP_current × 1.0001^(Δtick) en términos de valor real; TickMath redondea el resultado Q64.96.<sup>[[13]](#references)</sup>
- Aproxima una entrada de token0 (zero-for-one) con la fórmula compatible con Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Haz coincidir el redondeo específico de la dirección de la rutina del core.<sup>[[12]](#references)</sup>
- Ajusta Δin en ±1 wei alrededor del límite para encontrar la rama en la que el hook redondea a tu favor.

4) Amplificar con préstamos flash
- Pide prestado un monto nominal grande (p. ej., 3M USDT o 2000 WETH) para ejecutar muchas iteraciones de forma atómica.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Ejecuta el bucle de swaps calibrado y luego retira los fondos y paga el préstamo dentro de la callback del préstamo flash.

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

5) Salida y replicación entre cadenas
- Si los hooks están desplegados en varias cadenas, repite la misma calibración en cada una.
- En el incidente de Bunni, la liquidez de flash loans y las rutas de los puentes diferían según la cadena, así que ten en cuenta esas restricciones específicas de cada cadena al reproducir el análisis.<sup>[[1]](#references)[[2]](#references)</sup>

## Causas raíz comunes en las matemáticas de los hooks

- Semánticas de redondeo mixtas: mulDiv redondea hacia abajo, mientras que las rutas posteriores efectivamente redondean hacia arriba; o las conversiones entre tokens y liquidez aplican distintos tipos de redondeo.
- Errores de alineación de ticks: usar ticks sin redondear en una ruta y redondeo según el espaciado de ticks en otra.
- Problemas de signo/desbordamiento de BalanceDelta al convertir entre int256 y uint256 durante la liquidación.
- Pérdida de precisión en conversiones Q64.96 (sqrtPriceX96) que no se refleja en el mapeo inverso.
- Vías de acumulación: los residuos por swap se registran como créditos que el caller puede retirar en vez de quemarse o quedar en suma cero.

## Contabilidad personalizada y amplificación de deltas

- La contabilidad personalizada de Uniswap v4 permite que los hooks devuelvan deltas que ajustan directamente lo que el caller debe o recibe. Si el hook lleva un registro interno de créditos, los residuos de redondeo pueden acumularse a lo largo de muchas operaciones pequeñas **antes** de que se produzca la liquidación final.<sup>[[4]](#references)</sup>
- Si el hook expone una ruta de retiro compatible, un atacante puede alternar `swap → withdraw → swap` dentro de la misma callback de desbloqueo de PoolManager, obligando al hook a recalcular los deltas con un estado ligeramente distinto mientras los saldos siguen pendientes hasta que se liquida el desbloqueo.<sup>[[4]](#references)[[10]](#references)</sup>
- Al revisar hooks, sigue siempre cómo se generan y liquidan BalanceDelta/HookDelta. Un único redondeo sesgado en una rama puede convertirse en un crédito acumulativo cuando los deltas se recalculan repetidamente.

## Recomendaciones de defensa

- Pruebas diferenciales: compara las matemáticas del hook con una implementación de referencia que use aritmética racional de alta precisión y verifica la igualdad o un error acotado que siempre sea adversarial (nunca favorable al caller).
- Pruebas de invariantes/propiedades:
  - La suma de los deltas (tokens, liquidez) en las rutas de swap y los ajustes del hook debe conservar el valor, salvo las comisiones.
  - Ninguna ruta debe generar un crédito neto positivo para quien inicia el swap tras iteraciones repetidas de exactInput.
  - Pruebas de límites de umbral/tick con entradas de ±1 wei para exactInput y exactOutput.
- Política de redondeo: centraliza las funciones auxiliares de redondeo para que siempre redondeen en contra del usuario; elimina conversiones inconsistentes y redondeos hacia abajo implícitos.
- Destinos de liquidación: acumula los residuos de redondeo inevitables en la tesorería del protocolo o quémalos; nunca los atribuyas a msg.sender.
- Límites/controles de seguridad: tamaños mínimos de swap para activar rebalanceos; desactiva los rebalanceos si los deltas son menores que un wei; comprueba que los deltas estén dentro de los rangos esperados.
- Revisa integralmente las callbacks del hook: beforeSwap/afterSwap y los cambios de liquidez before/after deben coincidir en la alineación de ticks y el redondeo de deltas.

## Caso de estudio: Bunni V2 (2025‑09‑02)

- Protocolo: Bunni V2, un hook de Uniswap v4 que usa una Liquidity Density Function (LDF) para calcular la densidad de tokens y las estimaciones de liquidez total.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools afectados: USDC/USDT en Ethereum y weETH/ETH en Unichain, con un total de unos $8.4M.<sup>[[1]](#references)</sup>
- Paso 1 (movimiento del precio): el atacante tomó prestados ~3M USDT mediante un flash loan e hizo un swap para llevar el tick a ~5000, reduciendo el saldo **activo** de USDC a ~28 wei.<sup>[[1]](#references)</sup>
- Paso 2 (drenaje por redondeo): 44 retiros pequeños aprovecharon el redondeo hacia abajo en `BunniHubLogic::withdraw()` para reducir el saldo activo de USDC de 28 wei a 4 wei (-85.7%), mientras solo se quemaba una fracción minúscula de las participaciones LP. La liquidez total disminuyó ~84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Paso 3 (sándwich de recuperación de liquidez): un swap grande movió el tick a ~839,189 (1 USDC ≈ 2.77e36 USDT). Las estimaciones de liquidez cambiaron y aumentaron ~16.8%, lo que permitió un sándwich en el que el atacante hizo el swap de vuelta al precio inflado y salió con ganancias.<sup>[[1]](#references)</sup>
- Solución identificada en el análisis post mortem: cambiar la actualización del saldo inactivo para que redondee **hacia arriba**, de modo que los retiros pequeños repetidos ya no reduzcan gradualmente el saldo activo del pool.<sup>[[1]](#references)</sup>

Línea vulnerable simplificada (y solución del análisis post mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Lista de comprobación de búsqueda

- ¿El pool usa una dirección de hooks distinta de cero? ¿Qué callbacks están habilitados?
- ¿Hay redistribuciones/rebalances por swap que usen matemática personalizada? ¿Hay lógica de tick/umbral?
- ¿Dónde se usan divisiones/mulDiv, conversiones Q64.96 o SafeCast? ¿La semántica de redondeo es coherente en todo el sistema?
- ¿Puedes construir un Δin que apenas cruce un límite y dé lugar a una rama de redondeo favorable? Prueba ambas direcciones, con exactInput y exactOutput.
- ¿El hook registra créditos o deltas por caller que se puedan retirar más adelante? Asegúrate de neutralizar el remanente.

## References

- [1] [Autopsia post mortem del exploit de Bunni (sep. de 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit de Bunni V2: análisis completo del hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit de Bunni V2: $8.3M drenados mediante un fallo de liquidez (resumen)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Libro blanco de Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Antecedentes de Uniswap v4 (investigación de QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mecánicas de liquidez en el core de Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mecánicas de swap en el core de Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks de Uniswap v4 y consideraciones de seguridad](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Uniswap v4 core Pool.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [Uniswap v4 core PoolManager.sol](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [Uniswap v4 SwapParams](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [Uniswap v4 core SqrtPriceMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [Uniswap v4 core TickMath.sol](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [Uniswap v4 PoolKey](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
