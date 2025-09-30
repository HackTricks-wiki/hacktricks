# Explotación DeFi/AMM: Abuso de Precisión/Redondeo de Hooks en Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una clase de técnicas de explotación DeFi/AMM contra DEXes estilo Uniswap v4 que extienden la matemática núcleo con hooks personalizados. Un incidente reciente en Bunni V2 aprovechó un fallo de redondeo/precisión en una Liquidity Distribution Function (LDF) ejecutada en cada swap, permitiendo al atacante acumular créditos positivos y drenar la liquidez.

Idea clave: si un hook implementa contabilidad adicional que depende de matemática de punto fijo, redondeo de ticks y lógica de umbrales, un atacante puede crear swaps exact‑input que crucen umbrales específicos de modo que las discrepancias de redondeo se acumulen a su favor. Repetir el patrón y luego retirar el saldo inflado realiza beneficio, a menudo financiado con un flash loan.

## Antecedentes: Uniswap v4 hooks y flujo de swaps

- Los hooks son contratos que PoolManager llama en puntos específicos del ciclo de vida (p.ej., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Los pools se inicializan con un PoolKey que incluye la dirección de hooks. Si no es cero, PoolManager realiza callbacks en cada operación relevante.
- La matemática núcleo usa formatos de punto fijo como Q64.96 para sqrtPriceX96 y aritmética de tick con 1.0001^tick. Cualquier matemática personalizada añadida encima debe casar cuidadosamente la semántica de redondeo para evitar drift en el invariante.
- Los swaps pueden ser exactInput o exactOutput. En v3/v4, el precio se mueve a lo largo de los ticks; cruzar un límite de tick puede activar/desactivar la liquidez de rango. Los hooks pueden implementar lógica extra en cruces de umbrales/ticks.

## Arquetipo de vulnerabilidad: drift por precisión/redondeo al cruzar umbrales

Un patrón vulnerable típico en hooks personalizados:

1. El hook calcula deltas de liquidez o balance por swap usando división entera, mulDiv, o conversiones de punto fijo (p.ej., token ↔ liquidity usando sqrtPrice y rangos de tick).
2. La lógica de umbral (p.ej., reequilibrio, redistribución por pasos, o activación por rango) se dispara cuando el tamaño del swap o el movimiento de precio cruza una frontera interna.
3. El redondeo se aplica de forma inconsistente (p.ej., truncamiento hacia cero, floor versus ceil) entre el cálculo adelantado y la ruta de liquidación. Pequeñas discrepancias no se cancelan y en su lugar acreditan al caller.
4. Exact‑input swaps, calibrados con precisión para atravesar esos límites, cosechan repetidamente el resto positivo de redondeo. El atacante luego llama a la ruta de retiro/liquidación del hook para extraer el crédito acumulado.

Precondiciones del ataque
- Un pool que usa un v4 hook que realiza matemática adicional en cada swap (p.ej., un LDF/rebalancer).
- Al menos un camino de ejecución donde el redondeo beneficia al iniciador del swap a través de cruces de umbral.
- Capacidad para repetir muchos swaps de forma atómica (flash loans son ideales para suministrar float temporal y amortizar gas).

## Metodología práctica de ataque

1) Identificar pools candidatos con hooks
- Enumerar pools v4 y comprobar PoolKey.hooks != address(0).
- Inspeccionar hook bytecode/ABI para callbacks: beforeSwap/afterSwap y cualquier método de rebalancing personalizado.
- Buscar matemática que: divida por liquidity, convierta entre token amounts y liquidity, o agregue BalanceDelta con redondeo.

2) Modelar la matemática y umbrales del hook
- Recrear la fórmula de liquidity/redistribution del hook: las entradas típicas incluyen sqrtPriceX96, tickLower/Upper, currentTick, fee tier y net liquidity.
- Mapear funciones de umbral/pasos: ticks, límites de buckets o breakpoints del LDF. Determinar en qué lado de cada frontera se redondea el delta.
- Identificar dónde las conversiones castean entre uint256/int256, usan SafeCast, o dependen de mulDiv con floor implícito.

3) Calibrar exact‑input swaps para cruzar fronteras
- Usar Foundry/Hardhat en simulaciones para computar el Δin mínimo necesario para mover el precio justo al otro lado de una frontera y disparar la rama del hook.
- Verificar que la liquidación afterSwap acredita al caller más de lo que cuesta, dejando un BalanceDelta positivo o crédito en la contabilidad del hook.
- Repetir swaps para acumular crédito; luego llamar al camino de retiro/liquidación del hook.

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
Calibrando el exactInput
- Calcula ΔsqrtP para un paso de tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Aproxima Δin usando las fórmulas de v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Asegúrate de que la dirección de redondeo coincida con la matemática del core.
- Ajusta Δin ±1 wei alrededor del umbral para encontrar la rama donde el hook redondea a tu favor.

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
5) Salida y replicación entre cadenas
- Si los hooks están desplegados en múltiples cadenas, repite la misma calibración por cadena.
- Los fondos del puente vuelven a la cadena objetivo y opcionalmente se ciclan vía protocolos de lending para ofuscar los flujos.

## Causas raíz comunes en la matemática de hooks

- Semánticas de redondeo mixtas: mulDiv trunca hacia abajo mientras rutas posteriores efectivamente redondean hacia arriba; o conversiones entre token/liquidity aplican diferentes redondeos.
- Errores de alineación de tick: usar ticks sin redondear en una ruta y redondeo espaciado por tick en otra.
- Problemas de signo/desbordamiento en BalanceDelta al convertir entre int256 y uint256 durante el settlement.
- Pérdida de precisión en conversiones Q64.96 (sqrtPriceX96) no reflejada en el mapeo inverso.
- Vías de acumulación: remanentes por swap rastreados como créditos retirables por el caller en vez de quemarse/ser zero‑sum.

## Guía defensiva

- Differential testing: refleja la matemática del hook frente a una implementación de referencia usando aritmética racional de alta precisión y afirma igualdad o un error acotado que siempre sea adversarial (nunca favorable al caller).
- Tests de invariantes/propiedades:
- La suma de los deltas (tokens, liquidity) a través de las rutas de swap y ajustes del hook debe conservar valor módulo fees.
- Ninguna ruta debe crear crédito neto positivo para el iniciador del swap en iteraciones repetidas de exactInput.
- Tests de umbrales/límites de tick alrededor de entradas de ±1 wei para ambos exactInput/exactOutput.
- Política de redondeo: centraliza helpers de redondeo que siempre redondeen en contra del usuario; elimina casts inconsistentes y floors implícitos.
- Sinks de settlement: acumula el residuo de redondeo inevitable en el tesoro del protocolo o quémalo; nunca atribuirlo a msg.sender.
- Límites/tasas de control: tamaños mínimos de swap para triggers de reequilibrio; deshabilitar rebalances si los deltas son sub‑wei; sanity‑check de deltas contra rangos esperados.
- Revisar los callbacks del hook de forma holística: beforeSwap/afterSwap y before/after liquidity changes deben coincidir en la alineación de ticks y el redondeo de deltas.

## Estudio de caso: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) con un LDF aplicado por swap para reequilibrar.
- Causa raíz: error de redondeo/precisión en el accounting de liquidez LDF durante swaps que cruzan un umbral; discrepancias por swap que se acumularon como créditos positivos para el caller.
- Ethereum leg: el atacante tomó un flash loan de ~3M USDT, realizó swaps calibrados exact‑input en USDC/USDT para generar créditos, retiró saldos inflados, reembolsó y enroutó fondos vía Aave.
- UniChain leg: repitió el exploit con un flash loan de 2000 WETH, desviando ~1366 WETH y bridgeándolos a Ethereum.
- Impact: ~USD 8.3M drenados a través de cadenas. No se requirió interacción de usuarios; todo on‑chain.

## Checklist de hunting

- ¿La pool usa una dirección de hooks distinta de cero? ¿Qué callbacks están habilitados?
- ¿Hay redistribuciones/rebalances por swap usando matemática custom? ¿Alguna lógica de tick/threshold?
- ¿Dónde se usan divisiones/mulDiv, conversiones Q64.96, o SafeCast? ¿Son las semánticas de redondeo globalmente consistentes?
- ¿Puedes construir Δin que apenas cruce un límite y obtenga una rama de redondeo favorable? Prueba ambas direcciones y tanto exactInput como exactOutput.
- ¿El hook rastrea créditos o deltas por caller que puedan retirarse más tarde? Asegura que el residuo quede neutralizado.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
