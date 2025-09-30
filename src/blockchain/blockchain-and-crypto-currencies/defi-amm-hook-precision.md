# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma classe de técnicas de exploração DeFi/AMM contra DEXes no estilo Uniswap v4 que estendem a matemática core com hooks customizados. Um incidente recente no Bunni V2 explorou uma falha de arredondamento/precisão em uma Liquidity Distribution Function (LDF) executada em cada swap, permitindo ao atacante acumular créditos positivos e drenar liquidez.

Ideia principal: se um hook implementa contabilidade adicional que depende de matemática em ponto fixo, arredondamento de tick e lógica de limiar, um atacante pode montar swaps exact‑input que cruzem limiares específicos de forma que discrepâncias de arredondamento se acumulem a seu favor. Repetir o padrão e então sacar o saldo inflado realiza o lucro, frequentemente financiado por um flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks são contracts que o PoolManager chama em pontos específicos do ciclo de vida (ex.: beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Pools são inicializados com um PoolKey incluindo hooks address. Se diferente de zero, o PoolManager executa callbacks em cada operação relevante.
- A matemática core usa formatos em ponto fixo como Q64.96 para sqrtPriceX96 e aritmética de tick com 1.0001^tick. Qualquer matemática custom adicional precisa casar cuidadosamente as semânticas de arredondamento para evitar drift de invariantes.
- Swaps podem ser exactInput ou exactOutput. Em v3/v4, o preço se move ao longo de ticks; cruzar um boundary de tick pode ativar/desativar range liquidity. Hooks podem implementar lógica extra em crossings de tick/limiar.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Um padrão tipicamente vulnerável em hooks customizados:

1. O hook calcula deltas de liquidity ou balance por swap usando divisão inteira, mulDiv, ou conversões em ponto fixo (ex.: token ↔ liquidity usando sqrtPrice e tick ranges).
2. Lógica de limiar (ex.: rebalancing, redistribuição por degraus, ou ativação por range) é disparada quando o tamanho do swap ou movimento de preço cruza um boundary interno.
3. Arredondamento é aplicado de forma inconsistente (ex.: truncamento em direção a zero, floor versus ceil) entre o cálculo à frente e o caminho de settlement. Pequenas discrepâncias não se cancelam e, ao invés disso, creditam o caller.
4. Exact‑input swaps, precisamente dimensionados para atravessar esses boundaries, colhem repetidamente o resto positivo do arredondamento. O atacante depois retira o crédito acumulado.

Precondições do ataque
- Um pool usando um hook v4 custom que faz matemática adicional em cada swap (ex.: uma LDF/rebalancer).
- Pelo menos um caminho de execução onde o arredondamento beneficia o swap initiator ao cruzar limiares.
- Capacidade de repetir muitos swaps atomicamente (flash loans são ideais para prover float temporário e amortizar gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumere v4 pools e verifique PoolKey.hooks != address(0).
- Inspecione hook bytecode/ABI para callbacks: beforeSwap/afterSwap e quaisquer métodos custom de rebalancing.
- Procure matemática que: divide por liquidity, converte entre token amounts e liquidity, ou agrega BalanceDelta com arredondamento.

2) Model the hook’s math and thresholds
- Recrie a fórmula de liquidity/redistribution do hook: inputs tipicamente incluem sqrtPriceX96, tickLower/Upper, currentTick, fee tier, e net liquidity.
- Mapeie funções de limiar/degrau: ticks, bucket boundaries, ou LDF breakpoints. Determine de que lado de cada boundary o delta é arredondado.
- Identifique onde conversões fazem cast entre uint256/int256, usam SafeCast, ou dependem de mulDiv com floor implícito.

3) Calibrate exact‑input swaps to cross boundaries
- Use Foundry/Hardhat simulations para computar o Δin mínimo necessário para mover o preço pouco além de um boundary e disparar a branch do hook.
- Verifique que, após o settlement do afterSwap, o caller recebe crédito maior que o custo, deixando um BalanceDelta positivo ou crédito na contabilidade do hook.
- Repita swaps para acumular crédito; então invoque o caminho de withdrawal/settlement do hook.

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
- Tome emprestado um notional grande (por exemplo, 3M USDT ou 2000 WETH) para executar muitas iterações atomicamente.
- Execute o loop de swap calibrado, então retire e pague dentro do callback do flash loan.

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
5) Saída e cross‑chain replication
- Se hooks estiverem implantados em múltiplas chains, repita a mesma calibração por chain.
- O bridge retorna para a chain alvo e, opcionalmente, cicla via lending protocols para ofuscar os fluxos.

## Causas raiz comuns na matemática dos hooks

- Semânticas de arredondamento mistas: mulDiv faz floor enquanto caminhos posteriores efetivamente arredondam para cima; ou conversões entre token/liquidity aplicam arredondamentos diferentes.
- Erros de alinhamento de tick: usar ticks não arredondados em um caminho e arredondamento por espaçamento de tick em outro.
- Problemas de sinal/overflow em BalanceDelta ao converter entre int256 e uint256 durante o settlement.
- Perda de precisão em conversões Q64.96 (sqrtPriceX96) não espelhada no mapeamento reverso.
- Caminhos de acumulação: restos por swap rastreados como credits resgatáveis pelo caller em vez de serem queimados/zero‑sum.

## Orientação defensiva

- Differential testing: espelhe a matemática do hook vs uma implementação de referência usando aritmética racional de alta precisão e asserte igualdade ou erro limitado que seja sempre adversarial (nunca favorável ao caller).
- Testes de invariantes/propriedades:
- A soma dos deltas (tokens, liquidity) através dos caminhos de swap e ajustes do hook deve conservar valor modulo fees.
- Nenhum caminho deve criar crédito líquido positivo para o swap initiator em iterações repetidas de exactInput.
- Testes de limites de threshold/tick em torno de ±1 wei de entrada para ambos exactInput/exactOutput.
- Política de arredondamento: centralize helpers de rounding que sempre arredondam contra o usuário; elimine casts inconsistentes e floors implícitos.
- Settlement sinks: acumule resíduos de arredondamento inevitáveis no protocol treasury ou queime-os; nunca atribua a msg.sender.
- Rate‑limits/guardrails: tamanhos mínimos de swap para gatilhos de rebalancing; desabilite rebalances se os deltas forem sub‑wei; verifique sanidade dos deltas contra faixas esperadas.
- Revise callbacks do hook de forma holística: beforeSwap/afterSwap e antes/depois de liquidity changes devem concordar sobre alinhamento de tick e arredondamento de deltas.

## Estudo de caso: Bunni V2 (2025‑09‑02)

- Protocolo: Bunni V2 (Uniswap v4 hook) com um LDF aplicado por swap para rebalancear.
- Causa raiz: erro de rounding/precision na contabilidade de liquidity do LDF durante swaps que cruzam threshold; discrepâncias por swap acumuladas como credits positivos para o caller.
- Perna Ethereum: attacker pegou um flash loan de ~3M USDT, realizou swaps calibrated exact‑input em USDC/USDT para construir credits, sacou saldos inflados, pagou o empréstimo e roteou fundos via Aave.
- Perna UniChain: repetiu o exploit com um flash loan de 2000 WETH, surrupiando ~1366 WETH e fazendo bridge para Ethereum.
- Impacto: ~USD 8.3M drenados across chains. Nenhuma interação de usuário requerida; inteiramente on‑chain.

## Checklist de hunting

- O pool usa um endereço de hooks não nulo? Quais callbacks estão habilitados?
- Existem redistribuições/rebalances por swap usando math customizada? Alguma lógica de tick/threshold?
- Onde estão divisions/mulDiv, conversões Q64.96, ou SafeCast usadas? As semânticas de rounding são globalmente consistentes?
- Você consegue construir Δin que mal cruza um limite e gera um branch de arredondamento favorável? Teste ambas as direções e tanto exactInput quanto exactOutput.
- O hook rastreia credits ou deltas por caller que podem ser sacados depois? Garanta que o resíduo seja neutralizado.

## Referências

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
