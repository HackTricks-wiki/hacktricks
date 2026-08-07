# Exploração de DeFi/AMM: Abuso de Precisão/Arredondamento em Hooks do Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma classe de técnicas de exploração de DeFi/AMM contra DEXes no estilo Uniswap v4 que estendem a matemática principal com hooks customizados. Um incidente recente no Bunni V2 explorou uma falha de arredondamento/precisão em uma Liquidity Distribution Function (LDF) executada a cada swap, permitindo que o atacante acumulasse créditos positivos e drenasse liquidez.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Ideia principal: se um hook implementa contabilidade adicional que depende de matemática de ponto fixo, arredondamento de ticks e lógica de limiares, um atacante pode criar swaps exact-input que atravessem limiares específicos, fazendo com que discrepâncias de arredondamento se acumulem a seu favor. Repetir o padrão e, em seguida, retirar o saldo inflado gera lucro, frequentemente financiado com um flash loan.

## Contexto: hooks do Uniswap v4 e fluxo de swap

- Hooks são contratos que o PoolManager chama em pontos específicos do ciclo de vida (por exemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Os pools são inicializados com um PoolKey que inclui o endereço do hook. Se não for zero, o PoolManager executa callbacks em todas as operações relevantes.<sup>[[6]](#references)</sup>
- Hooks podem retornar **custom deltas** que modificam as alterações finais de saldo de um swap ou ação de liquidez (custom accounting). Esses deltas são liquidados como saldos líquidos ao final da chamada, portanto qualquer erro de arredondamento na matemática do hook se acumula antes da liquidação.<sup>[[5]](#references)</sup>
- A matemática principal usa formatos de ponto fixo, como Q64.96 para sqrtPriceX96, e aritmética de ticks com 1.0001^tick. Qualquer matemática customizada adicionada deve corresponder cuidadosamente às semânticas de arredondamento para evitar desvios do invariant.<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps podem ser exactInput ou exactOutput. No v3/v4, o preço se move ao longo dos ticks; atravessar um limite de tick pode ativar/desativar a liquidez de um intervalo. Hooks podem implementar lógica adicional em cruzamentos de limiares/ticks.<sup>[[5]](#references)</sup>

## Arquétipo da vulnerabilidade: desvio de precisão/arredondamento ao cruzar limiares

Um padrão vulnerável típico em hooks customizados:

1. O hook calcula deltas de liquidez ou saldo por swap usando divisão inteira, mulDiv ou conversões de ponto fixo (por exemplo, token ↔ liquidez usando sqrtPrice e intervalos de ticks).
2. A lógica de limiar (por exemplo, rebalanceamento, redistribuição em etapas ou ativação por intervalo) é acionada quando o tamanho do swap ou o movimento do preço atravessa um limite interno.
3. O arredondamento é aplicado de forma inconsistente (por exemplo, truncamento em direção a zero, floor versus ceil) entre o cálculo direto e o caminho de liquidação. Pequenas discrepâncias não são anuladas e, em vez disso, creditam o caller.
4. Swaps exact-input, dimensionados precisamente para ultrapassar esses limites, coletam repetidamente o resto positivo do arredondamento. Posteriormente, o atacante retira o crédito acumulado.

Pré-condições do ataque
- Um pool que use um hook customizado do v4 e execute matemática adicional a cada swap (por exemplo, um LDF/rebalancer).
- Pelo menos um caminho de execução em que o arredondamento beneficie o initiator do swap durante os cruzamentos de limiares.
- Capacidade de repetir muitos swaps atomicamente (flash loans são ideais para fornecer capital temporário e amortizar o gas).

## Metodologia prática de ataque

1) Identificar pools candidatos com hooks
- Enumerar pools do v4 e verificar se PoolKey.hooks != address(0).
- Inspecionar o bytecode/ABI do hook em busca de callbacks: beforeSwap/afterSwap e quaisquer métodos customizados de rebalanceamento.
- Procurar matemática que: divida pela liquidez, converta entre quantidades de tokens e liquidez ou agregue BalanceDelta com arredondamento.

2) Modelar a matemática e os limiares do hook
- Recriar a fórmula de liquidez/redistribuição do hook: as entradas normalmente incluem sqrtPriceX96, tickLower/Upper, currentTick, fee tier e liquidez líquida.
- Mapear funções de limiar/etapa: ticks, limites de buckets ou breakpoints do LDF. Determinar de que lado de cada limite o delta é arredondado.
- Identificar onde ocorrem conversões entre uint256/int256, onde é usado SafeCast ou onde se depende de mulDiv com floor implícito.

3) Calibrar swaps exact-input para atravessar os limites
- Usar simulações com Foundry/Hardhat para calcular o Δin mínimo necessário para mover o preço ligeiramente além de um limite e acionar o branch do hook.
- Verificar se a liquidação do afterSwap credita ao caller mais do que o custo, deixando um BalanceDelta positivo ou um crédito na contabilidade do hook.
- Repetir os swaps para acumular crédito; em seguida, chamar o caminho de withdrawal/settlement do hook.

Exemplo de test harness no estilo Foundry (pseudocode)
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
- Aproxime Δin usando as fórmulas do v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Garanta que a direção do arredondamento corresponda à core math.
- Ajuste Δin em ±1 wei ao redor do limite para encontrar a branch em que o hook arredonda a seu favor.

4) Amplifique com flash loans
- Pegue emprestado um notional elevado (por exemplo, 3M USDT ou 2000 WETH) para executar muitas iterações atomicamente.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Execute o loop de swap calibrado e, em seguida, faça o saque e o reembolso dentro do callback do flash loan.

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
5) Saída e replicação cross-chain
- Se os hooks forem deployed em múltiplas chains, repita a mesma calibração por chain.
- Faça a bridge dos proceeds de volta para a chain-alvo e, opcionalmente, faça um ciclo via protocolos de lending para ofuscar os fluxos.<sup>[[2]](#references)</sup>

## Causas-raiz comuns em matemática de hooks

- Semânticas de arredondamento mistas: `mulDiv` aplica floor, enquanto caminhos posteriores efetivamente arredondam para cima; ou conversões entre token/liquidez aplicam arredondamentos diferentes.
- Erros de alinhamento de ticks: uso de ticks não arredondados em um caminho e arredondamento com espaçamento de ticks em outro.
- Problemas de sinal/overflow de `BalanceDelta` ao converter entre `int256` e `uint256` durante a liquidação.
- Perda de precisão em conversões Q64.96 (`sqrtPriceX96`) não refletida no mapeamento reverso.
- Caminhos de acumulação: restos por swap rastreados como créditos que podem ser sacados pelo caller em vez de serem queimados ou tratados como zero-sum.

## Custom accounting e amplificação de deltas

- O custom accounting do Uniswap v4 permite que hooks retornem deltas que ajustam diretamente o que o caller deve/pode receber. Se o hook rastrear créditos internamente, resíduos de arredondamento podem se acumular em muitas operações pequenas **antes** da liquidação final ocorrer.<sup>[[5]](#references)</sup>
- Isso torna o abuso de limites/thresholds mais forte: o atacante pode alternar `swap → withdraw → swap` na mesma tx, forçando o hook a recalcular deltas em um estado ligeiramente diferente enquanto todos os saldos ainda estão pendentes.
- Ao revisar hooks, sempre rastreie como `BalanceDelta`/`HookDelta` é produzido e liquidado. Um único arredondamento enviesado em um branch pode se tornar um crédito cumulativo quando os deltas são recalculados repetidamente.

## Orientações defensivas

- Testes diferenciais: compare a matemática do hook com uma implementação de referência usando aritmética racional de alta precisão e exija igualdade ou um erro limitado que seja sempre adversarial (nunca favorável ao caller).
- Testes de invariantes/propriedades:
- A soma dos deltas (tokens, liquidez) em todos os caminhos de swap e ajustes do hook deve conservar valor, descontadas as fees.
- Nenhum caminho deve criar crédito líquido positivo para o iniciador do swap após iterações repetidas de `exactInput`.
- Testes de limites de threshold/tick em torno de entradas de ±1 wei para `exactInput`/`exactOutput`.
- Política de arredondamento: centralize helpers de arredondamento que sempre arredondem contra o usuário; elimine casts inconsistentes e floors implícitos.
- Destinos de liquidação: acumule resíduos inevitáveis de arredondamento no tesouro do protocolo ou queime-os; nunca os atribua a `msg.sender`.
- Rate-limits/guardrails: tamanhos mínimos de swap para triggers de rebalancing; desabilite rebalancings se os deltas forem sub-wei; valide a razoabilidade dos deltas em relação aos ranges esperados.
- Revise os callbacks do hook de forma holística: `beforeSwap`/`afterSwap` e as mudanças de liquidez `before`/`after` devem concordar quanto ao alinhamento de ticks e ao arredondamento de deltas.

## Estudo de caso: Bunni V2 (2025-09-02)

- Protocolo: Bunni V2 (hook do Uniswap v4) com um LDF aplicado por swap para fazer rebalancing.<sup>[[7]](#references)</sup>
- Pools afetados: USDC/USDT na Ethereum e weETH/ETH na Unichain, totalizando cerca de US$ 8,4 milhões.<sup>[[1]](#references)[[2]](#references)</sup>
- Etapa 1 (price push): o atacante fez um flash-borrow de ~3M USDT e realizou um swap para mover o tick para ~5000, reduzindo o saldo **ativo** de USDC para ~28 wei.<sup>[[7]](#references)</sup>
- Etapa 2 (drain por arredondamento): 44 withdrawals pequenos exploraram o arredondamento por floor em `BunniHubLogic::withdraw()` para reduzir o saldo ativo de USDC de 28 wei para 4 wei (-85,7%), enquanto apenas uma fração mínima das LP shares era queimada. A liquidez total foi subestimada em ~84,4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Etapa 3 (liquidity rebound sandwich): um swap grande moveu o tick para ~839.189 (1 USDC ≈ 2,77e36 USDT). As estimativas de liquidez inverteram-se e aumentaram ~16,8%, permitindo um sandwich no qual o atacante realizou o swap de volta ao preço inflado e saiu com lucro.<sup>[[7]](#references)</sup>
- Correção identificada no post-mortem: alterar a atualização do saldo idle para arredondar **para cima**, de modo que micro-withdrawals repetidos não possam reduzir gradualmente o saldo ativo do pool.<sup>[[7]](#references)</sup>

Linha vulnerável simplificada (e correção do post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklist de hunting

- O pool usa um endereço de hooks diferente de zero? Quais callbacks estão habilitados?
- Existem redistribuições/rebalances por swap usando matemática customizada? Há alguma lógica de tick/threshold?
- Onde são usados divisions/mulDiv, conversões Q64.96 ou SafeCast? As semânticas de arredondamento são globalmente consistentes?
- É possível construir um Δin que atravesse por pouco um limite e produza um branch de arredondamento favorável? Teste ambas as direções e tanto exactInput quanto exactOutput.
- O hook rastreia credits ou deltas por caller que podem ser retirados posteriormente? Garanta que o residue seja neutralizado.

## Referências

- [1] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Análise Completa do Hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Contexto do Uniswap v4 (pesquisa da QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Mecânicas de liquidez no core do Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Mecânicas de swap no core do Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Hooks do Uniswap v4 e considerações de segurança](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Post-mortem do Bunni Exploit (set. de 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Whitepaper do Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
