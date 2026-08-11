# Exploração de DeFi/AMM: Abuso de Precisão/Arredondamento de Hook do Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma classe de técnicas de exploração de DeFi/AMM contra DEXes no estilo Uniswap v4 que estendem a matemática principal com hooks personalizados. Um incidente da Bunni V2 ilustra uma falha relacionada: um bug na direção do arredondamento da contabilidade de retiradas subestimou a liquidez ativa, e um swap posterior expôs essa subestimação em um sandwich lucrativo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ideia principal: se um hook implementa contabilidade adicional que depende de matemática de ponto fixo, arredondamento de ticks e lógica de limiar, um atacante pode criar swaps de entrada exata que atravessem limiares específicos, fazendo com que as discrepâncias de arredondamento se acumulem a seu favor. Ao repetir o padrão e depois retirar o saldo inflado, o atacante realiza o lucro, geralmente financiado com um flash loan.

## Contexto: hooks e fluxo de swap do Uniswap v4

- Hooks são contratos que o PoolManager chama em pontos específicos do ciclo de vida (por exemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Os pools são inicializados com uma PoolKey que inclui o contrato do hook. Um endereço de hook diferente de zero habilita os callbacks selecionados para aquele pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks podem retornar **custom deltas** que modificam as alterações finais de saldo de um swap ou ação de liquidez (contabilidade personalizada). Esses deltas são liquidados como saldos líquidos ao final da chamada, portanto qualquer erro de arredondamento na matemática do hook se acumula antes da liquidação.<sup>[[4]](#references)</sup>
- A matemática principal usa formatos de ponto fixo, como Q64.96 para sqrtPriceX96, e aritmética de ticks com 1.0001^tick. Qualquer matemática personalizada aplicada sobre ela deve corresponder cuidadosamente às semânticas de arredondamento para evitar desvios do invariante.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps podem ser de entrada exata ou saída exata. No v3/v4, o preço se move ao longo dos ticks; atravessar um limite de tick pode ativar/desativar a liquidez de um intervalo. Hooks podem implementar lógica adicional em travessias de limiares/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Arquétipo da vulnerabilidade: desvio de precisão/arredondamento ao atravessar limiares

Um padrão vulnerável típico em hooks personalizados:

1. O hook calcula deltas de liquidez ou saldo por swap usando divisão inteira, mulDiv ou conversões de ponto fixo (por exemplo, token ↔ liquidez usando sqrtPrice e intervalos de ticks).
2. A lógica de limiar (por exemplo, rebalanceamento, redistribuição em etapas ou ativação por intervalo) é acionada quando o tamanho do swap ou o movimento do preço atravessa um limite interno.
3. O arredondamento é aplicado de forma inconsistente (por exemplo, truncamento em direção a zero, floor versus ceil) entre o cálculo direto e o caminho de liquidação. Pequenas discrepâncias não se anulam e, em vez disso, creditam o chamador.
4. Swaps de entrada exata, dimensionados precisamente para ultrapassar esses limites, coletam repetidamente o resto positivo do arredondamento. O atacante posteriormente retira o crédito acumulado.

Pré-condições do ataque
- Um pool que usa um hook v4 personalizado que realiza matemática adicional em cada swap (por exemplo, um LDF/rebalancer).
- Pelo menos um caminho de execução em que o arredondamento favoreça o iniciador do swap ao atravessar limiares.
- Capacidade de repetir muitos swaps atomicamente (flash loans são ideais para fornecer liquidez temporária e amortizar o gas).

## Metodologia prática do ataque

1) Identificar pools candidatos com hooks
- Enumerar pools v4 e verificar se PoolKey.hooks != address(0).
- Inspecionar o bytecode/ABI do hook em busca de callbacks: beforeSwap/afterSwap e quaisquer métodos personalizados de rebalanceamento.
- Procurar matemática que: divida pela liquidez, converta entre quantidades de tokens e liquidez ou agregue BalanceDelta com arredondamento.

2) Modelar a matemática e os limiares do hook
- Recriar a fórmula de liquidez/redistribuição do hook: as entradas normalmente incluem sqrtPriceX96, tickLower/Upper, currentTick, fee tier e liquidez líquida.
- Mapear as funções de limiar/etapa: ticks, limites de buckets ou pontos de quebra do LDF. Determinar de que lado de cada limite o delta é arredondado.
- Identificar onde as conversões fazem cast entre uint256/int256, usam SafeCast ou dependem de mulDiv com floor implícito.

3) Calibrar swaps de entrada exata para atravessar limites
- Usar simulações com Foundry/Hardhat para calcular o Δin mínimo necessário para mover o preço um pouco além de um limite e acionar o branch do hook.
- Verificar se a liquidação de afterSwap credita ao chamador mais do que o custo, deixando um BalanceDelta positivo ou crédito na contabilidade do hook.
- Repetir os swaps para acumular crédito; depois chamar o caminho de retirada/liquidação do hook.

No v4, o loop de swap deve ser executado a partir de um callback de unlock do PoolManager; `amountSpecified` negativo denota entrada exata, e `sqrtPriceLimitX96` deve estar estritamente dentro do intervalo válido. Um limite de preço zero causa revert, portanto o pseudocódigo abaixo usa o limite inferior para um swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Exemplo de harness de teste no estilo Foundry (pseudocódigo)
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
Calibrando o exactInput
- Calcule o alvo com o core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) em termos de valores reais; o resultado Q64.96 é arredondado pelo TickMath.<sup>[[13]](#references)</sup>
- Aproxime uma entrada de token0 (zero-for-one) usando a fórmula compatível com Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Corresponda ao arredondamento específico da direção da rotina core.<sup>[[12]](#references)</sup>
- Ajuste Δin em ±1 wei ao redor do limite para encontrar o branch em que o hook arredonda a seu favor.

4) Amplifique com flash loans
- Pegue emprestado um notional grande (por exemplo, 3M USDT ou 2000 WETH) para executar muitas iterações atomicamente.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Execute o loop de swap calibrado, depois retire e pague o empréstimo dentro do callback do flash loan.

Esqueleto de flash loan da Aave V3
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
- No incidente da Bunni, a liquidez de flash-loan e as rotas de bridge diferiam por chain; portanto, considere essas restrições específicas de cada chain ao reproduzir a análise.<sup>[[1]](#references)[[2]](#references)</sup>

## Causas-raiz comuns na matemática de hooks

- Semânticas de rounding mistas: mulDiv aplica floor, enquanto caminhos posteriores efetivamente aplicam round up; ou conversões entre token/liquidez aplicam roundings diferentes.
- Erros de alinhamento de tick: uso de ticks não arredondados em um caminho e rounding baseado no espaçamento de ticks em outro.
- Problemas de sinal/overflow de BalanceDelta ao converter entre int256 e uint256 durante a settlement.
- Perda de precisão em conversões Q64.96 (sqrtPriceX96) não espelhada no mapeamento reverso.
- Caminhos de acumulação: remainders por swap rastreados como créditos que podem ser sacados pelo caller em vez de serem queimados ou anulados em uma operação zero-sum.

## Custom accounting e amplificação de delta

- O custom accounting do Uniswap v4 permite que hooks retornem deltas que ajustam diretamente o que o caller deve/pode receber. Se o hook rastrear créditos internamente, o resíduo de rounding pode se acumular em muitas operações pequenas **antes** da settlement final ocorrer.<sup>[[4]](#references)</sup>
- Se o hook expuser um caminho de withdrawal compatível, um atacante poderá alternar `swap → withdraw → swap` dentro do mesmo callback de unlock do PoolManager, forçando o hook a recalcular deltas com um estado ligeiramente diferente enquanto os saldos permanecem pendentes até a settlement do unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Ao revisar hooks, sempre rastreie como BalanceDelta/HookDelta é produzido e liquidado. Um único rounding enviesado em um branch pode se tornar um crédito composto quando os deltas são recalculados repetidamente.

## Orientações defensivas

- Testes diferenciais: compare a matemática do hook com uma implementação de referência usando aritmética racional de alta precisão e exija igualdade ou um erro limitado que seja sempre adversarial (nunca favorável ao caller).
- Testes de invariantes/propriedades:
- A soma dos deltas (tokens, liquidez) em todos os caminhos de swap e ajustes do hook deve conservar valor, descontando as fees.
- Nenhum caminho deve criar crédito líquido positivo para o iniciador do swap em iterações repetidas de exactInput.
- Testes de limites de threshold/tick em torno de entradas de ±1 wei para exactInput/exactOutput.
- Política de rounding: centralize helpers de rounding que sempre arredondem contra o usuário; elimine casts inconsistentes e floors implícitos.
- Destinos de settlement: acumule resíduos inevitáveis de rounding no tesouro do protocolo ou queime-os; nunca os atribua a msg.sender.
- Rate-limits/guardrails: tamanhos mínimos de swap para triggers de rebalanceamento; desative rebalanceamentos se os deltas forem sub-wei; valide os deltas contra intervalos esperados.
- Revise os callbacks do hook de forma holística: beforeSwap/afterSwap e as alterações de liquidez before/after devem concordar quanto ao alinhamento de tick e ao rounding de delta.

## Estudo de caso: Bunni V2 (2025-09-02)

- Protocolo: Bunni V2, um hook do Uniswap v4 que usa uma Liquidity Density Function (LDF) para calcular a densidade dos tokens e estimativas de liquidez total.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools afetados: USDC/USDT na Ethereum e weETH/ETH na Unichain, totalizando aproximadamente $8.4M.<sup>[[1]](#references)</sup>
- Etapa 1 (price push): o atacante tomou emprestados ~3M USDT via flash-loan e fez swap para empurrar o tick para ~5000, reduzindo o saldo **ativo** de USDC para ~28 wei.<sup>[[1]](#references)</sup>
- Etapa 2 (drain por rounding): 44 withdrawals pequenos exploraram o floor rounding em `BunniHubLogic::withdraw()` para reduzir o saldo ativo de USDC de 28 wei para 4 wei (-85.7%), enquanto apenas uma fração mínima das LP shares era queimada. A liquidez total diminuiu ~84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Etapa 3 (sandwich de recuperação da liquidez): um swap grande moveu o tick para ~839,189 (1 USDC ≈ 2.77e36 USDT). As estimativas de liquidez inverteram-se e aumentaram ~16.8%, possibilitando um sandwich em que o atacante fez swap de volta pelo preço inflacionado e saiu com lucro.<sup>[[1]](#references)</sup>
- Correção identificada no post-mortem: alterar a atualização do saldo idle para aplicar **round up**, de modo que micro-withdrawals repetidos não reduzam progressivamente o saldo ativo do pool.<sup>[[1]](#references)</sup>

Linha vulnerável simplificada (e correção do post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Checklist de hunting

- O pool usa um endereço de hooks diferente de zero? Quais callbacks estão habilitados?
- Existem redistribuições/rebalanceamentos por swap usando matemática personalizada? Há alguma lógica de tick/threshold?
- Onde são usados divisions/mulDiv, conversões Q64.96 ou SafeCast? As semânticas de arredondamento são globalmente consistentes?
- É possível construir um Δin que ultrapasse por pouco um limite e produza um branch de arredondamento favorável? Teste ambas as direções e tanto exactInput quanto exactOutput.
- O hook rastreia credits ou deltas por caller que possam ser sacados posteriormente? Garanta que o residue seja neutralizado.

## References

- [1] [Autópsia do exploit da Bunni (set. 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit da Bunni V2: análise completa do hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit da Bunni V2: US$ 8,3 milhões drenados por uma falha de liquidez (resumo)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper da Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contexto da Uniswap v4 (pesquisa da QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mecânicas de liquidez no core da Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mecânicas de swap no core da Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks da Uniswap v4 e considerações de segurança](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol do core da Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol do core da Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams da Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol do core da Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol do core da Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey da Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
