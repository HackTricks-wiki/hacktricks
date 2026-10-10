# Exploração de DeFi/AMM: abuso de precisão/arredondamento em hooks do Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta uma classe de técnicas de exploração de DeFi/AMM contra DEXes no estilo Uniswap v4 que estendem a matemática do core com hooks personalizados. Um incidente com o Bunni V2 ilustra uma falha relacionada: um bug na direção do arredondamento na contabilização de saques subestimou a liquidez ativa, e uma swap posterior expôs essa subestimativa em um sandwich lucrativo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ideia-chave: se um hook implementa contabilização adicional que depende de matemática de ponto fixo, arredondamento de ticks e lógica de limiar, um atacante pode criar swaps exact-input que cruzam limiares específicos para que as discrepâncias de arredondamento se acumulem a seu favor. Ao repetir o padrão e depois sacar o saldo inflado, o atacante realiza o lucro, muitas vezes financiado com um flash loan.

## Contexto: hooks do Uniswap v4 e fluxo de swap

- Hooks são contratos que o PoolManager chama em pontos específicos do ciclo de vida (por exemplo, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools são inicializados com um PoolKey que inclui o contrato do hook. Um endereço de hook diferente de zero habilita os callbacks selecionados para aquele pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks podem retornar **deltas personalizados** que modificam as alterações finais de saldo de uma swap ou ação de liquidez (contabilização personalizada). Esses deltas são liquidados como saldos líquidos no fim da chamada, então qualquer erro de arredondamento na matemática do hook se acumula antes da liquidação.<sup>[[4]](#references)</sup>
- A matemática do core usa formatos de ponto fixo, como Q64.96 para sqrtPriceX96, e aritmética de ticks com 1.0001^tick. Qualquer matemática personalizada adicionada deve corresponder cuidadosamente às semânticas de arredondamento para evitar desvios dos invariantes.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps podem ser exactInput ou exactOutput. No v3/v4, o preço se move ao longo dos ticks; cruzar o limite de um tick pode ativar/desativar liquidez de intervalo. Hooks podem implementar lógica adicional ao cruzar limiares/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Arquétipo de vulnerabilidade: desvio de precisão/arredondamento ao cruzar limiares

Um padrão vulnerável típico em hooks personalizados:

1. O hook calcula deltas de liquidez ou saldo por swap usando divisão inteira, mulDiv ou conversões de ponto fixo (por exemplo, converter tokens ↔ liquidez usando sqrtPrice e intervalos de ticks).
2. A lógica de limiar (por exemplo, rebalanceamento, redistribuição em etapas ou ativação por intervalo) é acionada quando o tamanho da swap ou o movimento do preço cruza um limite interno.
3. O arredondamento é aplicado de forma inconsistente (por exemplo, truncamento em direção a zero, floor versus ceil) entre o cálculo direto e o caminho de liquidação. Pequenas discrepâncias não se anulam e, em vez disso, creditam o chamador.
4. Swaps exact-input, dimensionadas com precisão para cruzar esses limites, coletam repetidamente o resto positivo do arredondamento. O atacante saca posteriormente o crédito acumulado.

Pré-condições do ataque
- Um pool usando um hook v4 personalizado que realiza cálculos adicionais em cada swap (por exemplo, um LDF/rebalancer).
- Pelo menos um caminho de execução em que o arredondamento favorece quem inicia a swap ao cruzar limiares.
- Capacidade de repetir muitas swaps atomicamente (flash loans são ideais para fornecer fundos temporários e amortizar o gas).

## Metodologia prática do ataque

1) Identificar pools candidatos com hooks
- Enumerar pools v4 e verificar se PoolKey.hooks != address(0).
- Inspecionar o bytecode/ABI do hook em busca de callbacks: beforeSwap/afterSwap e quaisquer métodos personalizados de rebalanceamento.
- Procurar matemática que: divide pela liquidez, converte entre quantidades de tokens e liquidez ou agrega BalanceDelta com arredondamento.

2) Modelar a matemática e os limiares do hook
- Recriar a fórmula de liquidez/redistribuição do hook: as entradas normalmente incluem sqrtPriceX96, tickLower/Upper, currentTick, nível de fee e liquidez líquida.
- Mapear funções de limiar/etapas: ticks, limites de buckets ou pontos de quebra do LDF. Determinar para que lado de cada limite o delta é arredondado.
- Identificar onde as conversões fazem cast entre uint256/int256, usam SafeCast ou dependem de mulDiv com floor implícito.

3) Ajustar swaps exact-input para cruzar limites
- Usar simulações com Foundry/Hardhat para calcular o Δin mínimo necessário para mover o preço um pouco além de um limite e acionar a ramificação do hook.
- Verificar que a liquidação afterSwap credita ao chamador mais do que o custo, deixando um BalanceDelta positivo ou crédito na contabilização do hook.
- Repetir as swaps para acumular crédito; depois, chamar o caminho de saque/liquidação do hook.

No v4, o loop da swap precisa ser executado a partir de um callback de unlock do PoolManager; um `amountSpecified` negativo indica exact input, e `sqrtPriceLimitX96` precisa estar estritamente dentro do intervalo válido. Um limite de preço zero causa revert, então o pseudocódigo abaixo usa o limite inferior para uma swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Calcule o alvo usando o TickMath do core: sqrtP_next = sqrtP_current × 1.0001^(Δtick) em termos de valores reais; o resultado Q64.96 é arredondado pelo TickMath.<sup>[[13]](#references)</sup>
- Aproxime uma entrada de token0 (zero-for-one) usando a fórmula compatível com Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Aplique o arredondamento específico da direção usado pela rotina do core.<sup>[[12]](#references)</sup>
- Ajuste Δin em ±1 wei próximo ao limite para encontrar o ramo em que o hook arredonda a seu favor.

4) Amplifique com flash loans
- Pegue emprestado um valor nominal alto (por exemplo, 3M USDT ou 2000 WETH) para executar muitas iterações atomicamente.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Execute o loop de swaps calibrado, depois saque e pague o empréstimo dentro do callback do flash loan.

Estrutura básica de um flash loan da Aave V3
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

5) Saída e replicação entre chains
- Se hooks forem implantados em várias chains, repita a mesma calibração em cada uma.
- No incidente da Bunni, a liquidez de flash loan e as rotas de bridge diferiam entre chains; portanto, leve em conta essas restrições específicas de cada chain ao reproduzir a análise.<sup>[[1]](#references)[[2]](#references)</sup>

## Causas comuns de erros na matemática dos hooks

- Semânticas de arredondamento mistas: mulDiv arredonda para baixo, enquanto caminhos posteriores efetivamente arredondam para cima; ou conversões entre tokens/liquidez aplicam arredondamentos diferentes.
- Erros de alinhamento de tick: uso de ticks não arredondados em um caminho e arredondamento alinhado ao espaçamento de ticks em outro.
- Problemas de sinal/overflow de BalanceDelta ao converter entre int256 e uint256 durante a liquidação.
- Perda de precisão em conversões Q64.96 (sqrtPriceX96) que não é refletida no mapeamento inverso.
- Caminhos de acumulação: restos por swap são registrados como créditos que podem ser sacados pelo chamador, em vez de serem queimados ou zerados.

## Contabilidade personalizada e amplificação de deltas

- A contabilidade personalizada do Uniswap v4 permite que hooks retornem deltas que ajustam diretamente o que o chamador deve ou recebe. Se o hook rastrear créditos internamente, resíduos de arredondamento podem se acumular em muitas operações pequenas **antes** da liquidação final.<sup>[[4]](#references)</sup>
- Se o hook expuser um caminho de saque compatível, um atacante pode alternar `swap → withdraw → swap` dentro do mesmo callback de desbloqueio do PoolManager, forçando o hook a recalcular deltas com um estado ligeiramente diferente enquanto os saldos permanecem pendentes até a liquidação do desbloqueio.<sup>[[4]](#references)[[10]](#references)</sup>
- Ao revisar hooks, sempre rastreie como BalanceDelta/HookDelta é produzido e liquidado. Um único arredondamento enviesado em um ramo pode se transformar em um crédito acumulável quando os deltas são recalculados repetidamente.

## Orientações defensivas

- Testes diferenciais: compare a matemática do hook com uma implementação de referência usando aritmética racional de alta precisão e exija igualdade ou um erro limitado que seja sempre adversarial (nunca favorável ao chamador).
- Testes de invariantes/propriedades:
  - A soma dos deltas (tokens, liquidez) nos caminhos de swap e nos ajustes do hook deve conservar o valor, descontadas as taxas.
  - Nenhum caminho deve criar crédito líquido positivo para quem inicia o swap após iterações repetidas de exactInput.
  - Testes de limites de threshold/tick com entradas de ±1 wei para exactInput/exactOutput.
- Política de arredondamento: centralize funções auxiliares de arredondamento que sempre arredondem contra o usuário; elimine conversões inconsistentes e arredondamentos implícitos para baixo.
- Destinos de liquidação: acumule resíduos inevitáveis de arredondamento no tesouro do protocolo ou queime-os; nunca os atribua a msg.sender.
- Limites/guardrails: tamanhos mínimos de swap para acionar rebalanceamentos; desative rebalanceamentos se os deltas forem inferiores a um wei; verifique se os deltas estão dentro dos intervalos esperados.
- Revise os callbacks do hook de forma holística: beforeSwap/afterSwap e as alterações de liquidez before/after devem concordar quanto ao alinhamento de tick e ao arredondamento de deltas.

## Estudo de caso: Bunni V2 (2025‑09‑02)

- Protocolo: Bunni V2, um hook do Uniswap v4 que usa uma Liquidity Density Function (LDF) para calcular a densidade dos tokens e estimativas de liquidez total.<sup>[[1]](#references)[[2]](#references)</sup>
- Pools afetidos: USDC/USDT na Ethereum e weETH/ETH na Unichain, totalizando cerca de US$ 8,4 milhões.<sup>[[1]](#references)</sup>
- Etapa 1 (movimentação do preço): o atacante tomou emprestados ~3M USDT por flash loan e fez um swap para levar o tick a ~5000, reduzindo o saldo **ativo** de USDC para ~28 wei.<sup>[[1]](#references)</sup>
- Etapa 2 (drenagem por arredondamento): 44 saques pequenos exploraram o arredondamento para baixo em `BunniHubLogic::withdraw()` para reduzir o saldo ativo de USDC de 28 wei para 4 wei (-85,7%), queimando apenas uma fração minúscula das cotas de LP. A liquidez total diminuiu ~84,4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Etapa 3 (sandwich de recuperação da liquidez): um swap grande moveu o tick para ~839,189 (1 USDC ≈ 2.77e36 USDT). As estimativas de liquidez inverteram-se e aumentaram ~16,8%, permitindo um sandwich no qual o atacante fez o swap de volta pelo preço inflado e saiu com lucro.<sup>[[1]](#references)</sup>
- Correção identificada na análise post-mortem: alterar a atualização do saldo ocioso para arredondar **para cima**, impedindo que micro-saques repetidos reduzam gradualmente o saldo ativo do pool.<sup>[[1]](#references)</sup>

Linha vulnerável simplificada (e correção da análise post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Checklist de hunting

- O pool usa um endereço de hooks diferente de zero? Quais callbacks estão habilitados?
- Há redistribuições/rebalanceamentos por swap que usam matemática personalizada? Existe alguma lógica de tick/limiar?
- Onde são usados divisões/mulDiv, conversões Q64.96 ou SafeCast? As regras de arredondamento são consistentes globalmente?
- É possível construir um Δin que cruze por pouco um limite e resulte em uma ramificação de arredondamento favorável? Teste ambas as direções e tanto exactInput quanto exactOutput.
- O hook rastreia créditos ou deltas por chamador que possam ser retirados posteriormente? Garanta que qualquer resíduo seja neutralizado.

## References

- [1] [Análise pós-incidente do exploit da Bunni (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Exploit da Bunni V2: análise completa do hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Exploit da Bunni V2: US$ 8,3 milhões drenados por falha de liquidez (resumo)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper do Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Contexto do Uniswap v4 (pesquisa da QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Mecânica de liquidez no core do Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Mecânica de swap no core do Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks do Uniswap v4 e considerações de segurança](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol do core do Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol do core do Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams do Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol do core do Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol do core do Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey do Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
