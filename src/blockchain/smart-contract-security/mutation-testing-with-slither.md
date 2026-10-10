# Testes de mutação para smart contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Os testes de mutação "testam seus testes" ao introduzir sistematicamente pequenas alterações (mutantes) no código do contrato e executar novamente a suíte de testes. Se um teste falhar, o mutante é eliminado. Se os testes ainda passarem, o mutante sobrevive, revelando um ponto cego que a cobertura de linhas/ramificações não consegue detectar.

Ideia principal: a cobertura mostra que o código foi executado; os testes de mutação mostram se o comportamento foi realmente verificado.<sup>[[2]](#references)</sup>

## Por que a cobertura pode enganar

Considere esta simples verificação de limite:

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

Testes unitários que verificam apenas um valor abaixo e outro acima do limite podem alcançar 100% de cobertura de linhas/ramificações sem testar o limite de igualdade (`==`). Uma refatoração para `deposit >= 2 ether` ainda passaria nesses testes, quebrando silenciosamente a lógica do protocolo.<sup>[[2]](#references)</sup>

O mutation testing expõe essa lacuna ao mutar a condição e verificar se os testes falham.

Em smart contracts, mutantes sobreviventes frequentemente apontam para verificações ausentes relacionadas a:
- Autorização e limites de funções
- Invariantes de contabilidade/transferência de valores
- Condições de revert e caminhos de falha
- Condições de limite (`==`, valores zero, arrays vazios, valores máximos/mínimos)

## Operadores de mutação com maior sinal de segurança

Classes de mutação úteis para auditoria de contratos:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severidade**: substituir instruções por `revert()` para expor caminhos não executados
- **Média severidade**: comentar linhas / remover lógica para revelar efeitos colaterais não verificados
- **Baixa severidade**: trocas sutis de operadores ou constantes, como `>=` -> `>` ou `+` -> `-`
- Outras alterações comuns: substituição de atribuições, inversões booleanas, negação de condições e mudanças de tipo

Objetivo prático: eliminar todos os mutantes relevantes e justificar explicitamente os sobreviventes que forem irrelevantes ou semanticamente equivalentes.

## Por que mutação consciente da sintaxe é melhor do que regex

Mecanismos de mutação mais antigos dependiam de regex ou de reescritas orientadas por linha. Isso funciona, mas tem limitações importantes:<sup>[[1]](#references)</sup>
- É difícil mutar instruções de várias linhas com segurança
- A estrutura da linguagem não é compreendida, então comentários/tokens podem ser selecionados incorretamente
- Gerar todas as variantes possíveis em uma linha pouco relevante desperdiça muito tempo de execução

Ferramentas baseadas em AST ou Tree-sitter melhoram isso ao selecionar nós estruturados em vez de linhas brutas:<sup>[[1]](#references)</sup>
- **slither-mutate** usa o AST de Solidity do Slither.<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter como núcleo agnóstico à linguagem.<sup>[[6]](#references)</sup>
- **MuTON** se baseia em `mewt` e adiciona suporte nativo a linguagens TON, como FunC, Tolk e Tact.<sup>[[7]](#references)</sup>

Isso torna as construções de várias linhas e as mutações no nível de expressão muito mais confiáveis do que as abordagens baseadas apenas em regex.

## Executando mutation testing com slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opções e operadores de mutação:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Exemplo do Foundry (capture os resultados e mantenha um log completo):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Se você não usa Foundry, substitua `--test-cmd` pelo comando que você usa para executar os testes (por exemplo, `npx hardhat test`, `npm test`).

Por padrão, os artefatos são armazenados em `./mutation_campaign`. Os mutantes não capturados (sobreviventes) são copiados para lá para inspeção.<sup>[[5]](#references)</sup>

### Entendendo a saída

As linhas do relatório são assim:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- A tag entre colchetes é o alias do mutador (por exemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram com o comportamento mutado → falta uma asserção.

## Reduzindo o tempo de execução: priorize mutantes impactantes

As campanhas de mutação podem levar horas ou dias. Dicas para reduzir o custo:<sup>[[1]](#references)[[2]](#references)</sup>
- Escopo: comece apenas pelos contratos/diretórios críticos e, depois, amplie.
- Priorize os mutadores: se um mutante de alta prioridade em uma linha sobreviver (por exemplo, `revert()` ou comentário removido), ignore as variantes de prioridade mais baixa nessa linha.
- Use campanhas em duas fases: execute primeiro testes focados e rápidos; depois, teste novamente apenas os mutantes não capturados com a suíte completa.
- Sempre que possível, associe os alvos de mutação a comandos de teste específicos (por exemplo, código de autenticação -> testes de autenticação).
- Quando o tempo for curto, restrinja as campanhas a mutantes de severidade alta/média.
- Execute os testes em paralelo, se o executor permitir; armazene em cache as dependências/builds.
- Interrompa rapidamente: pare assim que uma alteração demonstrar claramente uma lacuna nas asserções.

O cálculo do tempo de execução é brutal: `1000 mutants x 5-minute tests ~= 83 hours`; por isso, o planejamento da campanha importa tanto quanto o próprio mutador.<sup>[[1]](#references)</sup>

## Campanhas persistentes e triagem em grande escala

Uma fragilidade dos fluxos de trabalho antigos é despejar os resultados apenas em `stdout`. Em campanhas longas, isso dificulta pausar/retomar, filtrar e revisar.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` melhoram isso armazenando mutantes e resultados em campanhas respaldadas por SQLite. Benefícios:<sup>[[1]](#references)</sup>
- Pause e retome execuções longas sem perder o progresso
- Filtre apenas os mutantes não capturados em um arquivo ou classe de mutação específicos
- Exporte/traduza resultados para SARIF para ferramentas de revisão
- Forneça à triagem assistida por IA conjuntos de resultados menores e filtrados, em vez de logs brutos do terminal

Os resultados persistentes são especialmente úteis quando os testes de mutação passam a fazer parte de um pipeline de auditoria, em vez de uma revisão manual pontual.

## Fluxo de trabalho de triagem para mutantes sobreviventes

1) Inspecione a linha e o comportamento mutados.
   - Reproduza o caso localmente aplicando a linha mutada e executando um teste focado.

2) Reforce os testes para verificar o estado, não apenas os valores retornados.
   - Adicione verificações de limites de igualdade (por exemplo, teste o limiar `==`).
   - Verifique as pós-condições: saldos, oferta total, efeitos de autorização e eventos emitidos.

3) Substitua mocks permissivos demais por comportamentos realistas.
   - Garanta que os mocks reproduzam transferências, caminhos de falha e emissões de eventos que ocorrem on-chain.

4) Adicione invariantes aos testes fuzz.
   - Por exemplo: conservação de valor, saldos não negativos, invariantes de autorização e oferta monotônica, quando aplicável.

5) Separe os verdadeiros positivos dos no-ops semânticos.
   - Exemplo: `x > 0` -> `x != 0` não faz diferença quando `x` é unsigned.

6) Execute novamente a campanha até eliminar os sobreviventes ou justificá-los explicitamente.

## Estudo de caso: revelando asserções de estado ausentes (protocolo Arkis)

Uma campanha de mutação durante uma auditoria do protocolo DeFi Arkis revelou sobreviventes como:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Comentar a atribuição não fez os testes falharem, comprovando a ausência de asserções sobre o estado final. Causa raiz: o código confiava em `_cmd.value`, controlado pelo usuário, em vez de validar as transferências reais de tokens. Um invasor poderia dessincronizar as transferências esperadas das reais para drenar fundos. Resultado: risco de alta gravidade para a solvência do protocolo.<sup>[[2]](#references)[[3]](#references)</sup>

Orientação: trate mutantes sobreviventes que afetam transferências de valor, contabilidade ou controle de acesso como de alto risco até serem eliminados.

## Não gere testes às cegas para eliminar todos os mutantes

A geração de testes orientada por mutações pode sair pela culatra se a implementação atual estiver errada. Exemplo: mutar `priority >= 2` para `priority > 2` altera o comportamento, mas a correção certa nem sempre é "escrever um teste para `priority == 2`". Esse comportamento pode ser, por si só, o bug.<sup>[[1]](#references)</sup>

Fluxo de trabalho mais seguro:
- Use os mutantes sobreviventes para identificar requisitos ambíguos
- Valide o comportamento esperado com base em especificações, documentação do protocolo ou revisores
- Só então codifique o comportamento como teste/invariante

Caso contrário, você corre o risco de incorporar acidentes da implementação à suíte de testes e ganhar uma falsa sensação de segurança.

## Lista de verificação prática

- Execute uma campanha direcionada:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefira mutadores que entendam a sintaxe (AST/Tree-sitter) a mutações baseadas apenas em regex, quando disponíveis.
- Analise os mutantes sobreviventes e escreva testes/invariantes que falhariam com o comportamento mutado.
- Verifique saldos, oferta, autorizações e eventos.
- Adicione testes de limites (`==`, overflows/underflows, endereço zero, valor zero, arrays vazios).
- Substitua mocks irreais; simule modos de falha.
- Persista os resultados quando a ferramenta oferecer suporte e filtre os mutantes não capturados antes da análise.
- Use campanhas em duas fases ou por alvo para manter o tempo de execução gerenciável.
- Repita até que todos os mutantes sejam eliminados ou justificados com comentários e fundamentação.

## References

- [1] [Teste de mutação para a era agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use o teste de mutação para encontrar os bugs que seus testes não detectam (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Revisão de segurança da Arkis DeFi Prime Brokerage (Apêndice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentação do Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
