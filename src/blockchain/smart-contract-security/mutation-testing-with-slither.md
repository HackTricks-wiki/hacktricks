# Mutation Testing para Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "testa seus testes" ao introduzir sistematicamente pequenas alterações (mutantes) no código do contrato e executar novamente a suíte de testes. Se um teste falhar, o mutante é eliminado. Se os testes continuarem passando, o mutante sobrevive, revelando um ponto cego que a coverage de linhas/branches não consegue detectar.

Ideia principal: a coverage mostra que o código foi executado; o mutation testing mostra se o comportamento é realmente verificado.<sup>[[2]](#references)</sup>

## Por que a coverage pode enganar

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
Testes unitários que verificam apenas um valor abaixo e um valor acima do limite podem alcançar 100% de cobertura de linhas/branches sem testar a fronteira de igualdade (`==`). Uma refatoração para `deposit >= 2 ether` ainda passaria nesses testes, quebrando silenciosamente a lógica do protocolo.<sup>[[2]](#references)</sup>

Mutation testing expõe essa lacuna ao mutar a condição e verificar se os testes falham.

Para smart contracts, os mutants sobreviventes frequentemente correspondem à ausência de verificações relacionadas a:
- Autorização e limites de roles
- Invariantes de contabilidade/transferência de valores
- Condições de revert e caminhos de falha
- Condições de limite (`==`, valores zero, arrays vazios, valores máximos/mínimos)

## Mutation operators com o maior security signal

Classes úteis de mutação para auditoria de contracts:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severidade**: substituir statements por `revert()` para expor caminhos não executados
- **Média severidade**: comentar linhas / remover lógica para revelar side effects não verificados
- **Baixa severidade**: substituições sutis de operadores ou constantes, como `>=` -> `>` ou `+` -> `-`
- Outras edições comuns: substituição de assignments, inversões booleanas, negação de condições e alterações de tipos

Objetivo prático: eliminar todos os mutants relevantes e justificar explicitamente os sobreviventes que sejam irrelevantes ou semanticamente equivalentes.

## Por que mutation syntax-aware é melhor do que regex

Engines de mutação antigos dependiam de regex ou reescritas orientadas a linhas. Isso funciona, mas tem limitações importantes:<sup>[[1]](#references)</sup>
- Statements multilinha são difíceis de mutar com segurança
- A estrutura da linguagem não é compreendida, portanto comments/tokens podem ser selecionados incorretamente
- Gerar todas as variantes possíveis em uma linha pouco expressiva desperdiça grandes quantidades de runtime

Ferramentas baseadas em AST ou Tree-sitter melhoram esse processo ao selecionar nodes estruturados em vez de linhas brutas:<sup>[[1]](#references)</sup>
- **slither-mutate** usa o AST de Solidity do Slither
- **mewt** usa Tree-sitter como core agnóstico de linguagem
- **MuTON** é baseado em `mewt` e adiciona suporte de primeira classe a linguagens da TON, como FunC, Tolk e Tact

Isso torna constructs multilinha e mutações em nível de expressão muito mais confiáveis do que abordagens baseadas somente em regex.

## Executando mutation testing com slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opções e mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemplo com Foundry (capturar resultados e manter um log completo):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se você não usa Foundry, substitua `--test-cmd` pelo comando usado para executar os testes (por exemplo, `npx hardhat test`, `npm test`).

Os artifacts são armazenados em `./mutation_campaign` por padrão. Os mutants não capturados (sobreviventes) são copiados para esse diretório para inspeção.<sup>[[5]](#references)</sup>

### Entendendo a saída

As linhas do relatório têm esta aparência:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- A tag entre colchetes é o alias do mutator (por exemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram sob o comportamento mutado → asserção ausente.

## Reduzindo o tempo de execução: priorize mutantes impactantes

Campanhas de mutation testing podem levar horas ou dias. Dicas para reduzir o custo:<sup>[[1]](#references)[[2]](#references)</sup>
- Escopo: comece apenas com contracts/diretórios críticos e depois amplie.
- Priorize mutators: se um mutante de alta prioridade em uma linha sobreviver (por exemplo, `revert()` ou comment-out), ignore as variantes de menor prioridade para essa linha.
- Use campanhas em duas fases: execute primeiro testes focados/rápidos e, em seguida, teste novamente apenas os mutantes não capturados com o conjunto completo de testes.
- Mapeie os alvos de mutação para comandos de teste específicos quando possível (por exemplo, código de autenticação -> testes de autenticação).
- Restrinja as campanhas a mutantes de severidade alta/média quando o tempo for limitado.
- Execute os testes em paralelo se o runner permitir; armazene em cache as dependências/builds.
- Fail-fast: pare cedo quando uma alteração demonstrar claramente uma lacuna de asserção.

A matemática do tempo de execução é brutal: `1000 mutants x 5-minute tests ~= 83 hours`; portanto, o design da campanha é tão importante quanto o próprio mutator.

## Campanhas persistentes e triagem em escala

Uma fraqueza dos workflows antigos é despejar os resultados apenas em `stdout`. Para campanhas longas, isso dificulta pausar/retomar, filtrar e revisar.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` melhoram isso armazenando mutantes e resultados em campanhas baseadas em SQLite. Benefícios:<sup>[[1]](#references)</sup>
- Pausar e retomar execuções longas sem perder o progresso
- Filtrar apenas mutantes não capturados em um arquivo específico ou classe de mutação
- Exportar/traduzir resultados para SARIF para ferramentas de revisão
- Fornecer à triagem assistida por IA conjuntos de resultados menores e filtrados, em vez de logs brutos do terminal

Resultados persistentes são especialmente úteis quando o mutation testing se torna parte de um pipeline de auditoria, em vez de uma revisão manual pontual.

## Workflow de triagem para mutantes sobreviventes

1) Inspecione a linha e o comportamento mutados.
- Reproduza localmente aplicando a linha mutada e executando um teste focado.

2) Fortaleça os testes para verificar o estado, não apenas os valores retornados.
- Adicione verificações dos limites de igualdade (por exemplo, teste o threshold `==`).
- Verifique as pós-condições: saldos, total supply, efeitos de autorização e eventos emitidos.

3) Substitua mocks permissivos demais por comportamentos realistas.
- Garanta que os mocks imponham transfers, failure paths e emissões de eventos que ocorram on-chain.

4) Adicione invariants aos testes de fuzz.
- Por exemplo, conservação de valor, saldos não negativos, invariants de autorização e supply monotônico quando aplicável.

5) Separe true positives de semantic no-ops.
- Exemplo: `x > 0` -> `x != 0` não tem significado quando `x` é unsigned.

6) Execute novamente a campanha até que os sobreviventes sejam eliminados ou explicitamente justificados.

## Estudo de caso: revelando asserções de estado ausentes (protocolo Arkis)

Uma campanha de mutation testing durante uma auditoria do protocolo DeFi Arkis revelou sobreviventes como:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar a atribuição não interrompeu os testes, comprovando a ausência de asserções de pós-estado. Causa raiz: o código confiava em um `_cmd.value` controlado pelo usuário, em vez de validar as transferências reais de tokens. Um atacante poderia dessincronizar as transferências esperadas das reais para drenar fundos. Resultado: risco de alta severidade para a solvência do protocolo.<sup>[[2]](#references)[[3]](#references)</sup>

Orientação: Trate mutants sobreviventes que afetem transferências de valor, contabilidade ou controle de acesso como de alto risco até que sejam eliminados.

## Não gere testes cegamente para eliminar todos os mutants

A geração de testes orientada por mutation testing pode sair pela culatra se a implementação atual estiver errada. Exemplo: mutar `priority >= 2` para `priority > 2` altera o comportamento, mas a correção certa nem sempre é "escrever um teste para `priority == 2`". Esse comportamento pode ser o próprio bug.<sup>[[1]](#references)</sup>

Workflow mais seguro:
- Use mutants sobreviventes para identificar requisitos ambíguos
- Valide o comportamento esperado com base em specs, documentação do protocolo ou revisores
- Só então codifique o comportamento como um teste/invariant

Caso contrário, você corre o risco de codificar acidentes de implementação na test suite e obter uma falsa sensação de confiança.

## Checklist prático

- Execute uma campanha direcionada:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefira mutators conscientes da sintaxe (AST/Tree-sitter) em vez de mutation baseada apenas em regex, quando disponível.
- Faça a triagem dos mutants sobreviventes e escreva testes/invariants que falhariam sob o comportamento mutado.
- Valide saldos, supply, autorizações e events.
- Adicione testes de limites (`==`, overflows/underflows, zero-address, zero-amount, arrays vazios).
- Substitua mocks irrealistas; simule modos de falha.
- Persista os resultados quando a ferramenta oferecer suporte e filtre os mutants não capturados antes da triagem.
- Use campanhas em duas fases ou por alvo para manter o runtime gerenciável.
- Repita até que todos os mutants sejam eliminados ou justificados com comentários e rationale.

## Referências

- [1] [Mutation testing para a era agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing para encontrar os bugs que seus testes não detectam (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Revisão de segurança da Arkis DeFi Prime Brokerage (Apêndice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentação do Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
