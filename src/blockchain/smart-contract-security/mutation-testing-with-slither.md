# Mutation Testing para Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

O Mutation testing "testa seus testes" ao introduzir sistematicamente pequenas alterações (mutantes) no código do contrato e executar novamente a test suite. Se um teste falhar, o mutante é eliminado. Se os testes continuarem passando, o mutante sobrevive, revelando um ponto cego que a cobertura de linhas/branches não consegue detectar.

Ideia principal: a cobertura mostra que o código foi executado; o mutation testing mostra se o comportamento é realmente validado.<sup>[[2]](#references)</sup>

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
Testes unitários que verificam apenas um valor abaixo e um valor acima do limite podem alcançar 100% de cobertura de linhas/branches sem verificar a fronteira de igualdade (==). Uma refatoração para `deposit >= 2 ether` ainda passaria nesses testes, quebrando silenciosamente a lógica do protocolo.<sup>[[2]](#references)</sup>

Mutation testing expõe essa lacuna ao modificar a condição e verificar se os testes falham.

Para smart contracts, mutantes sobreviventes frequentemente correspondem à ausência de verificações relacionadas a:
- Autorização e limites de funções
- Invariantes de contabilidade/transferência de valores
- Condições de revert e caminhos de falha
- Condições de fronteira (`==`, valores zero, arrays vazios, valores máximo/mínimo)

## Mutation operators with the highest security signal

Classes úteis de mutação para auditoria de contratos:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severidade**: substituir statements por `revert()` para expor caminhos não executados
- **Severidade média**: comentar linhas / remover lógica para revelar side effects não verificados
- **Baixa severidade**: substituições sutis de operadores ou constantes, como `>=` -> `>` ou `+` -> `-`
- Outras edições comuns: substituição de atribuições, inversões booleanas, negação de condições e alterações de tipo

Objetivo prático: eliminar todos os mutantes relevantes e justificar explicitamente os sobreviventes que sejam irrelevantes ou semanticamente equivalentes.

## Why syntax-aware mutation is better than regex

Engines de mutação antigos dependiam de regex ou reescritas orientadas por linhas. Isso funciona, mas apresenta limitações importantes:<sup>[[1]](#references)</sup>
- Statements multilinha são difíceis de modificar com segurança
- A estrutura da linguagem não é compreendida, portanto comentários/tokens podem ser selecionados incorretamente
- Gerar todas as variantes possíveis em uma linha inadequada desperdiça grandes quantidades de runtime

Ferramentas baseadas em AST ou Tree-sitter melhoram esse processo ao direcionar nós estruturados em vez de linhas brutas:<sup>[[1]](#references)</sup>
- **slither-mutate** usa o AST de Solidity do Slither.<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter como um core agnóstico de linguagem.<sup>[[6]](#references)</sup>
- **MuTON** é baseado em `mewt` e adiciona suporte de primeira classe a linguagens da TON, como FunC, Tolk e Tact.<sup>[[7]](#references)</sup>

Isso torna construções multilinha e mutações no nível de expressões muito mais confiáveis do que abordagens baseadas apenas em regex.

## Running mutation testing with slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opções e mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemplo de Foundry (capture os resultados e mantenha um log completo):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se você não usa Foundry, substitua `--test-cmd` pelo comando usado para executar os testes (por exemplo, `npx hardhat test`, `npm test`).

Por padrão, os artifacts são armazenados em `./mutation_campaign`. Mutantes não capturados (sobreviventes) são copiados para esse diretório para inspeção.<sup>[[5]](#references)</sup>

### Entendendo a saída

As linhas do relatório têm esta aparência:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- A tag entre colchetes é o alias do mutator (por exemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram sob o comportamento mutado → asserção ausente.

## Reduzindo o tempo de execução: priorize mutants impactantes

Campanhas de mutação podem levar horas ou dias. Dicas para reduzir o custo:<sup>[[1]](#references)[[2]](#references)</sup>
- Escopo: comece apenas pelos contracts/diretórios críticos e depois expanda.
- Priorize mutators: se um mutant de alta prioridade em uma linha sobreviver (por exemplo, `revert()` ou comment-out), ignore as variantes de menor prioridade para essa linha.
- Use campanhas em duas fases: execute primeiro testes focados/rápidos e, depois, teste novamente apenas os mutants `UNCAUGHT` com a suíte completa.
- Mapeie os alvos de mutação para comandos de teste específicos quando possível (por exemplo, código de autenticação -> testes de autenticação).
- Restrinja as campanhas a mutants de severidade alta/média quando o tempo for limitado.
- Paralelize os testes se o seu runner permitir; armazene em cache as dependências/builds.
- Fail-fast: pare antecipadamente quando uma alteração demonstrar claramente uma lacuna de asserção.

A matemática do tempo de execução é brutal: `1000 mutants x 5-minute tests ~= 83 hours`, portanto o design da campanha é tão importante quanto o próprio mutator.<sup>[[1]](#references)</sup>

## Campanhas persistentes e triagem em escala

Uma fraqueza dos workflows antigos é despejar os resultados apenas em `stdout`. Em campanhas longas, isso dificulta pausar/retomar, filtrar e revisar.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` melhoram isso armazenando mutants e resultados em campanhas baseadas em SQLite. Benefícios:<sup>[[1]](#references)</sup>
- Pausar e retomar execuções longas sem perder o progresso
- Filtrar apenas mutants `UNCAUGHT` em um arquivo ou mutation class específico
- Exportar/traduzir resultados para SARIF para ferramentas de revisão
- Fornecer à triagem assistida por IA conjuntos de resultados menores e filtrados, em vez de logs brutos do terminal

Resultados persistentes são especialmente úteis quando mutation testing se torna parte de um pipeline de auditoria, em vez de uma revisão manual pontual.

## Workflow de triagem para mutants sobreviventes

1) Inspecione a linha e o comportamento mutados.
- Reproduza localmente aplicando a linha mutada e executando um teste focado.

2) Fortaleça os testes para verificar o estado, não apenas os valores retornados.
- Adicione verificações de limites de igualdade (por exemplo, teste o limite `==`).
- Verifique as pós-condições: saldos, oferta total, efeitos de autorização e eventos emitidos.

3) Substitua mocks excessivamente permissivos por um comportamento realista.
- Garanta que os mocks imponham transferências, caminhos de falha e emissões de eventos que ocorram on-chain.

4) Adicione invariants aos testes de fuzz.
- Por exemplo, conservação de valor, saldos não negativos, invariants de autorização e oferta monotônica quando aplicável.

5) Separe os verdadeiros positivos dos no-ops semânticos.
- Exemplo: `x > 0` -> `x != 0` não tem significado quando `x` é unsigned.

6) Execute novamente a campanha até que os survivors sejam eliminados ou explicitamente justificados.

## Estudo de caso: revelando asserções de estado ausentes (protocolo Arkis)

Uma campanha de mutação durante uma auditoria do protocolo DeFi Arkis revelou survivors como:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar a atribuição não interrompeu os testes, comprovando a ausência de asserções do estado posterior. Causa-raiz: o código confiava em um `_cmd.value` controlado pelo usuário em vez de validar as transferências reais de tokens. Um atacante poderia dessincronizar as transferências esperadas e reais para drenar fundos. Resultado: risco de alta severidade para a solvência do protocolo.<sup>[[2]](#references)[[3]](#references)</sup>

Orientação: trate mutantes sobreviventes que afetem transferências de valor, contabilidade ou controle de acesso como de alto risco até serem eliminados.

## Não gere testes cegamente para eliminar todos os mutantes

A geração de testes orientada por mutações pode sair pela culatra se a implementação atual estiver errada. Exemplo: mutar `priority >= 2` para `priority > 2` altera o comportamento, mas a correção adequada nem sempre é "escrever um teste para `priority == 2`". Esse comportamento pode ser o próprio bug.<sup>[[1]](#references)</sup>

Fluxo de trabalho mais seguro:
- Use mutantes sobreviventes para identificar requisitos ambíguos
- Valide o comportamento esperado com base em especificações, documentação do protocolo ou revisores
- Só então codifique o comportamento como um teste/invariante

Caso contrário, você corre o risco de codificar acidentalmente detalhes da implementação no conjunto de testes e obter uma falsa confiança.

## Checklist prático

- Execute uma campanha direcionada:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefira mutators com conhecimento de sintaxe (AST/Tree-sitter) em vez de mutação baseada apenas em regex, quando disponível.
- Faça a triagem dos mutantes sobreviventes e escreva testes/invariantes que falhariam sob o comportamento mutado.
- Verifique saldos, supply, autorizações e eventos.
- Adicione testes de limites (`==`, overflows/underflows, zero-address, zero-amount, arrays vazios).
- Substitua mocks irreais; simule modos de falha.
- Persista os resultados quando a ferramenta oferecer suporte e filtre os mutantes não capturados antes da triagem.
- Use campanhas em duas fases ou por alvo para manter o tempo de execução gerenciável.
- Itere até que todos os mutantes sejam eliminados ou justificados com comentários e fundamentação.

## References

- [1] [Testes de mutação para a era agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use testes de mutação para encontrar os bugs que seus testes não detectam (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Revisão de segurança da Arkis DeFi Prime Brokerage (Apêndice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentação do Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
