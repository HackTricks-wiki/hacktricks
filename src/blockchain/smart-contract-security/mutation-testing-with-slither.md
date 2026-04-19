# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "testa seus testes" ao introduzir sistematicamente pequenas mudanças (mutants) no código do contrato e reexecutar a suíte de testes. Se um teste falhar, o mutant é morto. Se os testes ainda passarem, o mutant sobrevive, revelando um ponto cego que a cobertura de linha/branch não consegue detectar.

Ideia principal: Coverage mostra que o código foi executado; mutation testing mostra se o comportamento realmente foi asserted.

## Why coverage can deceive

Considere esta simples verificação de threshold:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testes unitários que apenas verificam um valor abaixo e um valor acima do threshold podem alcançar 100% de cobertura de linha/branch enquanto deixam de afirmar a igualdade na boundary (==). Um refactor para `deposit >= 2 ether` ainda passaria nesses testes, quebrando silenciosamente a lógica do protocolo.

Mutation testing expõe essa lacuna ao mutar a condição e verificar se os testes falham.

Para smart contracts, mutants que sobrevivem frequentemente apontam para checks ausentes em torno de:
- Authorization e limites de role
- Invariantes de accounting/value-transfer
- Condições de revert e caminhos de falha
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators com o maior sinal de security

Classes de mutação úteis para auditoria de contratos:
- **High severity**: substituir statements por `revert()` para expor caminhos não executados
- **Medium severity**: comentar linhas / remover lógica para revelar side effects não verificados
- **Low severity**: trocas sutis de operadores ou constantes, como `>=` -> `>` ou `+` -> `-`
- Outras edições comuns: substituição de assignment, flips booleanos, negação de condição e mudanças de tipo

Objetivo prático: matar todos os mutants significativos e justificar explicitamente os sobreviventes que sejam irrelevantes ou semanticamente equivalentes.

## Why syntax-aware mutation is better than regex

Motores de mutação mais antigos dependiam de regex ou de rewrites orientados por linha. Isso funciona, mas tem limitações importantes:
- Statements multi-line são difíceis de mutar com segurança
- A estrutura da linguagem não é entendida, então comments/tokens podem ser alvo de forma inadequada
- Gerar toda variante possível em uma linha fraca desperdiça muito runtime

Ferramentas baseadas em AST ou Tree-sitter melhoram isso ao mirar nós estruturados em vez de linhas brutas:
- **slither-mutate** usa o Solidity AST do Slither
- **mewt** usa Tree-sitter como um core agnóstico de linguagem
- **MuTON** se baseia em `mewt` e adiciona suporte de primeira classe para linguagens TON como FunC, Tolk e Tact

Isso torna constructs multi-line e mutações em nível de expressão muito mais confiáveis do que abordagens apenas com regex.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemplo de Foundry (capturar resultados e manter um log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se você não usar Foundry, substitua `--test-cmd` por como você executa os testes (por exemplo, `npx hardhat test`, `npm test`).

Os artefatos são armazenados em `./mutation_campaign` por padrão. Mutants não capturados (sobreviventes) são copiados para lá para inspeção.

### Entendendo a saída

As linhas do relatório ficam assim:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- A tag entre colchetes é o alias do mutator (por exemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram sob o comportamento mutado → assertion ausente.

## Reduzindo runtime: priorize mutants impactantes

Campaigns de Mutation Testing podem levar horas ou dias. Dicas para reduzir custo:
- Scope: Comece apenas com contratos/diretórios críticos, depois expanda.
- Priorize mutators: Se um mutant de alta prioridade em uma linha sobreviver (por exemplo `revert()` ou comment-out), pule variantes de menor prioridade para aquela linha.
- Use campanhas em duas fases: execute primeiro testes focados/rápidos, depois re-teste apenas mutants uncaught com a suíte completa.
- Mapeie os alvos de mutation para comandos específicos de teste quando possível (por exemplo código auth -> testes auth).
- Restrinja campaigns a mutants de severidade alta/média quando o tempo for curto.
- Paralelize os testes se seu runner permitir; faça cache de dependências/builds.
- Fail-fast: pare cedo quando uma mudança demonstrar claramente uma lacuna de assertion.

A matemática do runtime é brutal: `1000 mutants x 5-minute tests ~= 83 hours`, então o design da campaign importa tanto quanto o mutator em si.

## Campaigns persistentes e triagem em escala

Uma fraqueza dos workflows antigos é despejar resultados apenas em `stdout`. Para campaigns longas, isso dificulta pause/resume, filtragem e revisão.

`mewt`/`MuTON` melhoram isso armazenando mutants e outcomes em campaigns suportadas por SQLite. Benefícios:
- Pause e resume de execuções longas sem perder progresso
- Filtre apenas mutants uncaught em um arquivo específico ou classe de mutation
- Exporte/traduzza resultados para SARIF para tooling de review
- Dê à triagem assistida por IA conjuntos de resultados menores e filtrados em vez de logs brutos do terminal

Resultados persistentes são especialmente úteis quando mutation testing vira parte de um pipeline de audit em vez de uma revisão manual pontual.

## Workflow de triagem para mutants sobreviventes

1) Inspecione a linha mutada e o comportamento.
- Reproduza localmente aplicando a linha mutada e executando um teste focado.

2) Fortaleça os testes para afirmar estado, não apenas valores de retorno.
- Adicione checagens de boundary de igualdade (por exemplo, teste o threshold `==`).
- Afirme pós-condições: balances, total supply, efeitos de authorization e eventos emitidos.

3) Substitua mocks permissivos demais por comportamento realista.
- Garanta que os mocks imponham transfers, paths de falha e emissões de eventos que ocorrem on-chain.

4) Adicione invariants para fuzz tests.
- Por exemplo, conservação de valor, balances não negativos, invariants de authorization, supply monotônico quando aplicável.

5) Separe verdadeiros positivos de semantic no-ops.
- Exemplo: `x > 0` -> `x != 0` é sem sentido quando `x` é unsigned.

6) Execute a campaign novamente até que os survivors sejam mortos ou explicitamente justificados.

## Case study: revelando assertions de estado ausentes (Arkis protocol)

Uma mutation campaign durante uma audit do protocolo Arkis DeFi revelou survivors como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Orientação: Trate survivors que afetam value transfers, accounting, ou access control como high-risk até serem killed.

## Não gere testes cegamente para matar todo mutant

A geração de testes dirigida por mutation pode sair pela culatra se a implementação atual estiver errada. Exemplo: mutar `priority >= 2` para `priority > 2` muda o comportamento, mas a correção certa nem sempre é "escreva um teste para `priority == 2`". Esse comportamento pode ser justamente o bug.

Fluxo mais seguro:
- Use survivors para identificar requirements ambíguos
- Valide o comportamento esperado a partir de specs, protocol docs, ou reviewers
- Só então codifique o comportamento como teste/invariant

Caso contrário, você corre o risco de hard-code de acidentes de implementação no test suite e de ganhar uma falsa sensação de confiança.

## Checklist prático

- Rode uma campanha direcionada:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefira mutators com consciência de syntax (AST/Tree-sitter) em vez de mutation só por regex quando disponível.
- Triagem survivors e escreva testes/invariants que falhariam sob o comportamento mutado.
- Assert balances, supply, authorizations, and events.
- Adicione testes de boundary (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Substitua mocks irreais; simule failure modes.
- Persista resultados quando a tooling suportar, e filtre mutants uncaught antes da triagem.
- Use campanhas em duas fases ou por target para manter o runtime manejável.
- Itere até que todos os mutants sejam killed ou justificados com comentários e rationale.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
