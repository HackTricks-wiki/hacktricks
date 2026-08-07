# Mutation Testing para Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "testa seus testes" ao introduzir sistematicamente pequenas alterações (mutantes) no código do contrato e executar novamente a suíte de testes. Se um teste falhar, o mutante é eliminado. Se os testes continuarem passando, o mutante sobrevive, revelando um ponto cego que a cobertura de linhas/branches não consegue detectar.

Ideia principal: a cobertura mostra que o código foi executado; mutation testing mostra se o comportamento foi realmente validado.<sup>[[2]](#references)</sup>

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
Testes unitários que verificam apenas um valor abaixo e um valor acima do limite podem alcançar 100% de cobertura de linhas/branches sem testar a fronteira de igualdade (==). Uma refatoração para `deposit >= 2 ether` ainda passaria nesses testes, quebrando silenciosamente a lógica do protocolo.<sup>[[2]](#references)</sup>

Mutation testing expõe essa lacuna ao modificar a condição e verificar se os testes falham.

Para smart contracts, os mutants sobreviventes frequentemente correspondem à ausência de verificações relacionadas a:
- Autorização e limites de funções
- Invariantes de contabilidade/transferência de valores
- Condições de revert e caminhos de falha
- Condições de fronteira (`==`, valores zero, arrays vazios, valores máximos/mínimos)

## Mutation operators com o maior security signal

Classes úteis de mutação para auditoria de contracts:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severity**: substituir statements por `revert()` para expor caminhos não executados
- **Média severity**: comentar linhas / remover lógica para revelar side effects não verificados
- **Baixa severity**: substituições sutis de operadores ou constantes, como `>=` -> `>` ou `+` -> `-`
- Outras edições comuns: substituição de atribuições, inversões booleanas, negação de condições e alterações de tipos

Objetivo prático: matar todos os mutants relevantes e justificar explicitamente os sobreviventes que sejam irrelevantes ou semanticamente equivalentes.

## Por que mutation syntax-aware é melhor que regex

Engines de mutation mais antigos dependiam de regex ou reescritas orientadas a linhas. Isso funciona, mas tem limitações importantes:<sup>[[1]](#references)</sup>
- Statements multilinha são difíceis de modificar com segurança
- A estrutura da linguagem não é compreendida, então comentários/tokens podem ser direcionados incorretamente
- Gerar todas as variantes possíveis em uma linha pouco significativa desperdiça grandes quantidades de runtime

Ferramentas baseadas em AST ou Tree-sitter melhoram esse processo ao direcionar nodes estruturados em vez de linhas brutas:<sup>[[1]](#references)</sup>
- **slither-mutate** usa o AST de Solidity do Slither<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter como core agnóstico de linguagem<sup>[[6]](#references)</sup>
- **MuTON** é baseado em `mewt` e adiciona suporte de primeira classe a linguagens TON, como FunC, Tolk e Tact<sup>[[7]](#references)</sup>

Isso torna constructs multilinha e mutations em nível de expressão muito mais confiáveis do que abordagens baseadas somente em regex.

## Executando mutation testing com slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opções e mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemplo do Foundry (capture os resultados e mantenha um log completo):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se você não usa Foundry, substitua `--test-cmd` pela forma como executa os testes (por exemplo, `npx hardhat test`, `npm test`).

Por padrão, os artefatos são armazenados em `./mutation_campaign`. Mutantes não capturados (sobreviventes) são copiados para lá para inspeção.<sup>[[5]](#references)</sup>

### Entendendo a saída

As linhas do relatório têm esta aparência:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- A tag entre colchetes é o alias do mutator (por exemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram sob o comportamento mutado → asserção ausente.

## Reduzindo o runtime: priorize mutantes relevantes

As campanhas de mutation testing podem levar horas ou dias. Dicas para reduzir o custo:<sup>[[1]](#references)[[2]](#references)</sup>
- Escopo: comece apenas pelos contratos/diretórios críticos e expanda depois.
- Priorize os mutators: se um mutante de alta prioridade em uma linha sobreviver (por exemplo, `revert()` ou comment-out), ignore as variantes de prioridade inferior dessa linha.
- Use campanhas em duas fases: execute primeiro testes focados/rápidos e, depois, teste novamente apenas os mutantes não capturados com a suite completa.
- Mapeie os alvos de mutation para comandos de teste específicos quando possível (por exemplo, código de auth -> testes de auth).
- Restrinja as campanhas a mutantes de severidade alta/média quando o tempo for limitado.
- Execute os testes em paralelo se o seu runner permitir; armazene em cache as dependências/builds.
- Fail-fast: pare cedo quando uma alteração demonstrar claramente uma lacuna de asserção.

A matemática do runtime é brutal: `1000 mutants x 5-minute tests ~= 83 hours`, portanto o design da campanha é tão importante quanto o próprio mutator.<sup>[[1]](#references)</sup>

## Campanhas persistentes e triagem em escala

Uma fraqueza dos workflows antigos é despejar os resultados apenas em `stdout`. Em campanhas longas, isso dificulta pausar/retomar, filtrar e revisar.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` melhoram isso armazenando mutantes e resultados em campanhas baseadas em SQLite. Benefícios:<sup>[[1]](#references)</sup>
- Pausar e retomar execuções longas sem perder o progresso
- Filtrar apenas mutantes não capturados em um arquivo ou uma classe de mutation específica
- Exportar/converter os resultados para SARIF para ferramentas de revisão
- Fornecer à triagem assistida por AI conjuntos de resultados menores e filtrados, em vez de logs brutos do terminal

Resultados persistentes são especialmente úteis quando o mutation testing se torna parte de um pipeline de auditoria, em vez de uma revisão manual pontual.

## Workflow de triagem para mutantes sobreviventes

1) Inspecione a linha e o comportamento mutados.
- Reproduza localmente aplicando a linha mutada e executando um teste focado.

2) Fortaleça os testes para verificar o estado, não apenas os valores retornados.
- Adicione verificações dos limites de igualdade (por exemplo, teste o limiar `==`).
- Verifique as pós-condições: saldos, total supply, efeitos de autorização e eventos emitidos.

3) Substitua mocks permissivos demais por comportamentos realistas.
- Garanta que os mocks imponham transferências, caminhos de falha e emissões de eventos que ocorram on-chain.

4) Adicione invariantes aos testes de fuzz.
- Por exemplo, conservação de valor, saldos não negativos, invariantes de autorização e supply monotônico quando aplicável.

5) Separe os verdadeiros positivos dos semantic no-ops.
- Exemplo: `x > 0` -> `x != 0` não tem significado quando `x` é unsigned.

6) Execute novamente a campanha até que os sobreviventes sejam eliminados ou explicitamente justificados.

## Estudo de caso: revelando asserções de estado ausentes (protocolo Arkis)

Uma campanha de mutation testing durante uma auditoria do protocolo DeFi Arkis revelou sobreviventes como:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar a atribuição não interrompeu os testes, comprovando a ausência de asserções do estado posterior. Causa raiz: o código confiava em um `_cmd.value` controlado pelo usuário em vez de validar as transferências reais de tokens. Um atacante poderia dessincronizar as transferências esperadas das reais para drenar fundos. Resultado: risco de alta severidade para a solvência do protocolo.<sup>[[2]](#references)[[3]](#references)</sup>

Orientação: trate mutantes sobreviventes que afetem transferências de valor, contabilidade ou controle de acesso como de alto risco até serem eliminados.

## Não gere testes cegamente para eliminar todos os mutantes

A geração de testes orientada por mutação pode sair pela culatra se a implementação atual estiver errada. Exemplo: mutar `priority >= 2` para `priority > 2` altera o comportamento, mas a correção adequada nem sempre é "escrever um teste para `priority == 2`". Esse comportamento pode ser o próprio bug.<sup>[[1]](#references)</sup>

Fluxo de trabalho mais seguro:
- Use mutantes sobreviventes para identificar requisitos ambíguos
- Valide o comportamento esperado com base nas especificações, na documentação do protocolo ou em revisores
- Somente então codifique o comportamento como um teste/invariante

Caso contrário, você corre o risco de codificar acidentalmente detalhes da implementação na suíte de testes e obter uma falsa confiança.

## Checklist prático

- Execute uma campanha direcionada:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefira mutators conscientes da sintaxe (AST/Tree-sitter) em vez de mutação baseada apenas em regex, quando disponível.
- Faça a triagem dos mutantes sobreviventes e escreva testes/invariantes que falhariam sob o comportamento mutado.
- Verifique saldos, supply, autorizações e eventos.
- Adicione testes de limites (`==`, overflows/underflows, zero-address, zero-amount, arrays vazios).
- Substitua mocks irreais; simule modos de falha.
- Persista os resultados quando a ferramenta oferecer suporte e filtre os mutantes não capturados antes da triagem.
- Use campanhas em duas fases ou por alvo para manter o tempo de execução gerenciável.
- Itere até que todos os mutantes sejam eliminados ou justificados com comentários e fundamentação.

## Referências

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
