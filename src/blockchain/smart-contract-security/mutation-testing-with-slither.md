# Teste de Mutação para Solidity com Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" ao introduzir sistematicamente pequenas alterações (mutantes) no seu código Solidity e reexecutar sua suíte de testes. Se um teste falhar, o mutante é eliminado. Se os testes ainda passarem, o mutante sobrevive, revelando um ponto cego na sua suíte de testes que cobertura de linhas/ramificações não consegue detectar.

Ideia principal: a cobertura mostra que o código foi executado; o teste de mutação mostra se o comportamento foi realmente verificado.

## Por que a cobertura pode enganar

Considere esta verificação simples de limite:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testes unitários que só verificam um valor abaixo e um valor acima do limiar podem alcançar 100% de cobertura de linhas/branches enquanto deixam de afirmar o limite de igualdade (==). Um refactor para `deposit >= 2 ether` ainda passaria tais testes, quebrando silenciosamente a lógica do protocolo.

O teste por mutação expõe essa lacuna ao alterar a condição e verificar se seus testes falham.

## Operadores de mutação comuns em Solidity

O mecanismo de mutação do Slither aplica muitas edições pequenas que mudam a semântica, tais como:
- Substituição de operador: `+` ↔ `-`, `*` ↔ `/`, etc.
- Substituição de atribuição: `+=` → `=`, `-=` → `=`
- Substituição de constantes: não-zero → `0`, `true` ↔ `false`
- Negação/substituição de condição dentro de `if`/loops
- Comentar linhas inteiras (CR: Comment Replacement)
- Substituir uma linha por `revert()`
- Troca de tipos de dados: ex., `int128` → `int64`

Objetivo: eliminar 100% dos mutantes gerados, ou justificar os sobreviventes com raciocínio claro.

## Executando o teste por mutação com slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opções e mutadores:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemplo Foundry (capturar resultados e manter um log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se você não usar Foundry, substitua `--test-cmd` pela forma como executa os testes (por exemplo, `npx hardhat test`, `npm test`).

Artefatos e relatórios são armazenados em `./mutation_campaign` por padrão. Mutantes não capturados (sobreviventes) são copiados para lá para inspeção.

### Entendendo a saída

Linhas do relatório ficam assim:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- A tag entre colchetes é o alias do mutador (por exemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram sob o comportamento mutado → asserção faltando.

## Reduzindo o tempo de execução: priorize mutantes impactantes

Campanhas de mutação podem levar horas ou dias. Dicas para reduzir custo:
- Escopo: comece apenas com contratos/diretórios críticos, depois expanda.
- Priorize mutadores: se um mutante de alta prioridade em uma linha sobreviver (p.ex., linha inteira comentada), você pode pular variantes de prioridade menor para essa linha.
- Paralelize testes se seu runner permitir; faça cache de dependências/builds.
- Fail-fast: pare cedo quando uma mudança demonstrar claramente uma lacuna de asserção.

## Fluxo de triagem para mutantes sobreviventes

1) Inspecione a linha mutada e o comportamento.
- Reproduza localmente aplicando a linha mutada e executando um teste focado.

2) Fortaleça os testes para afirmar o estado, não apenas valores de retorno.
- Adicione checagens de igualdade/limite (p.ex., teste de limiar `==`).
- Asserte pós-condições: saldos, total supply, efeitos de autorização e eventos emitidos.

3) Substitua mocks excessivamente permissivos por comportamento realista.
- Garanta que os mocks imponham transferências, caminhos de falha e emissões de eventos que ocorrem on-chain.

4) Adicione invariantes para fuzz tests.
- Ex.: conservação de valor, saldos não-negativos, invariantes de autorização, supply monotônico quando aplicável.

5) Execute novamente slither-mutate até que os sobreviventes sejam eliminados ou justificados explicitamente.

## Estudo de caso: revelando asserções de estado ausentes (Arkis protocol)

Uma campanha de mutação durante uma auditoria do protocolo Arkis DeFi revelou sobreviventes como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar a atribuição não quebrou os testes, comprovando a falta de assertivas de pós-estado. Causa raiz: o código confiava em um `_cmd.value` controlado pelo usuário em vez de validar as transferências reais de tokens. Um atacante poderia dessincronizar transferências esperadas vs. reais para drenar fundos. Resultado: risco de alta severidade à solvência do protocolo.

Guidance: Trate mutantes sobreviventes que afetam transferências de valor, contabilidade ou controle de acesso como alto risco até serem eliminados.

## Checklist prático

- Execute uma campanha direcionada:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Classifique os mutantes sobreviventes e escreva testes/invariantes que falhariam sob o comportamento mutado.
- Asserte saldos, supply, autorizações e eventos.
- Adicione testes de fronteira (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Substitua mocks irrealistas; simule modos de falha.
- Itere até que todos os mutantes sejam eliminados ou justificados com comentários e justificativas.

## Referências

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
