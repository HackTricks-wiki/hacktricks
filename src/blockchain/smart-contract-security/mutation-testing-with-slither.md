# Teste de Mutação para Solidity com Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

O teste de mutação "testa seus testes" ao introduzir sistematicamente pequenas mudanças (mutantes) no seu código Solidity e reexecutar sua suíte de testes. Se um teste falhar, o mutante é eliminado. Se os testes ainda passarem, o mutante sobrevive, revelando um ponto cego na sua suíte de testes que a cobertura de linha/ramo não consegue detectar.

Ideia-chave: a cobertura mostra que o código foi executado; o teste de mutação mostra se o comportamento foi realmente verificado.

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
Testes unitários que verificam apenas um valor abaixo e um valor acima do limite podem alcançar 100% de cobertura de linhas/branches enquanto deixam de afirmar a condição de igualdade (==). Uma refatoração para `deposit >= 2 ether` ainda passaria esses testes, quebrando silenciosamente a lógica do protocolo.

O teste de mutação expõe essa lacuna ao mutar a condição e verificar que seus testes falham.

## Operadores de mutação comuns em Solidity

O mecanismo de mutação do Slither aplica muitas pequenas alterações que mudam a semântica, tais como:
- Substituição de operador: `+` ↔ `-`, `*` ↔ `/`, etc.
- Substituição de atribuição: `+=` → `=`, `-=` → `=`
- Substituição de constantes: não-zero → `0`, `true` ↔ `false`
- Negação/substituição de condição dentro de `if`/loops
- Comentar linhas inteiras (CR: Substituição de Comentário)
- Substituir uma linha por `revert()`
- Troca de tipos de dados: por exemplo, `int128` → `int64`

Objetivo: Eliminar 100% dos mutantes gerados, ou justificar os sobreviventes com justificativa clara.

## Executando teste de mutação com slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opções e mutadores:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Exemplo com Foundry (capturar os resultados e manter um log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se você não usa Foundry, substitua `--test-cmd` pela forma como executa os testes (por exemplo, `npx hardhat test`, `npm test`).

Artefatos e relatórios são armazenados em `./mutation_campaign` por padrão. Mutantes não capturados (sobreviventes) são copiados para lá para inspeção.

### Entendendo a saída

As linhas do relatório se parecem com:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- A tag entre colchetes é o apelido do mutador (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram sob o comportamento mutado → asserção ausente.

## Reduzindo tempo de execução: priorize mutantes de impacto

Campanhas de mutation testing podem levar horas ou dias. Dicas para reduzir custo:
- Escopo: comece apenas com contratos/diretórios críticos e depois expanda.
- Priorize mutators: se um mutante de alta prioridade numa linha sobrevive (ex.: toda a linha comentada), você pode pular variantes de menor prioridade daquela linha.
- Paralelize testes se seu runner permitir; faça cache de dependências/builds.
- Fail-fast: pare cedo quando uma mudança demonstra claramente uma lacuna de asserção.

## Fluxo de triagem para mutantes sobreviventes

1) Inspecione a linha mutada e o comportamento.
- Reproduza localmente aplicando a linha mutada e rodando um teste focado.

2) Fortaleça os testes para verificar estado, não apenas valores de retorno.
- Adicione checagens de igualdade/limite (por exemplo, testar threshold `==`).
- Asserte pós-condições: saldos, total supply, efeitos de autorização e eventos emitidos.

3) Substitua mocks excessivamente permissivos por comportamento realista.
- Garanta que mocks forcem transfers, caminhos de falha e emissão de eventos que ocorrem on-chain.

4) Adicione invariantes para fuzz tests.
- Ex.: conservação de valor, saldos não-negativos, invariantes de autorização, monotonicidade do supply quando aplicável.

5) Re-run slither-mutate até que os sobreviventes sejam eliminados ou justificados explicitamente.

## Case study: revelando asserções de estado faltantes (Arkis protocol)

Uma campanha de mutation durante uma auditoria do Arkis DeFi protocol revelou sobreviventes como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentando a atribuição não quebrou os testes, comprovando a falta de asserções de pós-estado. Causa raiz: o código confiava em um `_cmd.value` controlado pelo usuário em vez de validar as transferências reais de token. Um atacante poderia dessincronizar as transferências esperadas das reais para drenar fundos. Resultado: risco de alta severidade para a solvência do protocolo.

Orientação: Trate mutantes sobreviventes que afetam transferências de valor, contabilidade ou controle de acesso como alto risco até serem eliminados.

## Checklist prático

- Execute uma campanha direcionada:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Faça a triagem dos mutantes sobreviventes e escreva testes/invariantes que falhem sob o comportamento mutado.
- Asserte saldos, supply, autorizações, e eventos.
- Adicione testes de borda (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Substitua mocks irreais; simule modos de falha.
- Itere até que todos os mutantes sejam eliminados ou justificados com comentários e justificativa.

## Referências

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
