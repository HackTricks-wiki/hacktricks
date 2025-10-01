# Mutation Testing para Solidity com Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" ao introduzir sistematicamente pequenas mudanças (mutantes) no seu código Solidity e reexecutar sua suíte de testes. Se um teste falhar, o mutante é morto. Se os testes ainda passam, o mutante sobrevive, revelando um ponto cego na sua suíte de testes que a cobertura de linha/ramificação não consegue detectar.

Ideia-chave: a cobertura mostra que o código foi executado; mutation testing mostra se o comportamento está realmente sendo verificado.

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
Testes unitários que verificam apenas um valor abaixo e um valor acima do limite podem alcançar 100% de cobertura de linhas/branches enquanto falham em afirmar a igualdade (==). Uma refatoração para `deposit >= 2 ether` ainda passaria nesses testes, quebrando silenciosamente a lógica do protocolo.

O teste de mutação expõe essa falha ao mutar a condição e verificar se seus testes falham.

## Operadores comuns de mutação em Solidity

O mecanismo de mutação do Slither aplica muitas pequenas alterações que mudam a semântica, tais como:
- Substituição de operador: `+` ↔ `-`, `*` ↔ `/`, etc.
- Substituição de atribuição: `+=` → `=`, `-=` → `=`
- Substituição de constantes: não-zero → `0`, `true` ↔ `false`
- Negação/substituição de condição dentro de `if`/laços
- Comentar linhas inteiras (CR: Comment Replacement)
- Substituir uma linha por `revert()`
- Trocas de tipo de dado: por exemplo, `int128` → `int64`

Objetivo: Eliminar 100% dos mutantes gerados, ou justificar os sobreviventes com uma justificativa clara.

## Executando testes de mutação com slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opções e mutadores:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry exemplo (capturar resultados e manter um log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Se você não usa Foundry, substitua `--test-cmd` pela forma como executa os testes (por exemplo, `npx hardhat test`, `npm test`).

Artefatos e relatórios são armazenados em `./mutation_campaign` por padrão. Mutantes não capturados (sobreviventes) são copiados para lá para inspeção.

### Entendendo a saída

As linhas do relatório têm o seguinte formato:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- A tag entre colchetes é o alias do mutator (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` significa que os testes passaram sob o comportamento mutado → falta de asserção.

## Reduzindo tempo de execução: priorize mutantes com impacto

Campanhas de mutação podem levar horas ou dias. Dicas para reduzir custo:
- Escopo: comece apenas com contratos/diretórios críticos e depois expanda.
- Priorize mutators: se um mutante de alta prioridade em uma linha sobreviver (e.g., a linha inteira comentada), você pode pular variantes de menor prioridade para essa linha.
- Paralelize os testes se seu runner permitir; faça cache de dependências/builds.
- Fail-fast: pare cedo quando uma mudança claramente demonstra uma lacuna de asserção.

## Fluxo de triagem para mutantes sobreviventes

1) Inspecione a linha mutada e o comportamento.
- Reproduza localmente aplicando a linha mutada e executando um teste focado.

2) Fortaleça os testes para asserir o estado, não apenas valores de retorno.
- Adicione checagens de igualdade/limite (e.g., testar threshold `==`).
- Asserte pós-condições: saldos, fornecimento total, efeitos de autorização e eventos emitidos.

3) Substitua mocks excessivamente permissivos por comportamento realista.
- Assegure que os mocks imponham transferências, caminhos de falha e emissões de eventos que ocorrem on-chain.

4) Adicione invariantes para fuzz tests.
- Ex.: conservação de valor, saldos não-negativos, invariantes de autorização, supply monotônico quando aplicável.

5) Reexecute slither-mutate até que os sobreviventes sejam eliminados ou justificados explicitamente.

## Estudo de caso: revelando asserções de estado ausentes (protocolo Arkis)

Uma campanha de mutação durante uma auditoria do protocolo Arkis DeFi revelou sobreviventes como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar a atribuição não quebrou os testes, provando que faltavam asserções de pós-estado. Causa raiz: o código confiava em um `_cmd.value` controlado pelo usuário em vez de validar transferências reais de token. Um atacante poderia desincronizar as transferências esperadas e as reais para drenar fundos. Resultado: risco de alta gravidade para a solvência do protocolo.

Orientação: Considere mutantes sobreviventes que afetem transferências de valor, contabilidade ou controle de acesso como de alto risco até serem eliminados.

## Lista de verificação prática

- Execute uma campanha direcionada:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Faça triagem dos survivors e escreva testes/invariantes que falhariam sob o comportamento mutado.
- Verifique saldos, fornecimento (supply), autorizações e eventos.
- Adicione testes de borda (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Substitua mocks irreais; simule modos de falha.
- Itere até que todos os mutantes sejam eliminados ou justificados com comentários e rationale.

## Referências

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
