# Divergência de Estado e Bypasses de Autorização por Valores Padrão

{{#include ../../banners/hacktricks-training.md}}

A autorização às vezes depende de um estado econômico derivado em vez de uma role explícita — por exemplo, "o caller possui todo o supply". Se os valores desse predicado vêm de stores diferentes, uma cópia desatualizada pode transformar um atalho legítimo de ownership em um authorization bypass. O módulo Provenance marker demonstrou a combinação perigosa: um saldo ativo do caller era comparado com metadados de supply locais ao marker que não eram atualizados para assets com supply não fixo.<sup>[[1]](#references)</sup>

## Auditar estado duplicado como um limite de autorização

Para cada valor usado por uma permission check, enumere **todas as representações**: estado canônico do módulo, campos de objetos, agregados em cache, índices, snapshots, registros de bridge e mirrors off-chain. Em seguida, rastreie cada caminho de create, mint, burn, transfer, reset, migration e synchronization para determinar qual cópia é atualizada em cada modo de objeto. Um campo pode ser authoritative para um modo e informativo para outro.<sup>[[1]](#references)</sup>

Um workflow prático de review é:<sup>[[1]](#references)</sup>

1. Localize as ações protegidas e reduza cada branch de autorização a um predicado booleano.
2. Para cada operando, registre seu store, caminhos de atualização, estados do ciclo de vida e source of truth.
3. Gere transições que atualizem apenas uma representação e compare todas as cópias.
4. Tente executar a ação protegida a partir de uma conta nova após cada transição.
5. Continue além do bypass: se a ação edita uma ACL, atribua a si mesmo roles persistentes e invoque as APIs privilegiadas normais.

Padrões suspeitos incluem `cachedSupply == balance`, `metadataOwner == caller` ou `snapshotShares == currentShares` quando os dois lados têm regras de sincronização diferentes. Consultar um valor authoritative para um operando não torna a comparação segura quando o outro operando está desatualizado.<sup>[[1]](#references)</sup>

## Bypass de igualdade com valor padrão

Um predicado de igualdade também é inseguro quando ambos os operandos podem assumir independentemente o mesmo valor padrão. A check abaixo concede "controle de todo o supply" a qualquer conta vazia quando `supply` é zero, independentemente de zero resultar de metadados desatualizados ou de um objeto legitimamente sem funding.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Mudar para o armazenamento canônico corrige a divergência, mas **não** o caso do objeto vazio. A propriedade de segurança deve incluir uma condição de validade independente; o patch Provenance usa o supply atual do banco e rejeita um supply nil ou zero antes de comparar o saldo do chamador.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Aplique o mesmo raciocínio a contagens de quorum, percentuais de propriedade, dívida, colateral, epochs, nonces, timestamps e contadores: `callerValue == protectedValue` não deve autorizar um caller até que o valor protegido seja independentemente válido e pertença ao domínio esperado.<sup>[[1]](#references)</sup>

## ACL takeover to legitimate privileged operations

Um bypass em uma operação de edição de ACL é uma primitiva duradoura de privilege-escalation. No caso da Provenance, uma conta sem privilégios e com zero tokens podia passar no teste de supply obsoleto `0 == 0`, conceder a si mesma permissões administrativas, de mint e de withdrawal, e então usar message handlers comuns para fazer mint de assets ou realizar withdrawal de escrow. Portanto, o exploit não exigia uma segunda vulnerabilidade após a alteração da ACL.<sup>[[1]](#references)</sup>

Sequência geral de exploitation:<sup>[[1]](#references)</sup>

1. Encontre um objeto cujo campo não autoritativo seja diferente do estado atual, ou cujo valor protegido seja o default.
2. Use uma identidade nova/vazia para que seu valor local corresponda ao valor obsoleto/default.
3. Chame o endpoint de role-management, ownership-transfer ou policy-update e conceda a si mesmo capabilities duradouras.
4. Confirme a persistência lendo a ACL a partir do estado canônico.
5. Invoque a operação legítima de alto impacto (mint, withdrawal, upgrade, transfer ownership ou change policy).

Ao fazer a triagem do impacto, inspecione todas as capabilities alcançáveis a partir da nova role, em vez de parar no authorization bypass. Contas semelhantes a escrow podem custodiar assets não relacionados ao objeto cujo metadata obsoleto permitiu o takeover.<sup>[[1]](#references)</sup>

## Invariant and stateful-fuzzing targets

Especifique a autorização independentemente da implementação. Para um atalho de full-supply, o invariant mínimo é:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Use um fuzzer de model/state-machine para gerar sequências — não chamadas isoladas — abrangendo criação, inicialização com valor zero, ativação/finalização, minting, burning, transferências, resets, migrações, chamadas de sincronização e alterações de ACL. Após cada transição, compare as representações duplicadas e confirme que uma conta nova não pode executar nenhuma ação protegida. Inclua casos explícitos para valores zero, uma unidade, ownership parcial, ownership total, stale-low e stale-high.<sup>[[1]](#references)[[2]](#references)</sup>

As propriedades de regressão de maior sinal são:<sup>[[1]](#references)[[2]](#references)</sup>

- Uma supply autoritativa igual a zero nunca implica ownership ou administração.
- Detentores parciais não podem se tornar administradores quando uma supply duplicada é igual ao seu saldo.
- Um detentor total verdadeiro mantém o atalho pretendido quando a supply live é positiva.
- Falhas em self-grants não modificam a ACL nem habilitam chamadas privilegiadas downstream.
- Alterações de modo não podem mudar silenciosamente qual representação uma verificação de autorização considera autoritativa.

## References

- [1] [A divergência de estado permite acesso não autorizado (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Corrige verificações de supply obsoletas](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Commit c81fd65 do Provenance - Rejeita supply zero no atalho de autorização de total-supply](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
