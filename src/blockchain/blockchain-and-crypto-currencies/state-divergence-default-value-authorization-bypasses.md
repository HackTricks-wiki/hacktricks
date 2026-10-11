# Divergência de Estado e Bypasses de Autorização por Valores Padrão

{{#include ../../banners/hacktricks-training.md}}

A autorização às vezes depende de um estado econômico derivado, em vez de uma função explícita — por exemplo, “o chamador possui todo o fornecimento”. Se os valores desse predicado vêm de armazenamentos diferentes, uma cópia duplicada desatualizada pode transformar um atalho legítimo de propriedade em um bypass de autorização. O módulo de marcadores Provenance demonstrou essa combinação perigosa: o saldo atual do chamador era comparado com metadados de fornecimento locais ao marcador, que não eram atualizados para ativos com fornecimento não fixo.<sup>[[1]](#references)</sup>

## Audite o estado duplicado como limite de autorização

Para cada valor usado por uma verificação de permissão, enumere **todas as representações**: estado canônico do módulo, campos de objetos, agregados em cache, índices, snapshots, registros de bridge e espelhos off-chain. Em seguida, rastreie todos os caminhos de criação, mint, burn, transferência, redefinição, migração e sincronização para determinar qual cópia é atualizada em cada modo de objeto. Um campo pode ser autoritativo em um modo e informativo em outro.<sup>[[1]](#references)</sup>

Um fluxo de trabalho prático de revisão é:<sup>[[1]](#references)</sup>

1. Localize as ações protegidas e reduza cada ramificação de autorização a um predicado booleano.
2. Para cada operando, registre seu armazenamento, caminhos de atualização, estados do ciclo de vida e fonte da verdade.
3. Gere transições que atualizem apenas uma representação e, em seguida, compare todas as cópias.
4. Tente executar a ação protegida a partir de uma conta nova após cada transição.
5. Vá além do bypass: se a ação edita uma ACL, conceda a si mesmo funções persistentes e invoque APIs privilegiadas normais.

Padrões suspeitos incluem `cachedSupply == balance`, `metadataOwner == caller` ou `snapshotShares == currentShares` quando os dois lados têm regras de sincronização diferentes. Consultar um valor autoritativo para um operando não torna a comparação segura se o outro operando estiver desatualizado.<sup>[[1]](#references)</sup>

## Bypass de igualdade com valor padrão

Um predicado de igualdade também é inseguro quando os dois operandos podem assumir independentemente o mesmo valor padrão. A verificação abaixo concede “controle total do fornecimento” a qualquer conta vazia quando `supply` é zero, independentemente de o zero resultar de metadados desatualizados ou de um objeto legitimamente sem fundos.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

A mudança para o armazenamento canônico corrige a divergência, mas **não** o caso de objeto vazio. A propriedade de segurança deve incluir uma condição de validade independente; o patch da Provenance usa a oferta atual do banco e rejeita uma oferta nil ou zero antes de comparar o saldo do chamador.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Aplique o mesmo raciocínio a contagens de quorum, percentuais de propriedade, dívida, garantias, epochs, nonces, timestamps e contadores: `callerValue == protectedValue` não deve autorizar um caller até que o valor protegido seja validado de forma independente e pertença ao domínio esperado.<sup>[[1]](#references)</sup>

## Tomada de controle de ACL para operações privilegiadas legítimas

Um bypass em uma operação de edição de ACL é uma primitiva duradoura de escalada de privilégios. No caso Provenance, uma conta sem privilégios e sem tokens podia passar no teste de supply obsoleto `0 == 0`, conceder a si mesma permissões administrativas, de mint e de saque e, em seguida, usar os message handlers comuns para emitir ativos ou sacar valores em escrow. Portanto, após a alteração da ACL, o exploit não exigia uma segunda vulnerabilidade.<sup>[[1]](#references)</sup>

Sequência geral de exploração:<sup>[[1]](#references)</sup>

1. Encontre um objeto cujo campo não autoritativo seja diferente do estado atual ou cujo valor protegido seja o valor padrão.
2. Use uma identidade nova/vazia para que seu valor local corresponda a esse valor obsoleto/padrão.
3. Chame o endpoint de gerenciamento de funções, transferência de propriedade ou atualização de políticas e conceda a si mesmo capacidades duradouras.
4. Confirme a persistência lendo a ACL do estado canônico.
5. Invoque a operação legítima de alto impacto (mint, saque, upgrade, transferência de propriedade ou alteração de políticas).

Ao avaliar o impacto, inspecione todas as capacidades acessíveis pela nova função, em vez de parar no bypass de autorização. Contas semelhantes a escrow podem custodiar ativos não relacionados ao objeto cujos metadados obsoletos permitiram a tomada de controle.<sup>[[1]](#references)</sup>

## Alvos para invariantes e fuzzing com estado

Especifique a autorização de forma independente da implementação. Para um atalho de supply total, a invariante mínima é:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Use um fuzzer de modelo/máquina de estados para gerar sequências — não chamadas isoladas — que cubram criação, inicialização com valor zero, ativação/finalização, emissão, queima, transferências, redefinições, migrações, chamadas de sincronização e alterações de ACL. Após cada transição, compare as representações duplicadas e verifique que uma conta nova não consegue executar nenhuma ação protegida. Inclua casos explícitos para zero, uma unidade, propriedade parcial, propriedade total, valores desatualizados abaixo do correto e valores desatualizados acima do correto.<sup>[[1]](#references)[[2]](#references)</sup>

As propriedades de regressão mais reveladoras são:<sup>[[1]](#references)[[2]](#references)</sup>

- Uma oferta autoritativa igual a zero nunca implica propriedade ou administração.
- Titulares parciais não podem se tornar administradores quando uma oferta duplicada é igual ao seu saldo.
- Um titular que realmente possui tudo mantém o atalho pretendido quando a oferta atual é positiva.
- Tentativas malsucedidas de conceder permissões a si mesmo não alteram a ACL nem habilitam chamadas privilegiadas subsequentes.
- Mudanças de modo não podem alterar silenciosamente qual representação uma verificação de autorização considera autoritativa.

## References

- [1] [A divergência de estado permite acesso não autorizado (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Corrige verificações de oferta desatualizadas](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Rejeita oferta zero no atalho de autorização baseado na oferta total](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
