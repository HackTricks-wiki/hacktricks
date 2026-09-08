# Protocolos de Pagamento com Preservação de Privacidade

{{#include ../banners/hacktricks-training.md}}

Sistemas de pagamento avançados podem ocultar o pagador do comerciante, ocultar um destinatário ou valor de um ledger público, ou impedir que uma mint associe um saque a um resgate. Essas são propriedades diferentes. Nenhuma elimina registros de aquisição, dispositivo, rede, entrega, contabilidade, sanções ou endpoint.

O [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) fornece entradas padronizadas de `Pros`, `Cons`, `Procedure` passo a passo e `Detection` para cada família de pagamentos. Esta página detalha os protocolos avançados.

{% hint style="danger" %}
Use apenas fundos e contrapartes legais. Não use protocolos de privacidade para evitar identificação obrigatória, sanções, impostos, verificações de origem dos fundos ou comunicação de transações. Não opere uma exchange, mint ou serviço de transmissão sem compreender as obrigações de licenciamento, custódia, AML e proteção ao consumidor.
{% endhint %}

## Comparação das opções avançadas

| Protocolo | Oculta de público/comerciante | Parte confiável ou observadora | Maturidade/disponibilidade |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Observadores externos não conseguem associar um código de pagamento reutilizável às suas saídas de uso único | O grafo público do Bitcoin permanece; o servidor de wallet/index pode observar os scans | Especificação completa; o suporte das wallets varia |
| Zcash Orchard totalmente shielded | Remetente, destinatário e valor são criptografados on-chain | O backend da wallet/rede e a aquisição/off-ramp permanecem | Implementado; o suporte shielded varia conforme a wallet/exchange |
| GNU Taler | O comerciante não precisa saber a identidade do pagador; a receita do comerciante permanece sujeita a prestação de contas | A exchange/banco Taler vê o funding; o comerciante vê o pedido | As implementações são geograficamente limitadas |
| Federated Chaumian e-cash | A federação não deve associar notes emitidas a transferências/resgates internos | O quórum de guardians mantém a custódia das reservas; os gateways veem a atividade de fronteira | Implementações comunitárias emergentes |
| Lightning BOLT 12/route blinding | Reduz a divulgação do destinatário/nó e da rota | Endpoints, hops selecionados, cadeia de funding e serviços de wallet | O suporte depende da wallet |
| Virtual card/token | O comerciante recebe uma credencial limitada, não um PAN reutilizável | O emissor/rede mantém o pagador e a transação | Maduro e amplamente disponível |

## Bitcoin Silent Payments (BIP 352)

Silent Payments permitem que um destinatário publique um único código de pagamento estático enquanto cada remetente deriva uma saída Taproot exclusiva. Um observador externo da chain não consegue associar diretamente essas saídas ao código publicado, e nenhuma solicitação interativa de endereço ou saída de notificação on-chain é necessária. O BIP 352 está marcado como **Complete**, mas introduz custo de scanning e é incompatível com wallets que não o implementaram.<sup>[[1]](#references)</sup>

### Fluxo de trabalho do destinatário

1. Selecione uma wallet mantida que ofereça suporte explícito ao recebimento via BIP 352; verifique o recurso na documentação atual da wallet, não em uma alegação de mídia social.
2. Faça backup da seed da wallet e do material de descritor/chave do Silent Payment usando o método de recuperação documentado pela wallet. Teste a descoberta com um pequeno valor em testnet/mainnet antes de publicar o código.
3. Gere **labels** separadas para campanhas, invoices ou contrapartes quando a wallet oferecer suporte a labels do BIP 352. As labels auxiliam a contabilidade local sem publicar endereços associáveis.
4. Publique o código estático do Silent Payment por um canal autenticado. Ele é reutilizável, mas um impostor pode substituir o código pelo seu próprio.
5. Faça o scan por meio de um full node local quando for viável. Um servidor de index/scanning de terceiros pode aprender o horário das solicitações ou os dados dos filtros, mesmo que não possa gastar os fundos.
6. Mantenha os UTXOs descobertos identificados por labels e aplique as mesmas regras de coin control do Bitcoin comum. Gastá-los ou consolidá-los pode revelar relações de propriedade.
7. Confirme que a recuperação descobre os pagamentos sem depender de um index externo sem backup.

### Fluxo de trabalho do remetente

1. Confirme que a wallet oferece suporte ao envio para a versão do endereço e autentique o código estático longo do destinatário.
2. Permita que a wallet construa a saída; nunca converta nem trunque o código manualmente.
3. Revise cuidadosamente as inputs selecionadas. Silent Payments melhoram a privacidade do endereço do destinatário, mas as inputs do remetente continuam no grafo público.
4. Use o comportamento de fee bumping/PSBT suportado pela wallet. O BIP 352 exige a rederivação da saída se as inputs mudarem, e alguns modos de signing são inseguros.
5. Guarde um recibo ou comprovante criptografado necessário para disputas/contabilidade.

Silent Payments resolvem a publicação repetida do endereço do destinatário. Eles não ocultam o valor, o horário da transação, o cluster do remetente, o histórico de aquisição nem o co-spending posterior.

## Pagamentos Zcash totalmente shielded

O Zcash oferece pools de valor transparentes e shielded. As transações shielded Orchard usam provas de conhecimento zero para que os nodes possam verificar a validade enquanto os detalhes da transação permanecem criptografados; Unified Addresses podem conter vários tipos de destinatário.<sup>[[2]](#references)</sup> A privacidade depende do caminho efetivamente selecionado pela wallet, não do primeiro caractere de um endereço exibido.

### Fluxo de trabalho shielded

1. Escolha uma wallet mantida que identifique claramente o comportamento **shielded-by-default** e o suporte atual ao Orchard. Verifique o download e faça backup/teste da seed.
2. Obtenha ZEC legalmente e registre a base/origem. Uma exchange ainda conhece a aquisição e o withdrawal.
3. Receba em um Unified Address suportado pela wallet e verifique se a transação chegou a um pool shielded. Não presuma shielding automático sem confirmar o comportamento da wallet.
4. Prefira transferências **shielded-to-shielded**. Movimentações transparent-to-shielded e shielded-to-transparent expõem valores/horários públicos e podem permitir correlação de valores; a especificação Orchard observa que gastar para um endereço não Orchard revela o valor da transação.<sup>[[3]](#references)</sup>
5. Evite round trips com valores exatos e distintos e crossings imediatos de fronteira. Isso é higiene de privacidade, não uma autorização para ocultar propriedade ou comunicação.
6. Use o caminho de network privacy suportado pela wallet. A criptografia shielded não oculta IP/horário dos servidores da wallet ou dos peers.
7. Mantenha registros internos de compliance e use viewing keys apenas para auditoria/divulgação deliberada, após compreender seu escopo.
8. Confirme o suporte da wallet/exchange do destinatário antes de enviar; um destinatário transparente obrigatório altera a propriedade de privacidade.

## GNU Taler: pagador anônimo, comerciante responsável

GNU Taler é um protocolo aberto de pagamento eletrônico que usa moedas tradicionais, blind signatures e integração com exchange/banco regulados. Seu design busca manter os clientes anônimos para os comerciantes, enquanto os comerciantes permanecem identificáveis e sujeitos a tributação.<sup>[[4]](#references)</sup> Não é uma criptomoeda, e a disponibilidade depende de uma exchange, banco, wallet e comerciante regionais compatíveis.

### Fluxo de trabalho do usuário quando disponível

1. Identifique uma exchange Taler e um comerciante ativos na moeda/jurisdição relevante; leia seus termos, taxas, requisitos de KYC e avisos de privacidade atuais.
2. Instale a wallet oficial e verifique sua origem. Proteja os dados de backup/recuperação da wallet como dinheiro, pois o valor da wallet pode ser um bearer asset.
3. Faça o withdrawal de valor pelo fluxo de banco/exchange suportado usando informações verdadeiras. A instituição de funding/exchange pode conhecer o withdrawal, embora as blind signatures eliminem a associação direta entre a moeda e o withdrawal.
4. Revise o contrato do comerciante na wallet: identidade do comerciante, item/resumo, valor, taxas, reembolso e termos de entrega.
5. Pague e preserve os dados do recibo necessários para reembolso, garantia, contabilidade ou impostos.
6. Não reutilize identificadores opcionais de sessão/conta do comerciante se a unlinkability do comerciante for necessária.
7. Mantenha os metadados da wallet, da rede e da entrega no threat model; a criptografia de pagamento do Taler não oculta um endereço de entrega ou um endpoint comprometido.

O comerciante e a exchange continuam responsáveis, e operar qualquer um desses componentes pode ser uma atividade regulamentada de serviço de pagamento.

## Federated Chaumian e-cash

Chaumian e-cash usa blind signatures para que uma mint assine um token sem ver o token posteriormente desblinded que foi gasto. O Fedimint distribui a custódia das reservas e a assinatura entre uma federação de guardians; sua documentação afirma que os guardians veem as reservas agregadas/notes pendentes, mas não devem ver o saldo individual nem quem pagou a quem dentro da federação.<sup>[[5]](#references)</sup>

Trata-se de **valor custodial bearer**. Um quórum suficiente de guardians controla as reservas; falha da federação, guardians desonestos, bugs de software ou perda do estado do cliente podem causar perda. Deposits, withdrawals e gateways Lightning são eventos de fronteira visíveis e podem correlacionar horário/valor.

### Fluxo de trabalho de risco limitado

1. Use apenas uma pequena quantia que possa perder. Considere federações públicas/desconhecidas mais arriscadas que guardians com responsabilidade no mundo real.
2. Verifique o convite da federação por um canal autenticado e registre as identidades dos guardians, o quórum, a jurisdição, as taxas, a recuperação e a política de encerramento.
3. Instale uma wallet compatível e mantida, verifique-a e compreenda seu esquema de backup antes de depositar.
4. Deposite Bitcoin adquirido legalmente pelo caminho documentado. Registre o peg-in para fins contábeis e presuma que seu horário/valor é público ou conhecido na fronteira.
5. Dentro da federação, use solicitações de pagamento novas e evite adicionar identificadores de conta/chat/entrega que recriem o vínculo removido pela blind signature.
6. Para pagamentos Lightning, trate o gateway como um observador adicional de invoices e do horário de fronteira.
7. Faça o redeem/withdraw de acordo com a política, esperando que um valor distinto e um horário imediato possam ser correlacionados a um depósito ou pagamento externo.
8. Mantenha registros de impostos/origem/autorização em privado; não peça aos guardians ou gateways que deturpem a atividade.

Não descreva federated e-cash como trustless, self-custodial ou com anonimato garantido.

## BOLT 12 offers e route blinding

BOLT 12 offers podem ser reutilizadas sem publicar um endereço on-chain estável e podem usar blinded paths para que um pagador não precise conhecer a identidade/path claro do node do destinatário. Isso complementa, mas não substitui, o onion routing já existente do Lightning.

Antes de usar:

1. Confirme que as wallets do remetente e do destinatário oferecem suporte aos mesmos recursos atuais do BOLT 12; não deduza suporte a partir de uma marca genérica de “Lightning”.
2. Autentique a offer out of band e verifique o valor, o emissor/description e as regras de recorrência.
3. Use um contexto novo de invoice/payment gerado a partir da offer.
4. Mantenha aliases de nodes, informações de contato públicas e endpoints de rede estáveis no mínimo necessário.
5. Presuma que remetente/destinatário, primeiro/último hop, serviço de wallet, grafo de canais e funding/closure on-chain ainda divulgam partes da relação.

## Auditabilidade sem divulgação pública

Privacidade e auditoria podem coexistir:

- Mantenha labels, invoices, autorizações, custo de aquisição e mapeamento de propriedade criptografados fora do protocolo público.
- Separe uma **view/audit key** de uma spending key quando o protocolo fornecer uma; teste primeiro sua divulgação exata em uma wallet de amostra.
- Forneça ao auditor a prova mínima com escopo definido, em vez de uma seed ou credencial de spending sem restrições.
- Registre a versão do software, o protocolo/pool, o ID da transação ou prova, a finalidade da contraparte e a fonte da taxa de câmbio no momento da transação.
- Defina retenção e exclusão em vez de acumular um grafo de identidade permanente e não criptografado.

## Checklist de seleção

- [ ] O campo oculto e o observador estão identificados com precisão.
- [ ] O suporte da wallet/protocolo foi verificado na data da transação.
- [ ] Os vínculos de aquisição, rede, node/RPC, contraparte, entrega e gasto posterior estão documentados.
- [ ] Os riscos de custódia, recuperação, liquidez, solvência do emissor/federação e reembolso foram aceitos.
- [ ] Os registros obrigatórios de identidade, impostos, sanções, origem e organização permanecem precisos.
- [ ] Um teste pequeno de ponta a ponta, incluindo recuperação e prova de auditoria, foi concluído com sucesso.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Endereços unificados](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Protocolo Shielded Orchard](https://zips.z.cash/zip-0224)
- [4] [Documentação do GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Como funciona](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
