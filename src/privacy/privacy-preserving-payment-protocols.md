# Protocolos de pagamento com preservação de privacidade

Sistemas de pagamento avançados podem ocultar o pagador do merchant, ocultar um destinatário ou valor de um ledger público, ou impedir que uma mint associe o saque ao resgate. Essas são propriedades diferentes. Nenhuma elimina registros de aquisição, dispositivo, rede, entrega, contabilidade, sanções ou endpoints.

O [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) fornece uma entrada padronizada de `Pros`, `Cons`, `Procedure` passo a passo e `Detection` para cada família de pagamentos. Esta página detalha os protocolos avançados.

{% hint style="danger" %}
Use apenas fundos e contrapartes legais. Não use protocolos de privacidade para contornar identificação obrigatória, sanções, impostos, verificações de origem dos fundos ou relatórios de transações. Não opere um serviço de exchange, mint ou transmissão sem compreender as obrigações de licenciamento, custódia, AML e proteção ao consumidor.
{% endhint %}

## Comparação das opções avançadas

| Protocolo | Oculta de público/merchant | Parte confiável ou observadora | Maturidade/disponibilidade |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Terceiros não conseguem associar um código de pagamento reutilizável às suas saídas de uso único | O grafo público do Bitcoin permanece; o servidor de carteira/indexação pode ver as varreduras | Especificação concluída; o suporte das carteiras varia |
| Zcash totalmente shielded Orchard | Remetente, destinatário e valor são criptografados on-chain | O backend/rede da carteira e o ponto de aquisição/saída permanecem | Implantado; o suporte a shielded varia conforme a carteira/exchange |
| GNU Taler | O merchant não precisa conhecer a identidade do pagador; a receita do merchant permanece contabilizável | A exchange/banco do Taler vê o financiamento; o merchant vê o pedido | As implantações são geograficamente limitadas |
| Federated Chaumian e-cash | A federação não deve associar notas emitidas a transferências/resgates internos | O quórum de guardians mantém a custódia das reservas; os gateways veem a atividade de fronteira | Implantações comunitárias emergentes |
| Lightning BOLT 12/route blinding | Reduz a divulgação do destinatário/nó e da rota | Endpoints, hops selecionados, cadeia de financiamento e serviços de carteira | O suporte depende da carteira |
| Virtual card/token | O merchant recebe uma credencial limitada, não um PAN reutilizável | O emissor/rede mantém o pagador e a transação | Maduro e amplamente disponível |

## Bitcoin Silent Payments (BIP 352)

Silent Payments permitem que um destinatário publique um único código de pagamento estático enquanto cada remetente deriva uma saída Taproot exclusiva. Um observador externo da chain não consegue associar diretamente essas saídas ao código publicado, e nenhuma solicitação interativa de endereço ou saída de notificação on-chain é necessária. O BIP 352 está marcado como **Complete**, mas introduz custo de varredura e é incompatível com carteiras que não o implementaram.<sup>[[1]](#references)</sup>

### Fluxo de trabalho do destinatário

1. Selecione uma carteira mantida ativamente que ofereça suporte explícito ao recebimento via BIP 352; verifique o recurso na documentação atual da carteira, não em uma publicação de rede social.
2. Faça backup da seed da carteira e do material do descritor/chave de Silent Payment usando o método de recuperação documentado pela carteira. Teste a descoberta com um pequeno valor em testnet/mainnet antes de publicar o código.
3. Gere **labels** separadas para campanhas, invoices ou contrapartes quando a carteira oferecer suporte a labels do BIP 352. As labels ajudam na contabilidade local sem publicar endereços associáveis.
4. Publique o código estático de Silent Payment por um canal autenticado. Ele é reutilizável, mas um impostor pode substituí-lo pelo próprio código.
5. Faça a varredura por meio de um full node local quando for viável. Um servidor terceirizado de indexação/varredura pode descobrir o horário das solicitações ou os dados dos filtros, mesmo sem poder gastar os fundos.
6. Mantenha os UTXOs descobertos identificados por labels e aplique as mesmas regras de coin control usadas no Bitcoin comum. Gastá-los ou consolidá-los pode revelar relações de propriedade.
7. Confirme que a recuperação descobre os pagamentos sem depender de um índice externo que não tenha backup.

### Fluxo de trabalho do remetente

1. Confirme que a carteira oferece suporte ao envio para a versão do endereço e autentique o código estático longo do destinatário.
2. Deixe a carteira construir a saída; nunca converta nem trunque o código manualmente.
3. Revise cuidadosamente as entradas selecionadas. Silent Payments melhoram a privacidade do endereço do destinatário, mas as entradas do remetente ainda permanecem no grafo público.
4. Use o comportamento de fee bumping/PSBT oferecido pela carteira. O BIP 352 exige a nova derivação da saída se as entradas mudarem, e alguns modos de assinatura são inseguros.
5. Mantenha um recibo ou prova criptografada necessária para disputas/contabilidade.

Silent Payments resolvem a publicação repetida do endereço do destinatário. Eles não ocultam o valor, o horário da transação, o cluster do remetente, o histórico de aquisição nem os gastos posteriores em conjunto.

## Pagamentos Zcash totalmente shielded

O Zcash oferece pools de valor transparentes e shielded. As transações shielded Orchard usam provas de conhecimento zero para que os nós possam verificar a validade enquanto os detalhes da transação permanecem criptografados; Unified Addresses podem conter vários tipos de destinatário.<sup>[[2]](#references)</sup> A privacidade depende do caminho efetivamente selecionado pela carteira, não do primeiro caractere de um endereço exibido.

### Fluxo de trabalho shielded

1. Escolha uma carteira mantida ativamente que identifique claramente o comportamento **shielded-by-default** e o suporte atual ao Orchard. Verifique o download e faça backup/teste da seed.
2. Obtenha ZEC legalmente e registre a base/origem. Uma exchange ainda conhece a aquisição e o saque.
3. Receba em um Unified Address compatível com a carteira e depois verifique se a transação chegou a um pool shielded. Não presuma o shielding automático sem confirmar o comportamento da carteira.
4. Prefira transferências **shielded-to-shielded**. Movimentações de transparent-to-shielded e shielded-to-transparent expõem valores/horários públicos e podem permitir correlação de valores; a especificação Orchard observa que gastar para um endereço não-Orchard revela o valor da transação.<sup>[[3]](#references)</sup>
5. Evite round trips com valores exatos e distintos e travessias imediatas de fronteira. Isso é uma prática de higiene de privacidade, não uma permissão para ocultar propriedade ou relatórios.
6. Use o caminho de privacidade de rede compatível com a carteira. A criptografia shielded não oculta IP/horário dos servidores da carteira ou dos peers.
7. Mantenha registros internos de compliance e use viewing keys apenas para auditoria/divulgação deliberada, depois de compreender seu escopo.
8. Confirme o suporte da carteira/exchange do destinatário antes de enviar; um destinatário transparente obrigatório altera a propriedade de privacidade.

## GNU Taler: pagador anônimo, merchant responsável

GNU Taler é um protocolo aberto de pagamento eletrônico que usa moedas tradicionais, blind signatures e integração com exchange/banco regulamentados. Seu design busca manter os clientes anônimos para os merchants, enquanto os merchants permanecem identificáveis e sujeitos a tributação.<sup>[[4]](#references)</sup> Não é uma cryptocurrency, e a disponibilidade depende de uma exchange regional compatível, banco, carteira e merchant.

### Fluxo de trabalho do usuário onde implantado

1. Identifique uma exchange e um merchant Taler em operação na moeda/jurisdição relevante; leia os termos atuais, taxas, KYC e avisos de privacidade.
2. Instale a carteira oficial e verifique sua origem. Proteja os dados de backup/recuperação da carteira como dinheiro, pois o valor da carteira pode ser um bearer asset.
3. Saque o valor por meio do fluxo compatível de banco/exchange usando informações verdadeiras. A instituição de financiamento/exchange pode conhecer o saque, embora blind signatures quebrem a associação direta entre a moeda e o saque.
4. Revise o contrato do merchant na carteira: identidade do merchant, item/resumo, valor, taxas, reembolso e termos de entrega.
5. Pague e preserve os dados do recibo necessários para reembolso, garantia, contabilidade ou impostos.
6. Não reutilize identificadores opcionais de sessão/conta do merchant se a unlinkability em relação ao merchant for necessária.
7. Inclua no threat model os metadados da carteira, da rede e da entrega; a criptografia de pagamento do Taler não oculta um endereço de envio nem um endpoint comprometido.

O merchant e a exchange continuam responsáveis, e operar qualquer um desses componentes pode constituir uma atividade regulamentada de serviço de pagamento.

## Federated Chaumian e-cash

Chaumian e-cash usa blind signatures para que uma mint assine um token sem ver posteriormente o token não cegado que foi gasto. A Fedimint distribui a custódia das reservas e a assinatura entre uma federação de guardians; a documentação afirma que os guardians veem as reservas agregadas/notas em circulação, mas não devem ver o saldo individual nem quem pagou a quem dentro da federação.<sup>[[5]](#references)</sup>

Este é um **valor custodial bearer**. Um quórum suficiente de guardians controla as reservas; falha da federação, guardians desonestos, bugs de software ou perda do estado do cliente podem causar perdas. Depósitos, saques e gateways Lightning são eventos de fronteira visíveis e podem correlacionar horário/valor.

### Fluxo de trabalho de risco limitado

1. Use apenas um pequeno valor que você possa perder. Considere federações públicas/desconhecidas mais arriscadas que guardians com responsabilidade no mundo real.
2. Verifique o convite da federação por um canal autenticado e registre as identidades dos guardians, quórum, jurisdição, taxas, recuperação e política de encerramento.
3. Instale uma carteira compatível mantida ativamente, verifique-a e compreenda seu esquema de backup antes de depositar.
4. Deposite Bitcoin adquirido legalmente pelo caminho documentado. Registre o peg-in para contabilidade e presuma que seu horário/valor são públicos ou conhecidos na fronteira.
5. Dentro da federação, use solicitações de pagamento novas e evite adicionar identificadores de conta/chat/entrega que recriem a associação removida pela blind signature.
6. Para pagamentos Lightning, trate o gateway como um observador adicional das invoices e do horário da fronteira.
7. Resgate/saque conforme a política, esperando que um valor distinto e um horário imediato possam ser correlacionados a um depósito ou pagamento externo.
8. Mantenha registros de impostos/origem/autorização de forma privada; não peça aos guardians ou gateways que relatem a atividade de forma incorreta.

Não descreva federated e-cash como trustless, self-custodial ou garantidamente anônimo.

## BOLT 12 offers e route blinding

BOLT 12 offers podem ser reutilizáveis sem publicar um endereço on-chain estável e podem usar caminhos blindados para que o pagador não precise conhecer a identidade/nó/caminho claro do destinatário. Isso complementa, mas não substitui, o onion routing já existente do Lightning.

Antes de usar:

1. Confirme que as carteiras do remetente e do destinatário oferecem suporte aos mesmos recursos atuais do BOLT 12; não deduza suporte apenas pela marca genérica “Lightning”.
2. Autentique a offer out of band e verifique o valor, emissor/descrição e as regras de recorrência.
3. Use um contexto novo de invoice/pagamento gerado a partir da offer.
4. Mantenha aliases de nós, informações públicas de contato e endpoints de rede estáveis no mínimo necessário.
5. Presuma que remetente/destinatário, primeiro/último hop, serviço de carteira, grafo de canais e financiamento/fechamento on-chain ainda divulgam partes da relação.

## Auditabilidade sem divulgação pública

Privacidade e auditoria podem coexistir:

- Mantenha labels, invoices, autorizações, custo de aquisição e mapeamento de propriedade criptografados fora do protocolo público.
- Separe uma **view/audit key** de uma spending key quando o protocolo oferecer esse recurso; teste primeiro sua divulgação exata em uma carteira de amostra.
- Forneça ao auditor a prova mínima e delimitada, em vez de uma seed ou credencial de gasto irrestrita.
- Registre a versão do software, protocolo/pool, ID ou prova da transação, finalidade da contraparte e fonte da taxa de câmbio no momento da transação.
- Defina retenção e exclusão em vez de acumular um grafo de identidade permanente e não criptografado.

## Checklist de seleção

- [ ] O campo oculto e o observador foram nomeados com precisão.
- [ ] O suporte da carteira/protocolo foi verificado na data da transação.
- [ ] As associações de aquisição, rede, nó/RPC, contraparte, entrega e gastos posteriores foram documentadas.
- [ ] Os riscos de custódia, recuperação, liquidez, solvência do emissor/federação e reembolso foram aceitos.
- [ ] Os registros obrigatórios de identidade, impostos, sanções, origem e organização permanecem corretos.
- [ ] Um teste pequeno de ponta a ponta, incluindo recuperação e prova de auditoria, foi concluído com sucesso.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
