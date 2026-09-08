# Catálogo de Técnicas de Pagamento Anônimo

Este catálogo abrange **famílias** de pagamento, desde dinheiro comum até e-cash com blind signatures e obfuscation em public chains. “Anônimo” sempre significa anônimo em relação a um observador identificado. Um merchant, issuer, mint, exchange, blockchain analyst, network provider, empregador e observador físico veem fatos diferentes.

Os procedimentos abaixo destinam-se a fundos legais, contas verdadeiras e procurement autorizado. Técnicas cujo objetivo nos casos citados foi laundering, evasão de sanções ou fraude de identidade são explicadas e detectadas, mas seu procedimento é um exercício forense sintético — não instruções para cometer o crime.

## Coverage matrix

| Família | Principal propriedade de privacidade | Principal observador/confiança | Tratamento |
|---|---|---|---|
| Cash e equivalentes | nenhum registro remoto da payment network | recipient e ambiente físico | fluxo legal |
| Prepaid/gift/voucher value | separa o resgate do cartão principal | seller, issuer e redemption service | fluxo legal, varia conforme a jurisdição |
| Virtual/tokenized card | oculta o PAN reutilizável ou separa merchants | issuer/network/wallet ainda identifica o payer | fluxo legal |
| Payment app/intermediary | merchant pode ver um alias/intermediary | app coleta identidade/device/transaction | baseline de comparação |
| Bitcoin hygiene/Silent Payments | pseudônimos e unlinkability do recipient | public graph e fronteira wallet/network | deployable |
| PayJoin/CoinJoin | enfraquece heurísticas de propriedade comum/linkage | participants/coordinator/network/public graph | deployable quando suportado; revisão legal |
| Lightning/BOLT 12 | roteamento off-chain e redução do caminho do receiver | endpoints, hops, services e channel graph | deployable quando suportado |
| Monero/Zcash/MWEB | confidencialidade on-chain no nível do protocolo | acquisition, endpoint, network e fronteiras | deployable quando legal/suportado |
| Ethereum ZK application | oculta uma declaração/ligação de ação especificada | public inputs, RPC, relayer e app | específico da aplicação |
| Cashu/Fedimint/Taler | privacidade do payer por blind signatures | mint/federation/exchange custody e fronteiras | emergente/específico da implantação |
| Stablecoins | settlement digital conveniente | chain transparente mais issuer freeze/control | não é baseline anônimo |
| Swaps/bridges/DEX | move valor entre assets/chains | ambos os graphs, contracts e providers | mecânica forense; apenas swaps legais comuns |
| Mixers/peel/structuring | aumenta ambiguidade/trabalho do graph | entry/exit graph e service records | apenas exercício sintético de detecção |
| Nominees/mules/OTC/fronts | insere intermediários humanos/empresariais | facilitators, banks, communications | apenas análise de abuso criminoso |
| Reusable/stealth payment addresses | novo endereço do recipient por pagamento | public announcement/notification e wallet boundaries | deployable quando suportado |
| Confidential sidechain/state channel | oculta amount/asset ou updates intermediários | peers, bridge/federation e lifecycle settlement | específico do protocolo |
| Carrier/open-banking/platform billing | oculta o cartão principal do merchant | carrier, bank/PISP ou platform identifica o customer | pagamento comum identificado |
| Mutual credit/net settlement | menos registros externos de settlement | private ledger operator possui o mapeamento completo | apenas participants identificados |

## Cash

**Mecânica:** valor físico ao portador muda de mãos sem autorização online do issuer ou public ledger.

**Vantagens:** o merchant não precisa conhecer a identidade bancária/do cartão; não há graph remoto da transaction; é amplamente compreendido e final.

**Desvantagens:** apenas presencial; roubo/perda; controles de troco/recibo/serial ou reporte; saque, câmeras, testemunhas e localização ainda vinculam o payer.

**Procedimento:** (1) confirmar que cash é legal/aceito e verificar regras de valor/reporte; (2) sacar ou receber legalmente e manter registros contábeis privados; (3) pagar um merchant comum sem identificadores desnecessários de loyalty/account; (4) solicitar apenas o recibo exigido; (5) evitar dados de shipping/account quando a compra não exigir; (6) registrar internamente a finalidade comercial legítima.

**Detecção:** reconciliar caixa/recibo/inventário, câmeras e access logs conforme a policy aplicável; investigar refunds incomuns em cash ou valores repetidos logo abaixo de controles, sem tratar o uso comum de cash como suspeito por si só.

## Money order, postal order, cashier instrument e cash on delivery

**Mecânica:** um issuer regulado converte cash/account funds em um instrumento numerado pagável a um recipient identificado; COD adia a cobrança até a entrega.

**Vantagens:** o recipient pode não receber o número do banco/cartão principal do payer; utilizável quando cash não pode ser enviado remotamente; recibo claro.

**Desvantagens:** issuer/retailer retém dados de compra/identidade conforme exigido; rastreamento por serial; endereço do recipient/delivery; perda/fraude e restrições regionais; geralmente não é anônimo.

**Procedimento:** (1) verificar regras, limites, identificação e aceitação pelo recipient; (2) comprar com informações verdadeiras e fundos legais; (3) preencher payee/amount imediatamente; (4) preservar serial/recibo; (5) usar entrega rastreada adequada ao valor; (6) reconciliar redemption/refund.

**Detecção:** registro de compra/resgate do issuer, serial do instrumento, retailer/câmera, shipping e conta do recipient; sinalizar alterações, serials duplicados e resgates rápidos incompatíveis geograficamente.

## Open-loop prepaid card

**Mecânica:** uma credential de stored value com marca de network autoriza contra um saldo prepaid, em vez de uma conta de crédito principal.

**Vantagens:** limita exposição e perda no merchant; separa o merchant do PAN principal; utilizável online quando aceito.

**Desvantagens:** registros de compra/activation/reload/registration e device; KYC e limites variam; falhas de billing address; restrições de cash-out/refund; “sem nome” não significa ausência de registro do issuer.

**Procedimento:** (1) verificar identidade atual do issuer, fees, KYC, geografia e suporte online/recurring; (2) adquirir de seller autorizado com fundos legais; (3) registrar dados verdadeiros exigidos; (4) usar para um único compartment/purpose; (5) não estruturar loads nem falsificar residência; (6) guardar evidências de compra/despesa e encerrar/descartar conforme os termos do issuer.

**Detecção:** relacionar seller/activation, funding, device/IP, merchant authorization, balance checks e redemption/refund. Os padrões importam mais que o rótulo prepaid.

## Closed-loop gift card, voucher e transferable service credit

**Mecânica:** valor numerado resgatável apenas com um merchant/service ou ecosystem. Airtime/game/store credits são variantes.

**Vantagens:** o merchant recipient pode ver somente code/balance; blast radius limitado; gifting e separação de orçamento simples.

**Desvantagens:** seller e service registram purchase/activation/redemption; account/device/delivery ainda vinculam; scams, descontos de revenda e limites de expiração/região; direitos de refund limitados.

**Procedimento:** (1) comprar apenas de canais autorizados; (2) registrar o valor do code sem expor o segredo; (3) evitar vincular uma conta de loyalty identificadora quando desnecessário; (4) resgatar por uma conta/contexto legítimo separado; (5) guardar o recibo até a aceitação; (6) nunca comprar codes para uma solicitação não solicitada de “tax/support/ransom”.

**Detecção:** horário de emissão/resgate do code, convergência de device/account, compras em massa ou por limiar, um device consultando muitos balances e resgate rápido distante.

## Cryptocurrency-funded card ou gift-code broker

**Mecânica:** um intermediary aceita cryptocurrency e emite um card, voucher ou merchant code. É uma conversão cross-rail: o merchant vê valor comum de card/gift, enquanto o broker vincula o depósito on-chain à emissão e entrega.

**Vantagens:** o merchant não recebe a funding wallet; útil para merchants legítimos que não aceitam crypto; stored value limitado.

**Desvantagens:** não é anônimo perante broker/issuer; regras de KYC, sanções, exchange e card-program; public deposit graph; account/device/email e redemption do code reconectam os dois lados; risco de scam/insolvência.

**Procedimento:** (1) verificar entidade legal, card issuer, jurisdição suportada, KYC, fees e refund policy; (2) usar apenas fundos legais documentados; (3) testar a menor denominação; (4) verificar restrições de network/merchant antes da compra; (5) preservar a transaction blockchain e o receipt do broker para contabilidade; (6) nunca usar broker que prometa fraude de identidade, bypass de sanções ou cash-out “untraceable”.

**Detecção:** correlacionar deposit addresses do broker, amount/time únicos, account/device e autorização do card emitido ou redemption do gift-code; registros do issuer e broker conectam a public chain ao merchant.

## Virtual ou merchant-locked card

**Mecânica:** o issuer associa um PAN/token gerado à conta real, frequentemente restringindo merchant, amount ou expiration.

**Vantagens:** impede exposição de PAN reutilizável; compartmentation por merchant; limites de gasto e revogação simples; controle antifraude maduro.

**Desvantagens:** o issuer ainda conhece payer, funding, merchant, device/IP e time; o merchant vê account/delivery; alguns refunds/recurring charges falham; não é anônimo.

**Procedimento:** (1) usar o recurso oficial do issuer regulado; (2) criar um card para um único merchant/engagement; (3) definir o menor limite e expiry úteis; (4) usar billing correto quando exigido; (5) verificar statement descriptor/comportamento de refund; (6) freeze/delete após o settlement final, mantendo evidências de auditoria.

**Detecção:** mapeamento issuer token-to-account, merchant authorization, device e delivery. Defenders usam sinais de reuse específico do merchant, velocity e account takeover.

## Mobile-wallet network token

**Mecânica:** a tokenização de pagamento EMV substitui o PAN por uma credential limitada, frequentemente vinculada a device, merchant ou cenário de pagamento.<sup>[[1]](#references)</sup>

**Vantagens:** o merchant não recebe o PAN reutilizável; criptografia do device/dados dinâmicos reduzem cloning; revogável sem substituir o card.

**Desvantagens:** issuer, token service, wallet platform e network retêm mapeamentos/transactions; platform account, device e location podem identificar o payer.

**Procedimento:** (1) cadastrar um card legítimo na wallet oficial; (2) proteger platform account/device com autenticação forte; (3) verificar device token/últimos dígitos na compra; (4) desativar location/analytics desnecessários quando suportado; (5) remover imediatamente devices/tokens perdidos; (6) revisar registros do issuer e wallet.

**Detecção:** token requestor/device cryptogram e issuer mapping, wallet/account telemetry, merchant terminal e evidências físicas.

## Payment app, marketplace wallet e centralized intermediary

**Mecânica:** o service mantém accounts e transfere internamente ou por bank/card rails; o merchant pode ver um alias, enquanto o service vê ambas as partes.

**Vantagens:** conveniência, mecanismos de dispute/refund, recipient não necessariamente vê dados bancários/do card.

**Desvantagens:** graph centralizado de identidade/social/transaction/device; freezes e processo legal; counterparties podem expor o profile; uso de dados pode exceder a necessidade do pagamento.<sup>[[2]](#references)</sup>

**Procedimento:** (1) ler termos de identity, privacy, retention e buyer-protection; (2) minimizar sincronização opcional de profile/contact; (3) usar uma conta separada verdadeira somente quando os termos permitirem; (4) habilitar MFA/alerts; (5) verificar recipient e privacidade de memo/profile; (6) exportar registros e encerrar links não usados.

**Detecção:** account do provider, device/IP, contact graph, funding/withdrawal, memo e merchant records. Um alias é pseudonymity perante um counterparty, não anonymity perante a platform.

## Bank transfer, ACH, wire e instant-account payment

**Mecânica:** instituições reguladas movem valor entre accounts identificadas e trocam os dados exigidos do payment.

**Vantagens:** rápido, accountable, reversível em casos limitados, registros fortes; virtual account numbers podem reduzir divulgação ao merchant.

**Desvantagens:** banks/processors conhecem ambos os lados; statements e references; não é anônimo; dados cross-border e Travel Rule/AML.

**Procedimento:** usar somente quando accountability for aceitável: verificar o beneficiary independentemente, minimizar dados opcionais no memo, usar virtual account/reference fornecido pelo banco quando disponível, habilitar alerts, guardar invoice e reconciliar.

**Detecção:** registros determinísticos de bank/payment, propriedade do beneficiary/account, device/session e controles antifraude. Isso é um baseline, não uma técnica de anonymity.

## Account e merchant compartmentation

**Mecânica:** identities/accounts, email aliases, cards e delivery contexts legais separados impedem que merchants não relacionados unam trivialmente a atividade, enquanto issuer/controller mantém o mapeamento.

**Vantagens:** reduz linkage entre merchants e impacto de breaches; fácil de auditar; compatível com pagamentos regulados.

**Desvantagens:** provider ainda mapeia compartments; recovery phone/device/IP e shipping podem reconectá-los; a policy pode proibir múltiplas accounts.

**Procedimento:** (1) definir um purpose; (2) criar apenas aliases/subaccounts compatíveis com os termos; (3) usar token/card específico do merchant; (4) desabilitar personalização cross-account de contacts/ads; (5) manter um controller ledger criptografado; (6) aposentar identifiers após o fim das necessidades de refund/retention.

**Detecção:** providers unem recovery, device, funding e IP; merchants unem delivery, browser e comportamento de account. Defenders devem distinguir compartmentation legítima de fraude de synthetic identity.

## Controlled red-team procurement

**Mecânica:** o SOC não conhece uma purchase, enquanto um exercise controller mantém o mapeamento de legal entity, operator e infrastructure.

**Vantagens:** exercício realista de detecção; nenhuma exposição pessoal; deconfliction e auditoria imediatas.

**Desvantagens:** não é anônimo perante organization/provider; overhead de governance; leaks se o controller ledger for mal administrado.

**Procedimento:** (1) alocar organization card/wallet/budget específico do engagement; (2) separar funções de purchaser/operator; (3) registrar asset, amount, service, purpose e kill date; (4) armazenar attribution mapping com acesso limitado do controller; (5) nunca usar false identity/mule/stolen funds; (6) revelar/reconciliar indicators e refunds no encerramento.

**Detecção:** controller mapeia provider invoice e asset; SOC testa descoberta independente por domain, certificate, hosting e traffic, em vez de dados do cardholder.

## Bitcoin address hygiene e coin control

**Mecânica:** receive addresses novos, labeling local e gasto seletivo de UTXOs reduzem address reuse e merging acidental de compartments em um public ledger.

**Vantagens:** amplamente suportado; self-custodial; evita o linkage público mais simples.

**Desvantagens:** todas as transactions/amounts continuam públicas; common-input/change/timing e consolidação posterior vinculam atividade; records de acquisition/RPC/network permanecem.

**Procedimento:** (1) instalar/verificar wallet mantida; (2) fazer backup e testar seed recovery; (3) usar novo address por invoice; (4) rotular source/purpose localmente; (5) usar coin control para evitar merging de contexts; (6) preferir local node ou connection consciente de privacidade; (7) revisar change/fees e manter accounting legal.<sup>[[3]](#references)</sup>

**Detecção:** address graph, heurísticas de common-input/change com incerteza, amount/time exatos, consolidation, service deposits, timing de broadcast node/RPC e registros off-chain.

## Bitcoin Silent Payments

**Mecânica:** BIP 352 permite ao receiver publicar um código estático enquanto senders derivam outputs Taproot únicos via ECDH; observadores externos não conseguem vincular diretamente os outputs ao code.<sup>[[4]](#references)</sup>

**Vantagens:** identifier público reutilizável sem address reuse; nenhum pedido interativo de address ou output de notification; mistura-se a outputs Taproot.

**Desvantagens:** custo de scanning do receiver; suporte de wallet varia; graph de amount/sender e spending permanecem públicos; index server pode observar scans.

**Procedimento:** (1) selecionar wallet BIP 352 atual; (2) fazer backup/testar descriptor e recuperação de scanning; (3) gerar code rotulado quando suportado; (4) autenticar o code publicado; (5) sender revisar inputs e enviar um pequeno test; (6) receiver fazer scan preferencialmente pelo próprio node; (7) manter UTXOs recebidos separados.

**Detecção:** por design, não é identificável de modo confiável apenas pelo output; analysts usam sender inputs, amount/time, spending posterior, wallet/network/index e registros de counterparties.

## PayJoin

**Mecânica:** payer e payee contribuem com inputs para uma payment transaction, quebrando a suposição de que todos os inputs têm o mesmo owner.<sup>[[5]](#references)</sup>

**Vantagens:** pagamento comum com privacidade aprimorada; beneficia o graph geral ao enfraquecer uma heurística comum; não exige grupo de equal outputs.

**Desvantagens:** exige interação/suporte; disponibilidade do endpoint do receiver; amount e transaction final públicos; metadata de implementação e fallback.

**Procedimento:** (1) confirmar que ambas as wallets mantidas suportam a mesma versão de PayJoin; (2) autenticar invoice/endpoint; (3) iniciar pela payment URI habilitada para PayJoin da wallet; (4) inspecionar amount/fee finais e assinar somente os inputs esperados; (5) evitar manual transaction surgery; (6) verificar broadcast e receipt; (7) registrar fallback se a negociação falhar.

**Detecção:** blockchain analysts não devem aplicar clustering de common-input automaticamente; endpoint/provider pode registrar a negociação; usar evidências de wallet/network e later-spend, não apenas o formato da transaction.

## CoinJoin

**Mecânica:** vários participants criam colaborativamente uma transaction com muitos inputs/outputs, normalmente denominações iguais, aumentando a ambiguidade sobre a correspondência input-output.

**Vantagens:** conjunto maior de ambiguidade on-chain; existem designs self-custodial; estrutura de rounds mensurável.

**Desvantagens:** metadata de coordinator/peer/network; fees/liquidity; formato identificável; toxic change e consolidação posterior destroem ganhos; disponibilidade legal/provider varia.

**Procedimento:** (1) verificar disponibilidade e legalidade atuais da wallet/coordinator; (2) instalar wallet oficial e fazer backup; (3) usar apenas UTXOs legais; (4) entender denomination, fee e modelo do coordinator; (5) manter change e mixed outputs rotulados/separados; (6) nunca consolidá-los juntos; (7) encaminhar network traffic conforme suporte oficial e preservar accounting.

**Detecção:** identificar estrutura colaborativa sem presumir crime; calcular possíveis mappings/anonymity set e observar change/consolidation, service boundaries e registros de network/coordinator.

## Lightning Network

**Mecânica:** payments HTLC atravessam channels com onion routing; a maioria dos detalhes do payment não é publicada on-chain, enquanto funding/closing e informações públicas de channels são.

**Vantagens:** rápido e barato; intermediaries normalmente veem apenas hops adjacentes; detalhes rotineiros permanecem off-chain.

**Desvantagens:** sender/receiver e first/last hop sabem mais; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets identificam users.

**Procedimento:** (1) escolher conscientemente self-custodial ou custodial; (2) verificar wallet/seed/channel recovery; (3) usar invoice para o payment exato; (4) preferir private channels/LSP features somente após avaliar tradeoffs; (5) proteger node IP com Tor suportado quando necessário; (6) evitar reutilizar invoices identificadoras; (7) manter accounting de channels e payments.<sup>[[6]](#references)</sup>

**Detecção:** logs de node/LSP/custodian, channel graph/probes, falhas/timing de payment e funding/closure on-chain; ausência de transaction pública não significa ausência de records.

## BOLT 12 offers e route blinding

**Mecânica:** uma offer reutilizável produz invoices novos e pode anunciar blinded paths, para que o payer não precise conhecer o node/path claro do receiver.

**Vantagens:** privacidade do receiver; endpoint reutilizável de donation/payment sem invoice estática; integra-se ao Lightning onion routing.

**Desvantagens:** suporte de wallet varia; endpoints, hops selecionados e funding permanecem; contato público ou endpoint de network pode reidentificar o receiver.

**Procedimento:** (1) confirmar suporte compatível a BOLT 12; (2) autenticar offer; (3) solicitar invoice nova; (4) revisar amount/issuer/recurrence; (5) pagar pela wallet; (6) verificar receipt/refund behavior; (7) minimizar alias/contact do node e preservar accounting.<sup>[[7]](#references)</sup>

**Detecção:** telemetry de wallet/LSP e first/last-hop, account de distribuição da offer, timing/value e funding graph; route blinding limita intencionalmente a visibilidade do payer.

## Monero

**Mecânica:** stealth addresses de uso único ocultam o vínculo do recipient, RingCT oculta amounts e ring signatures fornecem ambiguidade ao sender.

**Vantagens:** privacidade padrão on-chain; confidencialidade de sender/receiver/amount; ecossistema maduro de wallet/node dedicado.

**Desvantagens:** registros de acquisition/off-ramp e endpoint/network/counterparty; remote node vê queries/IP; suporte de exchange/tratamento legal variam; pequenos erros operacionais ainda vinculam contexts.

**Procedimento:** (1) adquirir legalmente e preservar basis/source; (2) instalar/verificar wallet oficial mantida; (3) fazer backup/testar seed; (4) usar local node ou caminho documentado de Tor/I2P para remote node; (5) usar nova subaddress por payer/invoice; (6) rotular contexts localmente; (7) divulgar transaction proof/view access apenas deliberadamente.<sup>[[8]](#references)</sup>

**Detecção:** focar em exchange/merchant/device/network e evidências de wallet apreendida; o uso do protocolo isoladamente não é suspeito e a public chain deliberadamente expõe menos.

## Zcash fully shielded Orchard

**Mecânica:** zero-knowledge proofs validam shielded transfers enquanto sender, receiver e amount são criptografados; transparent pools e transições de pool permanecem públicas.

**Vantagens:** forte confidencialidade on-chain shielded; viewing keys podem permitir auditoria limitada; validade imposta pelo protocolo.

**Desvantagens:** suporte de wallet/exchange e escolha real de pool variam; correlação de timing/value nas fronteiras transparentes; network/RPC e endpoint permanecem.

**Procedimento:** (1) selecionar wallet Orchard mantida e shielded-by-default; (2) verificar/fazer backup; (3) obter ZEC legalmente; (4) receber em Unified Address suportado e confirmar pool; (5) preferir shielded-to-shielded; (6) usar network privacy suportada; (7) testar divulgação de viewing-key em uma wallet pequena antes da auditoria.<sup>[[9]](#references)</sup>

**Detecção:** registros de transparent boundary e services, metadata de wallet/network e viewing keys quando legalmente fornecidas; não presumir que todos os payments de Unified Address foram shielded.

## Mimblewimble e Litecoin MWEB

**Mecânica:** confidential transactions ocultam amounts e a agregação no estilo Mimblewimble remove o histórico convencional rico em addresses; Litecoin implementa um extension block opcional junto à chain transparente.

**Vantagens:** amounts confidenciais e fungibilidade melhorada no domínio privado; pruning/aggregation eficientes.

**Desvantagens:** fronteira opt-in de peg-in/out é pública e correlacionável; suporte de wallet/exchange; diferenças no modelo interativo/de addresses; registros de network e acquisition.

**Procedimento:** (1) escolher wallet mantida com suporte explícito a MWEB; (2) verificar/fazer backup e testar pequeno amount; (3) adquirir legalmente; (4) fazer peg para MWEB e verificar o balance domain; (5) transacionar apenas com receiver compatível; (6) evitar peg-out imediato e distintivo; (7) manter registros privados de auditoria.<sup>[[10]](#references)</sup>

**Detecção:** timing/value de public peg-in/out, dados de exchange/wallet/node e spends transparentes posteriores; detalhes internos de confidential transfer são intencionalmente reduzidos.

## Ethereum zero-knowledge privacy applications

**Mecânica:** um circuit prova uma declaração — membership, ownership de note válida ou authorization — sem revelar o segredo; um verifier contract verifica. Deposits, withdrawals, public inputs, events e gas ainda podem expor links.

**Vantagens:** selective disclosure programável; aplicações com anonymous set; regras verificáveis sem revelar todos os dados.

**Desvantagens:** bugs em contract/circuit; anonymous set pequeno; public boundaries; RPC/IP/session/analytics/gas funding; riscos legais e de aplicação/sanções.

**Procedimento:** (1) definir exatamente o que o proof oculta; (2) usar aplicação auditada e mantida quando legal; (3) inspecionar public inputs/events e regras de deposit/withdraw; (4) separar action wallet e gas sponsorship conforme a intenção do protocolo; (5) usar caminho de RPC/network consciente de privacidade; (6) testar com valor pequeno; (7) preservar registros de compliance.<sup>[[11]](#references)</sup>

**Detecção:** contract events, timing/value de deposit/withdraw, relayer/paymaster, RPC/session, frontend storage/analytics e eventual exchange/merchant boundary. Não afirmar que o ZK proof oculta campos declarados públicos.

## Stablecoins

**Mecânica:** tokens são transferidos em uma public chain; centralized issuers podem congelar/blacklist ou resgatar contra accounts identificadas.

**Vantagens:** estabilidade de preço, liquidity e suporte de merchant; settlement rápido; accounting simples.

**Desvantagens:** graph transparente de address/amount/contract; gas funding; identity/control de issuer e exchange; sanctions screening; anonimato geralmente fraco.

**Procedimento:** tratar como pagamento identificado: usar fresh business address apenas para compartmentation, verificar token contract/network, testar pequeno amount, proteger wallet, usar trusted RPC/local node, preservar basis/source e verificar as parties exigidas.

**Detecção:** token event graph completo, issuer freeze list/actions, exchange/RPC/device e relações de gas-funding.

## Cashu Chaumian e-cash

**Mecânica:** um mint assina cegamente bearer secrets gerados pelo client, respaldados pelas reservas Bitcoin/Lightning do mint; pode impedir double-spend sem vincular diretamente issuance ao redemption posterior.

**Vantagens:** bearer tokens sem account; transferência peer-to-peer instantânea; mint não consegue vincular diretamente withdrawal blinded ao spend; tokens podem circular como data/QR.

**Desvantagens:** custody/solvency/censorship do mint; perda/roubo de bearer data; denomination/timing e fronteiras Lightning; metadata de network; ecossistema de software inicial.<sup>[[12]](#references)</sup>

**Procedimento:** (1) usar primeiro um test mint oficial ou valor mínimo descartável; (2) instalar wallet mantida e testar limitações de backup/restore; (3) autenticar mint e revisar custody/fees; (4) mintar pequeno amount; (5) enviar token por channel/QR privado autenticado; (6) receiver trocar o token antes de tratá-lo como final; (7) resgatar e reconciliar. Nunca guardar valor relevante em mint não confiável.

**Detecção:** mint vê network, fronteiras de issue/redeem/Lightning e conjunto de spent tokens, mas blinding remove o vínculo direto do token; endpoints/messages e amount/timing distintivos podem restaurar links.

## Fedimint federated e-cash

**Mecânica:** um threshold de guardians mantém reserves e assina e-cash cegamente; transfers internos bearer são privados perante guardians, enquanto gateways Lightning conectam payments externos.

**Vantagens:** custody distribuída; transferência interna privada; governance comunitária; nenhum guardian controla a reserve abaixo do threshold.

**Desvantagens:** risco de guardian quorum/custody/software; gateway observa invoices/timing; fronteiras de deposit/withdraw; complexidade de recuperação do client-state.

**Procedimento:** (1) verificar invite/guardians/quorum/jurisdição da federation; (2) instalar client mantido e testar recovery; (3) depositar pequeno amount legal; (4) usar fresh internal payment requests; (5) tratar gateway como observer do Lightning; (6) testar redemption; (7) manter source/tax records fora dos dados públicos de payment.<sup>[[13]](#references)</sup>

**Detecção:** federation vê issuance/redemption agregados, gateways veem invoices externos, Bitcoin/Lightning mostram boundaries, e evidências de endpoint/communication podem vincular transfers internos.

## GNU Taler

**Mecânica:** e-cash com blind signatures integrado a bank busca manter o payer anônimo perante merchants, enquanto merchants e income permanecem accountable.

**Vantagens:** privacidade do payer por design; moeda comum; accountability/refunds do merchant; nenhum token especulativo necessário.

**Desvantagens:** deployments limitados; exchange/bank vê funding; merchant vê order/delivery; risco de bearer/recovery da wallet; operators regulados.

**Procedimento:** (1) localizar exchange/merchant atual para a jurisdição/currency; (2) ler KYC/fees/privacy; (3) instalar wallet oficial; (4) retirar legalmente de bank/exchange suportado; (5) revisar merchant contract; (6) pagar e preservar receipt/refund data; (7) evitar identifiers de merchant session desnecessários.<sup>[[14]](#references)</sup>

**Detecção:** withdrawal do bank/exchange e merchant deposit são fronteiras accountable; order/device/delivery e timing do merchant podem correlacionar mesmo quando coins são blinded.

## Cross-chain bridge, atomic swap e decentralized exchange

**Mecânica:** um contract/service locks/burns um asset e libera/mint outro, ou counterparties fazem uma troca atômica. Isso quebra a visão de um único ledger, não a continuidade econômica.

**Vantagens:** interoperabilidade de asset/network; pode evitar um custodian centralizado; uso comum de portfolio/liquidity.

**Desvantagens:** ambas as chains são públicas; time/value/fees/liquidity e contracts correlacionam; registros de bridge/relayer/frontend/RPC; riscos de smart-contract/counterparty e regulatórios.

**Procedimento para swaps legais:** (1) verificar contract/service oficial e disponibilidade legal; (2) inspecionar custody/audit/fees/slippage; (3) usar pequeno test; (4) registrar ambos os transaction IDs e a rate; (5) proteger approvals; (6) reconciliar destination asset e revogar approvals desnecessárias. Não usar swaps para disfarçar a origem dos fundos.

**Detecção:** bridge deposit/withdraw events, amount único menos fees, ordem temporal, liquidity, relayer/RPC/frontend e deposits posteriores em services.

## Centralized mixer ou tumbler

**Mecânica:** um service recebe deposits em um pool e devolve unidades diferentes posteriormente, tentando obscurecer o mapping direto input-output.

**Vantagens:** pode ampliar a ambiguidade da transaction em teoria.

**Desvantagens:** operator pode roubar/registrar; análise de timing/value entry/exit; exposição a sanções, money-transmission e crimes; seizures expõem mappings; risco de taint/rejection.

**Procedimento:** nenhum guia operacional de mixing é fornecido. Reproduzir o graph com segurança ampliando [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): criar synthetic deposits, pooled outputs, fees e delays; fornecer mappings incompletos aos analysts; medir quais heuristics funcionam; então revelar ground truth.

**Detecção:** identificação de service wallet/contract, candidate sets de entry/exit, amount/fee/timing, reuse de deposit address, seized/provider logs e consolidação downstream. Rotular attribution probabilística.

## Peel chains, fan-out/fan-in e structuring

**Mecânica:** transactions repetidas retiram pequenos payments do change, dividem value entre muitos addresses, reconvergem collectors ou dividem amounts para evitar review.

**Vantagens:** aumenta o trabalho do analyst ingênuo e a quantidade de addresses.

**Desvantagens:** continuidade reconhecível de value/cadence/transaction; consolidation e service endpoints; structuring pode ser ilegal; fees e erros operacionais.

**Procedimento:** usar somente dados sintéticos de CSV/testnet: gerar uma source grande, edges repetidos de payment/change, branches paralelos e um collector; adicionar exemplos benignos semelhantes a exchange; ajustar detecção e documentar false positives.

**Detecção:** graph continuity, repeated change pattern, cadence, amounts logo abaixo de controles, service endpoint comum e records off-chain. Exchange hot wallets podem parecer com esses padrões, portanto contexto é obrigatório.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker e front company

**Mecânica:** outra pessoa/account/company recebe, converte ou gasta funds, inserindo camadas legais e operacionais entre controller e transaction.

**Vantagens para um adversary:** account identificada não revela imediatamente o controller; pode conectar cash, crypto, goods e jurisdictions.

**Desvantagens:** exposição a identity fraud/money-laundering; cada participant adiciona communications, bank/company/tax/shipping records, fees, inconsistencies e witnesses; reuse do facilitator cria hubs.

**Procedimento:** não emular com pessoas/accounts reais. Criar graph sintético com controller, recruiter, mule, OTC, shell merchant e beneficiary; inserir edges de device/IP/message/bank; solicitar que investigators distingam account holder de controller e registrem a confiança da evidência.

**Detecção:** shared device/IP/recovery, beneficiary/velocity incomuns, muitos senders sem relação, movimento imediato onward, inconsistência de company/director/invoice, communications e entrega de cash/commodity.

## NFTs, gambling, merchant goods e refund loops

**Mecânica:** value é convertido em asset de preço próprio, gambling balance, goods revendáveis ou refunds para criar narrativa transacional diferente.

**Vantagens para um adversary:** altera a forma do asset e introduz intermediaries de marketplace/merchant.

**Desvantagens:** marketplace/account/device e wash-trade graph; odds/play e refund records; evidências de delivery/resale; fees/losses; responsabilidade por fraud/laundering.

**Procedimento:** nenhum workflow de concealment. Usar marketplace data sintético com self-trades de related wallets, pricing implausível, play mínimo, refund instrument incompatível e shipping comum; validar a detecção contra collectors/customers legítimos.

**Detecção:** trades circulares/self-funded, ownership/funding comuns, outliers de preço, resale/refund imediato, atividade econômica mínima, device/delivery compartilhados e reconvergência de proceeds.

## Physical bearer wallet ou offline token transfer

**Mecânica:** um device, paper/QR, hardware bearer instrument ou e-cash token transfere controle de um secret em vez de transmitir um payment no handover.

**Vantagens:** nenhum evento de network ao vivo durante a exchange; útil offline; custody física semelhante a cash.

**Desvantagens:** cópia/roubo/perda e exclusividade incerta; redemption/broadcast posterior cria links; encontro/shipping físico; risco de counterfeit/tamper.

**Procedimento:** (1) usar apenas instrument/protocol revisado; (2) inicializar/verificar authenticity privadamente; (3) carregar somente pequeno valor legal; (4) transferir em contexto autorizado documentado; (5) receiver verificar ou sweep prontamente conforme o protocolo; (6) nunca presumir que o sender não reteve uma cópia; (7) registrar ownership/tax evidence privadamente.

**Detecção:** purchase/funding e eventual sweep/redemption, device serial/tamper evidence, delivery/meeting e endpoint records.

## Merchant-scoped invoice ou one-time payment request

**Mecânica:** o merchant cria uma request de uso único contendo amount, expiry e order reference. O payer liquida por um rail suportado sem expor diretamente uma credential reutilizável ao merchant; issuer ou payment processor ainda pode identificar ambas as partes.

**Vantagens:** limita credential reuse e identifiers cross-merchant acidentais; amount/expiry exatos reduzem erros; compatível com accounting e refunds comuns.

**Desvantagens:** invoice, delivery, browser, processor e issuer ainda vinculam o order; amount/time únicos podem fortalecer correlação; payment links maliciosos são comuns.

**Procedimento:** (1) autenticar o merchant independentemente; (2) solicitar invoice nova com amount, asset/network e expiry exatos; (3) inspecionar destination e refund rules; (4) pagar pelo engagement compartment aprovado; (5) verificar que o merchant reconhece a mesma invoice; (6) preservar receipt e transaction reference; (7) deixar a request expirar em vez de reutilizá-la.

**Detecção:** merchant e processor unem invoice, session e settlement; amounts/timing únicos e delivery identificam o payer. **Captured wallet/device:** invoice history expõe counterparties e purpose; minimizar memo data desnecessário, criptografar o device e manter o accounting autoritativo no finance system controlado.

## Prepaid service credit e capability token

**Mecânica:** um service converte payment convencional em créditos internos limitados ou capability bearer. O uso subsequente de API/resource pode evitar apresentar o card original em cada request, mas o service frequentemente consegue mapear issuance a redemption.

**Vantagens:** limita spend e perda por compromise; separa workers cotidianos da funding credential; permite budgets por project e revocation.

**Desvantagens:** geralmente pseudonymous, não anonymous; service database, redemption IP e padrão de uso único vinculam atividade; bearer tokens podem ser roubados; refunds podem exigir o payer original.

**Procedimento:** (1) comprar credits por organization account; (2) criar um project e budget; (3) emitir token limitado com restrições de service, amount e expiry; (4) armazená-lo somente no secret manager aprovado ou caminho de workload identity; (5) testar rejeição fora do escopo e após expiry; (6) monitorar consumption; (7) revogar e reconciliar valor não usado.

**Detecção:** provider une funding account, project, token issuance e usage; defenders alertam para mudanças de geographic/process e consumption anômala. **Captured node:** assumir que seu capability restante pode ser gasto; usar expiry curto, saldo baixo, audience binding e revocation server-side imediata.

## Privacy Pass ou blinded authorization token

**Mecânica:** um issuer produz um authorization token com preservação de privacidade que um origin pode validar sem vincular redemption a issuance. Pode representar entitlement pago ou acesso limitado por rate, mas não é uma currency geral. A arquitetura separa os papéis de client, attester, issuer e origin e alerta que IP/timing ou collusion podem desfazer unlinkability.<sup>[[18]](#references)</sup>

**Vantagens:** redemption unlinkable para services suportados; nenhum account cookie reutilizável no origin; tokens em cache podem separar issuance e use no tempo.

**Desvantagens:** específico da aplicação; confiança em issuer/attester e partitioning do anonymity-set; IP e browser metadata permanecem; token theft ou timing distintivo de issuance podem correlacionar uso.

**Procedimento:** (1) usar implementação compatível com o tipo de token Privacy Pass relevante; (2) definir exatamente qual entitlement o token prova; (3) separar issuer e origin administration quando o threat model exigir; (4) minimizar challenge metadata; (5) emitir vários test tokens e resgatar cada um uma vez em origins próprios; (6) comparar logs procurando identifiers estáveis proibidos; (7) testar replay, expiry e controles de revocation/abuse.

**Detecção:** origins veem redemption IP/time e token validity; issuers/attesters veem issuance context; analysts testam timing e metadata partitions sem presumir cryptographic break. **Captured client:** bearer tokens não gastos podem ser utilizáveis; limitar value, lifetime e audience, e nunca armazenar funding credential junto deles.

## Delegated organization procurement ou fiscal sponsor

**Mecânica:** uma procurement team, reseller ou fiscal sponsor autorizada contrata e paga enquanto a operational team recebe um service limitado. É role separation com registros verdadeiros, não nominee ou false identity.

**Vantagens:** vendors não precisam receber a identidade de cada operator ou payment details pessoais; compliance, tax e refund centralizados; budget e offboarding claros.

**Desvantagens:** sponsor conhece beneficiary e purpose; contracts, approvals, delivery e accounts permanecem; delay/fees adicionais; separação fraca se a mesma pessoa administrar todas as camadas.

**Procedimento:** (1) documentar business purpose, beneficiary e approving authority; (2) escolher intermediary aprovado pela organization; (3) contratar com dados verdadeiros; (4) provisionar subaccount por project sem personal billing credential; (5) separar finance administrators de operators; (6) reconciliar invoices e access; (7) encerrar service e delegated access no closeout.

**Detecção:** procurement, identity-provider, vendor e delivery records unem a cadeia. **Captured operational device:** deve revelar o service project, mas não finance credentials; manter invoices e payer identities no finance system, não em field nodes.

## Escrow ou conditional settlement

**Mecânica:** um escrow agent confiável ou smart contract mantém value até que condições documentadas sejam cumpridas. Pode reduzir divulgação direta entre payer e payee, enquanto escrow e payment rails subjacentes mantêm a relação.

**Vantagens:** proteção contra dispute/delivery; payer e merchant podem expor menos credentials reutilizáveis entre si; release conditions auditáveis.

**Desvantagens:** custody/contract risk do escrow, fees e identity obligations; on-chain contracts são públicos; order, shipping e dispute data permanecem; não é anônimo perante o intermediary.

**Procedimento:** (1) verificar legal entity, custody, fees, dispute forum e assets suportados; (2) criar milestone escrito exato e caminho de refund; (3) funding por organization account aprovado; (4) verificar receipt e release authorization independentemente; (5) liberar somente após evidence; (6) preservar audit record completo; (7) fechar permissions ou contract approvals não usados.

**Detecção:** escrow account/contract events, funding e release time, beneficiary e dispute records revelam a transaction. **Captured device:** session tokens ou contract approvals podem permitir release; exigir approver/MFA separado e revogar sessões ativas em caso de perda.

## Batched ou pooled organization settlement

**Mecânica:** múltiplas obrigações aprovadas são agregadas e liquidadas em menos bank/blockchain transactions, com private internal ledger atribuindo cada parcela. Batching pode reduzir detalhes públicos por purchase, mas o coordinator mantém attribution completa.

**Vantagens:** fees menores; menos graph edges públicos; oculta line items individuais de um public observer quando amounts são agregados; accounting interno simples.

**Desvantagens:** coordinator é observer completo e alvo valioso; totals/timing distintivos podem correlacionar; riscos de custody/reconciliation; pode parecer structuring se abusado.

**Procedimento:** (1) definir participants e obrigações legais no accounting system; (2) estabelecer janela regular justificada pelo negócio, não thresholds para evitar controles; (3) exigir dual approval do agregado; (4) liquidar para recipients autenticados; (5) reconciliar cada internal line ao batch; (6) tratar refunds como corrections vinculadas; (7) proteger ledger access e retê-lo conforme policy.

**Detecção:** coordinator ledger, approval e beneficiary records fornecem ground truth; public analysts usam clustering de input/output/value/time com cautela. **Captured payer device:** deve conter apenas sua requisition, não signing key ou participant ledger do pool.

## Account-abstraction paymaster ou sponsored gas

**Mecânica:** um relayer/bundler envia uma smart-account operation e um paymaster paga transaction fees, evitando uma funding edge direta de native gas da user wallet. Melhora uma propriedade do graph; operation, contract e service telemetry continuam públicas ou observáveis.<sup>[[19]](#references)</sup>

**Vantagens:** remove um link comum de gas-funding; permite sponsorship limitado e rate limits; melhor onboarding para privacy applications legítimas.

**Desvantagens:** paymaster/bundler/RPC/front end pode correlacionar requests; contract events e public inputs permanecem; sponsorship policy cria fingerprint de cohort; contracts ou approvals maliciosos podem roubar assets.

**Procedimento:** (1) usar smart account e paymaster auditados e mantidos na network correta; (2) inspecionar campos públicos e logs do sponsor; (3) limitar sponsorship por contract, function, amount, nonce e expiry; (4) testar com baixo value; (5) enviar pelo privacy-aware path pretendido pela application; (6) verificar operation e fee payer on-chain; (7) revogar allowances/session keys e manter compliance records.

**Detecção:** unir logs de UserOperation, EntryPoint, paymaster, bundler/RPC e application; agrupar policies de sponsorship idênticas com cautela. **Captured wallet:** session keys e approvals pendentes podem ser usados mesmo sem gas; limitar rigorosamente e revogar pela recovery policy da account.

## Threshold ou multisignature payment authorization

**Mecânica:** gastar exige um threshold de signers independentes. Não oculta a transaction, mas separa payment authority de um laptop, field node ou operator capturado.

**Vantagens:** forte resistência a compromise/insider; approval accountable; nenhum field device possui signing authority completa; permite recovery.

**Desvantagens:** coordination e availability; metadata de signer/device/account pode correlacionar participants; backup ruim causa perda; padrões públicos de multisig podem ser identificáveis.

**Procedimento:** (1) definir signers, threshold, limits e recovery antes do funding; (2) inicializar em hardware/accounts separados; (3) verificar addresses e backups independentemente; (4) fornecer a field workloads apenas capacidade de unsigned requisition; (5) exigir review out-of-band de recipient, amount e purpose; (6) testar recovery e perda de um signer com pequeno value; (7) rotacionar signer após compromise.

**Detecção:** approval system, signer device e public script/contract fornecem evidências; defenders alertam para mudanças de policy ou signer-set. **Captured node:** deve expor no máximo uma session key de baixa autoridade ou unsigned request; nunca armazenar material de quorum junto.

## Closed-loop community ou event currency

**Mecânica:** cooperative, conference ou private test environment emite credits resgatáveis apenas entre participants inscritos. Transferência interna pode expor menos às payment networks globais, enquanto o operator controla issuance/redemption.

**Vantagens:** domínio econômico limitado; permite testar UX de payment offline ou privacy-preserving; limita exposição de card externo; controles experimentais claros.

**Desvantagens:** anonymity set pequeno; operator e merchants observam activity; acceptance/redemption limitados; licensing, consumer-protection e tax rules podem aplicar-se mesmo a valor local.

**Procedimento:** (1) obter revisão legal/compliance e publicar issuer terms; (2) cadastrar test participants consentindo; (3) limitar issuance e proibir misuse semelhante a cash; (4) usar fresh payment requests e minimizar identifiers públicos de participants; (5) registrar reserves agregadas e receipts individuais privados; (6) testar loss/refund/redemption; (7) fechar ledger e devolver residual value conforme prometido.

**Detecção:** issuer ledger, enrollment, merchant e redemption records reconstroem fluxos; transfers circulares incomuns ou cash-out rápido merecem review. **Captured wallet:** saldo local e counterparties podem ser expostos; limitar value, criptografar state e permitir freeze/reissue do issuer com registro auditável.

## Bitcoin reusable payment codes e private payment instructions

**Mecânica:** BIP 47 payment codes usam um identifier público reutilizável com one-time deposit addresses derivados por ECDH; BIP 351 especifica um design mais recente de private-payment instruction. Reduzem address reuse público ao permitir que um recipient publique instruções estáveis. Notification, wallet support, funding e coin selection posterior ainda afetam a privacidade.<sup>[[20]](#references)</sup>

**Vantagens:** uma instruction pública pode produzir addresses distintos; recipient não precisa publicar cada invoice address; wallets compatíveis podem monitorar payments derivados; útil para donors/customers legais recorrentes.

**Desvantagens:** interoperabilidade de wallet varia; notification transactions ou payment code publicado vinculam um contexto de relationship; sender, recipient e public graph ainda veem transactions; consolidation ou change handling descuidado elimina o benefício.

**Procedimento:** (1) confirmar que ambas as wallets mantidas suportam a mesma specification/version; (2) fazer backup e testar recovery em wallet de baixo value; (3) autenticar o recipient payment code out-of-band; (4) enviar pequeno test legal; (5) verificar uso de novo derived address; (6) rotular relationship localmente e aplicar coin control; (7) testar recovery e refund behavior antes de depender dele.

**Detecção:** analysts examinam notification patterns, funding/change, later consolidation e service boundaries; publicação do public code identifica o contexto do recipient mesmo quando deposit addresses diferem. **Capture-resilient OPSEC:** manter spend keys fora dos field devices e expor no máximo uma relationship view watch-only. **Monitoring:** alertar para notification transactions inesperadas, derived addresses reutilizados, erros de wallet gap-limit/recovery e consolidation não planejada.

## EVM stealth addresses (ERC-5564)

**Mecânica:** um sender deriva uma stealth account one-time a partir de uma stealth meta-address do recipient e publica um announcement com ephemeral public key e view tag. O recipient escaneia announcements com viewing key e deriva o spend key correspondente. O vínculo com o recipient melhora, mas sender, amount/token, gas, announcement e spending posterior permanecem visíveis.<sup>[[21]](#references)</sup>

**Vantagens:** fresh receiver address não interativo; meta-address reutilizável; separação de viewing/spending roles; funciona entre EVM assets/applications suportados.

**Desvantagens:** scanning de announcements e spam; funding do gas da nova address pode relink; sender conhece recipient; public token/amount e consolidation posterior permanecem; implementação/wallet support variam.

**Procedimento:** (1) usar implementação auditada e mantida primeiro em test network; (2) gerar material separado de viewing e spending e fazer backup; (3) autenticar meta-address; (4) enviar pequeno test e announcement; (5) fazer scan e derivar stealth account; (6) testar gas sponsorship suportado sem personal funding edge; (7) registrar public fields e preservar accounting legal.

**Detecção:** acompanhar announcement caller, token/amount, timing, gas sponsor, spending e consolidation; view key pode provar receipt sem conceder spend. **Capture-resilient OPSEC:** networked scanner deve ter apenas viewing role quando suportado; manter spend/recovery keys em outro local. **Monitoring:** alertar para announcements malformados/spam, acesso à view-key, derivação de spend inesperada e stealth outputs movidos sem approval.

## Liquid Confidential Transactions

**Mecânica:** Liquid oculta amounts e asset types dos outputs por padrão usando commitments e proofs, mas deixa visíveis transaction graph, input/output count, fee e block time. Peg-in/peg-out e service boundaries continuam vinculáveis, e users podem divulgar seletivamente blinding data.<sup>[[22]](#references)</sup>

**Vantagens:** amount e asset type confidenciais por padrão; settlement rápido em sidechain; auditoria seletiva por blinding keys/descriptors; oculta valores comerciais sensíveis de public observers.

**Desvantagens:** graph structure e timing permanecem; confiança em federation/bridge e exchange; peg boundaries e unconfidential outputs; wallet/node/network records; receiver e sender conhecem a transaction.

**Procedimento:** (1) selecionar Liquid wallet mantida e verificar seu backup model; (2) usar testnet ou pequeno amount legal; (3) receber em confidential address e confirmar que a wallet marca o output como blinded; (4) enviar confidential transaction de teste; (5) inspecionar quais explorer fields continuam públicos; (6) exportar apenas o blinding proof limitado necessário à auditoria; (7) documentar peg/exchange boundaries e reconciliar funds.

**Detecção:** analisar graph/fee/time visíveis, peg e exchange records, network metadata e posterior unblinding evidence; não inferir hidden amount ou asset. **Capture-resilient OPSEC:** separar spend seed, blinding/view data e watch-only operations. **Monitoring:** alertar para unconfidential addresses acidentais, peg requests desconhecidos, mudanças de descriptor e exportação não aprovada de unblinding-key.

## General payment ou state channel

**Mecânica:** participants bloqueiam funds, trocam off-chain state updates assinados e publicam on-chain apenas opening, closing ou disputed state. Payments intermediários não são globalmente transmitidos, mas peers e routing/intermediary services observam sua parte e endpoints devem manter o último state enforceable.<sup>[[23]](#references)</sup>

**Vantagens:** muitas interações rápidas e baratas, privadas perante o public ledger; menos detalhes globais de transaction; channel balance limitado; útil para services medidos e counterparties recorrentes.

**Desvantagens:** channel peers conhecem uns aos outros e podem guardar updates; opening/closing/value/timing correlacionam; monitoring online pode ser necessário em challenge windows; implementation/liquidity risk; por si só não cria um anonymity set grande.

**Procedimento:** (1) escolher implementação auditada e mantida e entender dispute window; (2) abrir low-value test channel entre parties próprias; (3) trocar state updates assinados com nonces únicos; (4) fazer backup do último state enforceable; (5) fechar cooperativamente; (6) ensaiar stale-state rejection em testnet; (7) preservar accounting e channel-peer records.

**Detecção:** public chain expõe lifecycle/disputes; peers, watch services e application transport expõem timing e parties off-chain. **Capture-resilient OPSEC:** limitar hot balance e manter último state assinado em encrypted recoverable store separado dos field nodes. **Monitoring:** monitorar continuamente stale-state publication, backup ausente, peer-key change e aproximação do challenge deadline.

## Mobile carrier billing

**Mecânica:** um online service cobra uma purchase na mobile subscription ou prepaid balance através do carrier billing system. O merchant pode receber carrier authorization em vez de card/bank details, enquanto carrier conhece subscriber/line, device/network context, merchant, amount e time.<sup>[[24]](#references)</sup>

**Vantagens:** nenhum card number no merchant; ampla disponibilidade telefônica; útil para digital goods de baixo valor; carrier pode limitar e reverter charges.

**Desvantagens:** fortemente identificado por SIM/account e frequentemente device; limites pequenos e fees altos; restrições de merchant category; risco de account takeover/SIM-swap; carrier e aggregator criam trail completo da transaction.

**Procedimento:** (1) confirmar availability, limit, fee e refund terms com a organization carrier account; (2) habilitar apenas em dedicated organization line quando justificado; (3) definir menor spend cap útil; (4) comprar benign test item; (5) verificar receipts do merchant e carrier; (6) desabilitar recurring authorization; (7) reconciliar e desligar o recurso após a avaliação.

**Detecção:** carrier, aggregator e merchant records unem line, subscriber, IP/device e charge; enterprise telecom invoices expõem o uso. **Capture-resilient OPSEC:** não usar número pessoal e exigir carrier-account MFA fora do field device. **Monitoring:** habilitar instant charge/SIM-change alerts e interromper diante de premium-service enrollment, forwarding ou account recovery inesperados.

## Open-banking payment initiation

**Mecânica:** com consentimento explícito do user, um payment-initiation service provider (PISP) regulado solicita ao account-servicing bank que inicie uma transfer. O merchant pode não receber card credentials, mas PISP e banks retêm registros regulados de payer, payee, consent, device e transaction.<sup>[[25]](#references)</sup>

**Vantagens:** nenhum card number reutilizável no checkout; autenticação bancária forte; settlement account-to-account exato; APIs de consent/status; reconciliation clara.

**Desvantagens:** não é anonymous perante banks/PISP; payee frequentemente vê legal account details ou reference; risco de phishing/redirect; jurisdição e refund protections variam; consent metadata adiciona outro observer.

**Procedimento:** (1) verificar se o PISP é atualmente regulado e se o merchant callback domain é autêntico; (2) iniciar pela merchant request; (3) revisar payee, amount, reference e consent solicitado no bank; (4) autorizar apenas o payment único; (5) verificar status final independentemente; (6) revogar consent residual, se houver; (7) guardar receipt e reconciliar.

**Detecção:** bank/PISP/merchant logs e transfer references fornecem atribuição forte. **Capture-resilient OPSEC:** manter banking authentication e recovery fora de operational/field devices; o device deve conter apenas uma service entitlement paga. **Monitoring:** usar bank transaction/consent alerts e investigar novos PISP grants, payee alterado ou status callbacks fora da sessão esperada.

## Platform wallet, app-store balance ou in-app credit

**Mecânica:** uma platform cobra o user ou resgata account credit e depois emite signed receipt/entitlement para uma application. O app developer pode não receber o funding instrument original, enquanto a platform mapeia account, device, funding, product e redemption.<sup>[[26]](#references)</sup>

**Vantagens:** merchant/developer não recebe primary PAN; controles de fraud/refund e family/business; pequeno prepaid balance limita exposição; signed receipts simplificam entitlement verification.

**Desvantagens:** platform account é forte hub de identity/behavior; device e storefront geography; trail de gift-balance purchase/redemption; cash-out limitado; fraud controls podem congelar funds; não é money cross-platform.

**Procedimento:** (1) usar organization-managed platform account quando a policy permitir; (2) revisar regras de funding, region, refund e transferable value; (3) adicionar apenas o budget aprovado; (4) comprar produto benigno pela official store; (5) verificar que a application recebe apenas os receipt fields esperados; (6) desabilitar recurring purchase; (7) reconciliar e remover a account do operational hardware.

**Detecção:** platform receipts/server notifications, account/device login e funding records reconstroem a purchase. **Capture-resilient OPSEC:** nunca fazer login de um field node em personal store account; fornecer apenas scoped app entitlement quando possível. **Monitoring:** habilitar new-device/purchase alerts e investigar receipt replay, family/account changes ou restore events inesperados.

## Mutual credit, clearing ou periodic net settlement

**Mecânica:** participants registram obligations em private ledger e periodicamente liquidam somente cada net position. Events individuais de service podem não criar payments públicos separados, mas ledger operator e counterparties retêm atribuição detalhada.

**Vantagens:** menos transactions externas e fees; public observers veem apenas net settlement; funciona para organizations recorrentes; credit limits explícitos limitam exposure.

**Desvantagens:** centralized ledger é evidência completa e alvo de fraud; risco de counterparty/default; obrigações legais/accounting/tax; membership pequeno; net transfers incomuns ainda podem revelar relationships.

**Procedimento:** (1) usar somente identified consenting organizations com aprovação legal/accounting; (2) definir unit, credit limit, settlement interval e dispute rules; (3) registrar cada obligation com immutable approval; (4) finance roles separadas calculam e aprovam net positions; (5) liquidar por ordinary lawful rail; (6) reconciliar individual lines ao settlement; (7) encerrar access e reter records conforme policy.

**Detecção:** ledger, invoices, approvals e final bank/chain settlement fornecem ground truth; analysts não devem inferir gross activity ausente apenas do net transfer. **Capture-resilient OPSEC:** operational devices podem enviar bounded requisitions, mas não editar balances ou autorizar settlement. **Monitoring:** alertar para credit-limit breach, backdated entries, administrator changes, reconciliation mismatch e settlement para novo beneficiary.

## Capture/compromise exposure matrix

Isso aplica um teste de seizure/loss a cada família. O objetivo é limitar spend authority e divulgação de identity não relacionada, mantendo accounting legal — não apagar transactions nem impedir uma investigação.

| Família da técnica | O que um wallet/device/account capturado pode revelar | Controle autorizado mínimo |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, bearer value restante e contatos físicos | carregar apenas amount aprovado; accounting privado separado; reportar perda prontamente; nenhum registro falso |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption e account/session tokens | saldo baixo; um propósito; registration verdadeira; issuer freeze/revocation quando disponível |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery e merchant history | device lock; transaction alerts; merchant scope; issuer suspension remota; nenhuma recovery account compartilhada |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices e project | role separation; subaccount least-privilege; finance credentials nunca em operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator ou dispute trail | request de uso único; approver separado; session limitada; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph e network configuration | hardware/offline signing; wallet criptografada; passphrase limits; watch-only field view; recovery documentado |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP e payment database | hot balance mínimo; encrypted backup; node identity separado; close/recover conforme plano documentado |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC e boundary transactions | spend/view roles separados; hardware quando disponível; nenhuma exchange session no field node |
| Stablecoins, swaps, bridges e DEX | transparent graph, approvals, RPC/front-end state e destination assets | revogar allowances; contracts verificados; low-value test; reconciliation completa |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | saldo pequeno; encrypted backup conforme protocolo; redeem/reissue; nunca colocar funding credential junto |
| Paymaster, multisig/threshold | session key, um signer, pending operations e sponsor policy | session key limitada; quorum independente; signer rotation; field device não alcança threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | provider incriminador, communications, graph e participant records | nenhum uso operacional; emular apenas com evidence sintética/testnet |
| Community/event currency | enrollment, local balance, counterparties e redemption | value limitado; issuer freeze/reissue; consent e ledger privado auditável |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements e derived outputs | network role watch/view-only; spend role offline/hardware; nenhuma personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries e disputes | spend/view/state backup separado; hot balance baixo; dispute monitor independente |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device e funding source | organization account; external MFA; low limit; nenhuma personal account no field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals e settlement ledger | apenas operational requisition; immutable ledger separado e dual finance approval |

## Monitoring possible discovery ou payment compromise

Payment denial, compliance review ou wallet offline não provam que existe uma investigation. Monitorar apenas accounts, ledgers e infrastructure que a organization tem direito de observar; nunca sondar providers ou counterparties para testar se estão cooperando com investigators.

| Técnicas abrangidas | Sinais seguros de monitoring | Condição de freeze/stop |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, redemption/refund inesperado ou loss report | instrument ausente, redemption fora do order aprovado, receipt alterado ou quebra de custody |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, novo device/consent/payee, token reuse, SIM/account recovery | authorization desconhecida, payee alterado, novo recovery factor, SIM swap ou recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice e consumption | cross-project token, admin desconhecido, limit breach, invoice mismatch ou destination não suportado |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation e beneficiary change | amount/payee alterado, ledger backdated, release unilateral ou batch não reconciliado |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels e consolidation | spend desconhecido, recipient output reutilizado, wallet gap/recovery failure ou merge não aprovado |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | output substituído, fee excessiva, input disclosure inesperado ou coordinator policy alterada |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP e chain dispute | invoice payment desconhecido, peer-key change, close stale ou dispute deadline próximo |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor e boundary transaction | spend sem approval, downgrade transparent/unconfidential, key export ou boundary desconhecida |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key e issuer action | contract/public field incorreto, approval/spend desconhecido, paymaster change ou issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway e bearer balance | redemption desconhecido, mint key/terms change, restore failure ou balance inconsistente |
| Swaps/bridges/DEX | verified contract, allowance, confirmations de ambas as chains, rate e destination | contract/route mismatch, unlimited approval, destination ausente ou bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum e recovery audit | proposal/signer desconhecido, threshold reduction, recovery activation ou policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | apenas synthetic lab ground truth e detection output | qualquer account, person ou value real entrando na emulation: stop imediato |

## Selection e verification workflow

1. Nomear qual party não deve aprender qual field.
2. Identificar issuer/mint/custodian, public ledger, network/RPC, merchant e physical observers.
3. Verificar support, legality, limits, custody, recovery e refund behavior atuais.
4. Usar um pequeno lawful end-to-end test.
5. Inspecionar merchant receipt, provider statement, public chain e wallet/node logs.
6. Testar backup/recovery e deliberate audit disclosure.
7. Manter source, ownership, tax, sanctions e engagement records exigidos corretos, mas com acesso controlado.

## References

- [1] [EMVCo — Tokenização de pagamentos](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observações sobre a coleta de dados por grandes plataformas de pagamento](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Proteja sua privacidade](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Uma proposta simples de Payjoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Protocolo de Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Especificações técnicas e privacidade da network](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Construindo aplicações de privacidade com zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol e limitações de privacidade](https://docs.cashu.space/faq)
- [13] [Fedimint — Como funciona](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Indicadores de risco de Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers e users de virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — informações de transferência e crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — A arquitetura Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State e payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
