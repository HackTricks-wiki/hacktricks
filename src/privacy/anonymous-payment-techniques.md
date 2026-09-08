# Catálogo de técnicas de pagamento anônimo

{{#include ../banners/hacktricks-training.md}}

Este catálogo abrange **famílias** de pagamento, desde dinheiro comum até e-cash com blind-signature e obfuscation em public-chain. “Anônimo” sempre significa anônimo perante um observador identificado. Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer e observador físico veem fatos diferentes.

Os procedimentos abaixo destinam-se a fundos legais, contas verdadeiras e procurement autorizado. Técnicas cujo objetivo nos casos citados foi laundering, sanctions evasion ou identity fraud são explicadas e detectadas, mas seu procedimento é um exercício forense sintético — não instruções para cometer o crime.

## Coverage matrix

| Família | Principal propriedade de privacidade | Principal observador/confiança | Tratamento |
|---|---|---|---|
| Cash and cash equivalents | nenhum registro remoto da payment-network | recipient e ambiente físico | fluxo legal |
| Prepaid/gift/voucher value | separa redemption do cartão primário | seller, issuer e redemption service | fluxo legal, varia por jurisdição |
| Virtual/tokenized card | oculta PAN reutilizável ou separa merchants | issuer/network/wallet ainda identifica o payer | fluxo legal |
| Payment app/intermediary | merchant pode ver alias/intermediary | app coleta identidade/device/transaction | baseline de comparação |
| Bitcoin hygiene/Silent Payments | pseudônimos e unlinkability do recipient | public graph e fronteira wallet/network | deployable |
| PayJoin/CoinJoin | enfraquece heurísticas de common ownership/linkage | participants/coordinator/network/public graph | deployable quando suportado; revisão legal |
| Lightning/BOLT 12 | roteamento off-chain e redução do caminho do receiver | endpoints, hops, services e channel graph | deployable quando suportado |
| Monero/Zcash/MWEB | confidencialidade on-chain no nível do protocolo | acquisition, endpoint, network e boundary permanecem | deployable quando legal/suportado |
| Ethereum ZK application | oculta um link específico entre statement/action | public inputs, RPC, relayer e app | específico da aplicação |
| Cashu/Fedimint/Taler | privacidade do payer por blind-signature | mint/federation/exchange custody e boundaries | emergente/específico da implantação |
| Stablecoins | settlement digital conveniente | chain transparente e freeze/control do issuer | não é baseline anônimo |
| Swaps/bridges/DEX | move valor entre assets/chains | ambos os graphs, contracts e providers | mecânica forense; somente swaps legais comuns |
| Mixers/peel/structuring | aumenta ambiguidade/trabalho do graph | entry/exit graph e registros do serviço | somente exercício sintético de detecção |
| Nominees/mules/OTC/fronts | insere intermediários humanos/empresariais | facilitators, banks, communications | somente análise de abuso criminoso |
| Reusable/stealth payment addresses | novo endereço de receiver por pagamento | anúncio/notification público e fronteiras da wallet | deployable quando suportado |
| Confidential sidechain/state channel | oculta amount/asset ou atualizações intermediárias | peers, bridge/federation e settlement do lifecycle | específico do protocolo |
| Carrier/open-banking/platform billing | oculta o cartão primário do merchant | carrier, bank/PISP ou platform identifica o customer | pagamento comum identificado |
| Mutual credit/net settlement | menos registros externos de settlement | private ledger operator possui o mapeamento completo | somente participants identificados |

## Cash

**Mecânica:** valor físico ao portador muda de mãos sem autorização online do issuer ou public ledger.

**Vantagens:** merchant não precisa descobrir a identidade bancária/do cartão; nenhum transaction graph remoto; amplamente compreensível e final.

**Desvantagens:** somente face-to-face; roubo/perda; controles de troco/recibo/serial ou reporting; withdrawal, câmeras, testemunhas e localização ainda vinculam o payer.

**Procedimento:** (1) confirmar que cash é legal/aceito e qualquer regra de valor/reporting; (2) sacar ou recebê-lo legalmente e manter registros privados de contabilidade; (3) pagar um merchant comum sem identificadores desnecessários de loyalty/account; (4) solicitar somente o recibo necessário; (5) evitar shipping/account data se a compra não exigir; (6) registrar internamente o legítimo business purpose.

**Detecção:** reconciliar till/receipt/inventory, câmeras e access logs conforme a policy aplicável; investigar refunds incomuns em cash ou valores repetidos logo abaixo do limite de controle, sem tratar o uso comum de cash como suspeito por si só.

## Money order, postal order, cashier instrument and cash on delivery

**Mecânica:** um issuer regulado converte cash/account funds em um instrumento numerado pagável a um recipient identificado; COD adia a cobrança até a entrega.

**Vantagens:** recipient pode não receber o primary bank/card number do payer; utilizável quando cash não pode ser transportado remotamente; recibo claro.

**Desvantagens:** issuer/retailer retém purchase/identity data conforme exigido; rastreamento por serial; recipient/delivery address; perda/fraude e restrições regionais; geralmente não é anônimo.

**Procedimento:** (1) verificar regras, limites, identificação e aceitação pelo recipient; (2) comprar com informações verdadeiras e fundos legais; (3) preencher payee/amount imediatamente; (4) preservar serial/receipt; (5) usar delivery rastreável adequado ao valor; (6) reconciliar redemption/refund.

**Detecção:** purchase/redemption record do issuer, instrument serial, retailer/camera, shipping e recipient account; sinalizar alteração, serials duplicados e redemption rápida geograficamente inconsistente.

## Open-loop prepaid card

**Mecânica:** uma credencial branded pela network autoriza contra um saldo prepaid em vez de uma conta de crédito primária.

**Vantagens:** limita exposição e perda do merchant; separa o merchant do PAN principal; utilizável online onde aceito.

**Desvantagens:** registros de purchase/activation/reload/registration e device; KYC e limits variam; falhas de billing-address; restrições de cash-out/refund; “sem nome” não significa ausência de registro do issuer.

**Procedimento:** (1) verificar identidade atual do issuer, fees, KYC, geography e suporte a online/recurring; (2) adquirir por seller autorizado com fundos legais; (3) registrar dados verdadeiros exigidos; (4) usar para um purpose/compartment; (5) não estruturar loads nem falsificar residency; (6) manter evidências de purchase/expense e encerrar/descartar conforme os termos do issuer.

**Detecção:** associar seller/activation, funding, device/IP, merchant authorization, balance checks e redemption/refund. Padrões importam mais que o rótulo prepaid.

## Closed-loop gift card, voucher and transferable service credit

**Mecânica:** valor numerado pode ser resgatado somente com um merchant/service ou ecosystem. Airtime/game/store credits são variantes.

**Vantagens:** merchant recipient pode ver somente code/balance; blast radius limitado; fácil gifting e separação de orçamento.

**Desvantagens:** seller e service registram purchase/activation/redemption; account/device/delivery ainda vinculam; scams, resale discounts e expiry/region limits; direitos de refund fracos.

**Procedimento:** (1) comprar somente por canais autorizados; (2) registrar o valor do code sem expor o secret; (3) evitar anexar loyalty account identificadora se desnecessário; (4) resgatar por uma conta/contexto legítimo separado do merchant; (5) guardar receipt até a aceitação; (6) nunca comprar codes para uma solicitação não solicitada de “tax/support/ransom”.

**Detecção:** issuance/redemption time do code, convergência de device/account, compras em massa ou com padrões de threshold, um device consultando muitos balances e redemption rápida distante.

## Cryptocurrency-funded card or gift-code broker

**Mecânica:** um intermediary aceita cryptocurrency e emite card, voucher ou merchant code. É uma conversão cross-rail: merchant vê card/gift value comum, enquanto broker vincula o on-chain deposit à issuance e delivery.

**Vantagens:** merchant não recebe a funding wallet; útil para merchants legítimos que não aceitam crypto; stored value limitado.

**Desvantagens:** não é anônimo perante broker/issuer; regras de KYC, sanctions, exchange e card-program; public deposit graph; account/device/email e code redemption reconectam os lados; risco de scam/insolvency.

**Procedimento:** (1) verificar legal entity, card issuer, supported jurisdiction, KYC, fees e refund policy; (2) usar somente funds legais documentados; (3) testar a menor denomination; (4) verificar network/merchant restrictions antes da compra; (5) preservar blockchain transaction e broker receipt para accounting; (6) nunca usar broker que prometa identity fraud, sanctions bypass ou cash-out “untraceable”.

**Detecção:** correlacionar broker deposit addresses, amount/time únicos, account/device e card authorization ou gift-code redemption; registros do issuer e broker ligam a public chain ao merchant.

## Virtual or merchant-locked card

**Mecânica:** o issuer mapeia um PAN/token gerado à conta real, frequentemente restringindo merchant, amount ou expiration.

**Vantagens:** impede exposição de PAN reutilizável; compartimentação por merchant; spend limits e revogação fácil; fraud control maduro.

**Desvantagens:** issuer ainda conhece payer, funding, merchant, device/IP e time; merchant vê account/delivery; alguns refunds/recurring charges falham; não é anônimo.

**Procedimento:** (1) usar o recurso oficial do issuer regulado; (2) criar um card para um merchant/engagement; (3) definir o menor limit e expiry úteis; (4) usar billing correto quando exigido; (5) verificar statement descriptor/refund behavior; (6) congelar/deletar após o settlement final, mantendo audit evidence.

**Detecção:** issuer token-to-account mapping, merchant authorization, device e delivery. Defenders usam sinais de reuse específico do merchant, velocity e account takeover.

## Mobile-wallet network token

**Mecânica:** EMV payment tokenization substitui o PAN por uma credencial limitada, geralmente vinculada a device, merchant ou cenário de pagamento.<sup>[[1]](#references)</sup>

**Vantagens:** merchant não recebe o PAN reutilizável; device cryptography/dynamic data reduzem cloning; revogável sem substituir o card.

**Desvantagens:** issuer, token service, wallet platform e network retêm mappings/transactions; device/platform account e location podem identificar o payer.

**Procedimento:** (1) cadastrar um card legítimo na wallet oficial; (2) proteger platform account/device com autenticação forte; (3) verificar device token/últimos dígitos na compra; (4) desativar location/analytics desnecessários quando suportado; (5) remover imediatamente devices/tokens perdidos; (6) revisar registros do issuer e wallet.

**Detecção:** token requestor/device cryptogram e issuer mapping, wallet/account telemetry, merchant terminal e evidências físicas.

## Payment app, marketplace wallet and centralized intermediary

**Mecânica:** o service mantém accounts e realiza transfers internamente ou por bank/card rails; merchant pode ver um alias enquanto o service vê ambas as partes.

**Vantagens:** conveniência, mecanismos de dispute/refund, recipient não necessariamente vê dados bancários/do card.

**Desvantagens:** identity/social/transaction/device graph centralizado; freezes e legal process; counterparties podem expor o profile; uso de dados pode exceder a necessidade do pagamento.<sup>[[2]](#references)</sup>

**Procedimento:** (1) ler identity, privacy, retention e buyer-protection terms; (2) minimizar sincronização opcional de profile/contact; (3) usar uma conta separada e verdadeira somente quando os termos permitirem; (4) habilitar MFA/alerts; (5) verificar recipient e privacidade de memo/profile; (6) exportar records e fechar links não utilizados.

**Detecção:** provider account, device/IP, contact graph, funding/withdrawal, memo e merchant records. Um alias é pseudonymity perante uma counterparty, não anonymity perante a platform.

## Bank transfer, ACH, wire and instant-account payment

**Mecânica:** instituições reguladas movem valor entre contas identificadas e trocam os payment data exigidos.

**Vantagens:** rápido, accountable, reversível em casos limitados, com records fortes; virtual account numbers podem reduzir a divulgação ao merchant.

**Desvantagens:** banks/processors conhecem ambos os lados; statements e references; não é anônimo; dados cross-border e Travel Rule/AML.

**Procedimento:** usar somente quando accountability for aceitável: verificar beneficiary independentemente, minimizar memo data opcional, usar virtual account/reference fornecido pelo bank quando disponível, habilitar alerts, guardar invoice e reconciliar.

**Detecção:** registros determinísticos de bank/payment, account ownership do beneficiary, device/session e fraud controls. É um baseline, não uma técnica de anonimato.

## Account and merchant compartmentation

**Mecânica:** identidades/accounts, email aliases, cards e delivery contexts separados impedem que merchants não relacionados unam trivialmente a atividade, enquanto issuer/controller mantém o mapping.

**Vantagens:** reduz breach e linkage entre merchants; fácil de auditar; compatível com payments regulados.

**Desvantagens:** provider ainda mapeia compartments; recovery phone/device/IP e shipping podem reconectá-los; policy pode proibir múltiplas accounts.

**Procedimento:** (1) definir um purpose; (2) criar somente aliases/subaccounts compatíveis com os termos; (3) usar token/card específico do merchant; (4) desativar contact/ad personalization entre accounts; (5) manter encrypted controller ledger; (6) aposentar identifiers após o fim das necessidades de refund/retention.

**Detecção:** providers associam recovery, device, funding e IP; merchants associam delivery, browser e account behavior. Defenders devem distinguir compartmentation legítima de synthetic identity fraud.

## Controlled red-team procurement

**Mecânica:** o SOC desconhece uma purchase enquanto um exercise controller mantém o mapeamento da legal entity, operator e infrastructure.

**Vantagens:** exercício realista de detecção; nenhuma exposição pessoal; deconfliction e audit imediatos.

**Desvantagens:** não é anônimo perante organization/provider; overhead de governance; leaks se o controller ledger for mal tratado.

**Procedimento:** (1) alocar organization card/wallet/budget específico do engagement; (2) separar papéis de purchaser/operator; (3) registrar asset, amount, service, purpose e kill date; (4) armazenar attribution mapping com acesso limitado ao controller; (5) nunca usar false identity/mule/stolen funds; (6) revelar e reconciliar indicators e refunds no encerramento.

**Detecção:** controller mapeia provider invoice e asset; SOC testa discovery independente por domain, certificate, hosting e traffic, em vez de cardholder data.

## Bitcoin address hygiene and coin control

**Mecânica:** fresh receive addresses, labeling local e selective UTXO spending reduzem address reuse e a mesclagem acidental de compartments em um public ledger.

**Vantagens:** amplamente suportado; self-custodial; evita o public linkage mais simples.

**Desvantagens:** todas as transactions/amounts permanecem públicas; common-input/change/timing e consolidação posterior vinculam atividade; records de acquisition/RPC/network permanecem.

**Procedimento:** (1) instalar/verificar uma wallet mantida; (2) fazer backup e testar seed recovery; (3) usar novo address por invoice; (4) rotular source/purpose localmente; (5) usar coin control para evitar mesclar contexts; (6) preferir local node ou conexão privacy-aware; (7) revisar change/fees e manter lawful accounting.<sup>[[3]](#references)</sup>

**Detecção:** address graph, common-input/change heuristics com incerteza, amount/time exatos, consolidation, service deposits, node/RPC broadcast timing e off-chain records.

## Bitcoin Silent Payments

**Mecânica:** BIP 352 permite ao receiver publicar um static code enquanto senders derivam unique Taproot outputs via ECDH; observadores externos não conseguem vincular diretamente outputs ao code.<sup>[[4]](#references)</sup>

**Vantagens:** public identifier reutilizável sem address reuse; nenhum pedido interativo de address ou notification output; mistura-se a Taproot outputs.

**Desvantagens:** custo de scanning do receiver; suporte da wallet varia; sender graph e amount/spending continuam públicos; index server pode observar scans.

**Procedimento:** (1) selecionar uma wallet BIP 352 atual; (2) fazer backup/testar descriptor e scanning recovery; (3) gerar code rotulado quando suportado; (4) autenticar o code publicado; (5) sender revisar inputs e enviar pequeno test; (6) receiver fazer scan preferencialmente pelo próprio node; (7) manter received UTXOs separados.

**Detecção:** por design, não é identificável com confiabilidade somente pelo output; analysts usam sender inputs, amount/time, later spending, wallet/network/index e counterparty records.

## PayJoin

**Mecânica:** payer e payee contribuem inputs para uma payment transaction, quebrando a suposição de que todos os inputs pertencem ao mesmo owner.<sup>[[5]](#references)</sup>

**Vantagens:** pagamento comum com privacidade melhorada; beneficia o graph amplo ao enfraquecer uma heurística comum; não exige crowd de equal outputs.

**Desvantagens:** requisito interativo/de suporte; disponibilidade do receiver endpoint; amount e final transaction públicos; implementação e fallback metadata.

**Procedimento:** (1) confirmar que ambas as maintained wallets suportam a mesma versão do PayJoin; (2) autenticar invoice/endpoint; (3) iniciar pela wallet's PayJoin-enabled payment URI; (4) inspecionar final amount/fee e assinar somente inputs esperados; (5) evitar manual transaction surgery; (6) verificar broadcast e receipt; (7) registrar fallback se a negociação falhar.

**Detecção:** blockchain analysts não devem impor common-input clustering; endpoint/provider pode registrar negotiation; usar wallet/network e later-spend evidence, não somente transaction shape.

## CoinJoin

**Mecânica:** múltiplos participants criam colaborativamente uma transaction com muitos inputs/outputs, geralmente denominations iguais, aumentando a ambiguidade da correspondência input-output.

**Vantagens:** maior on-chain ambiguity set; existem designs self-custodial; round structure mensurável.

**Desvantagens:** coordinator/peer/network metadata; fees/liquidity; transaction shape identificável; toxic change e later consolidation destroem ganhos; legal/provider availability varia.

**Procedimento:** (1) verificar disponibilidade e legalidade atuais da wallet/coordinator; (2) instalar official wallet e fazer backup; (3) usar somente UTXOs legais; (4) entender denomination, fee e coordinator model; (5) manter change e mixed outputs rotulados/separados; (6) nunca consolidá-los juntos; (7) encaminhar network traffic conforme oficialmente suportado e preservar accounting.

**Detecção:** identificar collaborative structure sem presumir crime; calcular possíveis mappings/anonymity set e observar change/consolidation, service boundaries e network/coordinator records.

## Lightning Network

**Mecânica:** HTLC payments atravessam channels com onion routing; a maioria dos payment details não é publicada on-chain, enquanto funding/closing e public channel information são.

**Vantagens:** rápido, baixo fee; intermediaries normalmente veem hops adjacentes; detalhes rotineiros permanecem off-chain.

**Desvantagens:** sender/receiver e first/last hop sabem mais; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets identificam users.

**Procedimento:** (1) escolher conscientemente self-custodial ou custodial; (2) verificar wallet/seed/channel recovery; (3) usar invoice para o pagamento exato; (4) preferir private channels/LSP features somente após ler os tradeoffs; (5) proteger node IP com Tor suportado quando necessário; (6) evitar invoices identificadoras reutilizadas; (7) manter channel e payment accounting.<sup>[[6]](#references)</sup>

**Detecção:** node/LSP/custodian logs, channel graph/probes, payment failure/timing e on-chain funding/closure; ausência de public transaction não significa ausência de records.

## BOLT 12 offers and route blinding

**Mecânica:** uma reusable offer produz fresh invoices e pode anunciar blinded paths, para que o payer não precise conhecer o clear node/path do receiver.

**Vantagens:** privacidade do receiver; endpoint reutilizável de donation/payment sem static invoice; integra-se ao Lightning onion routing.

**Desvantagens:** suporte da wallet varia; endpoints, hops selecionados e funding permanecem; public contact ou network endpoint pode reidentificar o receiver.

**Procedimento:** (1) confirmar suporte compatível a BOLT 12; (2) autenticar offer; (3) solicitar fresh invoice; (4) revisar amount/issuer/recurrence; (5) pagar pela wallet; (6) verificar receipt/refund behavior; (7) minimizar node alias/contact e preservar accounting.<sup>[[7]](#references)</sup>

**Detecção:** wallet/LSP e first/last-hop telemetry, offer distribution account, timing/value e funding graph; route blinding limita intencionalmente a visibilidade do payer.

## Monero

**Mecânica:** one-time stealth addresses ocultam recipient linkage, RingCT oculta amounts e ring signatures fornecem sender ambiguity.

**Vantagens:** privacidade padrão on-chain; confidencialidade de sender/receiver/amount; ecossistema maduro de dedicated wallet/node.

**Desvantagens:** records de acquisition/off-ramp e endpoint/network/counterparty; remote node vê queries/IP; exchange support/legal treatment varia; pequenos erros operacionais ainda vinculam contexts.

**Procedimento:** (1) adquirir legalmente e manter basis/source; (2) instalar/verificar official maintained wallet; (3) fazer backup/testar seed; (4) usar local node ou caminho documentado Tor/I2P para remote node; (5) usar nova subaddress por payer/invoice; (6) rotular contexts localmente; (7) divulgar transaction proof/view access somente deliberadamente.<sup>[[8]](#references)</sup>

**Detecção:** focar em exchange/merchant/device/network e evidências de seized-wallet; uso do protocolo isoladamente não é suspeito e a public chain deliberadamente expõe menos.

## Zcash fully shielded Orchard

**Mecânica:** zero-knowledge proofs validam shielded transfers enquanto sender, receiver e amount são criptografados; transparent pools e pool transitions permanecem públicas.

**Vantagens:** forte confidencialidade shielded on-chain; viewing keys podem permitir audit escopo; validade imposta pelo protocolo.

**Desvantagens:** wallet/exchange support e escolha real do pool variam; correlação de timing/value na fronteira transparente; network/RPC e endpoint permanecem.

**Procedimento:** (1) selecionar uma maintained Orchard shielded-by-default wallet; (2) verificar/fazer backup; (3) obter ZEC legalmente; (4) receber em Unified Address suportado e confirmar pool; (5) preferir shielded-to-shielded; (6) usar network privacy suportada; (7) testar viewing-key disclosure em uma wallet pequena antes do audit.<sup>[[9]](#references)</sup>

**Detecção:** transparent boundary e service records, wallet/network metadata e viewing keys quando legalmente fornecidas; não presumir que todos os pagamentos de Unified Address foram shielded.

## Mimblewimble and Litecoin MWEB

**Mecânica:** confidential transactions ocultam amounts e a aggregation no estilo Mimblewimble remove o histórico convencional rico em addresses; Litecoin implementa um extension block opcional junto à sua chain transparente.

**Vantagens:** confidential amounts e fungibility melhorada no domínio privado; pruning/aggregation eficientes.

**Desvantagens:** opt-in boundary peg-in/out é público e correlacionável; wallet/exchange support; diferenças de interactive/address model; records de network e acquisition.

**Procedimento:** (1) escolher wallet mantida com suporte explícito a MWEB; (2) verificar/fazer backup e testar pequeno amount; (3) adquirir legalmente; (4) fazer peg into MWEB e verificar balance domain; (5) transacionar somente com receiver compatível; (6) evitar peg-out imediato e distintivo; (7) manter private audit records.<sup>[[10]](#references)</sup>

**Detecção:** peg-in/out público por timing/value, exchange/wallet/node data e later transparent spends; detalhes de confidential transfer internos são intencionalmente reduzidos.

## Ethereum zero-knowledge privacy applications

**Mecânica:** um circuit prova um statement — membership, valid note ownership ou authorization — sem revelar o secret; um verifier contract o verifica. Deposits, withdrawals, public inputs, events e gas ainda podem expor links.

**Vantagens:** selective disclosure programável; anonymous-set applications; regras verificáveis sem revelar todos os dados.

**Desvantagens:** bugs de contract/circuit; anonymity set pequeno; public boundaries; RPC/IP/session/analytics/gas funding; riscos de application e sanctions/legal.

**Procedimento:** (1) definir exatamente o que o proof oculta; (2) usar application auditada e mantida quando legal; (3) inspecionar public inputs/events e regras de deposit/withdraw; (4) separar action wallet e gas sponsorship conforme o protocolo; (5) usar caminho privacy-aware de RPC/network; (6) testar com pequeno value; (7) preservar compliance records.<sup>[[11]](#references)</sup>

**Detecção:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics e eventual exchange/merchant boundary. Não afirmar que o ZK proof oculta fields declarados públicos.

## Stablecoins

**Mecânica:** tokens transferem-se em uma public chain; centralized issuers podem freeze/blacklist ou redeem contra accounts identificadas.

**Vantagens:** price stability, liquidity e merchant support; settlement rápido; accounting fácil.

**Desvantagens:** transparent address/amount/contract graph; gas funding; issuer e exchange identity/control; sanctions screening; geralmente anonymity ruim.

**Procedimento:** tratar como identified payment: usar fresh business address somente para compartmentation, verificar token contract/network, testar pequeno amount, proteger wallet, usar trusted RPC/local node, manter basis/source e fazer screening das partes exigidas.

**Detecção:** token event graph completo, issuer freeze list/actions, exchange/RPC/device e gas-funding relationships.

## Cashu Chaumian e-cash

**Mecânica:** um mint assina cegamente bearer secrets gerados pelo client, respaldados por Bitcoin/Lightning reserves do mint; pode impedir double-spend sem vincular diretamente issuance a redemption posterior.

**Vantagens:** bearer tokens sem account; peer transfer instantâneo; mint não vincula diretamente blinded withdrawal ao spend; tokens podem circular como data/QR.

**Desvantagens:** custody/solvency/censorship do mint; perda/roubo do bearer data; denomination/timing e Lightning boundaries; network metadata; ecossistema inicial de software.<sup>[[12]](#references)</sup>

**Procedimento:** (1) usar primeiro um official test mint ou valor descartável pequeno; (2) instalar maintained wallet e testar limitações de backup/restore; (3) autenticar mint e revisar custody/fees; (4) mintar pequeno amount; (5) enviar token por private channel/QR autenticado; (6) receiver trocar o token antes de tratá-lo como final; (7) redeem e reconcile. Nunca armazenar valor relevante em mint não confiável.

**Detecção:** mint vê network, issue/redeem/Lightning boundaries e spent-token set, mas blinding remove o token linkage direto; endpoints/messages e distinctive amount/timing podem restaurar links.

## Fedimint federated e-cash

**Mecânica:** um threshold de guardians mantém reserves e assina e-cash cegamente; internal bearer transfers são privadas perante guardians, enquanto Lightning gateways conectam pagamentos externos.

**Vantagens:** custody distribuída; internal transfer privada; community governance; nenhum guardian controla a reserve abaixo do threshold.

**Desvantagens:** riscos de guardian quorum/custody/software; gateway observa invoices/timing; deposit/withdraw boundaries; complexidade de recovery do client-state.

**Procedimento:** (1) verificar federation invite/guardians/quorum/jurisdiction; (2) instalar maintained client e testar recovery; (3) depositar pequeno amount legal; (4) usar fresh internal payment requests; (5) tratar gateway como observer do Lightning; (6) testar redemption; (7) manter source/tax records fora dos public payment data.<sup>[[13]](#references)</sup>

**Detecção:** federation vê aggregate issuance/redemption, gateways veem external invoices, Bitcoin/Lightning mostram boundaries e endpoint/communication evidence pode vincular internal transfers.

## GNU Taler

**Mecânica:** e-cash com blind-signature integrado ao banco busca manter o payer anônimo perante merchants, enquanto merchants e income permanecem accountable.

**Vantagens:** privacidade do payer por design; currency comum; merchant accountability/refunds; nenhum speculative token necessário.

**Desvantagens:** deployments limitados; exchange/bank vê funding; merchant vê order/delivery; risco de bearer/recovery da wallet; operators regulados.

**Procedimento:** (1) localizar exchange/merchant atual para jurisdiction/currency; (2) ler KYC/fees/privacy; (3) instalar official wallet; (4) withdraw legalmente de supported bank/exchange; (5) revisar merchant contract; (6) pagar e preservar receipt/refund data; (7) evitar merchant session identifiers desnecessários.<sup>[[14]](#references)</sup>

**Detecção:** bank/exchange withdrawal e merchant deposit são boundaries accountable; merchant order/device/delivery e timing podem correlacionar mesmo com coins blinded.

## Cross-chain bridge, atomic swap and decentralized exchange

**Mecânica:** um contract/service bloqueia/queima um asset e libera/minta outro, ou counterparties trocam atomicamente. Isso rompe a visão de um único ledger, não a continuidade econômica.

**Vantagens:** interoperabilidade de asset/network; pode evitar um centralized custodian; uso comum de portfolio/liquidity.

**Desvantagens:** ambas as chains são públicas; time/value/fees/liquidity e contracts correlacionam; bridge/relayer/frontend/RPC records; riscos de smart-contract/counterparty e regulatórios.

**Procedimento para swaps legais:** (1) verificar official contract/service e legal availability; (2) inspecionar custody/audit/fees/slippage; (3) usar small test; (4) registrar ambos os transaction IDs e rate; (5) proteger approvals; (6) reconciliar destination asset e revogar approval desnecessária. Não usar swaps para disfarçar source of funds.

**Detecção:** bridge deposit/withdraw events, unique amount menos fees, time order, liquidity, relayer/RPC/frontend e later service deposits.

## Centralized mixer or tumbler

**Mecânica:** um service recebe deposits em um pool e retorna units diferentes depois, tentando obscurecer o input-output mapping direto.

**Vantagens:** teoricamente pode ampliar transaction ambiguity.

**Desvantagens:** operator pode roubar/logar; entry/exit timing/value analysis; sanctions/money-transmission e criminal exposure; seizures expõem mappings; risco de taint/rejection.

**Procedimento:** nenhum operational mixing guide é fornecido. Reproduzir o graph com segurança estendendo [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): criar synthetic deposits, pooled outputs, fees e delays; fornecer mappings incompletos aos analysts; medir quais heuristics funcionam; então revelar ground truth.

**Detecção:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs e downstream consolidation. Rotular probabilistic attribution.

## Peel chains, fan-out/fan-in and structuring

**Mecânica:** transactions repetidas retiram pequenos payments do change, dividem value entre muitos addresses, reconvergem collectors ou dividem amounts para evitar review.

**Vantagens:** aumenta o trabalho do analyst ingênuo e o número de addresses.

**Desvantagens:** value/cadence/transaction continuity reconhecíveis; consolidation e service endpoints; structuring pode ser ilegal por si só; fees e erros operacionais.

**Procedimento:** usar somente synthetic CSV/testnet data: gerar grande source, repeated payment/change edges, parallel branches e um collector; adicionar exemplos benignos semelhantes a exchange; ajustar detection e documentar false positives.

**Detecção:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint e off-chain records. Exchange hot wallets podem parecer com esses padrões, portanto contexto é obrigatório.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker and front company

**Mecânica:** outra pessoa/account/company recebe, converte ou gasta funds, inserindo layers legais e operacionais entre controller e transaction.

**Vantagens para um adversary:** named account não identifica imediatamente o controller; pode conectar cash, crypto, goods e jurisdictions.

**Desvantagens:** exposição a identity fraud/money-laundering; cada participant adiciona communications, bank/company/tax/shipping records, fees, inconsistencies e witnesses; reuse de facilitators cria hubs.

**Procedimento:** não emular com pessoas/accounts reais. Construir graph sintético com controller, recruiter, mule, OTC, shell merchant e beneficiary; semear device/IP/message/bank edges; pedir aos investigators que distingam account holder de controller e registrem confidence da evidência.

**Detecção:** shared device/IP/recovery, beneficiary/velocity incomum, muitos senders não relacionados, onward movement imediato, inconsistência de company/director/invoice, communications e entrega de cash/commodity.

## NFTs, gambling, merchant goods and refund loops

**Mecânica:** value é convertido em self-priced asset, wagering balance, goods revendíveis ou refunds para criar uma narrativa transacional diferente.

**Vantagens para um adversary:** muda a forma do asset e introduz marketplace/merchant intermediaries.

**Desvantagens:** marketplace/account/device e wash-trade graph; odds/play e refund records; delivery/resale evidence; fees/losses; responsabilidade por fraud/laundering.

**Procedimento:** nenhum workflow de concealment. Usar synthetic marketplace data com self-trades entre related wallets, pricing implausível, minimal play, refund instrument incompatível e shipping comum; validar detection contra collectors/customers legítimos.

**Detecção:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery e reconvergência de proceeds.

## Physical bearer wallet or offline token transfer

**Mecânica:** device, paper/QR, hardware bearer instrument ou e-cash token transfere controle de um secret em vez de transmitir um payment durante a entrega.

**Vantagens:** nenhum live network event durante a troca; útil offline; custody semelhante a cash físico.

**Desvantagens:** copy/theft/loss e exclusividade incerta; later redemption/broadcast vincula; physical meeting/shipping; counterfeit/tamper risk.

**Procedimento:** (1) usar somente instrument/protocol revisado; (2) inicializar/verificar authenticity privadamente; (3) carregar somente pequeno lawful value; (4) transferir em contexto autorizado documentado; (5) receiver verificar ou sweep prontamente conforme o protocolo; (6) nunca presumir que sender não reteve cópia; (7) registrar ownership/tax evidence privadamente.

**Detecção:** purchase/funding e eventual sweep/redemption, device serial/tamper evidence, delivery/meeting e endpoint records.

## Merchant-scoped invoice or one-time payment request

**Mecânica:** merchant cria uma request de uso único com amount, expiry e order reference. Payer liquida por rail suportado sem expor diretamente uma credential reutilizável ao merchant; issuer/payment processor ainda pode identificar ambos.

**Vantagens:** limita credential reuse e identifiers cross-merchant acidentais; amount/expiry exatos reduzem erros; compatível com accounting e refunds comuns.

**Desvantagens:** invoice, delivery, browser, processor e issuer ainda vinculam order; amount/time único pode fortalecer correlação; malicious payment links são comuns.

**Procedimento:** (1) autenticar merchant independentemente; (2) solicitar fresh invoice com exact amount, asset/network e expiry; (3) inspecionar destination e refund rules; (4) pagar pelo approved engagement compartment; (5) verificar que merchant reconhece a mesma invoice; (6) preservar receipt e transaction reference; (7) expirar em vez de reutilizar a request.

**Detecção:** merchant e processor associam invoice, session e settlement; amounts/timing únicos e delivery identificam o payer. **Captured wallet/device:** invoice history expõe counterparties e purpose; minimizar memo data desnecessária, criptografar device e manter authoritative accounting no controlled finance system.

## Prepaid service credit and capability token

**Mecânica:** service converte um payment convencional em bounded internal credits ou bearer capability. O uso posterior de API/resource pode evitar apresentar o card original em cada request, mas o service frequentemente consegue mapear issuance a redemption.

**Vantagens:** limita spend e compromise loss; separa workers diários da funding credential; permite budgets por project e revocation.

**Desvantagens:** geralmente pseudonymous, não anonymous; service database, redemption IP e usage pattern único vinculam activity; bearer tokens podem ser roubados; refunds podem exigir payer original.

**Procedimento:** (1) comprar credits por organization account; (2) criar um project e budget; (3) emitir narrow token com service, amount e expiry constraints; (4) armazená-lo somente no approved secret manager ou workload identity path; (5) testar rejeição fora do scope e após expiry; (6) monitorar consumption; (7) revogar e reconciliar unused value.

**Detecção:** provider associa funding account, project, token issuance e usage; defenders alertam para mudanças geográficas/processuais e consumption anômalo. **Captured node:** assumir que sua capability restante pode ser gasta; usar short expiry, low balance, audience binding e revogação imediata server-side.

## Privacy Pass or blinded authorization token

**Mecânica:** issuer produz um authorization token com privacy-preserving properties que um origin pode validar sem vincular redemption a issuance. Pode representar paid entitlement ou acesso limitado por rate, mas não é currency geral. A arquitetura separa client, attester, issuer e origin roles e alerta que IP/timing ou collusion podem desfazer unlinkability.<sup>[[18]](#references)</sup>

**Vantagens:** redemption unlinkable para services suportados; nenhum reusable account cookie no origin; cached tokens podem separar issuance e use no tempo.

**Desvantagens:** específico da application; issuer/attester trust e anonymity-set partitioning; IP e browser metadata permanecem; token theft ou distinctive issuance timing podem correlacionar use.

**Procedimento:** (1) usar implementation conforme ao Privacy Pass token type relevante; (2) definir exatamente qual entitlement o token prova; (3) separar issuer e origin administration quando o threat model exigir; (4) minimizar challenge metadata; (5) emitir vários test tokens e resgatar cada um uma vez em owned origins; (6) comparar logs em busca de stable identifiers proibidos; (7) testar replay, expiry e revocation/abuse controls.

**Detecção:** origins veem redemption IP/time e token validity; issuers/attesters veem issuance context; analysts testam timing e metadata partitions sem presumir cryptographic break. **Captured client:** bearer tokens não gastos podem ser utilizáveis; limitar value, lifetime e audience e nunca armazenar funding credential junto deles.

## Delegated organization procurement or fiscal sponsor

**Mecânica:** procurement team, reseller ou fiscal sponsor autorizado contrata e paga enquanto a operational team recebe um service limitado. É role separation com records verdadeiros, não nominee ou false identity.

**Vantagens:** vendors não precisam receber a identidade de cada operator ou personal payment details; compliance, tax e refund centralizados; budget e offboarding claros.

**Desvantagens:** sponsor conhece beneficiary e purpose; contracts, approvals, delivery e accounts permanecem; delay/fees adicionais; separation fraca se a mesma pessoa administrar todas as layers.

**Procedimento:** (1) documentar business purpose, beneficiary e approving authority; (2) selecionar intermediary aprovado pela organization; (3) contratar com dados verdadeiros; (4) provisionar subaccount com scope de project e sem personal billing credential; (5) separar finance administrators de operators; (6) reconciliar invoices e access; (7) terminar service e delegated access no closeout.

**Detecção:** procurement, identity-provider, vendor e delivery records unem a cadeia. **Captured operational device:** deve revelar o service project, mas não finance credentials; manter invoices e payer identities no finance system, não em field nodes.

## Escrow or conditional settlement

**Mecânica:** trusted escrow agent ou smart contract mantém value até condições documentadas serem atendidas. Pode reduzir disclosure direto entre payer e payee, enquanto escrow e payment rails subjacentes preservam a relação.

**Vantagens:** proteção de dispute/delivery; payer e merchant podem expor menos reusable credentials entre si; release conditions auditáveis.

**Desvantagens:** custody/contract risk do escrow, fees e identity obligations; on-chain contracts são públicos; order, shipping e dispute data permanecem; não é anônimo perante intermediary.

**Procedimento:** (1) verificar legal entity, custody, fees, dispute forum e supported assets; (2) criar milestone escrito exato e refund path; (3) financiar por approved organization account; (4) verificar receipt e release authorization independentemente; (5) liberar somente após evidence; (6) preservar complete audit record; (7) fechar permissions ou contract approvals não usados.

**Detecção:** escrow account/contract events, funding e release time, beneficiary e dispute records revelam a transaction. **Captured device:** session tokens ou contract approvals podem permitir release; exigir separate approver/MFA e revogar active sessions em caso de perda.

## Batched or pooled organization settlement

**Mecânica:** múltiplas obrigações aprovadas são agregadas e liquidadas em menos bank ou blockchain transactions, com private internal ledger atribuindo cada share. Batching pode reduzir public per-purchase detail, mas coordinator mantém attribution completa.

**Vantagens:** fees menores; menos public graph edges; oculta line items individuais de um public observer quando amounts são agregados; accounting interno direto.

**Desvantagens:** coordinator é observer completo e alvo de alto valor; totals/timing distintos podem correlacionar; riscos de custody/reconciliation; pode parecer structuring se abusado.

**Procedimento:** (1) definir participants e lawful obligations no accounting system; (2) estabelecer regular business-justified batch window, não thresholds criados para evitar controls; (3) exigir dual approval do aggregate; (4) liquidar para recipients autenticados; (5) reconciliar cada internal line com o batch; (6) tratar refunds como linked corrections; (7) proteger ledger access e retê-lo conforme policy.

**Detecção:** coordinator ledger, approval e beneficiary records fornecem ground truth; public analysts usam input/output/value/time clustering cautelosamente. **Captured payer device:** deve conter somente sua requisition, não signing key ou participant ledger do pool.

## Account-abstraction paymaster or sponsored gas

**Mecânica:** relayer/bundler submete smart-account operation e paymaster paga transaction fees, evitando uma direct native-gas funding edge da user wallet. Melhora uma propriedade do graph; operation, contract e service telemetry permanecem públicas ou observáveis.<sup>[[19]](#references)</sup>

**Vantagens:** remove common gas-funding link; permite scoped sponsorship e rate limits; melhora onboarding para privacy applications legítimas.

**Desvantagens:** paymaster/bundler/RPC/front end podem correlacionar requests; contract events e public inputs permanecem; sponsorship policy identifica uma cohort; malicious contracts/approvals podem roubar assets.

**Procedimento:** (1) usar audited maintained smart account e paymaster na network correta; (2) inspecionar quais fields são públicos e o que sponsor registra; (3) limitar sponsorship por contract, function, amount, nonce e expiry; (4) testar com baixo value; (5) submeter pelo intended privacy-aware path da application; (6) verificar operation e fee payer on-chain; (7) revogar allowances/session keys e manter compliance records.

**Detecção:** associar UserOperation, EntryPoint, paymaster, bundler/RPC e application logs; agrupar sponsorship policy idêntica com cautela. **Captured wallet:** session keys e pending approvals podem ser utilizáveis mesmo sem gas; limitar rigorosamente e revogar pela recovery policy da account.

## Threshold or multisignature payment authorization

**Mecânica:** gastar exige threshold de signers independentes. Não oculta transaction, mas separa payment authority de qualquer laptop, field node ou operator capturado.

**Vantagens:** forte resistência a compromise/insider; approval accountable; nenhum field device isolado possui signing authority completa; suporta recovery.

**Desvantagens:** coordination/availability; signer/device/account metadata pode correlacionar participants; backup ruim causa perda; public multisig patterns podem ser identificáveis.

**Procedimento:** (1) definir signers, threshold, limits e recovery antes do funding; (2) inicializar em hardware/accounts suportados separados; (3) verificar addresses e backups independentemente; (4) dar a field workloads somente unsigned requisition capability; (5) exigir out-of-band review de recipient, amount e purpose; (6) testar recovery e perda de um signer com pequeno value; (7) rotacionar signer após compromise.

**Detecção:** approval system, signer device e public script/contract fornecem evidências; defenders alertam para alterações de policy ou signer-set. **Captured node:** deve expor no máximo uma low-authority session key ou unsigned request; nunca armazenar quorum material em conjunto.

## Closed-loop community or event currency

**Mecânica:** cooperative, conference ou private test environment emite credits resgatáveis somente entre participants enrolled. Internal transfer pode expor menos às global payment networks, enquanto operator controla issuance e redemption.

**Vantagens:** economic domain limitado; permite testar UX de pagamentos offline ou privacy-preserving; limita exposição de card externo; controles experimentais claros.

**Desvantagens:** anonymity set pequeno; operator e merchants observam activity; acceptance/redemption limitadas; licensing, consumer-protection e tax rules podem aplicar mesmo a local value.

**Procedimento:** (1) obter legal/compliance review e publicar issuer terms; (2) cadastrar test participants consentindo; (3) limitar issuance e proibir misuse semelhante a cash; (4) usar fresh payment requests e minimizar public participant identifiers; (5) registrar aggregate reserves e private individual receipts; (6) testar loss/refund/redemption; (7) fechar ledger e devolver residual value conforme prometido.

**Detecção:** issuer ledger, enrollment, merchant e redemption records reconstroem flows; transfers circulares incomuns ou cash-out rápido merecem review. **Captured wallet:** local balance e counterparties podem ser expostos; limitar value, criptografar state e suportar issuer-side freeze/reissue com record auditável.

## Bitcoin reusable payment codes and private payment instructions

**Mecânica:** BIP 47 payment codes usam um reusable public identifier e one-time deposit addresses derivados por ECDH; BIP 351 especifica um design mais recente de private-payment instruction. Reduzem public address reuse ao permitir que recipient publique payment instructions estáveis. Notification, wallet support, funding e coin selection posterior ainda afetam a privacidade.<sup>[[20]](#references)</sup>

**Vantagens:** uma public instruction pode gerar addresses distintos; recipient não precisa publicar todo invoice address; wallets compatíveis podem monitorar derived payments; útil para donors/customers legais recorrentes.

**Desvantagens:** wallet interoperability varia; notification transactions ou payment code publicado vinculam relationship context; sender, recipient e public graph ainda veem transactions; consolidation ou change handling descuidado elimina o benefício.

**Procedimento:** (1) confirmar que ambas maintained wallets suportam exatamente a mesma specification/version; (2) fazer backup e testar recovery em wallet de baixo value; (3) autenticar recipient payment code out of band; (4) enviar pequeno lawful test; (5) verificar uso de fresh derived address; (6) rotular relationship localmente e aplicar coin control; (7) testar recovery e refund behavior antes de depender dele.

**Detecção:** analysts examinam notification patterns, funding/change, later consolidation e service boundaries; publicação do public code identifica o recipient context mesmo com deposit addresses diferentes. **Capture-resilient OPSEC:** manter spend keys fora de field devices e expor no máximo watch-only relationship view. **Monitoring:** alertar para notification transactions inesperadas, derived addresses reutilizados, gap-limit/recovery errors e consolidation não planejada.

## EVM stealth addresses (ERC-5564)

**Mecânica:** sender deriva uma one-time stealth account a partir do stealth meta-address do recipient e publica announcement com ephemeral public key e view tag. Recipient faz scan dos announcements com viewing key e deriva a correspondente spend key. Recipient linkage melhora, mas sender, amount/token, gas, announcement e later spending permanecem visíveis.<sup>[[21]](#references)</sup>

**Vantagens:** fresh receiver address não interativo; meta-address reutilizável; viewing e spending roles separados; funciona entre assets/applications EVM suportados.

**Desvantagens:** announcement scanning e spam; funding de gas para a nova address pode relinká-la; sender conhece recipient; public token/amount e eventual consolidation permanecem; implementation e wallet support variam.

**Procedimento:** (1) usar audited maintained implementation primeiro em test network; (2) gerar e fazer backup de viewing e spending material separados; (3) autenticar meta-address; (4) enviar low-value test e announcement; (5) fazer scan e derivar stealth account; (6) testar supported gas sponsorship sem personal funding edge; (7) registrar public fields e preservar lawful accounting.

**Detecção:** seguir announcement caller, token/amount, timing, gas sponsor, spending e consolidation; view key pode provar receipt sem conceder spend. **Capture-resilient OPSEC:** networked scanner deve ter somente viewing role quando suportado; manter spend e recovery keys em outro local. **Monitoring:** alertar para malformed/spam announcements, view-key access, unexpected spend derivation e stealth outputs movimentados sem approval.

## Liquid Confidential Transactions

**Mecânica:** Liquid oculta output amounts e asset types por padrão usando commitments e proofs, mantendo visíveis transaction graph, input/output count, fee e block time. Peg-in/peg-out e service boundaries continuam vinculáveis, e users podem divulgar seletivamente blinding data.<sup>[[22]](#references)</sup>

**Vantagens:** confidential amount e asset type por padrão; settlement sidechain rápido; selective audit por blinding keys/descriptors; oculta valores comercialmente sensíveis de public observers.

**Desvantagens:** graph structure e timing permanecem; federation/bridge e exchange trust; peg boundaries e unconfidential outputs; wallet/node/network records; receiver e sender conhecem sua transaction.

**Procedimento:** (1) selecionar Liquid wallet mantida e verificar backup model; (2) usar testnet ou pequeno lawful amount; (3) receber em confidential address e verificar que wallet marca output como blinded; (4) enviar small confidential transaction de teste; (5) inspecionar quais explorer fields permanecem públicos; (6) exportar somente scoped blinding proof necessário para audit; (7) documentar peg/exchange boundaries e reconciliar funds.

**Detecção:** analisar visible graph/fee/time, peg e exchange records, network metadata e later unblinding evidence; não inferir hidden amount ou asset. **Capture-resilient OPSEC:** separar spend seed, blinding/view data e watch-only operations. **Monitoring:** alertar para unconfidential addresses acidentais, unknown peg requests, descriptor changes e unapproved unblinding-key export.

## General payment or state channel

**Mecânica:** participants bloqueiam funds, trocam off-chain state updates assinados e publicam somente opening, closing ou disputed state on-chain. Intermediate payments não são globalmente transmitidos, mas peers e routing/intermediary services observam sua parte e endpoints precisam reter o latest enforceable state.<sup>[[23]](#references)</sup>

**Vantagens:** muitas interações rápidas e low-fee, privadas perante o public ledger; menos global transaction detail; channel balance limitado; útil para metered services e counterparties recorrentes.

**Desvantagens:** channel peers conhecem-se e podem reter updates; opening/closing/value/timing correlacionam; online monitoring pode ser necessário durante challenge windows; implementation e liquidity risk; por si só não é large anonymity set.

**Procedimento:** (1) escolher audited maintained implementation e entender dispute window; (2) abrir low-value test channel entre parties próprias; (3) trocar signed state updates com unique nonces; (4) fazer backup do latest enforceable state; (5) fechar cooperativamente; (6) ensaiar stale-state rejection em testnet; (7) preservar accounting e channel-peer records.

**Detecção:** public chain expõe lifecycle/disputes; peers, watch services e application transport expõem timing e parties off-chain. **Capture-resilient OPSEC:** limitar hot balance e manter latest signed state em encrypted recoverable store separado de field nodes. **Monitoring:** observar continuamente stale-state publication, missed backup, peer-key change e challenge deadline próximo.

## Mobile carrier billing

**Mecânica:** um online service cobra purchase de uma mobile subscription ou prepaid balance pelo carrier billing system. Merchant pode receber carrier authorization em vez de card/bank details, enquanto carrier conhece subscriber/line, device/network context, merchant, amount e time.<sup>[[24]](#references)</sup>

**Vantagens:** nenhum card number no merchant; ampla disponibilidade telefônica; útil para digital goods de baixo value; carrier pode limitar e reverter charges.

**Desvantagens:** fortemente identificado por SIM/account e frequentemente device; limites pequenos e fees altos; restrições por merchant category; risco de account takeover/SIM-swap; carrier e aggregator criam transaction trail completo.

**Procedimento:** (1) confirmar availability, limit, fee e refund terms com organization carrier account; (2) habilitar somente em dedicated organization line se justificado; (3) definir menor spend cap útil; (4) comprar benign test item; (5) verificar merchant e carrier receipts; (6) desativar recurring authorization; (7) reconciliar e desligar o recurso após assessment.

**Detecção:** carrier, aggregator e merchant records associam line, subscriber, IP/device e charge; enterprise telecom invoices expõem. **Capture-resilient OPSEC:** não usar personal number e exigir carrier-account MFA fora do field device. **Monitoring:** habilitar charge/SIM-change alerts imediatos e parar diante de premium-service enrollment, forwarding ou account recovery inesperado.

## Open-banking payment initiation

**Mecânica:** com user consent explícito, um payment-initiation service provider regulado (PISP) solicita ao account-servicing bank que inicie uma transfer. Merchant pode não receber card credentials, mas PISP e banks mantêm records regulados de payer, payee, consent, device e transaction.<sup>[[25]](#references)</sup>

**Vantagens:** nenhum reusable card number no checkout; bank authentication forte; settlement account-to-account exato; consent/status APIs; reconciliation clara.

**Desvantagens:** não é anônimo perante banks/PISP; payee geralmente vê legal account details ou reference; phishing/redirect risk; jurisdiction e refund protections variam; consent metadata adiciona outro observer.

**Procedimento:** (1) verificar se PISP é regulado atualmente e se merchant callback domain é autêntico; (2) iniciar pelo merchant request; (3) revisar payee, amount, reference e requested consent no bank; (4) autorizar somente single payment; (5) verificar final status independentemente; (6) revogar residual consent, se houver; (7) preservar receipt e reconciliar.

**Detecção:** bank/PISP/merchant logs e transfer references fornecem atribuição forte. **Capture-resilient OPSEC:** manter banking authentication e recovery fora de operational/field devices; device deve conter apenas paid-service entitlement. **Monitoring:** usar bank transaction/consent alerts e investigar novos PISP grants, changed payee ou status callbacks fora da session esperada.

## Platform wallet, app-store balance or in-app credit

**Mecânica:** uma platform cobra o user ou resgata account credit e então emite signed receipt ou entitlement para uma application. App developer pode não receber o funding instrument original, enquanto platform mapeia account, device, funding, product e redemption.<sup>[[26]](#references)</sup>

**Vantagens:** merchant/developer não recebe primary PAN; fraud/refund e family/business controls; pequeno prepaid balance limita exposure; signed receipts simplificam entitlement verification.

**Desvantagens:** platform account é forte hub de identity e behavior; device e storefront geography; gift-balance purchase/redemption trail; cash-out limitado; fraud controls podem congelar funds; não é dinheiro cross-platform.

**Procedimento:** (1) usar organization-managed platform account quando policy permitir; (2) revisar funding, region, refund e transferable-value rules; (3) adicionar somente approved budget; (4) comprar benign product pela official store; (5) verificar que application recebe somente receipt fields esperados; (6) desativar recurring purchase; (7) reconciliar e remover account do operational hardware.

**Detecção:** platform receipts/server notifications, account/device login e funding records reconstroem purchase. **Capture-resilient OPSEC:** nunca iniciar personal store account em field node; fornecer somente scoped app entitlement quando possível. **Monitoring:** habilitar new-device/purchase alerts e investigar receipt replay, family/account changes ou unexpected restore events.

## Mutual credit, clearing or periodic net settlement

**Mecânica:** participants registram obligations em private ledger e liquidam periodicamente somente cada net position. Individual service events não precisam criar payments públicos separados, mas ledger operator e counterparties retêm attribution detalhada.

**Vantagens:** menos external transactions e fees; public observers veem somente net settlement; funciona para organizations recorrentes; credit limits explícitos limitam exposure.

**Desvantagens:** centralized ledger é evidência completa e alvo de fraude; counterparty/default risk; obrigações legais/accounting/tax; membership pequeno; net transfers incomuns ainda revelam relações.

**Procedimento:** (1) usar somente identified consenting organizations com legal/accounting approval; (2) definir unit, credit limit, settlement interval e dispute rules; (3) registrar cada obligation com immutable approval; (4) roles de finance separados calculam e aprovam net positions; (5) liquidar por ordinary lawful rail; (6) reconciliar individual lines ao settlement; (7) fechar access e conservar records conforme policy.

**Detecção:** ledger, invoices, approvals e final bank/chain settlement fornecem ground truth; analysts não devem inferir gross activity ausente somente a partir do net transfer. **Capture-resilient OPSEC:** operational devices podem enviar bounded requisitions, mas não editar balances ou autorizar settlement. **Monitoring:** alertar para credit-limit breach, backdated entries, administrator changes, reconciliation mismatch e settlement para novo beneficiary.

## Capture/compromise exposure matrix

Isso aplica um seizure/loss test a cada família. O objetivo é limitar spend authority e divulgação de identidade não relacionada, mantendo lawful accounting — não apagar transactions ou impedir investigation.

| Família da técnica | O que um wallet/device/account capturado pode revelar | Controle autorizado mínimo |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value e contatos físicos | carregar somente amount aprovado; accounting privado separado; reportar perda prontamente; nenhum registro falso |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption e account/session tokens | low balance; um purpose; registration verdadeira; issuer freeze/revocation quando disponível |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery e merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; nenhum recovery account compartilhado |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices e project | role separation; least-privilege subaccount; finance credentials nunca em operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator ou dispute trail | single-use request; separate approver; limited session; authoritative central ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph e network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; recovery documentado |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP e payment database | minimal hot balance; encrypted backup; separate node identity; close/recover conforme plano documentado |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC e boundary transactions | separate spend/view roles; hardware support quando disponível; nenhum exchange session em field node |
| Stablecoins, swaps, bridges and DEX | transparent graph, approvals, RPC/front-end state e destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup conforme protocolo; redeem/reissue; nunca colocar funding credential junto |
| Paymaster, multisig/threshold | session key, one signer, pending operations e sponsor policy | narrow session key; independent quorum; signer rotation; field device não alcança threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph e participant records | nenhum uso operacional; emular apenas com synthetic/testnet evidence |
| Community/event currency | enrollment, local balance, counterparties e redemption | capped value; issuer freeze/reissue; consent e private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements e derived outputs | watch/view-only network role; offline/hardware spend role; nenhum personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries e disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device e funding source | organization account; external MFA; low limit; nenhum personal account em field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals e settlement ledger | operational requisition only; separate immutable ledger e dual finance approval |

## Monitoring possible discovery or payment compromise

Payment denial, compliance review ou uma wallet offline não provam que existe investigation. Monitorar somente accounts, ledgers e infrastructure que a organization tem direito de observar; nunca sondar providers ou counterparties para testar se cooperam com investigators.

| Técnicas cobertas | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund ou loss report | missing instrument, redemption fora do order aprovado, altered receipt ou custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap ou recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice e consumption | cross-project token, unknown admin, limit breach, invoice mismatch ou unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation e beneficiary change | altered amount/payee, backdated ledger, unilateral release ou unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels e consolidation | unknown spend, reused recipient output, wallet gap/recovery failure ou unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure ou coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP e chain dispute | unknown invoice payment, peer-key change, stale close ou approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor e boundary transaction | spend sem approval, transparent/unconfidential downgrade, key export ou unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key e issuer action | wrong contract/public field, unknown approval/spend, paymaster change ou issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway e bearer balance | unknown redemption, mint key/terms change, restore failure ou balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate e destination | contract/route mismatch, unlimited approval, missing destination ou bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum e recovery audit | unknown proposal/signer, threshold reduction, recovery activation ou policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | synthetic lab ground truth e detection output somente | qualquer real account, person ou value entrando na emulation: parar imediatamente |

## Selection and verification workflow

1. Nomear qual party não deve aprender qual field.
2. Identificar issuer/mint/custodian, public ledger, network/RPC, merchant e physical observers.
3. Verificar support atual, legality, limits, custody, recovery e refund behavior.
4. Usar pequeno lawful end-to-end test.
5. Inspecionar merchant receipt, provider statement, public chain e wallet/node logs.
6. Testar backup/recovery e deliberate audit disclosure.
7. Manter source, ownership, tax, sanctions e engagement records exigidos corretos, mas com acesso controlado.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observations on data collection by large payment platforms](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Protect your privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — A Simple Payjoin Proposal](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Building privacy applications with zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — How it works](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — The Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
