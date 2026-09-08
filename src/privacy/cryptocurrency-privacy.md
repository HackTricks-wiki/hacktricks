# Privacidade de criptomoedas

A privacidade de criptomoedas é uma questão de protocolo e operações, não um sinônimo de sigilo ou imunidade. Ledgers públicos, exchanges, servidores de wallet, peers da rede, comerciantes e transações posteriores expõem diferentes partes do grafo.

Comece pelo [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) para consultar o formato de prós/contras/procedimento/detecção de cada técnica. Esta página amplia os mecanismos específicos de criptomoedas e os limites operacionais.

{% hint style="danger" %}
Este capítulo destina-se à self-custody legal e à minimização de dados. Não o use para lavar recursos, evadir sanções/impostos/obrigações de declaração, realizar transações com partes proibidas, induzir um provedor regulado ao erro ou operar um serviço de transmissão sem licença. A tecnologia de privacidade não altera a origem legal nem a propriedade dos recursos.
{% endhint %}

## Modelo de ameaça por camada

| Camada | Observador | Divulgação comum |
|---|---|---|
| Aquisição/off-ramp | Exchange, banco, broker, contraparte P2P | Identidade, conta de financiamento, destino, dispositivo, IP, horário |
| Ledger | Qualquer pessoa executando analytics | Endereços/outputs, valores e horários em chains transparentes; metadados específicos do protocolo em outros casos |
| Backend da wallet | Provedor de RPC, explorer, remote node | Consultas de endereço, saldos, IP, transmissão de transações |
| Rede | ISP, peers, entrada da anonymity-network | IP, timing, volume e uso do protocolo |
| Contraparte | Pagador/beneficiário | Invoice/endereço, entrega, conversa, conta e timing |
| Endpoint | Malware, backup na cloud, apreensão física | Seed, keys, rótulos, histórico, screenshots e clipboard |

A self-custody pode remover um custodiante do caminho de controle, mas não apaga o ledger, o registro de aquisição, os metadados da rede nem as evidências do endpoint.

## Comparação de protocolos

| Método | Propriedade de privacidade útil | Limitações importantes |
|---|---|---|
| Bitcoin on-chain | Self-custody; endereços novos evitam a simples reutilização de endereços | Grafo público e permanente de transações; heurísticas de valor/timing e gastos |
| Bitcoin PayJoin | A entrada do receptor pode quebrar a heurística de propriedade comum das entradas | Ambas as wallets precisam de suporte; a transação continua pública; o suporte é desigual |
| Bitcoin CoinJoin | Cria ambiguidade entre participantes coordenados | Padrões reconhecíveis, links pré/pós, consolidação, risco de política/legal/provedor |
| Lightning | Pagamentos roteados por onion não são publicados globalmente como transferências comuns | Abertura/fechamento de canais on-chain; endpoints, peers, probes ou custodiante podem inferir dados |
| Monero | Maior confidencialidade on-chain padrão para receptor, valor e conjunto de remetentes | Links com exchange, node, timing, endpoint e contraparte permanecem |
| Ethereum/stablecoins | Ampla disponibilidade e interoperabilidade com smart contracts | Estado/ações públicos; metadados de RPC; emissores centralizados podem bloquear/congelar/denunciar |

## Bitcoin: baseline de preservação de privacidade

Bitcoin é pseudônimo, não anônimo. Transações confirmadas são públicas e duradouras; reutilização de endereços, propriedade comum das entradas, detecção de change e endereços identificados publicamente podem formar clusters.<sup>[[1]](#references)</sup>

### Workflow

1. **Escolha uma wallet de self-custody mantida.** Faça o download no projeto oficial, verifique assinaturas/hashes quando disponíveis e aplique atualizações de segurança.
2. **Crie a wallet em um endpoint confiável.** Registre a seed de recuperação offline; nunca a coloque em email, chat, screenshots ou notas comuns na cloud. Teste a recuperação antes de armazenar valores significativos.
3. **Mantenha hot apenas o valor operacional.** Use custódia offline/hardware adequada para valores de longo prazo, com um plano de recuperação que não exponha a seed a um único local frágil.
4. **Gere um endereço/invoice novo para recebimento em cada transação.** Não publique um endereço estático quando um servidor de invoices ou uma entrega privada autenticada for possível.
5. **Use seu próprio full node quando viável.** Um explorer/servidor electrum de terceiros pode descobrir os endereços consultados e os metadados de IP. Configure somente o comportamento de Tor/proxy suportado pela wallet; Tor oculta uma extremidade da rede, não o grafo do blockchain.
6. **Rotule cada UTXO privadamente** com origem, proprietário, finalidade e estado de compliance. Ative o coin control para que contextos de identidade não relacionados não sejam gastos juntos.
7. **Visualize a transação:** entradas selecionadas, destino do change, valor, fee, contraparte e se o gasto combina compartimentos. Evite consolidação desnecessária.
8. **Mantenha os registros legais separadamente e criptografados.** Preserve base de aquisição, invoices, autorização e informações fiscais/de declaração sem publicar o mapeamento.
9. **Trate gastos posteriores como parte da mesma decisão de privacidade.** Um recebimento bem separado pode ser vinculado novamente quando seu output for gasto junto com fundos identificados.

A documentação de privacidade do Bitcoin Core explica que um full node evita revelar consultas da wallet a servidores de terceiros, mas que a transmissão da transação e o histórico público ainda precisam ser analisados.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin é um pagamento colaborativo no qual o receptor adiciona uma entrada. Isso derrota a suposição simplista de que todas as entradas pertencem ao remetente. O BIP 78 descreve o protocolo interativo original; o draft BIP 77 define um design assíncrono v2 usando uma mailbox criptografada/OHTTP.<sup>[[3]](#references)</sup>

Uso seguro:

1. Confirme que ambas as wallets mantidas suportam a mesma versão do PayJoin.
2. Obtenha a invoice compatível com PayJoin por um canal autenticado; proteja-a como qualquer solicitação de pagamento.
3. Verifique o valor e o destino originais, depois deixe a wallet validar a proposta/PSBT, a contribuição para a fee e as substituições proibidas.
4. Confirme o resumo final da wallet. Não aprove manualmente um output, valor ou fee excessiva inesperados.
5. Se a negociação falhar, entenda se a wallet retorna com segurança a um pagamento comum ou exige uma nova invoice.
6. Retenha o recibo/registros privados necessários para propriedade, contabilidade e disputas.

PayJoin melhora uma heurística de chain analysis; não oculta o pagamento das partes, da plataforma de aquisição, dos endpoints ou do ledger público.

## CoinJoin: benefícios e limitações

CoinJoin coordena vários usuários em uma única transação para tornar o mapeamento entre entradas e outputs menos certo. Pesquisas sobre designs históricos específicos do Wasabi e Samourai encontraram transações altamente reconhecíveis e mostraram que o comportamento pré/pós-mix pode reduzir substancialmente o anonimato.<sup>[[4]](#references)</sup> Esse resultado não deve ser generalizado para toda implementação ou versão futura, mas demonstra por que um número de “conjunto de anonimato” não é uma garantia.

Antes de qualquer uso legal:

- verifique a legislação local atual, o status de sanções, a política da exchange/custodiante e as obrigações fiscais/de declaração;
- use software mantido e non-custodial obtido no projeto oficial;
- entenda o modelo do coordinator, as fees, os controles contra denial-of-service e se o serviço atual ainda opera — a zkSNACKs encerrou seu coordinator em 2024, embora outros coordinators do Wasabi possam existir;
- preserve privadamente os registros de origem dos recursos e das transações;
- nunca aceite recursos desconhecidos em nome de outra pessoa nem use um “mixer” custodial que prometa saques impossíveis de rastrear;
- mantenha os outputs separados por origem/contexto e evite consolidações posteriores que destruam a ambiguidade pretendida.

Os resultados legais dependem dos fatos e da jurisdição. As declarações de culpa da Samourai em 2025 envolveram a operação consciente de um money transmitter sem licença que movimentava recursos criminosos; elas não estabelecem que toda transação colaborativa ou todo usuário que busca privacidade seja criminoso.<sup>[[5]](#references)</sup>

## Lightning Network

O onion routing Sphinx do Lightning foi projetado para que um hop intermediário conheça seu predecessor e sucessor, em vez da rota inteira.<sup>[[6]](#references)</sup> Não é anonimato abrangente: o funding/fechamento de canais é público, nodes anunciam a topologia, contrapartes conhecem os endpoints, routing/probing pode inferir saldos ou partes, e uma custodial wallet vê a atividade da conta do usuário.

Para obter mais privacidade:

1. Prefira uma wallet mantida e non-custodial se a privacidade perante intermediários for importante; planeje primeiro o backup/recuperação dos canais.
2. Use uma invoice ou offer nova para cada pagamento. Verifique se a wallet específica suporta BOLT 12/route blinding, em vez de presumir que sim.
3. Evite publicar aliases de node, dados de contato e endpoints de rede estáveis desnecessários.
4. Conecte-se por uma rede de privacidade suportada, quando apropriado, entendendo que padrões de disponibilidade/timing ainda podem ser correlacionados.
5. Não presuma que um pagamento off-chain não deixa registros: remetente, receptor, peers, watchtowers, provedores de liquidez e serviços de wallet podem reter observações.

Pesquisas publicadas demonstraram inferências de remetente/receptor e de saldo de canais a partir de dados públicos e probing ativo, embora os ataques e as mitigações evoluam.<sup>[[7]](#references)</sup>

## Monero

Monero usa stealth addresses de uso único para outputs, RingCT para ocultar valores e ring signatures para fornecer ambiguidade probabilística do remetente; suas especificações técnicas atuais documentam um ring size de 16 (15 decoys).<sup>[[8]](#references)</sup> Esses são padrões mais fortes de confidencialidade on-chain do que os ledgers transparentes, não uma proteção mágica contra erros de endpoint ou operacionais.

### Workflow legal

1. **Adquira legalmente.** Uma exchange regulada pode conhecer a compra e o saque mesmo quando os detalhes on-chain posteriores são confidenciais. Mantenha registros de origem, base e declaração.
2. **Instale a wallet oficial mantida** e verifique o download de acordo com as instruções do projeto. Faça backup da seed offline e teste a restauração com um valor pequeno.
3. **Prefira um node local** para obter máxima privacidade nas consultas da wallet. Se isso não for prático, escolha um remote node confiável acessível por uma configuração onion/I2P oficialmente suportada. Um remote node pode registrar IP, solicitações, timing e IDs de transação; alguns designs lightweight divulgam uma view key.
4. **Use uma subaddress nova por pagador, campanha ou invoice.** Um pagador pode correlacionar o uso repetido da mesma subaddress.<sup>[[9]](#references)</sup>
5. **Rotule localmente os contextos recebidos.** Evite combinar operacionalmente receipts separados quando um pagador informado puder reconhecer o comportamento subsequente.
6. **Proteja os metadados da rede.** Siga a configuração oficial da anonymity-network; reconheça leaks documentados de timestamps, sincronização intermitente, padrão de largura de banda e reutilização de streams.<sup>[[10]](#references)</sup>
7. **Mantenha privados os dados de compliance/auditoria.** Divulgue uma view key ou prova de transação somente de forma deliberada, à parte/auditor pretendido, e entenda exatamente o que ela revela.

Estudos históricos de rastreabilidade incluem bugs e eras de seleção de decoys que foram alteradas desde então; não aplique percentuais antigos de sucesso a transações atuais. Da mesma forma, FCMP++ continua sendo trabalho de roadmap no cutoff de pesquisa de setembro de 2026 deste capítulo, não uma proteção implementada.<sup>[[11]](#references)</sup>

## Ethereum e stablecoins

O próprio material de privacidade do Ethereum observa que as ações on-chain são visíveis e que a infraestrutura de wallet/RPC acrescenta exposição de IP e metadados.<sup>[[12]](#references)</sup> Transferências de tokens, approvals, interações com smart contracts, name services e funding de gas podem conectar identidades.

Stablecoins centralizadas acrescentam controle do emissor. Os termos atuais da USDC e da Tether reservam poderes para bloquear/congelar endereços ou ativos e cumprir obrigações legais/processuais.<sup>[[13]](#references)</sup> Podem ser instrumentos de pagamento úteis, mas são escolhas ruins quando o requisito é resistência à censura ou anonimato on-chain.

## Limites de compliance

- As recomendações da FATF são implementadas pela legislação nacional e mudam ao longo do tempo; sua atualização de 2026 enfatiza o licenciamento/registro de VASPs e a implementação da Travel Rule.<sup>[[14]](#references)</sup>
- Nos EUA, a FinCEN distingue uma pessoa que usa convertible virtual currency para seus próprios bens/serviços de uma empresa que a aceita e transmite ou troca; os fatos e regras posteriores são relevantes.<sup>[[15]](#references)</sup>
- O Regulation (EU) 2023/1113 exige informações do originador/beneficiário quando um crypto-asset service provider está envolvido e acrescenta regras de verificação para certas transferências de/para endereços self-hosted.<sup>[[16]](#references)</sup>
- Sanções e obrigações fiscais continuam aplicáveis. Faça screening conforme exigido, recuse partes proibidas e mantenha registros; listas e status legal podem mudar rapidamente.<sup>[[17]](#references)</sup>

Antes de movimentar valores relevantes, realizar atividades transfronteiriças, coordenação com privacy-enhancing ou exchange/transmissão com características empresariais, obtenha orientação profissional atual para as jurisdições relevantes.

Para Bitcoin Silent Payments, Zcash totalmente shielded, GNU Taler, federated Chaumian e-cash e BOLT 12, consulte [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Proteja sua privacidade](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Recursos de privacidade](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Uma proposta simples de PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adoção e privacidade real de implementações descentralizadas de CoinJoin no Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Fundadores da Samourai Wallet se declaram culpados (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protocolo de Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Uma análise empírica da privacidade na Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) e [Especificações técnicas](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Redes](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Explorando a evolução da privacidade do Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacidade no Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Termos da USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Atualização direcionada de 2026 sobre virtual assets e VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Aplicação dos regulamentos da FinCEN a pessoas que administram, trocam ou usam virtual currencies](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Orientação de compliance de sanções para a indústria de virtual currency](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
