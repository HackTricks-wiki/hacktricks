# Privacidade de criptomoedas

{{#include ../banners/hacktricks-training.md}}

A privacidade de criptomoedas é uma questão de protocolo e operações, não um sinônimo de sigilo ou imunidade. Ledgers públicos, exchanges, servidores de wallet, peers de rede, comerciantes e transações posteriores expõem diferentes partes do grafo.

Comece pelo [Catálogo de técnicas de pagamentos anônimos](anonymous-payment-techniques.md) para consultar o formato de vantagens/desvantagens/procedimento/detecção de cada técnica. Esta página amplia os mecanismos e limites operacionais específicos de criptomoedas.

{% hint style="danger" %}
Este capítulo destina-se à autocustódia legal e à minimização de dados. Não o utilize para lavar valores, evitar sanções/impostos/obrigações de declaração, realizar transações com partes proibidas, induzir um provedor regulado ao erro ou operar um serviço de transmissão sem licença. A tecnologia de privacidade não altera a origem legal nem a propriedade dos fundos.
{% endhint %}

## Modelo de ameaça por camada

| Camada | Observador | Divulgação comum |
|---|---|---|
| Aquisição/off-ramp | Exchange, banco, broker, contraparte P2P | Identidade, conta de financiamento, destino, dispositivo, IP, horário |
| Ledger | Qualquer pessoa executando analytics | Endereços/outputs, valores e horários em chains transparentes; metadados específicos do protocolo em outros locais |
| Backend da wallet | Provedor RPC, explorer, nó remoto | Consultas de endereços, saldos, IP, transmissão de transações |
| Rede | ISP, peers, entrada da rede de anonimato | IP, horário, volume e uso do protocolo |
| Contraparte | Pagador/recebedor | Invoice/endereço, entrega, conversa, conta e horário |
| Endpoint | Malware, backup na cloud, apreensão física | Seed, chaves, rótulos, histórico, screenshots e clipboard |

A autocustódia pode remover um custodiante do caminho de controle, mas não apaga o ledger, o registro de aquisição, os metadados de rede nem as evidências do endpoint.

## Comparação de protocolos

| Método | Propriedade de privacidade útil | Limitações importantes |
|---|---|---|
| Bitcoin on-chain | Autocustódia; endereços novos evitam a reutilização simples de endereços | Grafo público e permanente de transações; heurísticas de valores/horários e gastos |
| Bitcoin PayJoin | O input do recebedor pode quebrar a heurística de propriedade comum dos inputs | Ambas as wallets precisam oferecer suporte; a transação continua pública; o suporte é desigual |
| Bitcoin CoinJoin | Cria ambiguidade entre participantes coordenados | Padrões reconhecíveis, vínculos anteriores/posteriores, consolidação, riscos de políticas/legais/provedores |
| Lightning | Pagamentos roteados por onion não são publicados globalmente como transferências comuns | A abertura/fechamento de canais ocorre on-chain; endpoints, peers, probes ou o custodiante podem inferir dados |
| Monero | Maior confidencialidade on-chain padrão para recebedor, valor e conjunto de remetentes | Vínculos com exchange, nó, horário, endpoint e contraparte permanecem |
| Ethereum/stablecoins | Ampla disponibilidade e interoperabilidade com smart contracts | Estado/ações públicas; metadados de RPC; emissores centralizados podem bloquear/congelar/reportar |

## Bitcoin: baseline de preservação de privacidade

Bitcoin é pseudônimo, não anônimo. Transações confirmadas são públicas e duráveis; reutilização de endereços, propriedade comum de inputs, detecção de change e endereços identificados publicamente podem formar clusters.<sup>[[1]](#references)</sup>

### Fluxo de trabalho

1. **Escolha uma wallet de autocustódia mantida.** Faça o download do projeto oficial, verifique assinaturas/hashes quando oferecidos e aplique atualizações de segurança.
2. **Crie a wallet em um endpoint confiável.** Registre a seed de recuperação offline; nunca a coloque em email, chat, screenshots ou notas comuns na cloud. Teste a recuperação antes de armazenar valores significativos.
3. **Mantenha hot apenas o valor operacional.** Use custódia offline/hardware adequada para valores de longo prazo, com um plano de recuperação que não exponha a seed a um único local frágil.
4. **Gere um endereço/invoice novo de recebimento para cada transação.** Não publique um endereço estático quando for possível usar um servidor de invoices ou uma entrega privada autenticada.
5. **Use seu próprio full node quando possível.** Um explorer/servidor electrum de terceiros pode descobrir os endereços consultados e os metadados de IP. Configure apenas o comportamento de Tor/proxy suportado pela wallet; Tor oculta uma extremidade da rede, não o grafo da blockchain.
6. **Rotule cada UTXO privadamente** com origem, proprietário, finalidade e estado de compliance. Ative o coin control para que contextos de identidade não relacionados não sejam gastos juntos.
7. **Visualize a transação:** inputs selecionados, destino do change, valor, fee, contraparte e se o gasto mescla compartimentos. Evite consolidação desnecessária.
8. **Mantenha os registros legais separadamente e criptografados.** Preserve base de aquisição, invoices, autorizações e informações fiscais/de declaração sem publicar o mapeamento.
9. **Trate gastos posteriores como parte da mesma decisão de privacidade.** Um recebimento bem separado pode ser relinkado quando seu output é gasto junto com fundos identificados.

A documentação de privacidade do Bitcoin Core explica que um full node evita revelar consultas da wallet a servidores de terceiros, mas que a transmissão de transações e o histórico público ainda precisam ser analisados.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin é um pagamento colaborativo no qual o recebedor adiciona um input. Isso derrota a suposição simplista de que todos os inputs pertencem ao remetente. O BIP 78 descreve o protocolo interativo original; o draft BIP 77 define um design assíncrono v2 usando uma mailbox criptografada/OHTTP.<sup>[[3]](#references)</sup>

Uso seguro:

1. Confirme que ambas as wallets mantidas oferecem suporte à mesma versão do PayJoin.
2. Obtenha a invoice compatível com PayJoin por um canal autenticado; proteja-a como qualquer solicitação de pagamento.
3. Verifique o valor e o destino originais e deixe a wallet validar a proposta/PSBT, a contribuição para a fee e as substituições proibidas.
4. Confirme o resumo final da wallet. Não aprove manualmente um output, valor ou fee excessiva inesperados.
5. Se a negociação falhar, entenda se a wallet faz fallback seguro para um pagamento comum ou exige uma nova invoice.
6. Preserve os recibos/registros privados necessários para propriedade, contabilidade e disputas.

PayJoin melhora uma heurística de análise de chains; não oculta o pagamento das partes, da plataforma de aquisição, dos endpoints ou do ledger público.

## CoinJoin: benefícios e limites

CoinJoin coordena vários usuários em uma transação para tornar o mapeamento entre inputs e outputs menos certo. Pesquisas sobre designs históricos específicos do Wasabi e Samourai encontraram transações altamente reconhecíveis e mostraram que o comportamento antes/depois do mix pode reduzir substancialmente o anonimato.<sup>[[4]](#references)</sup> Esse resultado não deve ser generalizado para toda implementação ou versão futura, mas demonstra por que um número de “conjunto de anonimato” não é uma garantia.

Antes de qualquer uso legal:

- verifique a legislação local atual, o status de sanções, a política da exchange/custodiante e as obrigações fiscais/de declaração;
- use software mantido e non-custodial obtido do projeto oficial;
- entenda o modelo do coordenador, as fees, os controles contra denial-of-service e se o serviço atual ainda opera — a zkSNACKs encerrou seu coordenador em 2024, embora outros coordenadores Wasabi possam existir;
- preserve privadamente os registros de origem dos fundos e das transações;
- nunca aceite fundos desconhecidos em nome de outra pessoa nem use um “mixer” custodial que prometa withdrawals impossíveis de rastrear;
- mantenha os outputs separados por origem/contexto e evite consolidação posterior que destrua a ambiguidade pretendida.

Os resultados legais dependem dos fatos e da jurisdição. As declarações de culpa da Samourai em 2025 diziam respeito à operação consciente de um transmissor de dinheiro sem licença que movimentava proceeds criminais; elas não estabelecem que toda transação colaborativa ou todo usuário que busca privacidade seja criminoso.<sup>[[5]](#references)</sup>

## Lightning Network

O roteamento onion Sphinx do Lightning foi projetado para que um hop intermediário conheça seu predecessor e sucessor, em vez da rota completa.<sup>[[6]](#references)</sup> Isso não é anonimato abrangente: o funding/fechamento de canais é público, os nós anunciam a topologia, as contrapartes conhecem os endpoints, o roteamento/probing pode inferir saldos ou partes, e uma wallet custodial vê a atividade da conta do usuário.

Para obter mais privacidade:

1. Prefira uma wallet mantida e non-custodial se a privacidade em relação ao intermediário for importante; planeje primeiro o backup/recuperação dos canais.
2. Use uma invoice ou offer nova para cada pagamento. Verifique se a wallet exata oferece suporte a BOLT 12/route blinding, em vez de presumir que oferece.
3. Evite publicar aliases de nós, dados de contato e endpoints de rede estáveis desnecessários.
4. Conecte-se por uma rede de privacidade compatível quando apropriado, entendendo que padrões de disponibilidade/horário ainda podem ser correlacionados.
5. Não conclua que um pagamento off-chain não deixa registros: remetente, recebedor, peers, watchtowers, provedores de liquidez e serviços de wallet podem reter observações.

Pesquisas publicadas demonstraram inferências de remetente/recebedor e saldo de canais a partir de dados públicos e probing ativo, embora os ataques e as mitigações evoluam.<sup>[[7]](#references)</sup>

## Monero

Monero usa stealth addresses de uso único para outputs, RingCT para ocultar valores e ring signatures para fornecer ambiguidade probabilística do remetente; suas especificações técnicas atuais documentam um ring size de 16 (15 decoys).<sup>[[8]](#references)</sup> Esses são padrões mais fortes de confidencialidade on-chain do que os ledgers transparentes, não uma proteção mágica contra erros de endpoint ou operacionais.

### Fluxo de trabalho legal

1. **Adquira legalmente.** Uma exchange regulada pode conhecer a compra e o withdrawal mesmo quando os detalhes on-chain posteriores são confidenciais. Mantenha registros de origem, base e declaração.
2. **Instale a wallet oficial mantida** e verifique o download de acordo com as instruções do projeto. Faça backup da seed offline e teste a restauração com uma quantia pequena.
3. **Prefira um nó local** para obter o máximo de privacidade nas consultas da wallet. Se isso não for prático, escolha um nó remoto confiável acessível por uma configuração onion/I2P oficialmente suportada. Um nó remoto pode registrar IP, solicitações, horários e IDs de transação; alguns designs lightweight divulgam uma view key.
4. **Use uma subaddress nova por pagador, campanha ou invoice.** Um pagador pode correlacionar o uso repetido da mesma subaddress.<sup>[[9]](#references)</sup>
5. **Rotule os contextos de entrada localmente.** Evite mesclar operacionalmente recebimentos separados quando um pagador informado puder reconhecer o comportamento subsequente.
6. **Proteja os metadados de rede.** Siga a configuração oficial da rede de anonimato; reconheça os leaks documentados de timestamps, sincronização intermitente, formato da largura de banda e reutilização de streams.<sup>[[10]](#references)</sup>
7. **Mantenha os dados de compliance/auditoria privados.** Divulgue uma view key ou prova de transação somente de forma deliberada, ao auditor/parte pretendido, e entenda exatamente o que ela revela.

Estudos históricos de rastreabilidade incluem bugs e períodos de seleção de decoys que mudaram desde então; não aplique percentuais antigos de sucesso a transações atuais. Da mesma forma, FCMP++ continua sendo trabalho de roadmap no fechamento da pesquisa deste capítulo, em setembro de 2026, e não uma proteção implementada.<sup>[[11]](#references)</sup>

## Ethereum e stablecoins

O material de privacidade do próprio Ethereum observa que as ações on-chain são visíveis e que a infraestrutura de wallet/RPC adiciona exposição de IP e metadados.<sup>[[12]](#references)</sup> Transferências de tokens, approvals, interações com smart contracts, name services e funding de gas podem conectar identidades.

Stablecoins centralizadas adicionam controle do emissor. Os termos atuais da USDC e da Tether reservam poderes para bloquear/congelar endereços ou ativos e cumprir obrigações legais/processuais.<sup>[[13]](#references)</sup> Elas podem ser instrumentos de pagamento úteis, mas são escolhas ruins quando o requisito é resistência à censura ou anonimato on-chain.

## Limites de compliance

- As recomendações da FATF são implementadas pela legislação nacional e mudam com o tempo; sua atualização de 2026 enfatiza o licenciamento/registro de VASPs e a implementação da Travel Rule.<sup>[[14]](#references)</sup>
- Nos EUA, a FinCEN distingue uma pessoa que usa moeda virtual conversível para seus próprios bens/serviços de uma empresa que a aceita e transmite ou troca; os fatos e regras posteriores são relevantes.<sup>[[15]](#references)</sup>
- O Regulamento da UE sobre Transferência de Fundos exige informações do originador/beneficiário quando um provedor de serviços de criptoativos está envolvido e adiciona regras de verificação para certas transferências de/para endereços self-hosted.<sup>[[16]](#references)</sup>
- Sanções e obrigações fiscais continuam aplicáveis. Faça screening conforme necessário, recuse partes proibidas e mantenha registros; listas e status legais podem mudar rapidamente.<sup>[[17]](#references)</sup>

Antes de movimentar valores relevantes, realizar atividades transfronteiriças, coordenação com aprimoramento de privacidade ou exchange/transmissão semelhante a uma atividade empresarial, obtenha aconselhamento profissional atual para as jurisdições relevantes.

Para Bitcoin Silent Payments, Zcash totalmente shielded, GNU Taler, e-cash Chaumian federado e BOLT 12, consulte [Protocolos de pagamento com preservação de privacidade](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Proteja sua privacidade](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Recursos de privacidade](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Uma proposta simples de Payjoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adoção e privacidade real de implementações descentralizadas de CoinJoin em Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Fundadores da Samourai Wallet se declaram culpados (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protocolo de roteamento Onion](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Uma análise empírica da privacidade na Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) e [Especificações técnicas](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Redes](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Explorando a evolução da privacidade do Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacidade no Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Termos da USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Atualização direcionada de 2026 sobre ativos virtuais e VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Aplicação dos regulamentos da FinCEN a pessoas que administram, trocam ou usam moedas virtuais](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulamento (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Orientação de compliance de sanções para a indústria de moedas virtuais](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
