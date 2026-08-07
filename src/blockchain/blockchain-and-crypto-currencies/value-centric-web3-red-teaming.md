# Red Teaming Web3 Centrado em Valor (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

A matriz MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) captura comportamentos de atacantes que manipulam valor digital, em vez de apenas infraestrutura. Trate-a como uma **base para modelagem de ameaças**: enumere cada componente capaz de criar, precificar, autorizar ou rotear ativos, mapeie esses pontos de contato para técnicas AADAPT e, em seguida, conduza cenários de red team que meçam se o ambiente consegue resistir a perdas econômicas irreversíveis.

## 1. Faça o inventário dos componentes que contêm valor
Crie um mapa de tudo que pode influenciar o estado do valor, mesmo que esteja off-chain.<sup>[[1]](#references)</sup>

- **Serviços de assinatura custodial** (clusters HSM/KMS, Vault/KMaaS, APIs de assinatura usadas por bots ou jobs de back-office). Registre IDs de chaves, policies, identidades de automação e workflows de aprovação.
- **Caminhos administrativos e de upgrade** dos contratos (admins de proxy, timelocks de governança, chaves de pausa de emergência, registros de parâmetros). Inclua quem/o que pode chamá-los e sob qual quorum ou atraso.
- **Lógica de protocolos on-chain** responsável por lending, AMMs, vaults, staking, bridges ou rails de settlement. Documente as invariantes assumidas (preços de oráculos, índices de collateral, cadência de rebalanceamento…).
- **Automação off-chain** que cria transações (bots de market-making, pipelines de CI/CD, cron jobs, funções serverless). Muitas vezes, eles mantêm API keys ou service principals capazes de solicitar assinaturas.
- **Oráculos e feeds de dados** (composição do aggregator, quorum, thresholds de desvio, cadência de atualização). Observe cada fonte upstream usada pela lógica automatizada de risco.
- **Bridges e cross-chain routers** (contratos de lock/mint, relayers, jobs de settlement) que conectam chains ou stacks custodiais.

Entregável: um diagrama de fluxo de valor mostrando como os ativos se movimentam, quem autoriza a movimentação e quais sinais externos influenciam a lógica de negócio.

## 2. Mapeie os componentes para comportamentos AADAPT
Converta a taxonomia AADAPT em candidatos concretos a ataques para cada componente.<sup>[[1]](#references)</sup>

| Componente | Foco principal do AADAPT |
| --- | --- |
| Ambientes de signing/KMS | Roubo de credenciais, bypass de policy, abuso de signing, takeover de governança |
| Oráculos/feeds | Input poisoning, manipulação de agregação, evasão de deviation thresholds |
| Protocolos on-chain | Manipulação econômica com flash loans, quebra de invariantes, reconfiguração de parâmetros |
| Pipelines de automação | Identidades de bots/CI comprometidas, replay de batches, deployment não autorizado |
| Bridges/routers | Evasão cross-chain, laundering por hops rápidos, dessincronização de settlement |

Esse mapeamento garante que você teste não apenas os contratos, mas também todas as identidades/automações que podem direcionar o valor indiretamente.

## 3. Priorize pela viabilidade para o atacante versus o impacto no negócio

1. **Fraquezas operacionais**: credenciais de CI expostas, roles de IAM com privilégios excessivos, policies de KMS mal configuradas, contas de automação que podem solicitar assinaturas arbitrárias, buckets públicos com configurações de bridges etc.
2. **Fraquezas específicas de valor**: parâmetros frágeis de oráculos, contratos upgradable sem aprovações multipartidárias, liquidez sensível a flash loans, ações de governança que ignoram timelocks.

Trabalhe na fila como um adversário: comece pelos footholds operacionais que poderiam ter sucesso hoje e, depois, avance para caminhos profundos de manipulação de protocolos/economia.<sup>[[1]](#references)</sup>

## 4. Execute em ambientes controlados e realistas em relação à produção
- **Mainnets forkeadas / testnets isoladas**: replique bytecode, storage e liquidez para que caminhos de flash loans, desvios de oráculos e fluxos de bridges sejam executados de ponta a ponta sem tocar em fundos reais.<sup>[[1]](#references)</sup>
- **Planejamento do blast radius**: defina circuit breakers, módulos pausáveis, runbooks de rollback e chaves administrativas exclusivas para testes antes de detonar um cenário.
- **Coordenação com stakeholders**: notifique custodians, operadores de oráculos, parceiros de bridges e compliance para que suas equipes de monitoramento esperem esse tráfego.
- **Aprovação jurídica**: documente o escopo, a autorização e as condições de parada quando as simulações puderem atravessar rails regulados.

## 5. Telemetria alinhada às técnicas AADAPT
Instrumente os fluxos de telemetria para que cada cenário produza dados de detecção acionáveis.<sup>[[1]](#references)</sup>

- **Traces no nível da chain**: call graphs completos, uso de gas, nonces de transações e timestamps de blocos — para reconstruir bundles de flash loans, estruturas semelhantes a reentrancy e hops entre contratos.
- **Logs de aplicação/API**: associe cada tx on-chain a uma identidade humana ou de automação (session ID, OAuth client, API key, CI job ID), incluindo IPs e métodos de autenticação.
- **Logs de KMS/HSM**: ID da chave, principal chamador, resultado da policy, endereço de destino e códigos de motivo para cada assinatura. Crie uma baseline de janelas de mudança e operações de alto risco.
- **Metadados de oráculos/feeds**: composição da fonte de dados por atualização, valor reportado, desvio em relação às médias móveis, thresholds acionados e caminhos de failover usados.
- **Traces de bridges/swaps**: correlacione eventos de lock/mint/unlock entre chains com correlation IDs, IDs de chains, identidade do relayer e timing dos hops.
- **Marcadores de anomalia**: métricas derivadas, como picos de slippage, índices anormais de collateralization, densidade incomum de gas ou velocidade cross-chain.

Marque tudo com IDs de cenário ou IDs de usuários sintéticos para que os analistas possam alinhar os observáveis à técnica AADAPT exercitada.

## 6. Ciclo de purple team e métricas de maturidade
1. Execute o cenário no ambiente controlado e capture as detecções (alerts, dashboards, responders notificados).<sup>[[1]](#references)</sup>
2. Mapeie cada etapa para as técnicas AADAPT específicas e para os observáveis produzidos nos planos de chain/app/KMS/oracle/bridge.
3. Formule e implemente hipóteses de detecção (regras de threshold, buscas de correlação, verificações de invariantes).
4. Reexecute até que o mean time to detect (MTTD) e o mean time to contain (MTTC) atendam às tolerâncias do negócio e os playbooks interrompam a perda de valor de forma confiável.

Acompanhe a maturidade do programa em três eixos:<sup>[[1]](#references)</sup>
- **Visibilidade**: cada caminho crítico de valor possui telemetria em cada plano.
- **Cobertura**: proporção das técnicas AADAPT priorizadas exercitadas de ponta a ponta.
- **Resposta**: capacidade de pausar contratos, revogar chaves ou congelar fluxos antes de uma perda irreversível.

Marcos típicos: (1) inventário de valor + mapeamento AADAPT concluídos, (2) primeiro cenário de ponta a ponta com detecções implementadas, (3) ciclos trimestrais de purple team expandindo a cobertura e reduzindo o MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Templates de cenários
Use estes blueprints repetíveis para criar simulações diretamente mapeadas para comportamentos AADAPT.<sup>[[1]](#references)</sup>

### Cenário A – Manipulação econômica com flash loan
- **Objetivo**: tomar capital temporário emprestado dentro de uma transação para distorcer preços/liquidez de AMMs e acionar empréstimos, liquidações ou mints com preço incorreto antes de quitar o empréstimo.
- **Execução**:
1. Faça o fork da chain-alvo e abasteça os pools com liquidez semelhante à de produção.
2. Tome um valor elevado por meio de flash loan.
3. Realize swaps calibrados para ultrapassar limites de preço/threshold usados pela lógica de lending, vault ou derivativos.
4. Invoque o contrato vítima imediatamente após a distorção (borrow, liquidate, mint) e quite o flash loan.
- **Medição**: A violação da invariante foi bem-sucedida? Monitores de slippage/desvio de preço, circuit breakers ou hooks de pausa de governança foram acionados? Quanto tempo levou até o analytics sinalizar o padrão anormal de gas/call graph?

### Cenário B – Poisoning de oracle/data feed
- **Objetivo**: determinar se feeds manipulados podem acionar ações automatizadas destrutivas (liquidações em massa, settlements incorretos).
- **Execução**:
1. No fork/testnet, faça deploy de um feed malicioso ou ajuste os pesos do aggregator/quorum/cadência de atualização para além do desvio tolerado.
2. Permita que os contratos dependentes consumam os valores poisoned e executem sua lógica padrão.
- **Medição**: alerts out-of-band no nível do feed, ativação do fallback oracle, aplicação de limites mínimo/máximo e latência entre o início da anomalia e a resposta do operador.

### Cenário C – Abuso de credenciais/assinaturas
- **Objetivo**: testar se o comprometimento de um único signer ou identidade de automação permite upgrades não autorizados, alterações de parâmetros ou drains de treasury.
- **Execução**:
1. Enumere as identidades com direitos de signing sensíveis (operadores, tokens de CI, service accounts que invocam KMS/HSM, participantes de multisig).
2. Simule o comprometimento (reutilize suas credenciais/chaves dentro do escopo do lab).
3. Tente ações privilegiadas: fazer upgrade de proxies, alterar parâmetros de risco, fazer mint/pausar ativos ou disparar propostas de governança.
- **Medição**: Os logs de KMS/HSM geram alerts de anomalia (horário, alteração de destino, rajada de operações de alto risco)? As policies ou thresholds de multisig impedem o abuso unilateral? Throttles/rate limits ou aprovações adicionais são aplicados?

### Cenário D – Evasão cross-chain e lacunas de rastreabilidade
- **Objetivo**: avaliar a capacidade dos defensores de rastrear e interceptar rapidamente ativos lavados por meio de bridges, DEX routers e privacy hops.
- **Execução**:
1. Encadeie operações de lock/mint em bridges comuns, intercale swaps/mixers em cada hop e mantenha correlation IDs por hop.
2. Acelere as transferências para estressar a latência do monitoramento (múltiplos hops em minutos/blocos).
- **Medição**: Tempo para correlacionar eventos entre a telemetria e o commercial chain analytics, completude do caminho reconstruído, capacidade de identificar choke points para congelamento em um incidente real e fidelidade dos alerts para velocidade/valor cross-chain anormais.

## Referências

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
