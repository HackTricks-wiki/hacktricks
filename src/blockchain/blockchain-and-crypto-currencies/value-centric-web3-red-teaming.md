# Red Teaming Web3 Centrado em Valor (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

O framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) categoriza ações e técnicas adversárias direcionadas a sistemas de ativos digitais.<sup>[[1]](#references)</sup> Trate-o como uma **base para threat modeling**: enumere cada componente que pode criar, precificar, autorizar ou rotear ativos, mapeie esses pontos de contato para técnicas AADAPT e, em seguida, conduza cenários de red team que meçam se o ambiente consegue resistir a perdas econômicas irreversíveis.

## 1. Inventarie os componentes que carregam valor
Crie um mapa de tudo que pode influenciar o estado do valor, mesmo que esteja off-chain.<sup>[[2]](#references)</sup>

- **Serviços de assinatura custodiais** (clusters HSM/KMS, Vault/KMaaS, APIs de assinatura usadas por bots ou jobs de back-office). Registre IDs de chaves, policies, identidades de automação e workflows de aprovação.
- **Caminhos administrativos e de upgrade** dos contratos (admins de proxies, timelocks de governança, chaves de pausa de emergência, registries de parâmetros). Inclua quem/o que pode chamá-los e sob qual quorum ou delay.
- **Lógica de protocolos on-chain** que processa lending, AMMs, vaults, staking, bridges ou rails de settlement. Documente as invariants que eles assumem (preços de oracles, collateral ratios, cadência de rebalanceamento…).
- **Automação off-chain** que cria transações (bots de market-making, pipelines de CI/CD, cron jobs, funções serverless). Eles frequentemente mantêm API keys ou service principals capazes de solicitar assinaturas.
- **Oracles e data feeds** (composição do aggregator, quorum, thresholds de desvio, cadência de atualização). Anote cada upstream utilizado pela lógica automatizada de risco.
- **Bridges e cross-chain routers** (contratos de lock/mint, relayers, jobs de settlement) que conectam chains ou stacks custodiais.

Entregável: um diagrama de fluxo de valor mostrando como os ativos se movimentam, quem autoriza a movimentação e quais sinais externos influenciam a lógica de negócio.

## 2. Mapeie os componentes para comportamentos AADAPT
Traduza a taxonomia AADAPT em candidatos concretos a ataques por componente.<sup>[[2]](#references)</sup>

| Componente | Foco principal do AADAPT |
| --- | --- |
| Estates de signing/KMS | Roubo de credenciais, bypass de policy, abuso de signing, takeover de governança |
| Oracles/feeds | Poisoning de inputs, manipulação de agregação, evasão de deviation thresholds |
| Protocolos on-chain | Manipulação econômica via flash-loan, quebra de invariants, reconfiguração de parâmetros |
| Pipelines de automação | Comprometimento de identidades de bots/CI, replay de batches, deployment não autorizado |
| Bridges/routers | Evasão cross-chain, laundering por hops rápidos, dessincronização de settlement |

Esse mapeamento garante que você teste não apenas os contratos, mas também cada identidade/automação capaz de direcionar valor indiretamente.

## 3. Priorize por viabilidade para o atacante versus impacto no negócio

1. **Fraquezas operacionais**: credenciais de CI expostas, roles de IAM com privilégios excessivos, policies de KMS mal configuradas, contas de automação que podem solicitar assinaturas arbitrárias, buckets públicos com configurações de bridges etc.
2. **Fraquezas específicas de valor**: parâmetros frágeis de oracles, contratos upgradable sem aprovações multipartidárias, liquidez sensível a flash-loans, ações de governança que ignoram timelocks.

Trabalhe na fila como um adversário: comece pelos footholds operacionais que poderiam ter sucesso hoje e, depois, avance para caminhos profundos de manipulação de protocolos/economia.<sup>[[2]](#references)</sup>

## 4. Execute em ambientes controlados e realistas para produção
- **Mainnets forkadas / testnets isoladas**: replique bytecode, storage e liquidez para que caminhos de flash-loan, desvios de oracles e fluxos de bridges sejam executados end-to-end sem tocar em fundos reais.<sup>[[2]](#references)</sup>
- **Planejamento do blast radius**: defina circuit breakers, módulos pausáveis, runbooks de rollback e admin keys exclusivas para testes antes de detonar um cenário.
- **Coordenação com stakeholders**: notifique custodians, operadores de oracles, parceiros de bridges e compliance para que suas equipes de monitoring esperem esse tráfego.
- **Aprovação jurídica**: documente escopo, autorização e condições de parada quando as simulações puderem atravessar rails regulados.

## 5. Telemetria alinhada às técnicas AADAPT
Instrumente os fluxos de telemetria para que cada cenário produza dados de detecção acionáveis.<sup>[[2]](#references)</sup>

- **Traces no nível da chain**: call graphs completos, uso de gas, nonces de transações e timestamps de blocos — para reconstruir bundles de flash-loans, estruturas semelhantes a reentrancy e hops entre contratos.
- **Logs de aplicação/API**: associe cada tx on-chain a uma identidade humana ou de automação (ID de sessão, cliente OAuth, API key, ID do job de CI), incluindo IPs e métodos de autenticação.
- **Logs de KMS/HSM**: ID da chave, principal chamador, resultado da policy, endereço de destino e códigos de motivo para cada assinatura. Estabeleça uma baseline de janelas de mudança e operações de alto risco.
- **Metadados de oracles/feeds**: composição da fonte de dados por atualização, valor reportado, desvio em relação às médias móveis, thresholds acionados e caminhos de failover utilizados.
- **Traces de bridges/swaps**: correlacione eventos de lock/mint/unlock entre chains com correlation IDs, IDs de chains, identidade do relayer e timing de cada hop.
- **Marcadores de anomalia**: métricas derivadas, como picos de slippage, collateralization ratios anormais, densidade incomum de gas ou velocidade cross-chain.

Identifique tudo com IDs de cenários ou IDs de usuários sintéticos para que os analistas possam alinhar os observáveis à técnica AADAPT exercitada.

## 6. Loop de purple team e métricas de maturidade
1. Execute o cenário no ambiente controlado e capture as detecções (alertas, dashboards, responders acionados).<sup>[[2]](#references)</sup>
2. Mapeie cada etapa para as técnicas AADAPT específicas e para os observáveis produzidos nos planos de chain/app/KMS/oracle/bridge.
3. Formule e implemente hipóteses de detecção (regras de threshold, buscas de correlação, verificações de invariants).
4. Execute novamente até que o mean time to detect (MTTD) e o mean time to contain (MTTC) atendam às tolerâncias do negócio e os playbooks interrompam de forma confiável a perda de valor.

Acompanhe a maturidade do programa em três eixos:<sup>[[2]](#references)</sup>
- **Visibilidade**: cada caminho crítico de valor possui telemetria em cada plano.
- **Cobertura**: proporção das técnicas AADAPT priorizadas exercitadas end-to-end.
- **Resposta**: capacidade de pausar contratos, revogar chaves ou congelar fluxos antes de uma perda irreversível.

Marcos típicos: (1) inventário de valor + mapeamento AADAPT concluídos, (2) primeiro cenário end-to-end com detecções implementadas, (3) ciclos trimestrais de purple team ampliando a cobertura e reduzindo o MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Templates de cenários
Use estes blueprints reutilizáveis para criar simulações que mapeiem diretamente para comportamentos AADAPT.<sup>[[2]](#references)</sup>

### Cenário A – Manipulação econômica via flash-loan
- **Objetivo**: tomar capital temporário emprestado dentro de uma única transação para distorcer preços/liquidez de AMMs e acionar empréstimos, liquidações ou mints com preço incorreto antes de pagar o empréstimo.
- **Execução**:
1. Faça um fork da chain-alvo e abasteça os pools com liquidez semelhante à de produção.
2. Tome um valor nocional elevado via flash loan.
3. Execute swaps calibrados para ultrapassar limites de preço/threshold dos quais dependem a lógica de lending, vault ou derivativos.
4. Invoque o contrato vítima imediatamente após a distorção (borrow, liquidate, mint) e pague o flash loan.
- **Medição**: A violação da invariant foi bem-sucedida? Monitors de slippage/desvio de preço, circuit breakers ou hooks de pausa de governança foram acionados? Quanto tempo levou até o analytics sinalizar o padrão anormal de gas/call graph?

### Cenário B – Poisoning de oracle/data feed
- **Objetivo**: determinar se feeds manipulados podem acionar ações automatizadas destrutivas (liquidações em massa, settlements incorretos).
- **Execução**:
1. No fork/testnet, implemente um feed malicioso ou ajuste os pesos/quorum/cadência de atualização do aggregator além do desvio tolerado.
2. Permita que os contratos dependentes consumam os valores envenenados e executem sua lógica padrão.
- **Medição**: Alertas out-of-band no nível do feed, ativação de fallback oracle, aplicação de limites mínimo/máximo e latência entre o início da anomalia e a resposta do operador.

### Cenário C – Abuso de credenciais/assinaturas
- **Objetivo**: testar se o comprometimento de um único signer ou identidade de automação permite upgrades, alterações de parâmetros ou drains de treasury não autorizados.
- **Execução**:
1. Enumere identidades com direitos de signing sensíveis (operadores, tokens de CI, service accounts que invocam KMS/HSM, participantes de multisig).
2. Simule o comprometimento (reutilize suas credenciais/chaves dentro do escopo do lab).
3. Tente ações privilegiadas: fazer upgrade de proxies, alterar parâmetros de risco, fazer mint/pause de ativos ou acionar propostas de governança.
- **Medição**: Os logs de KMS/HSM geram alertas de anomalia (horário, desvio do destino, rajada de operações de alto risco)? As policies ou thresholds de multisig impedem o abuso unilateral? Throttles/rate limits ou aprovações adicionais são aplicados?

### Cenário D – Evasão cross-chain e lacunas de rastreabilidade
- **Objetivo**: avaliar quão bem os defensores conseguem rastrear e interditar ativos rapidamente lavados por bridges, DEX routers e privacy hops.
- **Execução**:
1. Encadeie operações de lock/mint em bridges comuns, intercale swaps/mixers em cada hop e mantenha correlation IDs por hop.
2. Acelere as transferências para pressionar a latência do monitoring (múltiplos hops em minutos/blocos).
- **Medição**: Tempo para correlacionar eventos entre a telemetria e o chain analytics comercial, completude do caminho reconstruído, capacidade de identificar choke points para congelamento em um incidente real e fidelidade dos alertas para velocidade/valor cross-chain anormais.

## References

- [1] [Framework de Cyber Threat AADAPT(TM) para Ativos Digitais (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Framework MITRE AADAPT como Roadmap de Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
