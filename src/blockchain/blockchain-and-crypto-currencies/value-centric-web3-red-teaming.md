# Red Teaming Centrado em Valor Web3 (MITRE AADAPT)

O framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) categoriza ações e técnicas adversárias direcionadas a sistemas de ativos digitais.<sup>[[1]](#references)</sup> Trate-o como uma **base de threat modeling**: enumere cada componente que pode emitir, precificar, autorizar ou rotear ativos, mapeie esses pontos de contato para as técnicas do AADAPT e, em seguida, conduza cenários de red team que meçam se o ambiente consegue resistir a perdas econômicas irreversíveis.

## 1. Faça o inventário dos componentes que carregam valor
Crie um mapa de tudo que pode influenciar o estado de valor, mesmo que esteja off-chain.<sup>[[2]](#references)</sup>

- **Serviços de assinatura custodial** (clusters HSM/KMS, Vault/KMaaS, APIs de assinatura usadas por bots ou tarefas de back-office). Registre IDs de chaves, políticas, identidades de automação e workflows de aprovação.
- **Caminhos administrativos e de upgrade** dos contratos (admins de proxies, timelocks de governança, chaves de pausa de emergência, registries de parâmetros). Inclua quem/o que pode chamá-los e sob qual quorum ou atraso.
- **Lógica de protocolo on-chain** que gerencia lending, AMMs, vaults, staking, bridges ou trilhos de settlement. Documente os invariantes que ela pressupõe (preços de oracles, taxas de colateral, cadência de rebalanceamento…).
- **Automação off-chain** que constrói transações (bots de market-making, pipelines de CI/CD, tarefas cron, funções serverless). Frequentemente, eles armazenam API keys ou service principals que podem solicitar assinaturas.
- **Oracles e data feeds** (composição do aggregator, quorum, limites de desvio, cadência de atualização). Registre cada upstream usado pela lógica automatizada de risco.
- **Bridges e cross-chain routers** (contratos de lock/mint, relayers, tarefas de settlement) que conectam chains ou stacks custodiais.

Entregável: um diagrama de fluxo de valor mostrando como os ativos se movem, quem autoriza a movimentação e quais sinais externos influenciam a lógica de negócio.

## 2. Mapeie os componentes para comportamentos do AADAPT
Converta a taxonomia do AADAPT em candidatos concretos a ataques para cada componente.<sup>[[2]](#references)</sup>

| Componente | Foco principal do AADAPT |
| --- | --- |
| Ambientes de signing/KMS | Roubo de credenciais, bypass de políticas, abuso de signing, takeover de governança |
| Oracles/feeds | Input poisoning, manipulação de agregação, evasão de limites de desvio |
| Protocolos on-chain | Manipulação econômica com flash loan, quebra de invariantes, reconfiguração de parâmetros |
| Pipelines de automação | Identidades de bots/CI comprometidas, replay de batches, deployment não autorizado |
| Bridges/routers | Evasão cross-chain, laundering em hops rápidos, dessincronização de settlement |

Esse mapeamento garante que você teste não apenas os contratos, mas também cada identidade/automação que pode direcionar o valor indiretamente.

## 3. Priorize pela viabilidade para o atacante versus impacto no negócio

1. **Fragilidades operacionais**: credenciais de CI expostas, funções IAM com privilégios excessivos, políticas KMS mal configuradas, contas de automação que podem solicitar assinaturas arbitrárias, buckets públicos com configurações de bridges etc.
2. **Fragilidades específicas de valor**: parâmetros frágeis de oracles, contratos upgradable sem aprovações multipartidárias, liquidez sensível a flash loan, ações de governança que ignoram timelocks.

Trabalhe na fila como um adversário: comece pelos footholds operacionais que poderiam ter sucesso hoje e, depois, avance para caminhos profundos de manipulação de protocolo/economia.<sup>[[2]](#references)</sup>

## 4. Execute em ambientes controlados e realistas em relação à produção
- **Mainnets forked / testnets isoladas**: replique bytecode, storage e liquidez para que caminhos de flash loan, desvios de oracles e fluxos de bridges sejam executados de ponta a ponta sem tocar em fundos reais.<sup>[[2]](#references)</sup>
- **Planejamento do blast radius**: defina circuit breakers, módulos pausáveis, runbooks de rollback e chaves admin exclusivas para testes antes de detonar um cenário.
- **Coordenação com stakeholders**: notifique custodians, operadores de oracles, parceiros de bridges e compliance para que suas equipes de monitoramento esperem o tráfego.
- **Aprovação jurídica**: documente escopo, autorização e condições de parada quando as simulações puderem atravessar trilhos regulados.

## 5. Telemetria alinhada às técnicas do AADAPT
Instrumente os fluxos de telemetria para que cada cenário produza dados de detecção acionáveis.<sup>[[2]](#references)</sup>

- **Traces no nível da chain**: grafos completos de chamadas, uso de gas, nonces de transações e timestamps de blocos — para reconstruir bundles de flash loan, estruturas semelhantes a reentrancy e hops entre contratos.
- **Logs de aplicações/APIs**: vincule cada tx on-chain a uma identidade humana ou de automação (ID de sessão, cliente OAuth, API key, ID de job de CI), incluindo IPs e métodos de autenticação.
- **Logs de KMS/HSM**: ID da chave, principal chamador, resultado da política, endereço de destino e códigos de motivo para cada assinatura. Estabeleça uma baseline de janelas de mudança e operações de alto risco.
- **Metadados de oracles/feeds**: composição da fonte de dados por atualização, valor reportado, desvio em relação às médias móveis, limites acionados e caminhos de failover utilizados.
- **Traces de bridges/swaps**: correlacione eventos de lock/mint/unlock entre chains com IDs de correlação, IDs de chains, identidade do relayer e tempo de cada hop.
- **Marcadores de anomalias**: métricas derivadas, como picos de slippage, taxas anormais de colateralização, densidade incomum de gas ou velocidade cross-chain.

Aplique IDs de cenário ou IDs de usuários sintéticos a tudo para que os analistas possam alinhar os observáveis à técnica do AADAPT em teste.

## 6. Loop de purple team e métricas de maturidade
1. Execute o cenário no ambiente controlado e capture as detecções (alertas, dashboards, responders acionados).<sup>[[2]](#references)</sup>
2. Mapeie cada etapa para as técnicas específicas do AADAPT e para os observáveis produzidos nos planos de chain/app/KMS/oracle/bridge.
3. Formule e implemente hipóteses de detecção (regras de limite, buscas de correlação, verificações de invariantes).
4. Execute novamente até que o mean time to detect (MTTD) e o mean time to contain (MTTC) atendam às tolerâncias do negócio e os playbooks interrompam a perda de valor de forma confiável.

Acompanhe a maturidade do programa em três eixos:<sup>[[2]](#references)</sup>
- **Visibilidade**: cada caminho crítico de valor possui telemetria em cada plano.
- **Cobertura**: proporção das técnicas AADAPT priorizadas exercitadas de ponta a ponta.
- **Resposta**: capacidade de pausar contratos, revogar chaves ou congelar fluxos antes de uma perda irreversível.

Marcos típicos: (1) inventário de valor + mapeamento AADAPT concluídos, (2) primeiro cenário de ponta a ponta com detecções implementadas, (3) ciclos trimestrais de purple team ampliando a cobertura e reduzindo o MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Templates de cenários
Use estes blueprints reutilizáveis para criar simulações que mapeiem diretamente para os comportamentos do AADAPT.<sup>[[2]](#references)</sup>

### Cenário A – Manipulação econômica com flash loan
- **Objetivo**: tomar capital temporário emprestado dentro de uma única transação para distorcer preços/liquidez de AMMs e acionar empréstimos, liquidações ou mints com preço incorreto antes de pagar o empréstimo.
- **Execução**:
1. Faça fork da chain-alvo e abasteça os pools com liquidez semelhante à de produção.
2. Tome um valor elevado via flash loan.
3. Execute swaps calibrados para ultrapassar limites de preço/threshold usados pela lógica de lending, vault ou derivativos.
4. Invoque o contrato vítima imediatamente após a distorção (borrow, liquidate, mint) e pague o flash loan.
- **Medição**: A violação do invariante teve sucesso? Monitores de slippage/desvio de preço, circuit breakers ou hooks de pausa de governança foram acionados? Quanto tempo levou até que o analytics sinalizasse o padrão anormal de gas/grafo de chamadas?

### Cenário B – Poisoning de oracle/data feed
- **Objetivo**: determinar se feeds manipulados podem acionar ações automatizadas destrutivas (liquidações em massa, settlements incorretos).
- **Execução**:
1. No fork/testnet, implante um feed malicioso ou ajuste os pesos/quorum/cadência de atualização do aggregator além do desvio tolerado.
2. Permita que os contratos dependentes consumam os valores envenenados e executem sua lógica padrão.
- **Medição**: Alertas out-of-band no nível do feed, ativação do oracle de fallback, aplicação de limites mínimo/máximo e latência entre o início da anomalia e a resposta do operador.

### Cenário C – Abuso de credenciais/assinaturas
- **Objetivo**: testar se o comprometimento de um único signer ou identidade de automação permite upgrades não autorizados, alterações de parâmetros ou drains do treasury.
- **Execução**:
1. Enumere identidades com direitos de signing sensíveis (operadores, tokens de CI, service accounts que invocam KMS/HSM, participantes de multisig).
2. Simule o comprometimento (reutilize suas credenciais/chaves dentro do escopo do lab).
3. Tente ações privilegiadas: fazer upgrade de proxies, alterar parâmetros de risco, fazer mint/pausar ativos ou disparar propostas de governança.
- **Medição**: Os logs de KMS/HSM geram alertas de anomalia (horário, desvio de destino, rajada de operações de alto risco)? As políticas ou os thresholds de multisig impedem o abuso unilateral? Throttles/rate limits ou aprovações adicionais são aplicados?

### Cenário D – Evasão cross-chain e lacunas de rastreabilidade
- **Objetivo**: avaliar a capacidade dos defensores de rastrear e interceptar rapidamente ativos lavados através de bridges, DEX routers e hops de privacidade.
- **Execução**:
1. Encadeie operações de lock/mint em bridges comuns, intercale swaps/mixers em cada hop e mantenha IDs de correlação por hop.
2. Acelere as transferências para pressionar a latência do monitoramento (múltiplos hops em minutos/blocos).
- **Medição**: Tempo para correlacionar eventos entre a telemetria e o analytics comercial de chains, completude do caminho reconstruído, capacidade de identificar choke points para congelamento em um incidente real e fidelidade dos alertas para velocidade/valor cross-chain anormais.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
