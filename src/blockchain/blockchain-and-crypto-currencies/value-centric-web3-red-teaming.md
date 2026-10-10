# Red Teaming de Web3 Centrado em Valor (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

O framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) categoriza ações e técnicas adversariais que têm como alvo sistemas de ativos digitais.<sup>[[1]](#references)</sup> Trate-o como uma **estrutura central para modelagem de ameaças**: enumere todos os componentes capazes de emitir, precificar, autorizar ou encaminhar ativos, mapeie esses pontos de contato para as técnicas do AADAPT e, em seguida, crie cenários de red team que avaliem se o ambiente consegue resistir a perdas econômicas irreversíveis.

## 1. Inventariar componentes que movimentam valor
Crie um mapa de tudo o que pode influenciar o estado do valor, mesmo que esteja off-chain.<sup>[[2]](#references)</sup>

- **Serviços de assinatura custodial** (clusters HSM/KMS, Vault/KMaaS, APIs de assinatura usadas por bots ou tarefas de back-office). Registre IDs de chave, políticas, identidades de automação e fluxos de aprovação.
- **Caminhos de administração e atualização** de contratos (administradores de proxy, timelocks de governança, chaves de pausa de emergência, registros de parâmetros). Inclua quem/o que pode invocá-los e sob qual quórum ou atraso.
- **Lógica de protocolo on-chain** que lida com empréstimos, AMMs, vaults, staking, bridges ou rails de liquidação. Documente as invariantes presumidas por esses componentes (preços de oráculos, índices de colateralização, frequência de rebalanceamento…).
- **Automação off-chain** que cria transações (bots de market-making, pipelines de CI/CD, cron jobs, funções serverless). Esses componentes costumam ter API keys ou service principals capazes de solicitar assinaturas.
- **Oráculos e feeds de dados** (composição de agregadores, quórum, limites de desvio, frequência de atualização). Registre todas as fontes upstream das quais depende a lógica automatizada de risco.
- **Bridges e roteadores cross-chain** (contratos de lock/mint, relayers, tarefas de liquidação) que conectam chains ou sistemas custodiais.

Entregável: um diagrama de fluxo de valor mostrando como os ativos se movimentam, quem autoriza a movimentação e quais sinais externos influenciam a lógica de negócios.

## 2. Mapear componentes para comportamentos do AADAPT
Traduza a taxonomia do AADAPT em possíveis ataques concretos para cada componente.<sup>[[2]](#references)</sup>

| Componente | Foco principal do AADAPT |
| --- | --- |
| Ambientes de assinatura/KMS | Roubo de credenciais, bypass de políticas, abuso de assinatura, tomada de controle da governança |
| Oráculos/feeds | Envenenamento de dados de entrada, manipulação de agregação, evasão de limites de desvio |
| Protocolos on-chain | Manipulação econômica com flash loan, quebra de invariantes, reconfiguração de parâmetros |
| Pipelines de automação | Comprometimento de identidades de bots/CI, replay de lotes, implantação não autorizada |
| Bridges/roteadores | Evasão cross-chain, lavagem por saltos rápidos, dessincronização da liquidação |

Esse mapeamento garante que você teste não apenas os contratos, mas também todas as identidades/automações que podem direcionar valor indiretamente.

## 3. Priorizar de acordo com a viabilidade para o atacante e o impacto nos negócios

1. **Fragilidades operacionais**: credenciais de CI expostas, funções IAM com privilégios excessivos, políticas KMS mal configuradas, contas de automação capazes de solicitar assinaturas arbitrárias, buckets públicos com configurações de bridges etc.
2. **Fragilidades específicas de valor**: parâmetros frágeis de oráculos, contratos atualizáveis sem aprovações multipartidárias, liquidez vulnerável a flash loan, ações de governança que contornam timelocks.

Trabalhe a fila como um adversário: comece pelos pontos de apoio operacionais que poderiam ser explorados hoje e, em seguida, avance para caminhos profundos de manipulação de protocolo/econômica.<sup>[[2]](#references)</sup>

## 4. Executar em ambientes controlados e realistas em relação à produção
- **Mainnets forkadas/testnets isoladas**: replique bytecode, storage e liquidez para que os caminhos de flash loan, desvios de oráculo e fluxos de bridge possam ser executados de ponta a ponta sem tocar em fundos reais.<sup>[[2]](#references)</sup>
- **Planejamento do raio de impacto**: defina circuit breakers, módulos pausáveis, runbooks de rollback e chaves administrativas exclusivas para testes antes de detonar um cenário.
- **Coordenação com stakeholders**: notifique custodians, operadores de oráculos, parceiros de bridges e compliance para que suas equipes de monitoramento esperem esse tráfego.
- **Aprovação jurídica**: documente o escopo, a autorização e as condições de interrupção quando as simulações puderem atravessar rails regulados.

## 5. Telemetria alinhada às técnicas do AADAPT
Instrumente os fluxos de telemetria para que cada cenário gere dados de detecção acionáveis.<sup>[[2]](#references)</sup>

- **Rastros no nível da chain**: grafos completos de chamadas, uso de gas, nonces de transação, timestamps de blocos — para reconstruir bundles de flash loan, estruturas semelhantes a reentrancy e saltos entre contratos.
- **Logs de aplicação/API**: associe cada tx on-chain a uma identidade humana ou de automação (ID de sessão, cliente OAuth, API key, ID de tarefa de CI), incluindo IPs e métodos de autenticação.
- **Logs de KMS/HSM**: ID da chave, principal chamador, resultado da política, endereço de destino e códigos de motivo para cada assinatura. Estabeleça uma baseline para janelas de mudança e operações de alto risco.
- **Metadados de oráculos/feeds**: composição das fontes de dados por atualização, valor informado, desvio em relação às médias móveis, limites acionados e caminhos de failover usados.
- **Rastros de bridge/swap**: correlacione eventos de lock/mint/unlock entre chains usando IDs de correlação, IDs de chain, identidade do relayer e tempo entre saltos.
- **Marcadores de anomalia**: métricas derivadas, como picos de slippage, índices de colateralização anormais, densidade incomum de gas ou velocidade cross-chain.

Marque tudo com IDs de cenário ou IDs de usuário sintéticos para que os analistas possam alinhar os observáveis à técnica do AADAPT em teste.

## 6. Ciclo de purple team e métricas de maturidade
1. Execute o cenário no ambiente controlado e capture as detecções (alertas, dashboards, notificações enviadas aos responsáveis).<sup>[[2]](#references)</sup>
2. Mapeie cada etapa para as técnicas específicas do AADAPT e para os observáveis produzidos nas camadas de chain/app/KMS/oráculo/bridge.
3. Formule e implemente hipóteses de detecção (regras de limite, buscas de correlação, verificações de invariantes).
4. Repita até que o tempo médio de detecção (MTTD) e o tempo médio de contenção (MTTC) atendam às tolerâncias do negócio e os playbooks interrompam a perda de valor de forma confiável.

Acompanhe a maturidade do programa em três eixos:<sup>[[2]](#references)</sup>
- **Visibilidade**: todo caminho crítico de valor tem telemetria em cada camada.
- **Cobertura**: proporção das técnicas prioritárias do AADAPT exercitadas de ponta a ponta.
- **Resposta**: capacidade de pausar contratos, revogar chaves ou congelar fluxos antes de uma perda irreversível.

Marcos típicos: (1) inventário de valor e mapeamento AADAPT concluídos, (2) primeiro cenário de ponta a ponta com detecções implementadas, (3) ciclos trimestrais de purple team que ampliam a cobertura e reduzem o MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Modelos de cenário
Use estes modelos reutilizáveis para criar simulações que correspondam diretamente aos comportamentos do AADAPT.<sup>[[2]](#references)</sup>

### Cenário A – Manipulação econômica com flash loan
- **Objetivo**: tomar capital emprestado temporariamente dentro de uma única transação para distorcer preços/liquidez de AMM e acionar empréstimos, liquidações ou emissões a preços incorretos antes de pagar o empréstimo.
- **Execução**:
  1. Faça um fork da chain alvo e abasteça os pools com liquidez semelhante à de produção.
  2. Tome emprestado um valor nominal elevado via flash loan.
  3. Faça swaps calibrados para ultrapassar limites de preço/limiares dos quais dependam a lógica de empréstimo, vault ou derivativos.
  4. Invoque o contrato vítima imediatamente após a distorção (empréstimo, liquidação, emissão) e pague o flash loan.
- **Medição**: A violação da invariante foi bem-sucedida? Os monitores de slippage/desvio de preço, circuit breakers ou mecanismos de pausa de governança foram acionados? Quanto tempo levou até a análise sinalizar o padrão anormal de gas/grafo de chamadas?

### Cenário B – Envenenamento de oráculo/feed de dados
- **Objetivo**: determinar se feeds manipulados podem acionar ações automatizadas destrutivas (liquidações em massa, liquidações incorretas).
- **Execução**:
  1. No fork/testnet, implante um feed malicioso ou altere os pesos do agregador/quórum/frequência de atualização para além do desvio tolerado.
  2. Permita que os contratos dependentes consumam os valores envenenados e executem sua lógica padrão.
- **Medição**: alertas de feed fora da faixa, ativação de oráculo de fallback, aplicação de limites mínimo/máximo e latência entre o início da anomalia e a resposta do operador.

### Cenário C – Abuso de credenciais/assinatura
- **Objetivo**: testar se o comprometimento de um único signatário ou identidade de automação permite atualizações, alterações de parâmetros ou drenagem do tesouro sem autorização.
- **Execução**:
  1. Enumere identidades com direitos de assinatura sensíveis (operadores, tokens de CI, contas de serviço que invocam KMS/HSM, participantes de multisig).
  2. Simule o comprometimento (reutilize as credenciais/chaves dentro do escopo do laboratório).
  3. Tente ações privilegiadas: atualizar proxies, alterar parâmetros de risco, emitir/pausar ativos ou acionar propostas de governança.
- **Medição**: Os logs de KMS/HSM geram alertas de anomalia (horário, mudança de destino, sequência de operações de alto risco)? As políticas ou os limiares de multisig impedem o abuso unilateral? Há throttles/limites de taxa ou aprovações adicionais em vigor?

### Cenário D – Evasão cross-chain e lacunas de rastreabilidade
- **Objetivo**: avaliar a capacidade dos defensores de rastrear e interceptar ativos rapidamente lavados por bridges, roteadores DEX e saltos de privacidade.
- **Execução**:
  1. Encadeie operações de lock/mint por bridges comuns, intercale swaps/mixers em cada salto e mantenha IDs de correlação por salto.
  2. Acelere as transferências para testar a latência do monitoramento (vários saltos em minutos/blocos).
- **Medição**: Tempo para correlacionar eventos entre a telemetria e as ferramentas comerciais de análise de chain, completude do caminho reconstruído, capacidade de identificar pontos de estrangulamento para congelamento em um incidente real e precisão dos alertas para velocidade/valor cross-chain anormais.

## References

- [1] [AADAPT(TM) Cyber Threat Framework for Digital Assets (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Framework AADAPT da MITRE como roteiro de Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
