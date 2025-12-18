# Red Teaming Web3 Centrado em Valor (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

A matriz MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) captura comportamentos de atacantes que manipulam valor digital em vez de apenas infraestrutura. Trate-a como uma **coluna vertebral de threat-modeling**: enumere todos os componentes que podem mintar, precificar, autorizar ou roteirizar ativos, mapeie esses pontos de contato para técnicas AADAPT e então conduza cenários de red-team que meçam se o ambiente consegue resistir a perdas econômicas irreversíveis.

## 1. Inventariar componentes portadores de valor
Construa um mapa de tudo que pode influenciar o estado de valor, mesmo que esteja off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs used by bots or back-office jobs). Capture IDs de chaves, políticas, identidades de automação e workflows de aprovação.
- **Caminhos de administração & upgrade** para contratos (proxy admins, governance timelocks, emergency pause keys, parameter registries). Inclua quem/o que pode chamá-los e sob qual quórum ou delay.
- **On-chain protocol logic** tratando lending, AMMs, vaults, staking, bridges, ou settlement rails. Documente as invariantes assumidas (oracle prices, collateral ratios, rebalance cadence…).
- **Automação off-chain** que monta transações (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Estes frequentemente detêm API keys ou service principals que podem solicitar assinaturas.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Anote cada upstream em que a lógica automatizada de risco confia.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) que conectam chains ou stacks custodiais.

Entregável: um diagrama de fluxo de valor mostrando como os ativos se movem, quem autoriza o movimento e quais sinais externos influenciam a lógica de negócio.

## 2. Mapear componentes para comportamentos AADAPT
Traduza a taxonomia AADAPT em candidatos de ataque concretos por componente.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Esse mapeamento garante que você teste não só os contratos, mas toda identidade/automação que pode indiretamente direcionar valor.

## 3. Priorizar por viabilidade do atacante vs. impacto no negócio

1. **Fraquezas operacionais**: credenciais CI expostas, IAM roles com privilégios excessivos, políticas KMS mal configuradas, contas de automação que podem solicitar assinaturas arbitrárias, buckets públicos com configs de bridge, etc.
2. **Fraquezas específicas de valor**: parâmetros de oracle frágeis, contratos upgradables sem aprovações multipartes, liquidez sensível a flash-loan, ações de governance que contornam timelocks.

Trate a fila como um adversário: comece pelas brechas operacionais que poderiam funcionar hoje e então avance para caminhos profundos de manipulação protocolar/econômica.

## 4. Executar em ambientes controlados e realistas para produção
- **Forked mainnets / isolated testnets**: replique bytecode, storage e liquidez para que caminhos de flash-loan, drifts de oracle e fluxos de bridge rodem end-to-end sem tocar fundos reais.
- **Planejamento de blast-radius**: defina circuit breakers, módulos pausáveis, runbooks de rollback e chaves admin apenas para testes antes de detonar um cenário.
- **Coordenação com stakeholders**: notifique custodians, oracle operators, bridge partners e compliance para que suas equipes de monitoramento esperem o tráfego.
- **Assinatura legal**: documente escopo, autorização e condições de parada quando simulações puderem cruzar trilhas reguladas.

## 5. Telemetria alinhada com técnicas AADAPT
Instrumente streams de telemetria para que cada cenário produza dados acionáveis de detecção.

- **Chain-level traces**: grafos completos de chamada, uso de gas, nonces de transação, timestamps de bloco — para reconstruir flash-loan bundles, estruturas tipo reentrancy e saltos cross-contract.
- **Application/API logs**: vincule cada tx on-chain a uma identidade humana ou de automação (session ID, OAuth client, API key, CI job ID) com IPs e métodos de autenticação.
- **KMS/HSM logs**: key ID, caller principal, resultado de política, destination address e reason codes para cada assinatura. Baseie janelas de mudança e operações de alto risco.
- **Oracle/feed metadata**: por-update composição de fontes, valor reportado, desvio de médias móveis, thresholds disparados e caminhos de failover exercitados.
- **Bridge/swap traces**: correlacione eventos lock/mint/unlock entre chains com correlation IDs, chain IDs, identidade do relayer e timing dos hops.
- **Anomaly markers**: métricas derivadas como picos de slippage, razões de collateralização anormais, densidade de gas incomum ou cross-chain velocity.

Marque tudo com scenario IDs ou synthetic user IDs para que os analistas alinhem observáveis com a técnica AADAPT sendo exercitada.

## 6. Loop purple-team & métricas de maturidade
1. Rode o cenário no ambiente controlado e capture detecções (alerts, dashboards, responders acionados).
2. Mapeie cada passo para as técnicas AADAPT específicas além dos observáveis produzidos nas camadas chain/app/KMS/oracle/bridge.
3. Formule e implemente hipóteses de detecção (regras de threshold, correlation searches, checagens de invariantes).
4. Re-rode até que mean time to detect (MTTD) e mean time to contain (MTTC) atendam às tolerâncias do negócio e playbooks interrompam de forma confiável a perda de valor.

Acompanhe a maturidade do programa em três eixos:
- **Visibility**: todo caminho crítico de valor tem telemetria em cada plano.
- **Coverage**: proporção das técnicas AADAPT priorizadas exercitadas end-to-end.
- **Response**: capacidade de pausar contratos, revogar chaves ou congelar fluxos antes de perda irreversível.

Marcos típicos: (1) inventário de valor completo + mapeamento AADAPT, (2) primeiro cenário end-to-end com detecções implementadas, (3) ciclos purple-team trimestrais expandindo cobertura e reduzindo MTTD/MTTC.

## 7. Templates de cenário
Use esses blueprints repetíveis para desenhar simulações que mapeiam diretamente aos comportamentos AADAPT.

### Scenario A – Flash-loan economic manipulation
- **Objective**: borrow transient capital inside one transaction to distort AMM prices/liquidity and trigger mispriced borrows, liquidations, or mints before repaying.
- **Execution**:
1. Fork the target chain and seed pools with production-like liquidity.
2. Borrow large notional via flash loan.
3. Perform calibrated swaps to cross price/threshold boundaries relied on by lending, vault, or derivative logic.
4. Invoke the victim contract immediately after the distortion (borrow, liquidate, mint) and repay the flash loan.
- **Measurement**: Did the invariant violation succeed? Were slippage/price-deviation monitors, circuit breakers, or governance pause hooks triggered? How long until analytics flagged the abnormal gas/call graph pattern?

### Scenario B – Oracle/data-feed poisoning
- **Objective**: determine whether manipulated feeds can trigger destructive automated actions (mass liquidations, incorrect settlements).
- **Execution**:
1. In the fork/testnet, deploy a malicious feed or adjust aggregator weights/quorum/update cadence beyond tolerated deviation.
2. Let dependent contracts consume the poisoned values and execute their standard logic.
- **Measurement**: Feed-level out-of-band alerts, fallback oracle activation, min/max bound enforcement, and latency between anomaly onset and operator response.

### Scenario C – Credential/signing abuse
- **Objective**: test whether compromising a single signer or automation identity enables unauthorized upgrades, parameter changes, or treasury drains.
- **Execution**:
1. Enumerate identities with sensitive signing rights (operators, CI tokens, service accounts invoking KMS/HSM, multisig participants).
2. Simulate compromise (re-use their credentials/keys within the lab scope).
3. Attempt privileged actions: upgrade proxies, change risk parameters, mint/pause assets, or trigger governance proposals.
- **Measurement**: Do KMS/HSM logs raise anomaly alerts (time-of-day, destination drift, burst of high-risk operations)? Can policies or multisig thresholds prevent unilateral abuse? Are throttles/rate limits or additional approvals enforced?

### Scenario D – Cross-chain evasion & traceability gaps
- **Objective**: evaluate how well defenders can trace and interdict assets rapidly laundered across bridges, DEX routers, and privacy hops.
- **Execution**:
1. Chain together lock/mint operations across common bridges, interleave swaps/mixers on each hop, and maintain per-hop correlation IDs.
2. Accelerate transfers to stress monitoring latency (multi-hop within minutes/blocks).
- **Measurement**: Time to correlate events across telemetry + commercial chain analytics, completeness of the reconstructed path, ability to identify choke points for freezing in a real incident, and alert fidelity for abnormal cross-chain velocity/value.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
