# Red Teaming de Web3 centrado en el valor (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

The MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) matrix captura comportamientos de atacante que manipulan valor digital en lugar de solo infraestructura. Trátalo como una **columna vertebral de modelado de amenazas**: enumera cada componente que puede mint, price, authorize, o route assets, mapea esos puntos de contacto a técnicas AADAPT, y luego diseña escenarios de red-team que midan si el entorno puede resistir pérdidas económicas irreversibles.

## 1. Inventariar componentes que llevan valor
Construye un mapa de todo lo que puede influir en el estado de valor, incluso si está off-chain.

- **Custodial signing services** (HSM/KMS clusters, Vault/KMaaS, signing APIs usadas por bots o tareas de back-office). Captura key IDs, policies, automation identities y approval workflows.
- **Admin & upgrade paths** para contratos (proxy admins, governance timelocks, emergency pause keys, parameter registries). Incluye quién/qué puede llamarlos y bajo qué quorum o delay.
- **On-chain protocol logic** que maneja lending, AMMs, vaults, staking, bridges, o settlement rails. Documenta las invariantes que asumen (oracle prices, collateral ratios, rebalance cadence…).
- **Off-chain automation** que construye transacciones (market-making bots, CI/CD pipelines, cron jobs, serverless functions). Estos a menudo guardan API keys o service principals que pueden request signatures.
- **Oracles & data feeds** (aggregator composition, quorum, deviation thresholds, update cadence). Anota cada upstream en el que confía la lógica de riesgo automatizada.
- **Bridges and cross-chain routers** (lock/mint contracts, relayers, settlement jobs) que unen chains o stacks custodiales.

Deliverable: un diagrama de flujo de valor que muestre cómo se mueven los assets, quién autoriza el movimiento y qué señales externas influyen en la business logic.

## 2. Mapear componentes a comportamientos AADAPT
Traduce la taxonomía AADAPT en candidatos de ataque concretos por componente.

| Component | Primary AADAPT focus |
| --- | --- |
| Signing/KMS estates | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/feeds | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain protocols | Flash-loan economic manipulation, invariant breaking, parameter reconfiguration |
| Automation pipelines | Compromised bot/CI identities, batch replay, unauthorized deployment |
| Bridges/routers | Cross-chain evasion, rapid hop laundering, settlement desynchronization |

Este mapeo asegura que pruebes no solo los contratos, sino cada identidad/automatización que pueda dirigir el valor indirectamente.

## 3. Priorizar por factibilidad del atacante vs impacto al negocio

1. **Debilidades operativas**: credenciales de CI expuestas, IAM roles con privilegios excesivos, KMS policies mal configuradas, cuentas de automatización que pueden request arbitrary signatures, buckets públicos con configs de bridge, etc.
2. **Debilidades específicas de valor**: parámetros de oracle frágiles, contratos upgradables sin aprobaciones multipartitas, liquidez sensible a flash-loan, acciones de governance que evitan timelocks.

Trabaja la cola como un adversario: empieza con los footholds operativos que podrían triunfar hoy, luego avanza hacia rutas profundas de manipulación protocolaria/económica.

## 4. Ejecutar en entornos controlados y realistas para producción
- **Forked mainnets / isolated testnets**: replica bytecode, storage y liquidity para que flash-loan paths, oracle drifts y bridge flows funcionen end-to-end sin tocar fondos reales.
- **Blast-radius planning**: define circuit breakers, pausable modules, rollback runbooks y admin keys de solo-prueba antes de detonar un escenario.
- **Stakeholder coordination**: notifica a custodios, oracle operators, bridge partners y compliance para que sus equipos de monitoring esperen el tráfico.
- **Legal sign-off**: documenta scope, authorization y stop conditions cuando las simulaciones puedan cruzar rails regulados.

## 5. Telemetría alineada con técnicas AADAPT
Instrumenta streams de telemetry para que cada escenario produzca datos de detección accionables.

- **Chain-level traces**: grafos completos de llamadas, uso de gas, transaction nonces, block timestamps—para reconstruir flash-loan bundles, estructuras tipo reentrancy y saltos cross-contract.
- **Application/API logs**: enlaza cada tx on-chain con una identidad humana o de automatización (session ID, OAuth client, API key, CI job ID) con IPs y métodos de auth.
- **KMS/HSM logs**: key ID, caller principal, policy result, destination address y reason codes para cada signature. Baseline de ventanas de cambio y operaciones de alto riesgo.
- **Oracle/feed metadata**: por-update composición de data sources, valor reportado, desviación respecto a promedios móviles, thresholds disparados y failover paths ejercitados.
- **Bridge/swap traces**: correlaciona eventos de lock/mint/unlock entre chains con correlation IDs, chain IDs, relayer identity y hop timing.
- **Anomaly markers**: métricas derivadas como picos de slippage, ratios de collateralización anormales, densidad de gas inusual o cross-chain velocity.

Marca todo con scenario IDs o synthetic user IDs para que los analistas puedan alinear observables con la técnica AADAPT ejercitada.

## 6. Bucle purple-team y métricas de madurez
1. Ejecuta el escenario en el entorno controlado y captura detecciones (alerts, dashboards, responders paged).
2. Mapea cada paso a las técnicas AADAPT específicas además de los observables producidos en los planos chain/app/KMS/oracle/bridge.
3. Formula y despliega hipótesis de detección (reglas de umbral, búsquedas de correlación, checks de invariantes).
4. Re-ejecuta hasta que mean time to detect (MTTD) y mean time to contain (MTTC) cumplan las tolerancias del negocio y los playbooks detengan de forma confiable la pérdida de valor.

Rastrea la madurez del programa en tres ejes:
- **Visibility**: cada camino crítico de valor tiene telemetry en cada plano.
- **Coverage**: proporción de técnicas AADAPT priorizadas ejercitadas end-to-end.
- **Response**: capacidad para pausar contratos, revocar llaves o congelar flujos antes de una pérdida irreversible.

Hitos típicos: (1) inventario de valor completado + mapeo AADAPT, (2) primer escenario end-to-end con detecciones implementadas, (3) ciclos trimestrales de purple-team ampliando cobertura y reduciendo MTTD/MTTC.

## 7. Plantillas de escenarios
Usa estos blueprints repetibles para diseñar simulaciones que se mapeen directamente a comportamientos AADAPT.

### Escenario A – Flash-loan economic manipulation
- **Objective**: borrow transient capital inside one transaction para distorsionar precios/liquidez de AMM y disparar borrows, liquidations o mints mal tasados antes de repagar.
- **Execution**:
1. Fork the target chain y seed pools con liquidity parecida a producción.
2. Borrow large notional vía flash loan.
3. Realiza swaps calibrados para cruzar price/threshold boundaries en los que confían lending, vault o derivative logic.
4. Invoca el contrato víctima inmediatamente después de la distorsión (borrow, liquidate, mint) y repaga el flash loan.
- **Measurement**: ¿La violación de la invariante tuvo éxito? ¿Se dispararon los monitores de slippage/price-deviation, circuit breakers o governance pause hooks? ¿Cuánto tiempo hasta que analytics marcó el patrón anómalo de gas/call graph?

### Escenario B – Oracle/data-feed poisoning
- **Objective**: determinar si feeds manipulados pueden disparar acciones automatizadas destructivas (mass liquidations, incorrect settlements).
- **Execution**:
1. En el fork/testnet, despliega un feed malicioso o ajusta aggregator weights/quorum/update cadence más allá de la desviación tolerada.
2. Deja que los contratos dependientes consuman los valores envenenados y ejecuten su lógica estándar.
- **Measurement**: Alerts a nivel de feed out-of-band, activación de fallback oracle, enforcement de min/max bounds y latencia entre el inicio de la anomalía y la respuesta del operador.

### Escenario C – Credential/signing abuse
- **Objective**: probar si comprometer un solo signer o automation identity permite upgrades no autorizados, cambios de parámetros o drains del treasury.
- **Execution**:
1. Enumera las identities con derechos de signing sensibles (operators, CI tokens, service accounts que invocan KMS/HSM, multisig participants).
2. Simula compromiso (re-use sus credentials/keys dentro del scope del laboratorio).
3. Intenta acciones privilegiadas: upgrade proxies, change risk parameters, mint/pause assets o trigger governance proposals.
- **Measurement**: ¿Los logs de KMS/HSM levantan alertas de anomalía (time-of-day, destination drift, ráfaga de operaciones de alto riesgo)? ¿Pueden las policies o thresholds de multisig prevenir abuso unilateral? ¿Se aplican throttles/rate limits o approvals adicionales?

### Escenario D – Cross-chain evasion & traceability gaps
- **Objective**: evaluar qué tan bien los defensores pueden trazar e interdictar assets rápidamente lavados a través de bridges, DEX routers y privacy hops.
- **Execution**:
1. Encadena operaciones de lock/mint a través de bridges comunes, entrelaza swaps/mixers en cada hop y mantiene per-hop correlation IDs.
2. Acelera las transferencias para estresar la latencia de monitoring (multi-hop en minutos/blocks).
- **Measurement**: Tiempo para correlacionar eventos a través de la telemetry + analytics comerciales de chain, completitud del path reconstruido, capacidad para identificar choke points para congelar en un incidente real y fidelidad de las alertas para cross-chain velocity/value anormales.

## References

- [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
