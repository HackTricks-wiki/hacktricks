# Red Teaming de Web3 centrado en el valor (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

La matriz MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) recoge los comportamientos de los atacantes que manipulan el valor digital, no solo la infraestructura. Trátala como una **base para el threat modeling**: enumera cada componente que pueda crear, valorar, autorizar o enrutar activos, asigna esos puntos de contacto a las técnicas de AADAPT y, después, ejecuta escenarios de red team que midan si el entorno puede resistir pérdidas económicas irreversibles.

## 1. Inventariar los componentes que contienen valor
Crea un mapa de todo lo que pueda influir en el estado del valor, aunque esté off-chain.<sup>[[1]](#references)</sup>

- **Servicios de firma custodial** (clústeres HSM/KMS, Vault/KMaaS, APIs de firma utilizadas por bots o tareas de back-office). Registra los IDs de las claves, las políticas, las identidades de automatización y los workflows de aprobación.
- **Rutas de administración y upgrade** de los contratos (proxy admins, governance timelocks, claves de pausa de emergencia y registros de parámetros). Incluye quién o qué puede invocarlas y bajo qué quorum o delay.
- **Lógica de protocolos on-chain** que gestione lending, AMMs, vaults, staking, bridges o rails de settlement. Documenta las invariantes que asumen (precios de oracles, ratios de colateral, frecuencia de rebalanceo…).
- **Automatización off-chain** que construya transacciones (bots de market-making, pipelines de CI/CD, cron jobs y funciones serverless). A menudo contienen API keys o service principals capaces de solicitar firmas.
- **Oracles y feeds de datos** (composición del aggregator, quorum, deviation thresholds y frecuencia de actualización). Anota cada fuente upstream de la que dependa la lógica automatizada de riesgo.
- **Bridges y routers cross-chain** (contratos de lock/mint, relayers y tareas de settlement) que conecten chains o stacks custodiales.

Entregable: un diagrama de value-flow que muestre cómo se mueven los activos, quién autoriza el movimiento y qué señales externas influyen en la lógica de negocio.

## 2. Asignar componentes a los comportamientos de AADAPT
Traduce la taxonomía de AADAPT en candidatos de ataque concretos por componente.<sup>[[1]](#references)</sup>

| Componente | Enfoque principal de AADAPT |
| --- | --- |
| Entornos de signing/KMS | Robo de credenciales, bypass de políticas, abuso de signing y toma de control de governance |
| Oracles/feeds | Envenenamiento de entradas, manipulación de la agregación y evasión de deviation thresholds |
| Protocolos on-chain | Manipulación económica mediante flash-loan, ruptura de invariantes y reconfiguración de parámetros |
| Pipelines de automatización | Compromiso de identidades de bots/CI, replay de batches y deployment no autorizado |
| Bridges/routers | Evasión cross-chain, laundering mediante rapid hop y desincronización del settlement |

Este mapeo garantiza que pruebes no solo los contratos, sino también cada identidad o automatización capaz de dirigir indirectamente el valor.

## 3. Priorizar según la viabilidad para el atacante y el impacto empresarial

1. **Debilidades operativas**: credenciales de CI expuestas, roles de IAM con privilegios excesivos, políticas de KMS mal configuradas, cuentas de automatización que puedan solicitar firmas arbitrarias, buckets públicos con configuraciones de bridges, etc.
2. **Debilidades específicas del valor**: parámetros frágiles de oracles, contratos upgradable sin aprobaciones multipartitas, liquidez sensible a flash-loans y acciones de governance que eviten timelocks.

Gestiona la cola como lo haría un adversario: empieza por los footholds operativos que podrían tener éxito hoy y, después, avanza hacia rutas profundas de manipulación de protocolos y de la economía.<sup>[[1]](#references)</sup>

## 4. Ejecutar en entornos controlados y realistas para producción
- **Mainnets forked / testnets aisladas**: replica el bytecode, el storage y la liquidez para que las rutas de flash-loan, las desviaciones de oracles y los flujos de bridges se ejecuten end-to-end sin tocar fondos reales.<sup>[[1]](#references)</sup>
- **Planificación del blast radius**: define circuit breakers, módulos pausables, runbooks de rollback y claves de administración exclusivas para tests antes de detonar un escenario.
- **Coordinación con stakeholders**: notifica a custodios, operadores de oracles, partners de bridges y compliance para que sus equipos de monitoring esperen ese tráfico.
- **Aprobación legal**: documenta el scope, la autorización y las condiciones de parada cuando las simulaciones puedan atravesar rails regulados.

## 5. Telemetría alineada con las técnicas de AADAPT
Instrumenta los streams de telemetría para que cada escenario produzca datos de detección accionables.<sup>[[1]](#references)</sup>

- **Traces a nivel de chain**: grafos completos de llamadas, uso de gas, nonces de transacciones y timestamps de bloques para reconstruir bundles de flash-loan, estructuras similares a reentrancy y saltos entre contratos.
- **Logs de aplicaciones/APIs**: vincula cada tx on-chain con una identidad humana o de automatización (ID de sesión, cliente OAuth, API key, ID del job de CI), junto con las IPs y los métodos de autenticación.
- **Logs de KMS/HSM**: ID de la clave, principal invocador, resultado de la política, dirección de destino y códigos de motivo para cada firma. Establece una baseline de ventanas de cambio y operaciones de alto riesgo.
- **Metadatos de oracles/feeds**: composición de la fuente de datos por actualización, valor reportado, desviación respecto a las medias móviles, thresholds activados y rutas de failover utilizadas.
- **Traces de bridges/swaps**: correlaciona eventos de lock/mint/unlock entre chains mediante correlation IDs, IDs de chain, identidad del relayer y timing de cada hop.
- **Marcadores de anomalías**: métricas derivadas como picos de slippage, ratios anómalos de colateralización, densidad inusual de gas o velocidad cross-chain.

Etiqueta todo con IDs de escenario o IDs de usuarios sintéticos para que los analistas puedan alinear los observables con la técnica de AADAPT que se esté ejercitando.

## 6. Bucle de purple team y métricas de madurez
1. Ejecuta el escenario en el entorno controlado y registra las detecciones (alertas, dashboards y responders notificados).<sup>[[1]](#references)</sup>
2. Asigna cada paso a las técnicas específicas de AADAPT y a los observables producidos en los planos de chain, aplicación, KMS, oracle y bridge.
3. Formula y despliega hipótesis de detección (reglas de threshold, búsquedas de correlación y comprobaciones de invariantes).
4. Repite hasta que el mean time to detect (MTTD) y el mean time to contain (MTTC) cumplan las tolerancias del negocio y los playbooks detengan de forma fiable la pérdida de valor.

Haz seguimiento de la madurez del programa en tres ejes:<sup>[[1]](#references)</sup>
- **Visibilidad**: cada ruta crítica de valor tiene telemetría en cada plano.
- **Cobertura**: proporción de técnicas de AADAPT priorizadas que se han ejercitado end-to-end.
- **Respuesta**: capacidad de pausar contratos, revocar claves o congelar flujos antes de que se produzca una pérdida irreversible.

Hitos habituales: (1) inventario de valor y mapeo de AADAPT completados, (2) primer escenario end-to-end con detecciones implementadas, (3) ciclos trimestrales de purple team que amplíen la cobertura y reduzcan el MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Plantillas de escenarios
Usa estos blueprints repetibles para diseñar simulaciones que se asignen directamente a los comportamientos de AADAPT.<sup>[[1]](#references)</sup>

### Escenario A – Manipulación económica mediante flash-loan
- **Objetivo**: pedir prestado capital temporal dentro de una única transacción para distorsionar los precios o la liquidez de un AMM y activar préstamos, liquidaciones o mints con precios incorrectos antes de devolverlo.
- **Ejecución**:
1. Haz fork de la chain objetivo y abastece los pools con liquidez similar a la de producción.
2. Pide prestado un notional elevado mediante un flash loan.
3. Ejecuta swaps calibrados para atravesar los límites de precio/threshold en los que se basen la lógica de lending, vaults o derivados.
4. Invoca el contrato víctima inmediatamente después de la distorsión (borrow, liquidate, mint) y devuelve el flash loan.
- **Medición**: ¿Se consiguió violar la invariante? ¿Se activaron los monitores de slippage/desviación de precios, los circuit breakers o los hooks de pausa de governance? ¿Cuánto tiempo tardaron los analytics en marcar el patrón anómalo del grafo de gas/llamadas?

### Escenario B – Envenenamiento de oracle/data-feed
- **Objetivo**: determinar si feeds manipulados pueden activar acciones automatizadas destructivas (liquidaciones masivas y settlements incorrectos).
- **Ejecución**:
1. En el fork/testnet, despliega un feed malicioso o ajusta los pesos del aggregator, el quorum o la frecuencia de actualización más allá de la desviación tolerada.
2. Permite que los contratos dependientes consuman los valores envenenados y ejecuten su lógica estándar.
- **Medición**: alertas out-of-band a nivel del feed, activación del oracle de fallback, aplicación de límites min/max y latencia entre el inicio de la anomalía y la respuesta del operador.

### Escenario C – Abuso de credenciales/firma
- **Objetivo**: probar si el compromiso de un único signer o identidad de automatización permite upgrades no autorizados, cambios de parámetros o drains de treasury.
- **Ejecución**:
1. Enumera las identidades con permisos de signing sensibles (operadores, tokens de CI, service accounts que invoquen KMS/HSM y participantes de multisig).
2. Simula el compromiso (reutiliza sus credenciales/claves dentro del scope del laboratorio).
3. Intenta acciones privilegiadas: hacer upgrade de proxies, cambiar parámetros de riesgo, hacer mint/pause de activos o activar propuestas de governance.
- **Medición**: ¿Los logs de KMS/HSM generan alertas de anomalías (hora del día, desviación del destino y ráfaga de operaciones de alto riesgo)? ¿Pueden las políticas o los thresholds de multisig impedir el abuso unilateral? ¿Se aplican throttles/rate limits o aprobaciones adicionales?

### Escenario D – Evasión cross-chain y brechas de traceability
- **Objetivo**: evaluar la capacidad de los defensores para rastrear e interceptar activos rapidly laundered a través de bridges, routers de DEX y privacy hops.
- **Ejecución**:
1. Encadena operaciones de lock/mint a través de bridges habituales, intercala swaps/mixers en cada hop y conserva correlation IDs por hop.
2. Acelera las transferencias para estresar la latencia del monitoring (multi-hop en minutos/bloques).
- **Medición**: tiempo para correlacionar eventos entre la telemetría y los chain analytics comerciales, completitud de la ruta reconstruida, capacidad para identificar choke points donde congelar fondos durante un incidente real y fidelidad de las alertas ante una velocidad/valor cross-chain anómalos.

## References

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
