# Red Teaming centrado en el valor (MITRE AADAPT)

El framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) categoriza las acciones y técnicas adversarias dirigidas contra sistemas de activos digitales.<sup>[[1]](#references)</sup> Trátalo como una **base para el threat modeling**: enumera cada componente que pueda acuñar, valorar, autorizar o enrutar activos, asigna esos puntos de interacción a técnicas de AADAPT y, después, diseña escenarios de red team que midan si el entorno puede resistir pérdidas económicas irreversibles.

## 1. Inventariar los componentes que contienen valor
Crea un mapa de todo lo que pueda influir en el estado del valor, aunque esté off-chain.<sup>[[2]](#references)</sup>

- **Servicios de firma custodiales** (clusters HSM/KMS, Vault/KMaaS, APIs de firma usadas por bots o trabajos de back-office). Registra los IDs de clave, las policies, las identidades de automatización y los workflows de aprobación.
- **Rutas de administración y upgrade** de los contratos (proxy admins, governance timelocks, emergency pause keys, registros de parámetros). Incluye quién o qué puede llamarlas y bajo qué quorum o retraso.
- **Lógica de protocolos on-chain** que gestione lending, AMMs, vaults, staking, bridges o rails de settlement. Documenta las invariantes que asumen (precios de oracle, ratios de colateral, cadencia de rebalanceo…).
- **Automatización off-chain** que construye transacciones (bots de market-making, pipelines de CI/CD, trabajos cron, funciones serverless). A menudo contienen API keys o service principals que pueden solicitar firmas.
- **Oracles y data feeds** (composición del aggregator, quorum, umbrales de desviación, cadencia de actualización). Registra cada fuente upstream de la que dependa la lógica automatizada de riesgo.
- **Bridges y routers cross-chain** (contratos de lock/mint, relayers, trabajos de settlement) que conecten chains o stacks custodiales.

Entregable: un diagrama de value-flow que muestre cómo se mueven los activos, quién autoriza el movimiento y qué señales externas influyen en la lógica de negocio.

## 2. Mapear los componentes a comportamientos de AADAPT
Traduce la taxonomía de AADAPT en candidatos de ataque concretos para cada componente.<sup>[[2]](#references)</sup>

| Componente | Enfoque principal de AADAPT |
| --- | --- |
| Entornos de signing/KMS | Robo de credenciales, bypass de policies, signing-abuse, takeover de governance |
| Oracles/feeds | Input poisoning, manipulación de la agregación, evasión de umbrales de desviación |
| Protocolos on-chain | Manipulación económica mediante flash loans, ruptura de invariantes, reconfiguración de parámetros |
| Pipelines de automatización | Compromiso de identidades de bots/CI, replay de batches, deployment no autorizado |
| Bridges/routers | Evasión cross-chain, laundering mediante saltos rápidos, desincronización del settlement |

Este mapeo garantiza que pruebes no solo los contratos, sino también cada identidad o automatización que pueda dirigir el valor de forma indirecta.

## 3. Priorizar según la viabilidad para el atacante frente al impacto empresarial

1. **Debilidades operativas**: credenciales de CI expuestas, roles de IAM con privilegios excesivos, policies de KMS mal configuradas, cuentas de automatización que puedan solicitar firmas arbitrarias, buckets públicos con configuraciones de bridges, etc.
2. **Debilidades específicas del valor**: parámetros de oracle frágiles, contratos upgradable sin aprobaciones multipartitas, liquidez sensible a flash loans, acciones de governance que eviten timelocks.

Gestiona la cola como lo haría un adversario: empieza por los footholds operativos que podrían tener éxito hoy y, después, avanza hacia rutas profundas de manipulación económica o de protocolos.<sup>[[2]](#references)</sup>

## 4. Ejecutar en entornos controlados y realistas respecto a producción
- **Mainnets forked / testnets aisladas**: replica el bytecode, el storage y la liquidez para que las rutas de flash loans, las desviaciones de oracles y los flujos de bridges se ejecuten end-to-end sin tocar fondos reales.<sup>[[2]](#references)</sup>
- **Planificación del blast radius**: define circuit breakers, módulos pausable, runbooks de rollback y admin keys exclusivas para pruebas antes de detonar un escenario.
- **Coordinación con stakeholders**: notifica a custodios, operadores de oracles, partners de bridges y compliance para que sus equipos de monitoring esperen el tráfico.
- **Aprobación legal**: documenta el alcance, la autorización y las condiciones de detención cuando las simulaciones puedan cruzar rails regulados.

## 5. Telemetría alineada con las técnicas de AADAPT
Instrumenta los streams de telemetría para que cada escenario produzca datos de detección accionables.<sup>[[2]](#references)</sup>

- **Traces a nivel de chain**: grafos de llamadas completos, uso de gas, nonces de transacciones y timestamps de bloques, para reconstruir bundles de flash loans, estructuras similares a reentrancy y saltos entre contratos.
- **Logs de aplicaciones/APIs**: vincula cada tx on-chain con una identidad humana o de automatización (ID de sesión, cliente OAuth, API key, ID del trabajo de CI), junto con las IPs y los métodos de autenticación.
- **Logs de KMS/HSM**: ID de clave, principal solicitante, resultado de la policy, dirección de destino y códigos de motivo para cada firma. Establece una línea base para las ventanas de cambio y las operaciones de alto riesgo.
- **Metadatos de oracles/feeds**: composición de las fuentes de datos por actualización, valor reportado, desviación respecto a las medias móviles, umbrales activados y rutas de failover utilizadas.
- **Traces de bridges/swaps**: correlaciona eventos de lock/mint/unlock entre chains con IDs de correlación, IDs de chain, identidad del relayer y tiempo entre saltos.
- **Marcadores de anomalías**: métricas derivadas como picos de slippage, ratios de colateralización anómalos, densidad de gas inusual o velocidad cross-chain.

Etiqueta todo con IDs de escenarios o IDs de usuarios sintéticos para que los analistas puedan alinear los observables con la técnica de AADAPT que se está probando.

## 6. Bucle de purple team y métricas de madurez
1. Ejecuta el escenario en el entorno controlado y captura las detecciones (alertas, dashboards y responders notificados).<sup>[[2]](#references)</sup>
2. Asigna cada paso a las técnicas específicas de AADAPT y a los observables producidos en los planos de chain, aplicación, KMS, oracle y bridge.
3. Formula y despliega hipótesis de detección (reglas de umbral, búsquedas de correlación y comprobaciones de invariantes).
4. Repite hasta que el tiempo medio de detección (MTTD) y el tiempo medio de contención (MTTC) cumplan las tolerancias del negocio y los playbooks detengan de forma fiable la pérdida de valor.

Mide la madurez del programa en tres ejes:<sup>[[2]](#references)</sup>
- **Visibilidad**: cada ruta crítica de valor tiene telemetría en cada plano.
- **Cobertura**: proporción de las técnicas de AADAPT priorizadas que se prueban end-to-end.
- **Respuesta**: capacidad de pausar contratos, revocar claves o congelar flujos antes de que se produzca una pérdida irreversible.

Hitos habituales: (1) inventario de valor + mapeo de AADAPT completados, (2) primer escenario end-to-end con detecciones implementadas, (3) ciclos trimestrales de purple team que amplíen la cobertura y reduzcan el MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Plantillas de escenarios
Usa estos blueprints reutilizables para diseñar simulaciones que se asignen directamente a los comportamientos de AADAPT.<sup>[[2]](#references)</sup>

### Escenario A – Manipulación económica mediante flash loans
- **Objetivo**: pedir prestado capital temporal dentro de una única transacción para distorsionar los precios o la liquidez de un AMM y activar préstamos, liquidaciones o mints con precios incorrectos antes de devolverlo.
- **Ejecución**:
1. Haz fork de la chain objetivo y carga los pools con liquidez similar a la de producción.
2. Pide prestado un notional elevado mediante un flash loan.
3. Ejecuta swaps calibrados para cruzar los límites de precio o de umbral en los que se basen la lógica de lending, vaults o derivados.
4. Invoca inmediatamente el contrato víctima después de la distorsión (borrow, liquidate, mint) y devuelve el flash loan.
- **Medición**: ¿Tuvo éxito la violación de la invariante? ¿Se activaron los monitores de slippage o desviación de precio, los circuit breakers o los hooks de pausa de governance? ¿Cuánto tiempo tardaron los analytics en marcar el patrón anómalo de gas o del call graph?

### Escenario B – Poisoning de oracle/data feed
- **Objetivo**: determinar si feeds manipulados pueden activar acciones automatizadas destructivas (liquidaciones masivas, settlements incorrectos).
- **Ejecución**:
1. En el fork/testnet, despliega un feed malicioso o ajusta los pesos del aggregator, el quorum o la cadencia de actualización más allá de la desviación tolerada.
2. Permite que los contratos dependientes consuman los valores envenenados y ejecuten su lógica estándar.
- **Medición**: alertas out-of-band a nivel de feed, activación del oracle de fallback, aplicación de límites mínimos/máximos y latencia entre el inicio de la anomalía y la respuesta del operador.

### Escenario C – Abuso de credenciales/firma
- **Objetivo**: probar si el compromiso de un único signer o identidad de automatización permite upgrades, cambios de parámetros o drains del treasury no autorizados.
- **Ejecución**:
1. Enumera las identidades con permisos de firma sensibles (operadores, tokens de CI, cuentas de servicio que invoquen KMS/HSM y participantes de multisig).
2. Simula el compromiso (reutiliza sus credenciales/claves dentro del alcance del laboratorio).
3. Intenta acciones privilegiadas: hacer upgrade de proxies, cambiar parámetros de riesgo, hacer mint/pause de activos o activar propuestas de governance.
- **Medición**: ¿Los logs de KMS/HSM generan alertas de anomalías (hora del día, cambio de destino, ráfaga de operaciones de alto riesgo)? ¿Pueden las policies o los umbrales de multisig impedir el abuso unilateral? ¿Se aplican throttles/rate limits o aprobaciones adicionales?

### Escenario D – Evasión cross-chain y brechas de traceability
- **Objetivo**: evaluar la capacidad de los defensores para rastrear e interceptar activos rapidly laundered a través de bridges, routers DEX y privacy hops.
- **Ejecución**:
1. Encadena operaciones de lock/mint entre bridges comunes, intercala swaps/mixers en cada salto y conserva IDs de correlación por salto.
2. Acelera las transferencias para someter a presión la latencia del monitoring (multi-hop en minutos/bloques).
- **Medición**: tiempo para correlacionar eventos entre la telemetría y los chain analytics comerciales, integridad de la ruta reconstruida, capacidad para identificar choke points donde congelar fondos durante un incidente real y fidelidad de las alertas ante una velocidad/valor cross-chain anómalos.

## References

- [1] [Framework de Cyber Threat AADAPT(TM) para activos digitales (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Framework MITRE AADAPT como hoja de ruta para Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
