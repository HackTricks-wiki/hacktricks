# Red Teaming de Web3 centrado en el valor (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

El marco MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) clasifica las acciones y técnicas adversarias dirigidas a los sistemas de activos digitales.<sup>[[1]](#references)</sup> Trátalo como una **columna vertebral para el modelado de amenazas**: enumera cada componente que pueda acuñar, valorar, autorizar o enrutar activos, relaciona esos puntos de contacto con las técnicas AADAPT y, luego, plantea escenarios de Red Team para medir si el entorno puede resistir pérdidas económicas irreversibles.

## 1. Inventariar los componentes que contienen valor
Crea un mapa de todo lo que pueda influir en el estado del valor, incluso si está fuera de la cadena.<sup>[[2]](#references)</sup>

- **Servicios de firma de custodia** (clústeres HSM/KMS, Vault/KMaaS, API de firma usadas por bots o tareas administrativas). Registra los ID de las claves, las políticas, las identidades de automatización y los flujos de aprobación.
- **Rutas de administración y actualización** de contratos (administradores de proxy, timelocks de gobernanza, claves de pausa de emergencia, registros de parámetros). Incluye quién o qué puede invocarlas, y con qué quórum o retraso.
- **Lógica de protocolos on-chain** que gestiona préstamos, AMM, bóvedas, staking, bridges o vías de liquidación. Documenta los invariantes que asume (precios de oráculos, ratios de colateral, frecuencia de rebalanceo…).
- **Automatización off-chain** que construye transacciones (bots de market-making, pipelines de CI/CD, tareas cron, funciones serverless). Estos suelen tener claves de API o principales de servicio que pueden solicitar firmas.
- **Oráculos y feeds de datos** (composición del agregador, quórum, umbrales de desviación, frecuencia de actualización). Anota cada fuente upstream de la que dependa la lógica de riesgo automatizada.
- **Bridges y routers cross-chain** (contratos de lock/mint, relayers, tareas de liquidación) que conectan cadenas o sistemas de custodia.

Entregable: un diagrama de flujo de valor que muestre cómo se mueven los activos, quién autoriza su movimiento y qué señales externas influyen en la lógica de negocio.

## 2. Relacionar los componentes con los comportamientos de AADAPT
Traduce la taxonomía AADAPT en candidatos concretos de ataque para cada componente.<sup>[[2]](#references)</sup>

| Componente | Enfoque principal de AADAPT |
| --- | --- |
| Entornos de firma/KMS | Robo de credenciales, elusión de políticas, abuso de firmas, toma de control de la gobernanza |
| Oráculos/feeds | Envenenamiento de entradas, manipulación de agregación, evasión de umbrales de desviación |
| Protocolos on-chain | Manipulación económica con flash-loan, ruptura de invariantes, reconfiguración de parámetros |
| Pipelines de automatización | Identidades de bot/CI comprometidas, repetición de lotes, despliegue no autorizado |
| Bridges/routers | Evasión cross-chain, blanqueo mediante saltos rápidos, desincronización de liquidaciones |

Este mapeo garantiza que pruebes no solo los contratos, sino también cada identidad o sistema de automatización que pueda influir indirectamente en el valor.

## 3. Priorizar según la viabilidad para el atacante y el impacto empresarial

1. **Debilidades operativas**: credenciales de CI expuestas, roles de IAM con privilegios excesivos, políticas de KMS mal configuradas, cuentas de automatización que pueden solicitar firmas arbitrarias, buckets públicos con configuraciones de bridges, etc.
2. **Debilidades específicas del valor**: parámetros de oráculo frágiles, contratos actualizables sin aprobaciones multipartitas, liquidez vulnerable a flash-loan, acciones de gobernanza que eluden los timelocks.

Trabaja la lista como un adversario: empieza por los puntos de apoyo operativos que podrían funcionar hoy y luego avanza hacia rutas complejas de manipulación económica o de protocolos.<sup>[[2]](#references)</sup>

## 4. Ejecutar en entornos controlados y realistas respecto a producción
- **Mainnets bifurcadas / testnets aisladas**: replica el bytecode, el almacenamiento y la liquidez para que las rutas de flash-loan, las desviaciones de oráculos y los flujos de bridges se ejecuten de extremo a extremo sin tocar fondos reales.<sup>[[2]](#references)</sup>
- **Planificación del radio de impacto**: define interruptores de circuito, módulos que se puedan pausar, runbooks de reversión y claves administrativas solo para pruebas antes de detonar un escenario.
- **Coordinación con las partes interesadas**: notifica a custodios, operadores de oráculos, socios de bridges y equipos de cumplimiento para que sus equipos de monitorización esperen ese tráfico.
- **Aprobación legal**: documenta el alcance, la autorización y las condiciones de detención cuando las simulaciones puedan afectar vías reguladas.

## 5. Telemetría alineada con las técnicas AADAPT
Instrumenta los flujos de telemetría para que cada escenario genere datos de detección útiles.<sup>[[2]](#references)</sup>

- **Trazas a nivel de cadena**: grafos completos de llamadas, uso de gas, nonces de transacción y marcas de tiempo de bloques, para reconstruir bundles de flash-loan, estructuras similares a la reentrancia y saltos entre contratos.
- **Registros de aplicaciones/API**: vincula cada transacción on-chain con una identidad humana o de automatización (ID de sesión, cliente OAuth, clave de API, ID de tarea de CI), junto con las IP y los métodos de autenticación.
- **Registros de KMS/HSM**: ID de clave, principal invocador, resultado de la política, dirección de destino y códigos de motivo para cada firma. Establece líneas base para las ventanas de cambios y las operaciones de alto riesgo.
- **Metadatos de oráculos/feeds**: composición de las fuentes de datos por actualización, valor informado, desviación respecto de los promedios móviles, umbrales activados y rutas de failover utilizadas.
- **Trazas de bridges/swaps**: correlaciona eventos de lock/mint/unlock entre cadenas usando ID de correlación, ID de cadena, identidad del relayer y tiempo entre saltos.
- **Marcadores de anomalías**: métricas derivadas, como picos de slippage, ratios de colateralización anómalos, densidad inusual de gas o velocidad cross-chain.

Etiqueta todo con ID de escenario o ID de usuario sintéticos para que los analistas puedan relacionar los datos observables con la técnica AADAPT que se está probando.

## 6. Ciclo de Purple Team y métricas de madurez
1. Ejecuta el escenario en el entorno controlado y captura las detecciones (alertas, dashboards, avisos a los equipos de respuesta).<sup>[[2]](#references)</sup>
2. Relaciona cada paso con las técnicas AADAPT específicas y los datos observables generados en los planos de cadena, aplicación, KMS, oráculo y bridge.
3. Formula e implementa hipótesis de detección (reglas de umbral, búsquedas de correlación, comprobaciones de invariantes).
4. Repite hasta que el tiempo medio de detección (MTTD) y el tiempo medio de contención (MTTC) cumplan las tolerancias del negocio y los playbooks detengan de forma fiable la pérdida de valor.

Haz seguimiento de la madurez del programa en tres ejes:<sup>[[2]](#references)</sup>
- **Visibilidad**: todas las rutas críticas de valor tienen telemetría en cada plano.
- **Cobertura**: proporción de técnicas AADAPT priorizadas que se han probado de extremo a extremo.
- **Respuesta**: capacidad de pausar contratos, revocar claves o congelar flujos antes de que se produzca una pérdida irreversible.

Hitos típicos: (1) inventario de valor y mapeo AADAPT completados, (2) primer escenario de extremo a extremo con detecciones implementadas, (3) ciclos trimestrales de Purple Team que amplían la cobertura y reducen el MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Plantillas de escenarios
Usa estos planes repetibles para diseñar simulaciones que se relacionen directamente con los comportamientos de AADAPT.<sup>[[2]](#references)</sup>

### Escenario A – Manipulación económica con flash-loan
- **Objetivo**: tomar prestado capital transitorio dentro de una transacción para distorsionar los precios o la liquidez de un AMM y provocar préstamos, liquidaciones o acuñaciones a precios erróneos antes de devolverlo.
- **Ejecución**:
  1. Bifurca la cadena objetivo y dota los pools de una liquidez similar a la de producción.
  2. Toma prestado un importe elevado mediante un flash-loan.
  3. Realiza swaps calibrados para cruzar los límites de precio/umbral de los que dependa la lógica de préstamos, bóvedas o derivados.
  4. Invoca el contrato víctima inmediatamente después de la distorsión (pedir prestado, liquidar, acuñar) y devuelve el flash-loan.
- **Medición**: ¿Se logró vulnerar el invariante? ¿Se activaron las alertas de slippage/desviación de precio, los interruptores de circuito o los mecanismos de pausa de gobernanza? ¿Cuánto tardaron los análisis en marcar el patrón anómalo de gas/grafo de llamadas?

### Escenario B – Envenenamiento de oráculos/feeds de datos
- **Objetivo**: determinar si los feeds manipulados pueden activar acciones automatizadas destructivas (liquidaciones masivas, liquidaciones incorrectas).
- **Ejecución**:
  1. En la fork/testnet, despliega un feed malicioso o modifica los pesos del agregador, el quórum o la frecuencia de actualización para superar la desviación tolerada.
  2. Permite que los contratos dependientes consuman los valores envenenados y ejecuten su lógica habitual.
- **Medición**: alertas fuera de banda a nivel del feed, activación del oráculo de reserva, aplicación de límites mínimos/máximos y latencia entre el inicio de la anomalía y la respuesta del operador.

### Escenario C – Abuso de credenciales/firma
- **Objetivo**: probar si la vulneración de un único firmante o una identidad de automatización permite realizar actualizaciones, cambios de parámetros o retiros de tesorería no autorizados.
- **Ejecución**:
  1. Enumera las identidades con permisos de firma sensibles (operadores, tokens de CI, cuentas de servicio que invocan KMS/HSM, participantes de multisig).
  2. Simula la vulneración (reutiliza sus credenciales/claves dentro del alcance del laboratorio).
  3. Intenta acciones privilegiadas: actualizar proxies, cambiar parámetros de riesgo, acuñar/pausar activos o activar propuestas de gobernanza.
- **Medición**: ¿Los registros de KMS/HSM generan alertas de anomalía (hora del día, cambio de dirección de destino, ráfaga de operaciones de alto riesgo)? ¿Pueden las políticas o los umbrales de multisig impedir el abuso unilateral? ¿Se aplican límites de frecuencia o aprobaciones adicionales?

### Escenario D – Evasión cross-chain y brechas de trazabilidad
- **Objetivo**: evaluar la capacidad de los defensores para rastrear e interceptar activos blanqueados rápidamente a través de bridges, routers DEX y saltos por servicios de privacidad.
- **Ejecución**:
  1. Encadena operaciones de lock/mint a través de bridges comunes, intercala swaps/mixers en cada salto y conserva ID de correlación por salto.
  2. Acelera las transferencias para someter a presión la latencia de monitorización (varios saltos en minutos/bloques).
- **Medición**: tiempo para correlacionar eventos entre la telemetría y los análisis comerciales de cadenas, integridad de la ruta reconstruida, capacidad para identificar puntos de control para congelar fondos en un incidente real y precisión de las alertas sobre velocidad/valor cross-chain anómalos.

## References

- [1] [Marco de amenazas cibernéticas AADAPT(TM) para activos digitales (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [El marco MITRE AADAPT como hoja de ruta para Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
