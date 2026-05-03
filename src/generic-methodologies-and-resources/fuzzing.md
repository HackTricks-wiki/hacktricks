# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de gramática mutacional: cobertura vs. semántica

En **mutational grammar fuzzing**, las entradas se mutan mientras se mantienen **grammar-valid**. En modo guiado por cobertura, solo se guardan como seeds del corpus las muestras que activan **new coverage**. Para **language targets** (parsers, interpreters, engines), esto puede pasar por alto bugs que requieren **semantic/dataflow chains** donde la salida de una construcción se convierte en la entrada de otra.

**Modo de fallo:** el fuzzer encuentra seeds que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no preserva el dataflow encadenado**, así que la muestra “más cercana al bug” se descarta porque no añade cobertura. Con **3+ dependent steps**, la recombinación aleatoria se vuelve costosa y la retroalimentación de cobertura no guía la búsqueda.

**Implicación:** para gramáticas con muchas dependencias, considera **hybridizing mutational and generative phases** o sesgar la generación hacia patrones de **function chaining** (no solo cobertura).

## Trampas de diversidad del corpus

La mutación guiada por cobertura es **greedy**: una muestra con nueva cobertura se guarda de inmediato, a menudo conservando grandes regiones sin cambios. Con el tiempo, los corpora se vuelven **near-duplicates** con baja diversidad estructural. Una minimización agresiva puede eliminar contexto útil, así que un compromiso práctico es una **grammar-aware minimization** que **se detiene tras un mínimo umbral de tokens** (reducir ruido mientras se mantiene suficiente estructura alrededor para seguir siendo favorable a la mutación).

Una regla práctica de corpus para fuzzing mutacional es: **preferir un conjunto pequeño de seeds estructuralmente diferentes que maximicen la cobertura** frente a una gran pila de near-duplicates. En la práctica, esto suele significar:

- Empezar desde **real-world samples** (corpora públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema objetivo).
- Depurarlos con **coverage-based corpus minimization** en lugar de conservar cada muestra válida.
- Mantener los seeds **lo bastante pequeños** como para que las mutaciones caigan sobre campos significativos en vez de gastar la mayoría de los ciclos en bytes irrelevantes.
- Volver a ejecutar la minimización del corpus después de cambios importantes en el harness/instrumentation, porque el “mejor” corpus cambia cuando cambia la reachability.

## Comparison-Aware Mutation For Magic Values

Una razón común por la que los fuzzers se estancan no es la sintaxis sino las **hard comparisons**: magic bytes, comprobaciones de longitud, cadenas enum, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas `switch` o comparaciones en cascada. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte por byte.

Para estos objetivos, usa **comparison tracing** (por ejemplo AFL++ `CMPLOG` / workflows al estilo Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y sesgar las mutaciones hacia valores que las satisfagan.
```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```
**Notas prácticas:**

- Esto es especialmente útil cuando el objetivo oculta lógica profunda detrás de **file signatures**, **protocol verbs**, **type tags** o **version-dependent feature bits**.
- Combínalo con **dictionaries** extraídos de muestras reales, especificaciones de protocolo o debug logs. Un pequeño dictionary con tokens de gramática, nombres de chunks, verbs y delimitadores suele ser más valioso que una enorme wordlist genérica.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “magic” más tempranas y luego minimiza de nuevo el corpus resultante para que las etapas posteriores empiecen desde prefijos ya válidos.

## Stateful Fuzzing: Sequences Are Seeds

Para **protocols**, **authenticated workflows** y **multi-stage parsers**, la unidad interesante suele no ser un blob único, sino una **message sequence**. Concatenar todo el transcript en un solo archivo y mutarlo a ciegas suele ser ineficiente porque el fuzzer muta cada paso por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.

Un patrón más efectivo es tratar la **sequence** en sí como el seed y usar el **observable state** (response codes, protocol states, parser phases, returned object types) como feedback adicional:

- Mantén estables los **valid prefix messages** y enfoca las mutaciones en el mensaje que **drivea la transición**.
- Cachea identificadores y valores generados por el server a partir de respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere la mutación/splicing por mensaje en lugar de mutar todo el transcript serializado como un blob opaco.
- Si el protocol expone response codes con significado, úsalos como un **state oracle** barato para priorizar secuencias que avanzan más profundo.

Esta es la misma razón por la que los bugs autenticados, las transiciones ocultas o los bugs de parser de “solo después del handshake” suelen pasarse por alto con el fuzzing tipo file tradicional: el fuzzer debe preservar **orden, state y dependencies**, no solo estructura.

## Single-Machine Diversity Trick (Jackalope-Style)

Una forma práctica de combinar **generative novelty** con **coverage reuse** es **reiniciar workers de corta duración** contra un server persistente. Cada worker parte de un corpus vacío, se sincroniza después de `T` segundos, ejecuta otros `T` segundos sobre el corpus combinado, se sincroniza de nuevo y luego termina. Esto produce **estructuras frescas en cada generación** mientras sigue aprovechando la coverage acumulada.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Trabajadores secuenciales (bucle de ejemplo):**

<details>
<summary>Bucle de reinicio del trabajador Jackalope</summary>
```python
import subprocess
import time

T = 3600

while True:
subprocess.run(["rm", "-rf", "workerout"])
p = subprocess.Popen([
"/path/to/fuzzer",
"-grammar", "grammar.txt",
"-instrumentation", "sancov",
"-in", "empty",
"-out", "workerout",
"-t", "1000",
"-delivery", "shmem",
"-iterations", "10000",
"-mute_child",
"-nthreads", "6",
"-server", "127.0.0.1:8337",
"-server_update_interval", str(T),
"--", "./harness", "-m", "@@",
])
time.sleep(T * 2)
p.kill()
```
</details>

**Notas:**

- `-in empty` fuerza un **corpus nuevo** en cada generación.
- `-server_update_interval T` aproxima **sincronización retrasada** (novedad primero, reutilización después).
- En modo de fuzzing con grammar, la **sincronización inicial con el server se omite por defecto** (no hace falta `-skip_initial_server_sync`).
- El `T` óptimo **depende del target**; cambiarlo después de que el worker haya encontrado la mayor parte de la cobertura “fácil” suele funcionar mejor.

## Snapshot Fuzzing Para Targets Difíciles de Harnessar

Cuando el código que quieres probar solo es alcanzable **después de un gran coste de preparación** (arrancar una VM, completar un login, recibir un paquete, parsear un contenedor, inicializar un servicio), una alternativa útil es **snapshot fuzzing**:

1. Ejecuta el target hasta que el estado interesante esté listo.
2. Haz snapshot de **memoria + registros** en ese punto.
3. Para cada caso de prueba, escribe la entrada mutada directamente en el buffer relevante del guest/proceso.
4. Ejecuta hasta crash/timeout/reset.
5. Restaura solo las **dirty pages** y repite.

Esto evita pagar el coste completo de preparación en cada iteración y es especialmente útil para **network services**, **firmware**, **post-auth attack surfaces** y **binary-only targets** que son dolorosos de refactorizar en un harness clásico en proceso.

Un truco práctico es romper inmediatamente después de un punto `recv`/`read`/deserialización de paquete, anotar la dirección del buffer de entrada, hacer snapshot ahí y luego mutar ese buffer directamente en cada iteración. Esto te permite fuzzear la lógica de parseo profunda sin reconstruir todo el handshake cada vez.

## Harness Introspection: Encuentra Pronto los Fuzzers Superficiales

Cuando una campaña se estanca, el problema muchas veces no es el mutator sino el **harness**. Usa **reachability/coverage introspection** para encontrar funciones que son alcanzables estáticamente desde tu fuzz target pero rara vez o nunca cubiertas dinámicamente. Esas funciones suelen indicar uno de tres problemas:

- El harness entra al target demasiado tarde o demasiado pronto.
- El seed corpus carece de toda una familia de features.
- El target realmente necesita un **second harness** en lugar de un solo harness enorme de “hazlo todo”.

Si usas flujos de trabajo estilo OSS-Fuzz / ClusterFuzz, Fuzz Introspector es útil para este triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use el informe para decidir si añadir un nuevo harness para una ruta de parser no probada, ampliar el corpus para una feature específica, o dividir un harness monolítico en puntos de entrada más pequeños.

## Selección de objetivos de fuzzing y triaje de mutación basado en grafos

Si ya tienes **hallazgos de análisis estático**, **supervivientes de mutation testing** y **informes de cobertura**, no los triajes como listas independientes. Primero construye un **grafo de llamadas**, anota los nodos con **complejidad ciclomática**, **alcanzabilidad desde un punto de entrada/input no confiable**, y cualquier hallazgo externo, y luego haz preguntas sobre el grafo:

- ¿Qué funciones de alta complejidad son alcanzables desde input no confiable?
- ¿Qué supervivientes de mutación están en rutas desde parsers/handlers hacia código crítico de seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **blast radius** inusualmente alto?

Esto suele mostrar mejores objetivos de fuzzing que solo la “menor cobertura”. Un parser/decoder con **alta complejidad** y alcanzabilidad externa confirmada es un candidato más fuerte para un harness que un helper interno aislado con poca cobertura pero sin ruta controlada por un atacante.

### Flujo práctico de triaje

1. Construye un **grafo de código** a partir de la base de código y extrae métricas de complejidad/ramas por función.
2. Enumera los **entrypoints** que aceptan input controlado por un atacante: request handlers, decoders, importers, parsers de protocolos, lectores de CLI/archivos.
3. Ejecuta consultas de **ruta** desde esos entrypoints hacia funciones candidatas para separar la superficie de ataque alcanzable del código muerto o solo interno.
4. Prioriza nodos que combinen:
- alta **complejidad ciclomática**
- alcanzabilidad confirmada desde input no confiable
- alto **blast radius** o muchos dependientes posteriores
- evidencia corroborante como hallazgos de **SARIF**, notas de auditoría o supervivientes de mutación
5. Escribe harnesses focalizados para los nodos mejor puntuados primero, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Supervivientes de mutación: equivalentes vs accionables

El mutation testing a menudo produce una lista ruidosa de supervivientes. Antes de tratar cada superviviente como una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un entrypoint controlado por un atacante?
- ¿Todas las rutas de llamada están restringidas por invariantes más fuertes que la comprobación mutada?
- ¿El nodo está en código muerto, lógica solo de formato, o en una ruta aritmética/parser de alto impacto?

Los supervivientes que siguen siendo inalcanzables o estructuralmente restringidos suelen ser **mutantes equivalentes**. Los supervivientes que permanecen **alcanzables** y tocan **condiciones de borde**, **rutas de overflow/carry**, o **aritmética/parsing crítico para seguridad** deberían promoverse a:

- nuevos harnesses de fuzzing
- tests directos de propiedad/invariante
- vectores de edge-case dirigidos

### Correlaciona hallazgos externos sobre el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre nodos del grafo por **archivo + rango de líneas** y usa el grafo para expandir el impacto:

- calcula el **blast radius** de la función señalada
- comprueba si el hallazgo está en alguna ruta desde un entrypoint
- agrupa hallazgos cercanos que colapsan en el mismo punto de estrangulamiento

Esto es útil al decidir si dedicar tiempo de fuzzing a una función específica: un nodo que es **alcanzable**, **complejo** y ya tiene **hallazgos SAST** suele ser un mejor objetivo que un nodo meramente complejo sin ruta de atacante.

Example workflow with Trailmark:
```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```
La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir fuzz targets con el mayor valor de seguridad esperado, luego usa los mutation survivors para decidir qué boundaries e invariants debe estresar tu harness.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
