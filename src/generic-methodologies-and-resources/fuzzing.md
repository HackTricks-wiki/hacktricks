# Metodología de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing gramatical mutacional: cobertura vs. semántica

En **fuzzing gramatical mutacional**, las entradas se mutan mientras se mantienen **válidas según la gramática**. En modo guiado por cobertura, solo se guardan como semillas del corpus las muestras que activan **nueva cobertura**. Para **targets de lenguaje** (parsers, interpreters, engines), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos** donde la salida de una construcción se convierte en la entrada de otra.

**Modo de fallo:** el fuzzer encuentra semillas que individualmente ejercitan `document()` y `generate-id()` (o primitivas similares), pero **no preserva el flujo de datos encadenado**, así que la muestra “más cercana al bug” se descarta porque no añade cobertura. Con **3+ pasos dependientes**, la recombinación aleatoria se vuelve costosa y la retroalimentación de cobertura no guía la búsqueda.

**Implicación:** para gramáticas con muchas dependencias, considera **hibridar fases mutacionales y generativas** o sesgar la generación hacia patrones de **encadenamiento de funciones** (no solo cobertura).

## Trampas de diversidad del corpus

La mutación guiada por cobertura es **codiciosa**: una muestra con nueva cobertura se guarda de inmediato, a menudo conservando grandes regiones sin cambios. Con el tiempo, los corpora se vuelven **casi duplicados** con baja diversidad estructural. La minimización agresiva puede eliminar contexto útil, así que un compromiso práctico es la **minimización consciente de la gramática** que **se detiene tras un umbral mínimo de tokens** (reduce ruido sin perder suficiente estructura circundante para seguir siendo favorable a la mutación).

Una regla práctica de corpus para fuzzing mutacional es: **preferir un conjunto pequeño de semillas estructuralmente diferentes que maximicen la cobertura** frente a un montón de casi duplicados. En la práctica, esto suele significar:

- Empezar con **muestras del mundo real** (corpora públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema del target).
- Destilarlas con **minimización de corpus basada en cobertura** en lugar de conservar cada muestra válida.
- Mantener las semillas **lo bastante pequeñas** como para que las mutaciones caigan en campos significativos en vez de gastar la mayoría de los ciclos en bytes irrelevantes.
- Volver a ejecutar la minimización del corpus después de cambios importantes en el harness/instrumentación, porque el corpus “mejor” cambia cuando cambia la alcanzabilidad.

## Mutación consciente de comparaciones para valores mágicos

Una razón común por la que los fuzzers se estancan no es la sintaxis sino las **comparaciones duras**: bytes mágicos, comprobaciones de longitud, cadenas enum, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas `switch` o comparaciones encadenadas. La mutación aleatoria pura desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos targets, usa **comparison tracing** (por ejemplo, flujos de trabajo estilo AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de comparaciones fallidas y sesgar las mutaciones hacia valores que las satisfagan.
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
- Combínalo con **dictionaries** extraídos de muestras reales, especificaciones de protocolo o debug logs. Un pequeño dictionary con grammar tokens, chunk names, verbs y delimiters suele ser mucho más valioso que una enorme generic wordlist.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “magic” más tempranas y luego minimiza de nuevo el corpus resultante para que las etapas posteriores comiencen desde prefijos ya válidos.

## Stateful Fuzzing: Sequences Are Seeds

Para **protocols**, **authenticated workflows** y **multi-stage parsers**, la unidad interesante no suele ser un único blob, sino una **message sequence**. Concatenar todo el transcript en un solo archivo y mutarlo a ciegas suele ser ineficiente porque el fuzzer muta cada paso por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.

Un patrón más eficaz es tratar la **sequence** en sí misma como el seed y usar el **observable state** (response codes, protocol states, parser phases, returned object types) como feedback adicional:

- Mantén estables los **valid prefix messages** y centra las mutaciones en el mensaje que **drives the transition**.
- Cachea identifiers y valores generados por el server a partir de respuestas previas cuando el siguiente paso dependa de ellos.
- Prefiere la mutación/splicing por mensaje en lugar de mutar todo el transcript serializado como un blob opaco.
- Si el protocolo expone response codes significativos, úsalos como un **cheap state oracle** para priorizar secuencias que progresen más profundamente.

Esta es la misma razón por la que los authenticated bugs, hidden transitions o los bugs de parser “only-after-handshake” a menudo se pasan por alto con el file-style fuzzing clásico: el fuzzer debe preservar **order, state y dependencies**, no solo la estructura.

## Single-Machine Diversity Trick (Jackalope-Style)

Una forma práctica de hibridar **generative novelty** con **coverage reuse** es **reiniciar workers de corta duración** contra un server persistente. Cada worker empieza con un corpus vacío, se sincroniza tras `T` segundos, ejecuta otros `T` segundos sobre el corpus combinado, se sincroniza de nuevo y luego termina. Esto produce **fresh structures** en cada generación mientras sigue aprovechando la coverage acumulada.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Trabajadores secuenciales (bucle de ejemplo):**

<details>
<summary>Bucle de reinicio del worker Jackalope</summary>
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
- `-server_update_interval T` aproxima una **sincronización retrasada** (novedad primero, reutilización después).
- En modo de fuzzing con gramática, la **sincronización inicial con el server se omite por defecto** (no hace falta `-skip_initial_server_sync`).
- El `T` óptimo **depende del target**; cambiarlo después de que el worker haya encontrado la mayor parte de la cobertura “fácil” suele funcionar mejor.

## Snapshot Fuzzing Para Targets Difíciles De Harness

Cuando el código que quieres probar solo se vuelve alcanzable **después de un gran coste de preparación** (arrancar una VM, completar un login, recibir un paquete, parsear un container, inicializar un service), una alternativa útil es **snapshot fuzzing**:

1. Ejecuta el target hasta que el estado interesante esté listo.
2. Haz snapshot de **memoria + registros** en ese punto.
3. Para cada caso de prueba, escribe la entrada mutada directamente en el buffer relevante del guest/process.
4. Ejecuta hasta crash/timeout/reset.
5. Restaura solo las **dirty pages** y repite.

Esto evita pagar el coste completo de preparación en cada iteración y es especialmente útil para **network services**, **firmware**, **post-auth attack surfaces** y **binary-only targets** que son difíciles de refactorizar en un harness clásico en proceso.

Un truco práctico es interrumpir justo después de un punto `recv`/`read`/deserialización de paquete, anotar la dirección del buffer de entrada, hacer snapshot allí y luego mutar ese buffer directamente en cada iteración. Esto te permite hacer fuzzing de la lógica de parsing profunda sin reconstruir todo el handshake cada vez.

## Harness Introspection: Encuentra Shallow Fuzzers Temprano

Cuando una campaña se estanca, el problema a menudo no es el mutator sino el **harness**. Usa **reachability/coverage introspection** para encontrar funciones que son estáticamente alcanzables desde tu fuzz target pero que rara vez o nunca se cubren dinámicamente. Esas funciones suelen indicar uno de tres problemas:

- El harness entra al target demasiado tarde o demasiado pronto.
- El seed corpus carece de una familia completa de features.
- El target realmente necesita un **segundo harness** en lugar de uno demasiado grande que haga “todo”.

Si usas flujos de trabajo tipo OSS-Fuzz / ClusterFuzz, Fuzz Introspector es útil para este triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa el informe para decidir si añadir un nuevo harness para una ruta de parser no probada, ampliar el corpus para una característica específica, o dividir un harness monolítico en puntos de entrada más pequeños.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
