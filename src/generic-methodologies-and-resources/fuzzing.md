# Metodología de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de Gramática Mutacional: Cobertura vs. Semántica

En **fuzzing de gramática mutacional**, los inputs se mutan mientras se mantienen **válidos según la gramática**. En modo guiado por cobertura, solo se guardan como semillas del corpus las muestras que activan **nueva cobertura**. Para **targets de lenguaje** (parsers, interpreters, engines), esto puede pasar por alto bugs que requieren **cadenas semánticas/de dataflow** donde la salida de un constructo se convierte en la entrada de otro.

**Modo de fallo:** el fuzzer encuentra semillas que por separado ejercitan `document()` y `generate-id()` (o primitivas similares), pero **no preserva el dataflow encadenado**, así que la muestra “más cercana al bug” se descarta porque no añade cobertura. Con **3+ pasos dependientes**, la recombinación aleatoria se vuelve costosa y la retroalimentación de cobertura no guía la búsqueda.

**Implicación:** para gramáticas con muchas dependencias, considera **hibridar fases mutacionales y generativas** o sesgar la generación hacia patrones de **encadenamiento de funciones** (no solo cobertura).

## Problemas de Diversidad del Corpus

La mutación guiada por cobertura es **codiciosa**: una muestra con nueva cobertura se guarda inmediatamente, a menudo conservando grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con baja diversidad estructural. La minimización agresiva puede eliminar contexto útil, así que un compromiso práctico es una **minimización consciente de la gramática** que **se detiene tras un umbral mínimo de tokens** (reduce ruido mientras conserva suficiente estructura alrededor para seguir siendo amigable a la mutación).

Una regla práctica para el corpus en fuzzing mutacional es: **preferir un conjunto pequeño de semillas estructuralmente distintas que maximicen la cobertura** frente a una gran pila de casi duplicados. En la práctica, esto suele significar:

- Empezar con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema del target).
- Depurarlas con **minimización de corpus basada en cobertura** en vez de conservar cada muestra válida.
- Mantener las semillas **lo bastante pequeñas** para que las mutaciones caigan en campos significativos en lugar de gastar la mayoría de ciclos en bytes irrelevantes.
- Volver a ejecutar la minimización del corpus tras cambios importantes en el harness/instrumentación, porque el corpus “mejor” cambia cuando cambia la alcanzabilidad.

## Mutación Consciente de Comparaciones Para Valores Mágicos

Una razón común por la que los fuzzers se estancan no es la sintaxis sino las **comparaciones duras**: bytes mágicos, checks de longitud, cadenas enum, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas `switch` o comparaciones en cascada. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

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

- Esto es especialmente útil cuando el objetivo bloquea lógica profunda detrás de **file signatures**, **protocol verbs**, **type tags**, o **version-dependent feature bits**.
- Combínalo con **dictionaries** extraídos de muestras reales, especificaciones de protocolo o logs de depuración. Un diccionario pequeño con grammar tokens, chunk names, verbs y delimitadores suele ser mucho más valioso que una enorme wordlist genérica.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “magic” más tempranas y luego minimiza de nuevo el corpus resultante para que las etapas posteriores partan de prefijos ya válidos.

## Stateful Fuzzing: Sequences Are Seeds

Para **protocols**, **authenticated workflows** y **multi-stage parsers**, la unidad interesante a menudo no es un blob único, sino una **message sequence**. Concatenar toda la transcripción en un solo archivo y mutarla a ciegas suele ser ineficiente porque el fuzzer muta cada paso por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.

Un patrón más eficaz es tratar la **sequence** en sí como la seed y usar el **estado observable** (response codes, protocol states, parser phases, returned object types) como feedback adicional:

- Mantén estables los **valid prefix messages** y enfoca las mutaciones en el mensaje que impulsa la **transition**.
- Cachea identificadores y valores generados por el server a partir de respuestas previas cuando el siguiente paso dependa de ellos.
- Prefiere la mutación/splicing por mensaje en lugar de mutar toda la transcripción serializada como un blob opaco.
- Si el protocolo expone response codes significativos, úsalos como un **cheap state oracle** para priorizar las secuencias que avanzan más profundo.

Esta es la misma razón por la que los bugs authenticated, las transiciones ocultas o los bugs de parser “only-after-handshake” a menudo se pasan por alto con el fuzzing estilo archivo estándar: el fuzzer debe preservar **order**, **state** y **dependencies**, no solo la estructura.

## Single-Machine Diversity Trick (Jackalope-Style)

Una forma práctica de hibridar **generative novelty** con **coverage reuse** es **reiniciar workers de corta duración** contra un server persistente. Cada worker parte de un corpus vacío, se sincroniza después de `T` segundos, ejecuta otros `T` segundos sobre el corpus combinado, se sincroniza de nuevo y luego termina. Esto produce **fresh structures each generation** mientras sigue aprovechando la coverage acumulada.

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
- En modo de grammar fuzzing, la **sincronización inicial con el server se omite por defecto** (no hace falta `-skip_initial_server_sync`).
- El `T` óptimo **depende del target**; cambiarlo después de que el worker haya encontrado la mayoría de la cobertura “fácil” suele funcionar mejor.

## Snapshot Fuzzing Para Targets Difíciles de Harnessar

Cuando el código que quieres testear solo se vuelve alcanzable **después de un gran coste de preparación** (arrancar una VM, completar un login, recibir un packet, parsear un container, inicializar un service), una alternativa útil es **snapshot fuzzing**:

1. Ejecuta el target hasta que el estado interesante esté listo.
2. Haz un snapshot de **memoria + registers** en ese punto.
3. Para cada test case, escribe la entrada mutada directamente en el buffer relevante del guest/process.
4. Ejecuta hasta crash/timeout/reset.
5. Restaura solo las **dirty pages** y repite.

Esto evita pagar el coste completo de preparación en cada iteración y es especialmente útil para **network services**, **firmware**, **post-auth attack surfaces** y **binary-only targets** que son difíciles de refactorizar en un harness clásico in-process.

Un truco práctico es romper inmediatamente después de un punto `recv`/`read`/deserialización de packet, anotar la dirección del buffer de entrada, hacer snapshot ahí y luego mutar ese buffer directamente en cada iteración. Esto te permite fuzzear la lógica de parsing profunda sin reconstruir cada vez todo el handshake.

## Harness Introspection: Encuentra Pronto los Fuzzers Superficiales

Cuando una campaña se estanca, el problema muchas veces no es el mutator sino el **harness**. Usa **reachability/coverage introspection** para encontrar funciones que son estáticamente alcanzables desde tu fuzz target pero que rara vez o nunca se cubren de forma dinámica. Esas funciones suelen indicar uno de tres problemas:

- El harness entra al target demasiado tarde o demasiado pronto.
- El seed corpus carece de toda una familia de features.
- El target realmente necesita un **segundo harness** en lugar de un solo harness sobredimensionado que “hace de todo”.

Si usas workflows estilo OSS-Fuzz / ClusterFuzz, Fuzz Introspector es útil para este triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa el informe para decidir si añadir un nuevo harness para una ruta del parser no probada, ampliar el corpus para una característica específica, o dividir un harness monolítico en puntos de entrada más pequeños.

## Selección de fuzz target y triaje de mutación primero en grafo

Si ya tienes **hallazgos de static-analysis**, **mutation-testing survivors** y **coverage reports**, no los triages como listas independientes. Construye primero un **call graph**, anota los nodos con **cyclomatic complexity**, **entrypoint/untrusted-input reachability** y cualquier hallazgo externo, y luego haz preguntas sobre el grafo:

- ¿Qué funciones de alta complejidad son alcanzables desde input no confiable?
- ¿Qué mutation survivors están en rutas desde parsers/handlers hacia código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **blast radius** inusualmente alto?

Esto suele revelar mejores fuzz targets que solo la “menor cobertura”. Un parser/decoder con **alta complejidad** y **alcanzabilidad externa** confirmada es un mejor candidato para un harness que un helper interno aislado con cobertura débil pero sin ruta controlada por un atacante.

### Flujo práctico de triaje

1. Construye un **code graph** a partir de la base de código y extrae métricas de complejidad/ramificación por función.
2. Enumera los **entrypoints** que aceptan input controlado por el atacante: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Ejecuta consultas de **path** desde esos entrypoints hacia funciones candidatas para separar la superficie de ataque alcanzable del código muerto/sólo interno.
4. Prioriza los nodos que combinen:
- alta **cyclomatic complexity**
- **reachability from untrusted input** confirmada
- alto **blast radius** o muchos dependientes aguas abajo
- evidencia corroborante como hallazgos de **SARIF**, notas de auditoría o mutation survivors
5. Escribe harnesses focalizados para los nodos con mejor puntuación primero, especialmente **parsers/codecs** como decodificadores hex/Base64/IP/message.

### Mutation survivors: equivalentes vs accionables

La mutation testing a menudo produce una lista ruidosa de survivors. Antes de tratar cada survivor como una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un entrypoint controlado por un atacante?
- ¿Todas las rutas de llamada están restringidas por invariantes más fuertes que la comprobación mutada?
- ¿El nodo está en código muerto, lógica sólo de formato, o en una ruta aritmética/parser de alto impacto?

Los survivors que siguen siendo inalcanzables o estructuralmente restringidos suelen ser **equivalent mutants**. Los survivors que permanecen **reachables** y tocan **boundary conditions**, rutas de **overflow/carry**, o **security-critical arithmetic/parsing** deberían promoverse a:

- nuevos fuzz harnesses
- tests directos de propiedad/invariante
- vectores de casos borde dirigidos

### Correlaciona hallazgos externos sobre el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo por **file + line range** y usa el grafo para ampliar el impacto:

- calcula el **blast radius** de la función señalada
- comprueba si el hallazgo está en alguna ruta desde un entrypoint
- agrupa hallazgos cercanos que colapsen en el mismo punto de estrangulamiento

Esto es útil al decidir si dedicar tiempo de fuzzing a una función específica: un nodo que es **reachable**, **complex**, y ya tiene **SAST hits** suele ser un mejor objetivo que un nodo simplemente complejo sin ruta de atacante.

Ejemplo de flujo de trabajo con Trailmark:
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
La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir objetivos de fuzzing con el mayor valor de seguridad esperado, y luego usa los supervivientes de mutación para decidir qué límites e invariantes debe someter a estrés tu harness.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Si un target de Go ya tiene un harness nativo `testing.F`, una ruta práctica de mejora es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain de Go bifurcada que mantiene `go test -fuzz` pero cambia el backend a **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Esto es útil cuando el fuzzer nativo de Go se atasca con **hard comparisons**, **typed inputs** o **parser-heavy formats**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para seeds y `f.Fuzz(...)` para la callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar del toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con programación/mutación de LibAFL y mejores detectores alrededor.

### Convierte fallos silenciosos en fuzz findings

Un problema recurrente en evaluaciones de Go es que el comportamiento peligroso a menudo **no** provoca un crash por defecto. Con gosentry, puedes promover varias clases de estados “malos pero silenciosos” a findings:

- `--panic-on=pkg.Func,...` para hacer que las rutas de logging/error seleccionadas se comporten como crashes (útil para rutas de código estilo `log.Fatal` que, de otro modo, solo registran y continúan).
- `--catch-races=true` para reproducir las nuevas entradas de la queue con el detector de race de Go.
- `--catch-leaks=true` para reproducir las nuevas entradas de la queue con `goleak` y detenerse ante leaks de goroutines.
- Manejo de hangs de LibAFL para mantener **bucles infinitos / inputs muy lentos** como fuzz findings en lugar de dejarlos desaparecer como timeouts.
- Comprobaciones integradas de overflow aritmético por defecto, más comprobaciones opcionales de truncation mediante instrumentación estilo go-panikint.

Esto es especialmente valioso para targets donde el impacto de seguridad es un **panicless parser failure**, un **concurrency bug** o un **DoS-only hang** en lugar de corrupción de memoria.

### Struct-aware fuzzing para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede fuzzear **composite values** directamente (structs, slices, arrays, pointers) mientras sigue mutando bytes por debajo.
```go
type Input struct {
Data []byte
S    string
N    int
}

func FuzzStructInput(f *testing.F) {
f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
f.Fuzz(func(t *testing.T, in Input) {
Process(in)
})
}
```
Usar esto al construir un formato de wire falso solo para fuzzing ocultaría errores de lógica detrás de código de parsing solo para el harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y haz el parsing dentro del callback en su lugar.

### Fuzzing basado en gramáticas para parsers y entradas de protocolo

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **Nautilus grammar fuzzing** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería tomar un único argumento `[]byte` o `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodología:

- Usa grammar mode cuando las mutaciones a nivel de bytes mueren mayormente en las primeras comprobaciones de sintaxis.
- Mantén la grammar enfocada en el **subconjunto relevante para la seguridad** del lenguaje/protocolo en lugar de modelar la especificación completa.
- Usa valores límite grandes en terminales/no terminales para estresar integer, length y los bordes de state-machine.
- Grammar mode mantiene los inputs grammar-valid, pero el target sigue recibiendo **bytes/strings**, así que el parsing y las comprobaciones semánticas permanecen dentro del código harnessed.

### Differential fuzzing: compara implementaciones, no solo crashes

Un patrón sólido para ecosistemas Go es **grammar-based differential fuzzing**: generar inputs estructurados válidos y enviarlos a dos parsers, clients o motores de transición de estado.
```go
f.Fuzz(func(t *testing.T, data []byte) {
gotA, errA := ParseA(data)
gotB, errB := ParseB(data)
if (errA == nil) != (errB == nil) {
t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
}
_ = gotA
_ = gotB
})
```
Trata lo siguiente como findings:

- una implementación entra en panic mientras la otra rechaza limpiamente
- accepted/rejected input mismatches
- diferentes árboles de parseo u objetos decodificados
- transiciones de estado, nonces, balances o state roots divergentes

Esta es una forma práctica de encontrar **consensus mismatches**, **parser ambiguity** y **spec-vs-implementation drift** que el crash fuzzing puro a menudo pasa por alto.

### Reutiliza el corpus de la campaña para la cobertura report

Después de una campaña, vuelve a reproducir el queue corpus guardado para generar un Go coverage report sin exportar manualmente un corpus separado:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Ejecuta el comando desde el **mismo package** y con el mismo objetivo `-fuzz` para que gosentry resuelva el estado de campaña cacheado correcto.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
