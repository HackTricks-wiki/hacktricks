# Metodología de Fuzzing

## Fuzzing de Gramática Mutacional: Cobertura vs. Semántica

En el **fuzzing de gramática mutacional**, las entradas se modifican mientras siguen siendo **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como semillas del corpus las muestras que activan **nueva cobertura**. Para **objetivos de lenguaje** (parsers, intérpretes, engines), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos**, donde la salida de una construcción se convierte en la entrada de otra.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra semillas que ejercitan individualmente `document()` y `generate-id()` (u otras primitivas similares), pero **no conserva el flujo de datos encadenado**, por lo que la muestra “más cercana al bug” se descarta porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria se vuelve costosa y el feedback de cobertura no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **combinar fases mutacionales y generativas** o priorizar la generación de patrones de **encadenamiento de funciones** (no solo la cobertura).<sup>[[1]](#references)</sup>

## Problemas de Diversidad del Corpus

La mutación guiada por cobertura es **greedy**: una muestra con nueva cobertura se guarda inmediatamente, conservando a menudo grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, por lo que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene después de alcanzar un umbral mínimo de tokens** (reduce el ruido mientras conserva suficiente estructura circundante para seguir siendo fácil de mutar).<sup>[[1]](#references)</sup>

Una regla práctica para el corpus en el fuzzing mutacional es: **preferir un conjunto pequeño de semillas estructuralmente diferentes que maximicen la cobertura** en lugar de una gran cantidad de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empieza con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema objetivo).
- Destílalas mediante **minimización del corpus basada en cobertura** en lugar de conservar todas las muestras válidas.
- Mantén las semillas **lo bastante pequeñas** para que las mutaciones afecten a campos significativos en vez de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Vuelve a ejecutar la minimización del corpus después de cambios importantes en el harness o la instrumentación, porque el corpus “óptimo” cambia cuando cambia la alcanzabilidad.

## Mutación Consciente de Comparaciones Para Valores Mágicos

Una razón común por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, strings de enumeración, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas switch o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos objetivos, usa **trazado de comparaciones** (por ejemplo, workflows de estilo AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y orientar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>
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

- Esto resulta especialmente útil cuando el objetivo protege la lógica profunda mediante **firmas de archivos**, **verbos de protocolo**, **etiquetas de tipo** o **bits de funcionalidad dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o registros de depuración. Un diccionario pequeño con tokens de gramática, nombres de fragmentos, verbos y delimitadores suele ser más valioso que una wordlist genérica masiva.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las primeras comparaciones “mágicas” y vuelve a minimizar el corpus resultante para que las etapas posteriores comiencen con prefijos ya válidos.

## Fuzzing con estado: las secuencias son seeds

Para **protocolos**, **workflows autenticados** y **parsers de varias etapas**, la unidad interesante a menudo no es un blob individual, sino una **secuencia de mensajes**. Concatenar toda la transcripción en un solo archivo y mutarla a ciegas suele ser ineficiente, porque el fuzzer modifica cada paso por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.<sup>[[4]](#references)</sup>

Un patrón más eficaz consiste en tratar la **secuencia en sí como el seed** y utilizar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser y tipos de objetos devueltos) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor de respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere la mutación y el splicing por mensaje en lugar de mutar toda la transcripción serializada como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, utilízalos como un **oráculo de estado económico** para priorizar las secuencias que avanzan más profundamente.

Esta es la misma razón por la que los bugs autenticados, las transiciones ocultas o los bugs del parser que aparecen “solo después del handshake” suelen pasar desapercibidos con el fuzzing vanilla de estilo archivo: el fuzzer debe conservar el **orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

## Truco de diversidad en una sola máquina (estilo Jackalope)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de cobertura** consiste en **reiniciar workers de corta duración** contra un servidor persistente. Cada worker comienza con un corpus vacío, se sincroniza después de `T` segundos, ejecuta otros `T` segundos sobre el corpus combinado, vuelve a sincronizarse y después termina. Esto produce **estructuras nuevas en cada generación** y, al mismo tiempo, aprovecha la cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

**Servidor:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Workers secuenciales (bucle de ejemplo):**

<details>
<summary>Bucle de reinicio del worker de Jackalope</summary>
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

- `-in empty` fuerza un **fresh corpus** en cada generación.
- `-server_update_interval T` aproxima una **delayed sync** (primero novelty, después reuse).
- En el modo de grammar fuzzing, la **initial server sync** se omite de forma predeterminada (no es necesario usar `-skip_initial_server_sync`).
- El valor óptimo de `T` depende del **target**; normalmente funciona mejor cambiar después de que el worker haya encontrado la mayor parte de la coverage “easy”.

## Snapshot Fuzzing Para Targets Difíciles De Preparar

Cuando el código que quieres probar solo se vuelve accesible **después de un coste de preparación elevado** (iniciar una VM, completar un login, recibir un packet, analizar un container, inicializar un service), una alternativa útil es **snapshot fuzzing**: capturar el estado del process o VM listo, inyectar cada test case en la ruta de entrada del target, ejecutar hasta un crash/timeout y restaurar el snapshot. Esto evita repetir la inicialización o los prefijos del protocolo y resulta útil para **network services**, **firmware**, **post-auth attack surfaces** y **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el target hasta que el estado interesante esté listo.
2. Captura **memory + registers** en ese punto.
3. Para cada test case, escribe el input mutado directamente en el buffer relevante del guest/process.
4. Ejecuta hasta crash/timeout/reset.
5. Restaura el snapshot; para targets de VM, restaura únicamente las **dirty pages** cuando sea compatible y repite.

Coloca el snapshot lo más cerca posible del primer paso costoso de parse/dispatch, por ejemplo, después de un `recv`/`read` o de un punto de packet-deserialization, y registra el input buffer utilizado por el target. Esto sigue el principio de adaptive-placement: mover el snapshot más profundamente en el procesamiento del input para evitar repetir trabajo.<sup>[[11]](#references)</sup>

## Harness Introspection: Detectar Fuzzers Superficiales Pronto

Cuando una campaign se estanca, el problema a menudo no es el mutator, sino el **harness**. Usa **reachability/coverage introspection** para encontrar funciones que son estáticamente alcanzables desde tu fuzz target, pero que rara vez o nunca están cubiertas dinámicamente. Esas funciones normalmente indican uno de tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el target demasiado tarde o demasiado pronto.
- Al seed corpus le falta toda una familia de features.
- El target realmente necesita un **second harness** en lugar de un único harness sobredimensionado que lo haga “todo”.

Si usas workflows de estilo OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la reachability estática con la runtime coverage y generar reports a partir de un timed run o de un public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa el informe para decidir si añadir un nuevo harness para un parser path no probado, ampliar el corpus para una feature específica o dividir un harness monolítico en entry points más pequeños.

## Selección de Fuzz Targets y Triage de Mutaciones con Graph-First

Si ya tienes **static-analysis findings**, **mutation-testing survivors** y **coverage reports**, no los trates como listas independientes durante el triage. Construye primero un **call graph**, anota los nodos con **cyclomatic complexity**, **entrypoint/untrusted-input reachability** y cualquier finding externo, y después formula preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde un input no confiable?
- ¿Qué mutation survivors se encuentran en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son architectural choke points con un **blast radius** inusualmente alto?

Esto normalmente revela mejores fuzz targets que centrarse únicamente en la "lowest coverage". Un parser/decoder con **high complexity** y **external reachability** confirmada es un candidato más sólido para un harness que un helper interno aislado con una cobertura baja, pero sin una ruta controlada por el atacante.

### Flujo de trabajo práctico para el triage

1. Construye un **code graph** a partir del codebase y extrae las métricas de complejidad/branches de cada función.
2. Enumera los **entrypoints** que aceptan input controlado por el atacante: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Ejecuta **path queries** desde esos entrypoints hasta las funciones candidatas para separar la attack surface alcanzable del código muerto o únicamente interno.
4. Da prioridad a los nodos que combinen:
- alta **cyclomatic complexity**
- **reachability from untrusted input** confirmada
- alto **blast radius** o muchos dependents downstream
- evidencia adicional, como findings de **SARIF**, notas de auditoría o mutation survivors
5. Escribe harnesses enfocados para los nodos con mejor puntuación primero, especialmente **parsers/codecs**, como decoders de hex/Base64/IP/message.

### Mutation survivors: equivalentes frente a accionables

El mutation testing suele producir una lista ruidosa de survivors. Antes de tratar cada survivor como una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un entrypoint controlado por el atacante?
- ¿Todas las call paths están restringidas por invariants más fuertes que el check mutado?
- ¿El nodo se encuentra en código muerto, lógica que solo afecta al formatting o en una ruta aritmética/parser de alto impacto?

Los survivors que siguen siendo inalcanzables o están restringidos estructuralmente suelen ser **equivalent mutants**. Los survivors que continúan siendo **reachable** y afectan a **boundary conditions**, **overflow/carry paths** o **security-critical arithmetic/parsing** deben promoverse a:

- nuevos fuzz harnesses
- property/invariant tests directos
- edge-case vectors específicos

### Correlaciona los findings externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los findings sobre los nodos del grafo mediante **file + line range** y usa el grafo para ampliar el impacto.<sup>[[6]](#references)</sup>

- calcula el **blast radius** de la función señalada
- comprueba si el finding se encuentra en alguna ruta desde un entrypoint
- agrupa los findings cercanos que convergen en el mismo choke point

Esto resulta útil para decidir si dedicar tiempo de fuzzing a una función específica: un nodo que es **reachable**, complejo y que ya tiene **SAST hits** suele ser un target mejor que un nodo meramente complejo sin una ruta accesible para el atacante.

Ejemplo de flujo de trabajo con Trailmark.<sup>[[6]](#references)</sup>
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
La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para seleccionar los objetivos de fuzzing con el mayor valor de seguridad esperado y, después, usa los supervivientes de las mutaciones para decidir qué límites e invariantes debe someter a estrés tu harness.<sup>[[5]](#references)</sup>

## Fuzzing de Go con gosentry: motor más robusto, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo de `testing.F`, una vía práctica de mejora es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), un toolchain de Go bifurcado que conserva `go test -fuzz`, pero cambia el backend a **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Esto resulta útil cuando el fuzzer nativo de Go se atasca en **comparaciones difíciles**, **entradas tipadas** o **formatos con muchos parsers**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con scheduling/mutación de LibAFL y mejores detectores complementarios.

### Convertir fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en las evaluaciones de Go es que el comportamiento peligroso a menudo **no** provoca un crash de forma predeterminada. Con gosentry, puedes convertir varias clases de estados “incorrectos pero silenciosos” en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que determinadas rutas de logging/error se comporten como crashes (útil para rutas de código al estilo de `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para reproducir las entradas de cola recién descubiertas con el detector de race de Go.
- `--catch-leaks=true` para reproducir las nuevas entradas de cola con `goleak` y detenerse ante leaks de goroutines.
- El manejo de hangs de LibAFL para conservar los **bucles infinitos / inputs muy lentos** como hallazgos de fuzzing en lugar de dejar que desaparezcan como timeouts.
- Comprobaciones integradas de overflow aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto resulta especialmente valioso para objetivos cuyo impacto de seguridad es un **fallo de parser sin panic**, un **bug de concurrencia** o un **hang que solo provoca DoS**, en lugar de corrupción de memoria.

### Fuzzing consciente de structs para APIs de Go tipadas

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede hacer fuzzing directamente sobre **valores compuestos** (structs, slices, arrays, pointers) y seguir mutando bytes internamente.<sup>[[7]](#references)[[8]](#references)</sup>
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
Usa esto cuando construir un wire format falso solo para fuzzing pueda ocultar errores lógicos detrás de código de parsing exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y realiza el parsing dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolos

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **Nautilus grammar fuzzing** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodología:

- Usa el modo grammar cuando las mutaciones a nivel de byte mueran principalmente en las comprobaciones sintácticas iniciales.
- Mantén la grammar centrada en el **subconjunto relevante para la seguridad** del lenguaje/protocolo en lugar de modelar la especificación completa.
- Usa valores límite grandes en terminales/no terminales para poner a prueba los límites de enteros, longitudes y máquinas de estados.
- El modo grammar mantiene las entradas válidas según la grammar, pero el objetivo sigue recibiendo **bytes/cadenas**, por lo que el análisis sintáctico y las comprobaciones semánticas continúan dentro del código instrumentado.

### Differential fuzzing: comparar implementaciones, no solo crashes

Un patrón sólido para los ecosistemas de Go es el **grammar-based differential fuzzing**: generar entradas estructuradas válidas y pasarlas a dos parsers, clientes o motores de transición de estados.<sup>[[7]](#references)[[8]](#references)</sup>
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
Trata lo siguiente como hallazgos:

- una implementación entra en pánico mientras que la otra rechaza la entrada correctamente
- discrepancias entre entradas aceptadas/rechazadas
- diferentes árboles de análisis u objetos decodificados
- transiciones de estado, nonces, balances o raíces de estado divergentes

Esta es una forma práctica de encontrar **mismatches de consenso**, **ambigüedad del parser** y **desviaciones entre la especificación y la implementación** que el fuzzing puro de crashes suele pasar por alto.

### Reutiliza el corpus de la campaña para generar informes de cobertura

Después de una campaña, reproduce el corpus de la queue guardado para generar un informe de cobertura de Go sin exportar manualmente un corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Ejecuta el comando desde el **mismo package** y con el **mismo objetivo `-fuzz`** para que gosentry resuelva el estado correcto de la campaña en caché.

## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing de AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: sobre el fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing de Go le faltaba la mitad del kit de herramientas. Hemos bifurcado la toolchain para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática, no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptativos y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
