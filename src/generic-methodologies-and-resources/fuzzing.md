# Metodología de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Cobertura vs. Semántica

En **mutational grammar fuzzing**, las entradas se modifican mientras siguen siendo **válidas según la gramática**. En el modo coverage-guided, solo se guardan como corpus seeds las muestras que activan **nueva cobertura**. Para **language targets** (parsers, intérpretes, motores), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos** donde la salida de una construcción se convierte en la entrada de otra.

**Modo de fallo:** el fuzzer encuentra seeds que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no conserva el flujo de datos encadenado**, por lo que la muestra “más cercana al bug” se descarta porque no añade cobertura. Con **3+ pasos dependientes**, la recombinación aleatoria se vuelve costosa y el feedback de cobertura no guía la búsqueda.

**Implicación:** para gramáticas con muchas dependencias, considera **combinar fases mutational y generative** o sesgar la generación hacia patrones de **function chaining** (no solo hacia la cobertura).<sup>[[1]](#references)</sup>

## Problemas de Diversidad del Corpus

La mutación coverage-guided es **greedy**: una muestra con nueva cobertura se guarda inmediatamente y suele conservar grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **near-duplicates** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, por lo que un compromiso práctico es la **minimización grammar-aware**, que **se detiene después de alcanzar un umbral mínimo de tokens** (reduce el ruido mientras conserva suficiente estructura circundante para seguir facilitando las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para el corpus en mutational fuzzing es: **preferir un conjunto pequeño de seeds estructuralmente diferentes que maximicen la cobertura** en lugar de una gran acumulación de near-duplicates. En la práctica, esto normalmente significa:<sup>[[1]](#references)</sup>

- Comenzar con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema objetivo).
- Destilarlas mediante **minimización del corpus basada en cobertura** en lugar de conservar cada muestra válida.
- Mantener los seeds **lo suficientemente pequeños** para que las mutaciones afecten campos significativos, en lugar de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Volver a ejecutar la minimización del corpus después de realizar cambios importantes en el harness o la instrumentación, porque el corpus “óptimo” cambia cuando cambia la reachability.

## Mutación Basada en Comparaciones Para Magic Values

Una razón común por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: magic bytes, comprobaciones de longitud, cadenas enum, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas switch o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos objetivos, utiliza **trazado de comparaciones** (por ejemplo, flujos de trabajo de estilo AFL++ `CMPLOG` / Redqueen), de modo que el fuzzer pueda observar los operandos de las comparaciones fallidas y sesgar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>
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

- Esto resulta especialmente útil cuando el objetivo bloquea la lógica profunda tras **firmas de archivo**, **verbos de protocolo**, **etiquetas de tipo** o **bits de funcionalidades dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o logs de depuración. Un diccionario pequeño con tokens de gramática, nombres de chunks, verbos y delimitadores suele ser más valioso que una wordlist genérica enorme.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “mágicas” más tempranas y vuelve a minimizar el corpus resultante para que las etapas posteriores comiencen con prefijos ya válidos.

## Fuzzing con estado: las secuencias son seeds

Para **protocolos**, **workflows autenticados** y **parsers de varias etapas**, la unidad interesante a menudo no es un blob individual, sino una **secuencia de mensajes**. Concatenar todo el transcript en un único archivo y mutarlo a ciegas suele ser ineficiente, porque el fuzzer modifica cada paso por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.

Un patrón más eficaz consiste en tratar la **secuencia en sí como el seed** y utilizar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser, tipos de objetos devueltos) como feedback adicional:<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Almacena en caché los identificadores y valores generados por el servidor a partir de respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere la mutación/splicing por mensaje en lugar de mutar todo el transcript serializado como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, utilízalos como una **oracle de estado económica** para priorizar las secuencias que avanzan más profundamente.

Esta es la misma razón por la que los bugs autenticados, las transiciones ocultas o los bugs del parser que aparecen “solo después del handshake” suelen pasar desapercibidos con el fuzzing vanilla basado en archivos: el fuzzer debe conservar el **orden, el estado y las dependencias**, no solo la estructura.

## Truco de diversidad en una sola máquina (estilo Jackalope)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de cobertura** consiste en **reiniciar workers de corta duración** contra un servidor persistente. Cada worker comienza con un corpus vacío, sincroniza después de `T` segundos, se ejecuta otros `T` segundos sobre el corpus combinado, vuelve a sincronizar y después finaliza. Esto produce **estructuras nuevas en cada generación** y, al mismo tiempo, aprovecha la cobertura acumulada.<sup>[[2]](#references)</sup>

**Servidor:**
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
- `-server_update_interval T` aproxima una **sincronización retrasada** (primero novedad, después reutilización).
- En el modo de grammar fuzzing, la **sincronización inicial del servidor** se omite de forma predeterminada (no es necesario usar `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del target**; normalmente funciona mejor cambiar después de que el worker haya encontrado la mayor parte de la cobertura “fácil”.

## Snapshot Fuzzing Para Targets Difíciles De Preparar

Cuando el código que quieres probar solo se vuelve accesible **después de un coste de preparación elevado** (iniciar una VM, completar un inicio de sesión, recibir un paquete, analizar un container, inicializar un servicio), una alternativa útil es **snapshot fuzzing**:

1. Ejecuta el target hasta que el estado interesante esté listo.
2. Crea un snapshot de la **memoria + registros** en ese punto.
3. Para cada caso de prueba, escribe el input mutado directamente en el buffer relevante del guest/proceso.
4. Ejecuta hasta que se produzca un crash/timeout/reset.
5. Restaura solo las **páginas modificadas** y repite.

Esto evita pagar el coste total de preparación en cada iteración y es especialmente útil para **network services**, **firmware**, **attack surfaces posteriores a la autenticación** y **targets binary-only** que resulta complicado refactorizar en un harness clásico in-process.

Un truco práctico consiste en detener la ejecución inmediatamente después de un punto de `recv`/`read`/deserialización de paquetes, anotar la dirección del buffer de input, crear allí el snapshot y mutar después ese buffer directamente en cada iteración. Esto permite hacer fuzzing de la lógica de parsing profunda sin reconstruir todo el handshake cada vez.

## Introspección Del Harness: Detecta Pronto Los Fuzzers Superficiales

Cuando una campaña se estanca, a menudo el problema no es el mutator, sino el **harness**. Usa la **introspección de reachability/cobertura** para encontrar funciones que son alcanzables estáticamente desde tu fuzz target, pero que rara vez se cubren dinámicamente o nunca lo hacen. Estas funciones suelen indicar uno de tres problemas:

- El harness entra en el target demasiado tarde o demasiado pronto.
- Al seed corpus le falta una familia completa de funcionalidades.
- El target realmente necesita un **segundo harness** en lugar de un único harness sobredimensionado que “lo haga todo”.

Si utilizas workflows de tipo OSS-Fuzz / ClusterFuzz, Fuzz Introspector resulta útil para este triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa el informe para decidir si añadir un nuevo harness para una ruta de parser no probada, ampliar el corpus para una funcionalidad específica o dividir un harness monolítico en entry points más pequeños.

## Selección de objetivos de fuzzing basada primero en el grafo y triaje de mutaciones

Si ya tienes **hallazgos de static-analysis**, **supervivientes de mutation-testing** e **informes de cobertura**, no los clasifiques como listas independientes. Construye primero un **call graph**, anota los nodos con **complejidad ciclomática**, **alcanzabilidad desde entrypoints/entradas no confiables** y cualquier hallazgo externo, y después formula preguntas sobre el grafo:<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde entradas no confiables?
- ¿Qué supervivientes de mutaciones se encuentran en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **blast radius** inusualmente alto?

Esto suele revelar mejores objetivos de fuzzing que basarse únicamente en la "menor cobertura". Un parser/decoder con **alta complejidad** y **alcanzabilidad externa** confirmada es un candidato más sólido para un harness que un helper interno aislado con cobertura débil, pero sin una ruta controlada por el atacante.

### Flujo de trabajo práctico de triaje

1. Construye un **code graph** a partir del codebase y extrae las métricas de complejidad/ramas por función.
2. Enumera los **entrypoints** que aceptan input controlado por el atacante: request handlers, decoders, importers, protocol parsers, lectores de CLI/archivos.
3. Ejecuta **path queries** desde esos entrypoints hasta las funciones candidatas para separar la attack surface alcanzable del código muerto o solo interno.
4. Da prioridad a los nodos que combinen:
- alta **complejidad ciclomática**
- **alcanzabilidad desde input no confiable** confirmada
- alto **blast radius** o muchos dependientes downstream
- evidencias adicionales como hallazgos de **SARIF**, notas de auditoría o supervivientes de mutaciones
5. Escribe harnesses enfocados para los nodos con mayor puntuación primero, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Supervivientes de mutaciones: equivalentes frente a accionables

Mutation testing suele producir una lista ruidosa de supervivientes. Antes de tratar cada superviviente como una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un entrypoint controlado por el atacante?
- ¿Todas las call paths están limitadas por invariantes más fuertes que la comprobación mutada?
- ¿El nodo pertenece a código muerto, lógica que solo afecta al formato o a una ruta aritmética/parser de alto impacto?

Los supervivientes que siguen siendo inalcanzables o están restringidos estructuralmente suelen ser **mutantes equivalentes**. Los supervivientes que siguen siendo **alcanzables** y afectan a **condiciones límite**, **rutas de overflow/carry** o **aritmética/parsing crítico para la seguridad** deben promoverse a:

- nuevos fuzz harnesses
- tests directos de propiedades/invariantes
- vectores específicos de casos límite

### Correlacionar hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo mediante **archivo + rango de líneas** y usa el grafo para ampliar el impacto:

- calcula el **blast radius** de la función señalada
- comprueba si el hallazgo se encuentra en alguna ruta desde un entrypoint
- agrupa los hallazgos cercanos que converjan en el mismo punto de estrangulamiento

Esto resulta útil al decidir si dedicar tiempo de fuzzing a una función concreta: un nodo que sea **alcanzable**, **complejo** y que ya tenga **hallazgos de SAST** suele ser un objetivo mejor que un nodo meramente complejo sin ninguna ruta de ataque.

Flujo de trabajo de ejemplo con Trailmark:<sup>[[6]](#references)</sup>
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
La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para seleccionar objetivos de fuzzing con el mayor valor de seguridad esperado y, después, utiliza los supervivientes de las mutaciones para decidir qué límites e invariantes debe someter a estrés tu harness.

## Fuzzing de Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya cuenta con un harness nativo de `testing.F`, una ruta práctica de mejora consiste en ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una cadena de herramientas de Go bifurcada que mantiene `go test -fuzz`, pero cambia el backend a **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Esto resulta útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con uso intensivo de parsers**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar del toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con scheduling/mutation de LibAFL y mejores detectores adicionales.

### Convertir fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en las evaluaciones de Go es que el comportamiento peligroso a menudo **no** provoca un crash por defecto. Con gosentry, puedes convertir varias clases de estados “malos pero silenciosos” en hallazgos:

- `--panic-on=pkg.Func,...` para hacer que determinadas rutas de logging/error se comporten como crashes (útil para rutas de código de estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para reproducir las nuevas entradas descubiertas de la queue con el race detector de Go.
- `--catch-leaks=true` para reproducir las nuevas entradas de la queue con `goleak` y detenerse ante fugas de goroutines.
- Gestión de hangs de LibAFL para conservar los **bucles infinitos / inputs muy lentos** como hallazgos de fuzzing en lugar de dejarlos desaparecer como timeouts.
- Comprobaciones integradas de overflow aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto es especialmente valioso para targets cuyo impacto de seguridad consiste en un **fallo de parser sin panic**, un **bug de concurrencia** o un **hang que solo provoca DoS**, en lugar de corrupción de memoria.

### Fuzzing consciente de structs para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede hacer fuzzing directamente sobre **valores compuestos** (structs, slices, arrays, pointers) mientras sigue mutando bytes internamente.
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
Usa esto al crear un wire format falso únicamente para fuzzing, ya que ocultaría errores lógicos detrás de código de parsing exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y realiza el parsing dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolos

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **Nautilus grammar fuzzing** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodología:

- Usa **grammar mode** cuando las mutaciones a nivel de byte mueran principalmente en las primeras comprobaciones de sintaxis.
- Mantén la grammar enfocada en el **subconjunto relevante para la seguridad** del lenguaje/protocolo en lugar de modelar la especificación completa.
- Usa valores límite grandes en terminals/nonterminals para someter a estrés los límites de enteros, longitudes y máquinas de estados.
- **grammar mode** mantiene los inputs válidos según la grammar, pero el objetivo sigue recibiendo **bytes/strings**, por lo que el parsing y las comprobaciones semánticas permanecen dentro del código instrumentado.

### Differential fuzzing: compara implementaciones, no solo crashes

Un patrón sólido para los ecosistemas de Go es el **grammar-based differential fuzzing**: genera inputs estructurados válidos y pásalos a dos parsers, clientes o motores de transición de estados.
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
Considera lo siguiente como hallazgos:

- una implementación entra en pánico mientras que la otra rechaza la entrada correctamente
- discrepancias entre las entradas aceptadas/rechazadas
- diferentes árboles de análisis u objetos decodificados
- transiciones de estado, nonces, balances o raíces de estado divergentes

Esta es una forma práctica de encontrar **incompatibilidades de consenso**, **ambigüedad del parser** y **desviaciones entre la especificación y la implementación** que las pruebas de fuzzing centradas únicamente en fallos suelen pasar por alto.

### Reutiliza el corpus de la campaña para generar informes de cobertura

Después de una campaña, reproduce el corpus de la cola guardado para generar un informe de cobertura de Go sin exportar manualmente un corpus separado:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Ejecuta el comando desde el **mismo paquete** y con el mismo objetivo `-fuzz` para que gosentry resuelva el estado de campaña almacenado en caché correcto.

## Referencias

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
