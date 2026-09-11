# Metodología de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de Gramática Mutacional: Cobertura frente a Semántica

En el **fuzzing de gramática mutacional**, las entradas se modifican manteniéndose **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como seeds del corpus las muestras que activan **nueva cobertura**. Para **targets de lenguajes** (parsers, intérpretes, engines), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos**, donde la salida de una construcción se convierte en la entrada de otra.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra seeds que ejercitan individualmente `document()` y `generate-id()` (u otras primitivas similares), pero **no conserva el flujo de datos encadenado**, por lo que la muestra “más cercana al bug” se descarta porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria se vuelve costosa y la retroalimentación de cobertura no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **hibridar fases mutacionales y generativas** o dar prioridad a patrones de **encadenamiento de funciones** (no solo a la cobertura).<sup>[[1]](#references)</sup>

## Problemas de Diversidad del Corpus

La mutación guiada por cobertura es **codiciosa**: una muestra con nueva cobertura se guarda inmediatamente y suele conservar grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, por lo que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene después de alcanzar un umbral mínimo de tokens** (reduce el ruido mientras conserva suficiente estructura circundante para seguir siendo compatible con las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para el corpus en el fuzzing mutacional es: **preferir un conjunto pequeño de seeds estructuralmente diferentes que maximicen la cobertura** frente a una gran acumulación de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Comenzar con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema del target).
- Destilarlas mediante la **minimización del corpus basada en cobertura** en lugar de conservar cada muestra válida.
- Mantener los seeds **lo bastante pequeños** para que las mutaciones aterricen en campos relevantes, en vez de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Volver a ejecutar la minimización del corpus después de cambios importantes en el harness o la instrumentación, porque el corpus “óptimo” cambia cuando cambia la alcanzabilidad.

## Mutación Consciente de Comparaciones Para Valores Mágicos

Una razón habitual por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, strings de enumeración, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas switch o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos targets, utiliza **trazado de comparaciones** (por ejemplo, flujos de trabajo de estilo AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y orientar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>
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

- Esto resulta especialmente útil cuando el objetivo protege la lógica profunda mediante **firmas de archivos**, **verbos de protocolo**, **etiquetas de tipo** o **bits de funciones dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o registros de depuración. Un diccionario pequeño con tokens de gramática, nombres de fragmentos, verbos y delimitadores suele ser más valioso que una wordlist genérica enorme.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “mágicas” más tempranas y vuelve a minimizar el corpus resultante para que las etapas posteriores comiencen con prefijos ya válidos.

## Feedback más detallado cuando la cobertura de aristas combina rutas diferentes

La cobertura normal de aristas no puede distinguir dos ejecuciones que atraviesan el mismo helper desde diferentes callers o que toman distintas combinaciones de ramas dentro de una función. Esto es importante en decodificadores compartidos, dispatchers de protocolos y helpers de intérpretes, donde la **ruta** hacia una arista determina el estado activo. Rastrear ingenuamente cada contexto de llamada también es peligroso: el mapa de cobertura y la cola pueden crecer descontroladamente. Por ello, la investigación sobre fuzzing sensible al contexto recomienda refinar solo los contextos prometedores en lugar de tratar todo el grafo de llamadas como sensible al contexto.<sup>[[14]](#references)</sup>

Las compilaciones recientes de AFL++ proporcionan **cobertura de rutas por función de Ball-Larus** además de la cobertura normal de aristas. Asigna una feature a cada ruta acíclica que atraviesa una función; las aristas de retorno de los bucles se eliminan, por lo que este feedback distingue las combinaciones de ramas, pero **no el número de iteraciones de los bucles**. Comienza con el nivel relajado `1` y limita después los modos más estrictos al código sospechoso de parsers y máquinas de estados, porque el número de rutas puede crecer exponencialmente.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Para un helper invocado desde muchos puntos relevantes para la seguridad, el modo LTO puede combinar cada ruta de función con su punto de llamada inmediato:<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Guía de la campaña:** aplica feedback más rico de forma conservadora y supervisa su coste en el coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Ejecuta en paralelo una instancia ordinaria de edge-coverage; el feedback más rico solo es útil si el coste adicional en queue/map no destruye las ejecuciones por segundo.
- Usa `AFL_LLVM_ALLOWLIST` para restringir la instrumentación de paths/callers cuando las bibliotecas grandes y heavily templated o el código de utilidades genéricas dominen el map.
- Las funciones con un número excesivo de paths acíclicos pueden omitirse en AFL++; las advertencias durante la compilación indican que el target necesita allowlisting o un nivel menos estricto.
- Caller + path coverage solo admite una profundidad de caller. No lo combines con context stacks más profundos.
- Los path IDs pueden cambiar entre versiones principales de LLVM. Mantén el toolchain fijo durante una campaña y no sincronices corpus basados en PATH como si sus feature IDs fueran estables entre builds.
- Este feedback complementa a `CMPLOG`: el comparison tracing resuelve **qué valor supera un guard**, mientras que el feedback de path/caller conserva **qué ruta y combinación de branches llegaron hasta él**.

## Stateful Fuzzing: las secuencias son seeds

Para **protocolos**, **workflows autenticados** y **parsers multi-stage**, la unidad interesante a menudo no es un blob individual, sino una **secuencia de mensajes**. Concatenar todo el transcript en un único archivo y mutarlo a ciegas suele ser ineficiente porque el fuzzer muta cada paso por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.<sup>[[4]](#references)</sup>

Un patrón más eficaz consiste en tratar la **secuencia en sí como el seed** y usar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser, tipos de objetos devueltos) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor de respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere la mutación/splicing por mensaje en lugar de mutar todo el transcript serializado como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, úsalos como un **state oracle barato** para priorizar las secuencias que avanzan más profundamente.

Esta es la misma razón por la que los bugs autenticados, las transiciones ocultas o los bugs de parser que aparecen “solo después del handshake” suelen no ser detectados por el fuzzing vanilla de estilo file: el fuzzer debe preservar **el orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Una forma práctica de combinar la **novedad generativa** con el **reuse de coverage** consiste en **reiniciar workers de corta duración** contra un servidor persistente. Cada worker comienza con un corpus vacío, sincroniza después de `T` segundos, ejecuta durante otros `T` segundos sobre el corpus combinado, vuelve a sincronizar y después termina. Esto produce **estructuras nuevas en cada generación** y, al mismo tiempo, aprovecha la coverage acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

**Servidor:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Trabajadores secuenciales (bucle de ejemplo):**

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

- `-in empty` fuerza un **corpus nuevo** en cada generación.
- `-server_update_interval T` aproxima una **sincronización retrasada** (primero novelty, después reuse).
- En el modo de grammar fuzzing, la **sincronización inicial del servidor** se omite de forma predeterminada (no es necesario usar `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del target**; normalmente funciona mejor cambiar después de que el worker haya encontrado la mayor parte de la coverage “fácil”.

## Snapshot Fuzzing Para Targets Difíciles de Harness

Cuando el código que quieres probar solo se vuelve accesible **después de un coste de configuración elevado** (iniciar una VM, completar un login, recibir un paquete, parsear un contenedor o inicializar un servicio), una alternativa útil es **snapshot fuzzing**: captura el estado del proceso o la VM preparada, inyecta cada test case en la ruta de entrada del target, ejecuta hasta que ocurra un crash/timeout y restaura el snapshot. Esto evita repetir la inicialización o los prefijos del protocolo y resulta útil para **servicios de red**, **firmware**, **superficies de ataque post-auth** y **targets que solo disponen de binarios**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el target hasta que el estado interesante esté preparado.
2. Captura un snapshot de la **memoria + registros** en ese punto.
3. Para cada test case, escribe el input mutado directamente en el buffer relevante del guest/proceso.
4. Ejecuta hasta que ocurra un crash/timeout/reset.
5. Restaura el snapshot; para targets de VM, restaura solo las **páginas dirty** cuando sea posible y repite.

Coloca el snapshot lo más cerca posible del primer paso costoso de parse/dispatch, como después de un `recv`/`read` o de un punto de deserialización de paquetes, y registra el buffer de entrada utilizado por el target. Esto sigue el principio de colocación adaptativa, que consiste en mover el snapshot más profundamente en el procesamiento del input para evitar repetir trabajo.<sup>[[11]](#references)</sup>

## Introspección del Harness: Detecta Pronto los Fuzzers Superficiales

Cuando una campaña se estanca, a menudo el problema no es el **mutator**, sino el **harness**. Usa la **introspección de reachability/coverage** para encontrar funciones que son estáticamente alcanzables desde tu fuzz target, pero que rara vez o nunca están cubiertas dinámicamente. Estas funciones suelen indicar uno de tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el target demasiado tarde o demasiado pronto.
- Al seed corpus le falta toda una familia de funcionalidades.
- El target realmente necesita un **segundo harness** en lugar de un harness sobredimensionado que “lo haga todo”.

Si utilizas workflows de estilo OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la reachability estática con la coverage en runtime y generar informes a partir de un run cronometrado o de un corpus público.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa el informe para decidir si añadir un nuevo harness para una ruta del parser no probada, ampliar el corpus para una característica específica o dividir un harness monolítico en entry points más pequeños.

## Selección de objetivos de fuzzing basada primero en el grafo y triaje de mutaciones

Si ya tienes **hallazgos de análisis estático**, **supervivientes de mutation testing** e **informes de cobertura**, no los analices como listas independientes. Construye primero un **call graph**, anota los nodos con la **complejidad ciclomática**, la **alcanzabilidad desde entry points/input no confiable** y cualquier hallazgo externo, y después formula preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde input no confiable?
- ¿Qué supervivientes de mutaciones se encuentran en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **blast radius** inusualmente alto?

Esto suele revelar mejores objetivos de fuzzing que basarse únicamente en la "menor cobertura". Un parser/decoder con **alta complejidad** y **alcanzabilidad externa** confirmada es un candidato más sólido para un harness que un helper interno aislado con una cobertura débil, pero sin una ruta controlada por el atacante.

### Flujo de trabajo práctico de triaje

1. Construye un **code graph** a partir del codebase y extrae las métricas de complejidad/ramas por función.
2. Enumera los **entry points** que aceptan input controlado por el atacante: request handlers, decoders, importers, protocol parsers y lectores de CLI/archivos.
3. Ejecuta **path queries** desde esos entry points hasta las funciones candidatas para separar la superficie de ataque alcanzable del código muerto o solo interno.
4. Da prioridad a los nodos que combinen:
- alta **complejidad ciclomática**
- **alcanzabilidad confirmada desde input no confiable**
- alto **blast radius** o muchos dependientes posteriores
- evidencias adicionales, como hallazgos **SARIF**, notas de auditoría o supervivientes de mutaciones
5. Escribe primero harnesses enfocados para los nodos con mejor puntuación, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Supervivientes de mutaciones: equivalentes frente a accionables

El mutation testing suele producir una lista ruidosa de supervivientes. Antes de tratar cada superviviente como una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un entry point controlado por el atacante?
- ¿Todas las rutas de llamada están restringidas por invariantes más fuertes que la comprobación mutada?
- ¿El nodo se encuentra en código muerto, lógica relacionada únicamente con el formato o una ruta aritmética/parser de alto impacto?

Los supervivientes que siguen siendo inalcanzables o están restringidos estructuralmente suelen ser **mutantes equivalentes**. Los supervivientes que permanecen **alcanzables** y afectan a **condiciones límite**, **rutas de overflow/carry** o **aritmética/parsing crítico para la seguridad** deberían convertirse en:

- nuevos fuzz harnesses
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlacionar hallazgos externos en el grafo

Si tu pipeline SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo mediante **archivo + rango de líneas** y usa el grafo para ampliar el impacto.<sup>[[6]](#references)</sup>

- calcula el **blast radius** de la función señalada
- comprueba si el hallazgo se encuentra en alguna ruta desde un entry point
- agrupa los hallazgos cercanos que converjan en el mismo punto de estrangulamiento

Esto resulta útil al decidir si invertir tiempo de fuzzing en una función específica: un nodo que sea **alcanzable**, **complejo** y que ya tenga **hallazgos de SAST** suele ser un objetivo mejor que un nodo meramente complejo sin ninguna ruta controlada por el atacante.

Flujo de trabajo de ejemplo con Trailmark.<sup>[[6]](#references)</sup>
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
La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para seleccionar los objetivos de fuzzing con el mayor valor de seguridad esperado y, después, utiliza los supervivientes de las mutaciones para decidir qué límites e invariantes debe poner a prueba tu harness.<sup>[[5]](#references)</sup>

## Fuzzing en Go con gosentry: un engine más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo de `testing.F`, una ruta de actualización práctica consiste en ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una cadena de herramientas de Go bifurcada que conserva `go test -fuzz`, pero cambia el backend a **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Esto resulta útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con muchos parsers**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con scheduling/mutation de LibAFL y mejores detectores complementarios.

### Convertir fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en los assessments de Go es que el comportamiento peligroso a menudo **no** provoca un crash de forma predeterminada. Con gosentry, puedes convertir varias clases de estados “incorrectos pero silenciosos” en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que determinadas rutas de logging/error se comporten como crashes (útil para rutas de código de estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las nuevas entradas de la queue con el race detector de Go.
- `--catch-leaks=true` para volver a ejecutar las nuevas entradas de la queue con `goleak` y detenerse ante leaks de goroutines.
- Gestión de hangs de LibAFL para conservar los **bucles infinitos / inputs muy lentos** como hallazgos de fuzzing, en lugar de dejar que desaparezcan como timeouts.
- Checks integrados de overflow aritmético de forma predeterminada, además de checks opcionales de truncation mediante instrumentación de estilo go-panikint.

Esto resulta especialmente valioso para targets cuyo impacto de seguridad es un **fallo de parser sin panic**, un **bug de concurrencia** o un **hang que solo provoca DoS**, en lugar de corrupción de memoria.

### Fuzzing de structs para APIs de Go tipadas

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo test consume objetos tipados, gosentry puede hacer fuzzing directamente sobre **valores compuestos** (structs, slices, arrays, pointers) mientras sigue mutando bytes internamente.<sup>[[7]](#references)[[8]](#references)</sup>
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
Usa esto al crear un wire format falso únicamente para fuzzing, ya que ocultaría errores de lógica detrás de código de análisis exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único argumento `[]byte` o `string` y realiza el análisis dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolos

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **Nautilus grammar fuzzing** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas sobre metodología:

- Usa grammar mode cuando las mutaciones a nivel de byte mueren principalmente en las primeras comprobaciones de sintaxis.
- Mantén la gramática centrada en el **subconjunto relevante para la seguridad** del lenguaje/protocolo, en lugar de modelar la especificación completa.
- Usa valores límite grandes en terminales/no terminales para someter a estrés los límites de enteros, longitudes y máquinas de estados.
- grammar mode mantiene las entradas válidas según la gramática, pero el target sigue recibiendo **bytes/strings**, por lo que el análisis sintáctico y las comprobaciones semánticas permanecen dentro del código bajo prueba.

### Differential fuzzing: compara implementaciones, no solo crashes

Un patrón sólido para los ecosistemas de Go es **grammar-based differential fuzzing**: genera entradas estructuradas válidas y pásalas a dos parsers, clientes o motores de transición de estados.<sup>[[7]](#references)[[8]](#references)</sup>
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

- una implementación entra en panic mientras que la otra rechaza limpiamente
- discrepancias entre las entradas aceptadas/rechazadas
- árboles de análisis sintáctico u objetos decodificados diferentes
- transiciones de estado, nonces, balances o raíces de estado divergentes

Esta es una forma práctica de encontrar **discrepancias de consenso**, **ambigüedad del parser** y **desviaciones entre la especificación y la implementación** que el fuzzing puro de crashes suele pasar por alto.

### Reutilizar el corpus de la campaña para generar informes de cobertura

Después de una campaña, reproduce el corpus de la queue guardado para generar un informe de cobertura de Go sin exportar manualmente un corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Ejecuta el comando desde el **mismo paquete** y con el mismo objetivo de `-fuzz` para que gosentry resuelva el estado de campaña almacenado en caché correcto.



## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing de AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: sobre el fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte el código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing de Go le faltaba la mitad del kit de herramientas. Hemos bifurcado la toolchain para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática, no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptativos y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentación LLVM de AFL++: cobertura de rutas y de llamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predictivo sensible al contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
