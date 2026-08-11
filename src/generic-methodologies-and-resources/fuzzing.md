# Metodología de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Cobertura frente a semántica

En **mutational grammar fuzzing**, las entradas se mutan mientras siguen siendo **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como semillas del corpus las muestras que activan **nueva cobertura**. Para **objetivos de lenguajes** (parsers, intérpretes, engines), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos**, donde la salida de un constructo se convierte en la entrada de otro.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra semillas que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no conserva el flujo de datos encadenado**, por lo que la muestra “más cercana al bug” se descarta porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria se vuelve costosa y el feedback de cobertura no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **hibridar fases mutacionales y generativas** o sesgar la generación hacia patrones de **encadenamiento de funciones** (no solo hacia la cobertura).<sup>[[1]](#references)</sup>

## Problemas de diversidad del corpus

La mutación guiada por cobertura es **codiciosa**: una muestra con nueva cobertura se guarda inmediatamente, conservando a menudo grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, por lo que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene tras alcanzar un umbral mínimo de tokens** (reduce el ruido mientras conserva suficiente estructura circundante para seguir siendo favorable a la mutación).<sup>[[1]](#references)</sup>

Una regla práctica para el corpus en mutational fuzzing es: **preferir un conjunto pequeño de semillas estructuralmente diferentes que maximicen la cobertura** frente a una gran cantidad de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empieza con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema objetivo).
- Destílalas mediante **minimización del corpus basada en cobertura** en lugar de conservar todas las muestras válidas.
- Mantén las semillas **lo bastante pequeñas** para que las mutaciones recaigan sobre campos significativos, en vez de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Vuelve a ejecutar la minimización del corpus tras cambios importantes en el harness o la instrumentación, porque el corpus “mejor” cambia cuando cambia la alcanzabilidad.

## Mutación consciente de comparaciones para valores mágicos

Un motivo común por el que los fuzzers llegan a una meseta no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, strings de enumeración, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas `switch` o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos objetivos, usa **trazado de comparaciones** (por ejemplo, flujos de trabajo de estilo AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y sesgar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>
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

- Esto es especialmente útil cuando el objetivo bloquea la lógica profunda tras **firmas de archivos**, **verbos de protocolo**, **etiquetas de tipo** o **feature bits dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o debug logs. Un diccionario pequeño con tokens de gramática, nombres de chunks, verbos y delimitadores suele ser más valioso que una wordlist genérica masiva.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “magic” más tempranas y vuelve a minimizar el corpus resultante para que las etapas posteriores comiencen a partir de prefijos ya válidos.

## Stateful Fuzzing: las secuencias son seeds

Para **protocolos**, **workflows autenticados** y **parsers de varias etapas**, la unidad interesante a menudo no es un blob individual, sino una **secuencia de mensajes**. Concatenar todo el transcript en un único archivo y mutarlo a ciegas suele ser ineficiente porque el fuzzer modifica cada paso por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.<sup>[[4]](#references)</sup>

Un patrón más eficaz consiste en tratar la **secuencia como el seed** y utilizar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser y tipos de objetos devueltos) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor a partir de respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere la mutación/splicing por mensaje en lugar de mutar todo el transcript serializado como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, utilízalos como un **state oracle barato** para priorizar las secuencias que avanzan más profundamente.

Esta es la misma razón por la que los bugs autenticados, las transiciones ocultas o los bugs de parser que aparecen “solo después del handshake” suelen pasar desapercibidos con el fuzzing vanilla de estilo archivo: el fuzzer debe preservar el **orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de coverage** es **reiniciar workers de corta duración** contra un servidor persistente. Cada worker comienza con un corpus vacío, sincroniza después de `T` segundos, ejecuta durante otros `T` segundos sobre el corpus combinado, vuelve a sincronizar y luego termina. Esto produce **estructuras nuevas en cada generación** sin dejar de aprovechar la coverage acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` aproxima una **delayed sync** (primero novedad, después reutilización).
- En el modo de **grammar fuzzing**, la **initial server sync** se omite de forma predeterminada (no es necesario usar `-skip_initial_server_sync`).
- El valor óptimo de `T` depende del **target**; normalmente funciona mejor cambiar después de que el worker haya encontrado la mayor parte de la cobertura “fácil”.

## Snapshot Fuzzing For Hard-To-Harness Targets

Cuando el código que quieres probar solo se vuelve accesible **después de un coste de configuración elevado** (iniciar una VM, completar un login, recibir un paquete, parsear un contenedor, inicializar un servicio), una alternativa útil es **snapshot fuzzing**: captura el estado del proceso o VM listo, inyecta cada test case en la ruta de entrada del target, ejecuta hasta que se produzca un crash/timeout y restaura el snapshot. Esto evita repetir la inicialización o los prefijos del protocolo y resulta útil para **network services**, **firmware**, **post-auth attack surfaces** y **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el target hasta que el estado interesante esté listo.
2. Captura un snapshot de la **memoria + registros** en ese punto.
3. Para cada test case, escribe el input mutado directamente en el buffer relevante del guest/proceso.
4. Ejecuta hasta que se produzca un crash/timeout/reset.
5. Restaura el snapshot; para targets de VM, restaura únicamente las **dirty pages** cuando sea compatible y repite.

Coloca el snapshot lo más cerca posible del primer paso costoso de parseo/dispatch, por ejemplo, después de un `recv`/`read` o de un punto de deserialización de paquetes, y registra el buffer de entrada utilizado por el target. Esto sigue el principio de colocación adaptativa: mover el snapshot más profundamente en el procesamiento del input para evitar repetir trabajo.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Cuando una campaña se estanca, el problema a menudo no está en el mutator, sino en el **harness**. Usa **reachability/coverage introspection** para encontrar funciones que son estáticamente alcanzables desde tu fuzz target, pero que rara vez o nunca se cubren de forma dinámica. Esas funciones normalmente indican uno de tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el target demasiado tarde o demasiado pronto.
- Al seed corpus le falta toda una familia de funcionalidades.
- El target realmente necesita un **second harness** en lugar de un único harness sobredimensionado que “lo haga todo”.

Si utilizas flujos de trabajo al estilo OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la alcanzabilidad estática con la cobertura en tiempo de ejecución y generar informes a partir de una ejecución cronometrada o de un corpus público.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Usa el informe para decidir si añadir un nuevo harness para una ruta de parser no probada, ampliar el corpus para una funcionalidad específica o dividir un harness monolítico en varios puntos de entrada.

## Selección de objetivos de fuzzing basada primero en grafos y triaje de mutaciones

Si ya tienes **hallazgos de análisis estático**, **supervivientes de mutation testing** e **informes de cobertura**, no los sometas a triaje como listas independientes. Construye primero un **grafo de llamadas**, anota los nodos con **complejidad ciclomática**, **alcanzabilidad desde puntos de entrada/entradas no confiables** y cualquier hallazgo externo, y después plantea preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde entradas no confiables?
- ¿Qué supervivientes de mutaciones se encuentran en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **radio de impacto** inusualmente alto?

Esto suele revelar mejores objetivos de fuzzing que basarse únicamente en la "menor cobertura". Un parser/decoder con **alta complejidad** y **alcanzabilidad externa confirmada** es un candidato más sólido para un harness que un helper interno aislado con cobertura débil pero sin una ruta controlada por un atacante.

### Flujo de trabajo práctico de triaje

1. Construye un **grafo de código** a partir del código base y extrae las métricas de complejidad/ramas de cada función.
2. Enumera los **puntos de entrada** que aceptan entradas controladas por un atacante: request handlers, decoders, importers, protocol parsers y lectores de CLI/archivos.
3. Ejecuta **consultas de rutas** desde esos puntos de entrada hasta las funciones candidatas para separar la superficie de ataque alcanzable del código muerto o exclusivamente interno.
4. Da prioridad a los nodos que combinen:
- alta **complejidad ciclomática**
- **alcanzabilidad confirmada desde entradas no confiables**
- alto **radio de impacto** o muchos dependientes posteriores
- evidencias adicionales como hallazgos de **SARIF**, notas de auditoría o supervivientes de mutaciones
5. Escribe harnesses específicos para los nodos con mejor puntuación primero, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Supervivientes de mutaciones: equivalentes frente a accionables

Mutation testing suele producir una lista ruidosa de supervivientes. Antes de considerar cada superviviente una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un punto de entrada controlado por un atacante?
- ¿Todas las rutas de llamada están restringidas por invariantes más fuertes que la comprobación mutada?
- ¿El nodo se encuentra en código muerto, lógica relacionada únicamente con el formato o en una ruta aritmética/parser de alto impacto?

Los supervivientes que siguen siendo inalcanzables o están restringidos estructuralmente suelen ser **mutantes equivalentes**. Los supervivientes que siguen siendo **alcanzables** y afectan a **condiciones límite**, **rutas de overflow/carry** o **aritmética/parsing críticos para la seguridad** deberían convertirse en:

- nuevos fuzz harnesses
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlacionar hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo mediante **archivo + rango de líneas** y usa el grafo para ampliar el impacto.<sup>[[6]](#references)</sup>

- calcula el **radio de impacto** de la función señalada
- comprueba si el hallazgo se encuentra en alguna ruta desde un punto de entrada
- agrupa los hallazgos cercanos que converjan en el mismo punto de estrangulamiento

Esto resulta útil al decidir si dedicar tiempo de fuzzing a una función específica: un nodo que sea **alcanzable**, **complejo** y que ya tenga **hallazgos de SAST** suele ser un objetivo mejor que un nodo meramente complejo sin ninguna ruta controlada por un atacante.

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
La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir los objetivos de fuzzing con el mayor valor de seguridad esperado y, después, usa los supervivientes de las mutaciones para decidir qué límites e invariantes debe someter a estrés tu harness.<sup>[[5]](#references)</sup>

## Fuzzing de Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo de `testing.F`, una ruta práctica de actualización es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), un toolchain bifurcado de Go que conserva `go test -fuzz`, pero cambia el backend a **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Esto resulta útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con muchos parsers**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con scheduling/mutation de LibAFL y mejores detectores adicionales.

### Convertir los fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en los assessments de Go es que el comportamiento peligroso a menudo **no** provoca un crash de forma predeterminada. Con gosentry, puedes convertir varias clases de estados «incorrectos pero silenciosos» en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que determinadas rutas de logging/error se comporten como crashes (útil para rutas de código del estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las nuevas entradas de la cola con el detector de race de Go.
- `--catch-leaks=true` para volver a ejecutar las nuevas entradas de la cola con `goleak` y detenerse ante leaks de goroutines.
- Gestión de hangs de LibAFL para conservar los **bucles infinitos / inputs muy lentos** como hallazgos de fuzzing en lugar de permitir que desaparezcan como timeouts.
- Checks integrados de overflow aritmético de forma predeterminada, además de checks opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto es especialmente valioso para targets cuyo impacto en seguridad es un **fallo de parser sin panic**, un **bug de concurrencia** o un **hang que solo causa DoS**, en lugar de corrupción de memoria.

### Fuzzing aware de structs para APIs tipadas de Go

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
Usa esto al crear un wire format falso únicamente para fuzzing, ya que ocultaría errores lógicos detrás de código de análisis exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y realiza el análisis dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolos

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **Nautilus grammar fuzzing** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notas de metodología:

- Usa `grammar mode` cuando las mutaciones a nivel de byte mueran principalmente en las primeras comprobaciones de sintaxis.
- Mantén la gramática centrada en el **subconjunto relevante para la seguridad** del lenguaje/protocolo en lugar de modelar la especificación completa.
- Usa valores límite grandes en terminales/no terminales para someter a estrés los límites de enteros, longitudes y máquinas de estados.
- `grammar mode` mantiene las entradas válidas según la gramática, pero el objetivo aún recibe **bytes/strings**, por lo que el análisis sintáctico y las comprobaciones semánticas siguen ejecutándose dentro del código instrumentado.

### Differential fuzzing: comparar implementaciones, no solo crashes

Un patrón sólido para los ecosistemas de Go es el **grammar-based differential fuzzing**: generar entradas estructuradas válidas y proporcionárselas a dos parsers, clientes o motores de transición de estados.<sup>[[7]](#references)[[8]](#references)</sup>
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

- una implementación entra en panic mientras que la otra rechaza la entrada correctamente
- discrepancias entre las entradas aceptadas y rechazadas
- árboles de análisis o objetos decodificados diferentes
- transiciones de estado, nonces, balances o state roots divergentes

Esta es una forma práctica de encontrar **consensus mismatches**, **parser ambiguity** y **spec-vs-implementation drift** que el fuzzing basado únicamente en crashes suele pasar por alto.

### Reutiliza el corpus de la campaña para generar informes de cobertura

Después de una campaña, reproduce el corpus de queue guardado para generar un informe de cobertura de Go sin exportar manualmente un corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Ejecuta el comando desde el **mismo paquete** y con el **mismo objetivo de `-fuzz`** para que gosentry resuelva el estado correcto de la campaña almacenado en caché.

## References

- [1] [Fuzzing de gramáticas mutacionales](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing de AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: sobre el fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte el código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [A Go fuzzing le faltaba la mitad del toolkit. Hemos bifurcado la toolchain para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática, no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing eficiente con snapshots adaptables y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
