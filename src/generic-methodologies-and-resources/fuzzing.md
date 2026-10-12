# Metodología de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: cobertura frente a semántica

En **mutational grammar fuzzing**, las entradas se mutan sin dejar de ser **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como seeds del corpus las muestras que generan **nueva cobertura**. En los **objetivos de lenguaje** (parsers, intérpretes, engines), esto puede pasar por alto errores que requieren **cadenas semánticas/de dataflow**, donde la salida de un constructo se convierte en la entrada de otro.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra seeds que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no conserva el dataflow encadenado**, por lo que se descarta la muestra «más cercana al error» porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria resulta costosa y la retroalimentación de cobertura no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **combinar fases mutacionales y generativas** o dar prioridad a patrones de **encadenamiento de funciones** (no solo a la cobertura).<sup>[[1]](#references)</sup>

## Problemas de diversidad del corpus

La mutación guiada por cobertura es **codiciosa**: una muestra con nueva cobertura se guarda de inmediato y a menudo conserva grandes regiones sin cambios. Con el tiempo, los corpus se llenan de **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, así que un término medio práctico es la **minimización consciente de la gramática**, que **se detiene al alcanzar un umbral mínimo de tokens** (reduce el ruido y conserva suficiente estructura circundante para facilitar las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para el corpus en mutational fuzzing es: **priorizar un conjunto pequeño de seeds estructuralmente diferentes que maximicen la cobertura** frente a un montón de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empezar con **muestras del mundo real** (corpus públicos, rastreo, tráfico capturado, conjuntos de archivos del ecosistema del objetivo).
- Depurarlas con **minimización del corpus basada en cobertura** en vez de conservar todas las muestras válidas.
- Mantener las seeds **lo bastante pequeñas** para que las mutaciones afecten campos relevantes, en lugar de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Volver a ejecutar la minimización del corpus tras cambios importantes en el harness o la instrumentación, porque el corpus «óptimo» cambia cuando cambia la alcanzabilidad.

## Mutación consciente de las comparaciones para valores mágicos

Una razón común por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, cadenas de enum, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas switch o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos objetivos, usa **trazado de comparaciones** (por ejemplo, flujos de trabajo basados en AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y orientar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>

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

- Esto es especialmente útil cuando el objetivo bloquea la lógica profunda detrás de **firmas de archivo**, **verbos de protocolo**, **etiquetas de tipo** o **bits de características dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o registros de depuración. Un diccionario pequeño con tokens de gramática, nombres de chunks, verbos y delimitadores suele ser más valioso que una wordlist genérica enorme.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las primeras comparaciones «mágicas» y luego vuelve a minimizar el corpus resultante para que las etapas posteriores partan de prefijos ya válidos.

## Más información de retroalimentación cuando la cobertura de aristas fusiona distintas rutas

La cobertura normal de aristas no puede distinguir dos ejecuciones que atraviesan el mismo helper desde distintos callers o toman diferentes combinaciones de ramas dentro de una función. Esto es importante en decoders compartidos, despachadores de protocolos y helpers de intérprete, donde la **ruta** hacia una arista determina el estado activo. Hacer un seguimiento ingenuo de todos los contextos de llamada también es peligroso: el mapa de cobertura y la cola pueden crecer desmesuradamente. Por eso, la investigación sobre fuzzing sensible al contexto recomienda refinar solo los contextos prometedores, en lugar de tratar todo el grafo de llamadas como sensible al contexto.<sup>[[14]](#references)</sup>

Las versiones recientes de AFL++ ofrecen **cobertura de rutas por función de Ball-Larus**, además de la cobertura normal de aristas. Asigna una característica a cada ruta acíclica que atraviesa una función; se eliminan las aristas de retorno de los bucles, por lo que esta retroalimentación distingue combinaciones de ramas, pero **no el número de iteraciones de los bucles**. Empieza con el nivel relajado `1` y luego aplica modos más estrictos solo al código sospechoso del parser o de la máquina de estados, porque el número de rutas puede crecer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para un helper llamado desde muchos sitios relevantes para la seguridad, el modo LTO puede combinar la ruta de cada función con su sitio de llamada inmediato:<sup>[[13]](#references)</sup>

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

**Guía para campañas:** aplica la retroalimentación más rica de forma conservadora y supervisa su coste en el mapa de cobertura y la cola.<sup>[[13]](#references)[[14]](#references)</sup>

- Ejecuta en paralelo una instancia normal con cobertura de bordes; la retroalimentación más rica solo es útil si el coste adicional de la cola y el mapa no reduce demasiado las ejecuciones por segundo.
- Usa `AFL_LLVM_ALLOWLIST` para limitar la instrumentación de rutas/llamadores cuando las bibliotecas grandes con muchas plantillas o el código de utilidades genéricas dominen el mapa.
- Las funciones con demasiadas rutas acíclicas pueden omitirse en AFL++; las advertencias durante la compilación indican que el objetivo necesita una lista de permitidos o un nivel menos estricto.
- La cobertura de llamador + ruta solo admite un nivel de profundidad del llamador. No la combines con pilas de contexto más profundas.
- Los ID de ruta pueden cambiar entre versiones principales de LLVM. Mantén fija la cadena de herramientas durante una campaña y no sincronices corpus basados en PATH como si sus ID de características fueran estables entre compilaciones.
- Esta retroalimentación complementa `CMPLOG`: el seguimiento de comparaciones resuelve **qué valor supera una barrera**, mientras que la retroalimentación de ruta/llamador conserva **qué ruta y combinación de ramas permitieron llegar a ella**.

## Fuzzing con estado: las secuencias son semillas

En **protocolos**, **flujos de trabajo autenticados** y **analizadores sintácticos de varias etapas**, la unidad interesante suele ser una **secuencia de mensajes**, no un único bloque de datos. Concatenar toda la transcripción en un solo archivo y mutarla a ciegas suele ser ineficiente, porque el fuzzer muta todos los pasos por igual, aunque solo el mensaje posterior llegue al estado vulnerable.<sup>[[4]](#references)</sup>

Un patrón más eficaz consiste en tratar la **secuencia en sí como la semilla** y usar el **estado observable** (códigos de respuesta, estados del protocolo, fases del analizador sintáctico, tipos de objetos devueltos) como retroalimentación adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes válidos del prefijo** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor que se devuelvan en respuestas anteriores cuando el paso siguiente dependa de ellos.
- Prefiere mutar o combinar mensajes individuales en vez de mutar toda la transcripción serializada como un bloque opaco.
- Si el protocolo expone códigos de respuesta significativos, úsalos como **oráculo de estado económico** para priorizar las secuencias que avanzan más.

Por esta misma razón, los errores autenticados, las transiciones ocultas o los errores del analizador sintáctico que solo aparecen “después del handshake” suelen pasar desapercibidos con el fuzzing convencional de archivos: el fuzzer debe preservar el **orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de drivers con varios clientes

Una cobertura de bordes elevada aún puede pasar por alto errores del driver IPC, porque la cobertura no describe la **propiedad de los objetos, los recuentos de referencias, los mensajes pendientes, el orden de limpieza ni los intercalados entre hilos**. La página sobre [los componentes internos de Android Binder IPC](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) describe el modelo de objetos del driver; este ejemplo se centra en el harness del fuzzer. Android Binder es un modelo útil: alcanzar tanto las rutas de asignación como las de liberación no basta si el fuzzer no puede hacer que varios procesos operen sobre el mismo objeto del kernel en el orden requerido.<sup>[[15]](#references)</sup>

#### Modela el protocolo, no buffers `ioctl` aislados

Representa cada caso de prueba como una gramática ordenada de **identidad del cliente + operación + argumentos estructurados**. El fuzzer Binder LKL usa protobuf y `libprotobuf-mutator`, con un cliente persistente de administrador de contexto y dos clientes normales. Después, un harness semántico preserva las relaciones que la mutación ciega de bytes destruiría.<sup>[[15]](#references)</sup>

- Guarda en caché los valores devueltos por operaciones anteriores. Por ejemplo, `BC_FREE_BUFFER` debe reutilizar un puntero al búfer de una transacción devuelto por un `ioctl` anterior.
- Genera respuestas predeterminadas válidas para que las transacciones síncronas puedan completarse y las operaciones posteriores sigan siendo alcanzables.
- Rechaza transiciones imposibles, como las transacciones a sí mismo o varias transacciones pendientes dirigidas al mismo destino.
- Mantén el estado de inicialización único fuera del reinicio por entrada. Binder solo permite un registro `BINDER_SET_CONTEXT_MGR` por arranque, por lo que destruir y recrear repetidamente ese cliente invalidaría las entradas posteriores.

Una plantilla útil para provocar una condición de carrera de vida útil consiste en hacer que un cliente transfiera un objeto, iniciar la limpieza de un hilo o proceso y, al mismo tiempo, hacer que el cliente receptor libere el búfer de la transacción. En el ejemplo de CVE-2020-0423, la transferencia de un `BINDER_TYPE_WEAK_BINDER`, seguida de una carrera entre `BINDER_THREAD_EXIT` y `BC_FREE_BUFFER`, podía liberar un `binder_work` incrustado mientras la ruta de limpieza del hilo que estaba saliendo aún lo usaba.<sup>[[15]](#references)</sup>

#### Reintroduce intercalados controlados en un kernel de espacio de usuario

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) enlaza el código real del kernel en un harness de espacio de usuario y expone su interfaz de llamadas al sistema mediante `lkl_syscall`. Así, resulta fácil coordinar protobuf, cobertura y KASAN en un solo proceso. Sin embargo, LKL normalmente ejecuta una llamada al sistema sin que otro hilo del kernel la interrumpa. Para las campañas de carreras, inserta puntos `schedule()` alrededor de límites seleccionados de bloqueo/desbloqueo y vida útil; luego, permite que el harness elija aleatoriamente el siguiente cliente en cada cesión de ejecución. Mantén estos puntos bien delimitados, porque cada uno multiplica el espacio de búsqueda de planificación. El planificador aleatorio descrito por los investigadores **no** forma parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila y vuelve a ejecutar semillas de regresión serializadas

El harness upstream fija una versión compatible de `libprotobuf-mutator`, activa la instrumentación de fuzzing de LKL y KASAN con `LKL_FUZZING=1`, y habilita `CONFIG_MMU` para Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Tras obtener una revisión deliberadamente vulnerable o aplicar los parches de reversión documentados upstream, una semilla serializada puede reproducir toda la transición de estado entre varios clientes sin reconstruirla en una prueba de concepto ad hoc en C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trata el use-after-free de KASAN resultante como confirmación de que la seed alcanzó la ruta vulnerable del ciclo de vida. **No** demuestra las primitivas posteriores necesarias para ejecutar código en el kernel o escalar privilegios.<sup>[[16]](#references)</sup>

## Truco de diversidad en una sola máquina (estilo Jackalope)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de cobertura** consiste en **reiniciar workers de corta duración** frente a un servidor persistente. Cada worker comienza con un corpus vacío, sincroniza tras `T` segundos, ejecuta durante otros `T` segundos con el corpus combinado, vuelve a sincronizar y luego termina. Así se obtienen **estructuras nuevas en cada generación** y, al mismo tiempo, se aprovecha la cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` fuerza un **corpus nuevo** en cada generación.
- `-server_update_interval T` aproxima una **sincronización retardada** (primero novedades, reutilización después).
- En el modo de grammar fuzzing, la **sincronización inicial con el servidor se omite por defecto** (no hace falta `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del objetivo**; suele funcionar mejor cambiarlo cuando el worker ya ha encontrado la mayor parte de la cobertura «fácil».

## Snapshot Fuzzing Para Objetivos Difíciles De Preparar

Cuando el código que quieres probar solo es accesible **después de un proceso de preparación costoso** (arrancar una VM, completar un inicio de sesión, recibir un paquete, analizar un contenedor, inicializar un servicio), una alternativa útil es **snapshot fuzzing**: capturar el estado del proceso o la VM ya preparado, inyectar cada caso de prueba en la ruta de entrada del objetivo, ejecutar hasta que se produzca un crash o timeout y restaurar el snapshot. Así se evita repetir la inicialización o los prefijos del protocolo; resulta útil para **servicios de red**, **firmware**, **superficies de ataque posteriores a la autenticación** y **objetivos de los que solo se dispone del binario**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el objetivo hasta que esté listo el estado que te interesa.
2. Crea un snapshot de la **memoria y los registros** en ese momento.
3. Para cada caso de prueba, escribe la entrada mutada directamente en el buffer pertinente del guest o proceso.
4. Ejecuta hasta que se produzca un crash, timeout o reinicio.
5. Restaura el snapshot; para objetivos VM, restaura solo las **páginas modificadas** cuando sea posible y repite.

Coloca el snapshot tan cerca como sea práctico del primer paso costoso de análisis o despacho, por ejemplo, después de un `recv`/`read` o del punto de deserialización de paquetes, y registra el buffer de entrada que usa el objetivo. Esto sigue el principio de ubicación adaptativa: mover el snapshot más adentro del procesamiento de la entrada para evitar repetir trabajo.<sup>[[11]](#references)</sup>

## Introspección Del Harness: Detecta Pronto Los Fuzzers Superficiales

Cuando una campaña se estanca, a menudo el problema no es el mutator, sino el **harness**. Usa la **introspección de alcanzabilidad/cobertura** para encontrar funciones que sean alcanzables estáticamente desde tu objetivo de fuzzing, pero que rara vez o nunca se cubran dinámicamente. Esas funciones suelen indicar uno de estos tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el objetivo demasiado tarde o demasiado pronto.
- Al corpus de seeds le falta toda una familia de funcionalidades.
- El objetivo realmente necesita un **segundo harness** en lugar de un único harness sobredimensionado que «lo haga todo».

Si usas flujos de trabajo de tipo OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la alcanzabilidad estática con la cobertura en tiempo de ejecución y generar informes a partir de una ejecución cronometrada o un corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa el informe para decidir si añadir un nuevo harness para una ruta del parser no probada, ampliar el corpus para una función específica o dividir un harness monolítico en varios puntos de entrada más pequeños.

## Selección de objetivos de fuzzing basada primero en grafos y clasificación de mutaciones

Si ya tienes **hallazgos de análisis estático**, **mutantes supervivientes de mutation testing** e **informes de cobertura**, no los clasifiques como listas independientes. Primero, crea un **grafo de llamadas**, anota los nodos con la **complejidad ciclomática**, la **alcanzabilidad desde puntos de entrada o entradas no confiables** y cualquier hallazgo externo; después, analiza el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde entradas no confiables?
- ¿Qué mutantes supervivientes están en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **radio de impacto** inusualmente amplio?

Esto suele revelar mejores objetivos de fuzzing que basarse únicamente en la «menor cobertura». Un parser/decoder con **alta complejidad** y **alcanzabilidad externa** confirmada es mejor candidato para un harness que un helper interno aislado con poca cobertura, pero sin una ruta controlada por un atacante.

### Flujo de trabajo práctico de clasificación

1. Crea un **grafo de código** a partir del codebase y extrae métricas de complejidad/ramas por función.
2. Enumera los **puntos de entrada** que aceptan entradas controladas por un atacante: request handlers, decoders, importers, parsers de protocolos y lectores de CLI/archivos.
3. Ejecuta consultas de rutas desde esos puntos de entrada hasta las funciones candidatas para separar la superficie de ataque alcanzable del código muerto o solo interno.
4. Prioriza los nodos que combinen:
   - alta **complejidad ciclomática**
   - **alcanzabilidad desde entradas no confiables** confirmada
   - un **radio de impacto** amplio o muchos dependientes aguas abajo
   - evidencia que lo corrobore, como hallazgos **SARIF**, notas de auditoría o mutantes supervivientes
5. Escribe primero harnesses específicos para los nodos con mejor puntuación, especialmente **parsers/codecs**, como decoders de hex/Base64/IP/mensajes.

### Mutantes supervivientes: equivalentes frente a procesables

Mutation testing suele producir una lista ruidosa de mutantes supervivientes. Antes de considerar cada mutante como una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un punto de entrada controlado por un atacante?
- ¿Todas las rutas de llamadas están sujetas a invariantes más fuertes que la comprobación mutada?
- ¿El nodo está en código muerto, en lógica dedicada solo al formato o en una ruta aritmética/parser de alto impacto?

Los mutantes supervivientes que siguen siendo inalcanzables o están restringidos estructuralmente suelen ser **mutantes equivalentes**. Los que siguen siendo **alcanzables** y afectan a **condiciones de límite**, **rutas de overflow/carry** o **aritmética/parsing crítico para la seguridad** deberían convertirse en:

- nuevos harnesses de fuzzing
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlaciona los hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo usando **archivo + rango de líneas** y utiliza el grafo para ampliar el análisis del impacto.<sup>[[6]](#references)</sup>

- calcula el **radio de impacto** de la función señalada
- comprueba si el hallazgo está en alguna ruta desde un punto de entrada
- agrupa hallazgos cercanos que converjan en el mismo punto de estrangulamiento

Esto resulta útil para decidir si dedicar tiempo de fuzzing a una función específica: un nodo **alcanzable**, **complejo** y que ya presenta **hallazgos de SAST** suele ser mejor objetivo que un nodo meramente complejo sin una ruta accesible para un atacante.

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

La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir los objetivos de fuzzing con el mayor valor de seguridad esperado y, después, usa las mutaciones supervivientes para decidir qué límites e invariantes debe poner a prueba tu harness.<sup>[[5]](#references)</sup>

## Fuzzing de Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo de `testing.F`, una forma práctica de mejorarlo es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain de Go bifurcada que conserva `go test -fuzz`, pero cambia el backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Esto resulta útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con parsers complejos**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para la función callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con planificación y mutación de LibAFL y mejores detectores adicionales.

### Convierte los fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en las evaluaciones de Go es que, de forma predeterminada, los comportamientos peligrosos a menudo **no** provocan un crash. Con gosentry, puedes convertir varias clases de estados «malos pero silenciosos» en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que las rutas seleccionadas de logging/error se comporten como crashes (útil para rutas de código del estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las entradas nuevas descubiertas en la cola con el detector de carreras de Go.
- `--catch-leaks=true` para volver a ejecutar las entradas nuevas de la cola con `goleak` y detenerse si hay fugas de goroutines.
- La gestión de bloqueos de LibAFL para conservar los **bucles infinitos / las entradas muy lentas** como hallazgos de fuzzing, en lugar de descartarlos como timeouts.
- Comprobaciones integradas de desbordamiento aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto resulta especialmente valioso para objetivos cuyo impacto en la seguridad sea un **fallo de parser sin panic**, un **bug de concurrencia** o un **bloqueo que solo provoque DoS**, en lugar de corrupción de memoria.

### Fuzzing consciente de structs para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede hacer fuzzing directamente de **valores compuestos** (structs, slices, arrays, pointers) y, al mismo tiempo, mutar los bytes subyacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usar esto al crear un formato wire falso solo para fuzzing ocultaría errores lógicos detrás de código de análisis exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y analiza los datos dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolo

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **fuzzing gramatical Nautilus** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre la metodología:

- Usa el modo de gramática cuando las mutaciones a nivel de byte suelen fallar en las primeras comprobaciones de sintaxis.
- Limita la gramática al **subconjunto del lenguaje/protocolo relevante para la seguridad**, en lugar de modelar toda la especificación.
- Usa valores límite grandes en terminales/no terminales para poner a prueba los límites de enteros, longitudes y máquinas de estados.
- El modo de gramática mantiene las entradas válidas según la gramática, pero el objetivo sigue recibiendo **bytes/cadenas**, así que el análisis sintáctico y las comprobaciones semánticas siguen ejecutándose dentro del código instrumentado.

### Fuzzing diferencial: comparar implementaciones, no solo fallos

Un patrón eficaz en los ecosistemas de Go es el **fuzzing diferencial basado en gramáticas**: generar entradas estructuradas válidas y proporcionárselas a dos analizadores, clientes o motores de transición de estados.<sup>[[7]](#references)[[8]](#references)</sup>

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
- discrepancias entre entradas aceptadas y rechazadas
- árboles de análisis u objetos decodificados diferentes
- transiciones de estado, nonces, saldos o raíces de estado divergentes

Esta es una forma práctica de encontrar **discrepancias de consenso**, **ambigüedad del parser** y **divergencias entre la especificación y la implementación** que a menudo pasan desapercibidas con el fuzzing centrado únicamente en los crashes.

### Reutilizar el corpus de la campaña para informar la cobertura

Después de una campaña, vuelve a reproducir el corpus guardado en la cola para generar un informe de cobertura de Go sin exportar manualmente un corpus aparte.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Ejecuta el comando desde el **mismo paquete** y con el **mismo destino `-fuzz`** para que gosentry resuelva el estado de campaña almacenado en caché correcto.



## References

- [1] [Fuzzing de gramáticas mutacionales](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing con AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte el código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Al fuzzing de Go le faltaba la mitad del conjunto de herramientas. Modificamos el toolchain para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptativos y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentación LLVM de AFL++: cobertura de rutas y de llamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predictivo y sensible al contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de seguridad ofensiva de Android: fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer de Binder de LKL Android: documentación de compilación y semillas de regresión](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
