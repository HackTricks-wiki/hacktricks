# Metodología de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing mutacional basado en gramáticas: cobertura vs. semántica

En el **fuzzing mutacional basado en gramáticas**, las entradas se mutan sin dejar de ser **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como semillas del corpus las muestras que provocan **nueva cobertura**. En los **targets de lenguajes** (parsers, intérpretes, motores), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos**, donde la salida de una construcción pasa a ser la entrada de otra.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra semillas que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no conserva el flujo de datos encadenado**, por lo que se descarta la muestra «más cercana al bug» porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria se vuelve costosa y la retroalimentación de cobertura no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **combinar fases mutacionales y generativas** o sesgar la generación hacia patrones de **encadenamiento de funciones** (no solo hacia la cobertura).<sup>[[1]](#references)</sup>

## Errores comunes con la diversidad del corpus

La mutación guiada por cobertura es **codiciosa**: una muestra que alcanza nueva cobertura se guarda de inmediato y suele conservar grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, así que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene al alcanzar un umbral mínimo de tokens** (reduce el ruido y conserva suficiente estructura circundante para facilitar las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para los corpus de fuzzing mutacional es: **preferir un conjunto pequeño de semillas estructuralmente distintas que maximicen la cobertura** en lugar de una gran cantidad de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empieza con **muestras del mundo real** (corpus públicos, datos recopilados mediante crawling, tráfico capturado, conjuntos de archivos del ecosistema del target).
- Depúralas mediante **minimización del corpus basada en cobertura** en lugar de conservar todas las muestras válidas.
- Mantén las semillas **lo bastante pequeñas** para que las mutaciones afecten campos relevantes, en vez de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Vuelve a ejecutar la minimización del corpus después de cambios importantes en el harness o la instrumentación, porque el corpus «óptimo» cambia cuando cambia la alcanzabilidad.

## Mutación consciente de las comparaciones para valores mágicos

Una razón habitual por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, cadenas de enumeración, checksums o valores de despacho del parser protegidos por `memcmp`, tablas `switch` o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos tratando de adivinar estos valores byte a byte.

Para estos targets, usa **trazado de comparaciones** (por ejemplo, flujos de trabajo de estilo AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y orientar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>

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

- Esto resulta especialmente útil cuando el objetivo protege la lógica interna mediante **firmas de archivo**, **verbos de protocolo**, **etiquetas de tipo** o **bits de función dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o registros de depuración. Un diccionario pequeño con tokens de gramática, nombres de bloques, verbos y delimitadores suele ser más valioso que una lista de palabras genérica enorme.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones «mágicas» iniciales y luego vuelve a minimizar el corpus resultante para que las etapas posteriores empiecen con prefijos ya válidos.

## Más información de retroalimentación cuando la cobertura de aristas agrupa rutas distintas

La cobertura normal de aristas no puede distinguir dos ejecuciones que recorren el mismo helper desde distintos llamadores o toman distintas combinaciones de ramas dentro de una función. Esto importa en decodificadores compartidos, despachadores de protocolos y helpers de intérprete, donde la **ruta** hasta una arista determina el estado activo. Rastrear ingenuamente todos los contextos de llamada también es peligroso: el mapa de cobertura y la cola pueden crecer desmesuradamente. Por ello, la investigación sobre fuzzing sensible al contexto recomienda refinar solo los contextos prometedores, en lugar de tratar todo el grafo de llamadas como sensible al contexto.<sup>[[14]](#references)</sup>

Las versiones recientes de AFL++ ofrecen **cobertura de rutas Ball-Larus por función**, además de la cobertura normal de aristas. Asigna una característica a cada ruta acíclica dentro de una función; se eliminan las aristas de retorno de los bucles, por lo que esta retroalimentación distingue combinaciones de ramas, pero **no el número de iteraciones de los bucles**. Empieza con el nivel relajado `1` y luego limita los modos más estrictos al código sospechoso del analizador o de la máquina de estados, porque el número de rutas puede crecer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para un helper llamado desde muchos puntos relevantes para la seguridad, el modo LTO puede combinar cada ruta de función con su sitio de llamada inmediato:<sup>[[13]](#references)</sup>

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

**Guía para la campaña:** aplica la retroalimentación más rica con prudencia y supervisa su costo en el mapa de cobertura y la cola.<sup>[[13]](#references)[[14]](#references)</sup>

- Ejecuta en paralelo una instancia normal de cobertura de aristas; la retroalimentación más rica solo es útil si el costo adicional de cola/mapa no reduce las ejecuciones por segundo.
- Usa `AFL_LLVM_ALLOWLIST` para restringir la instrumentación de rutas/llamadores cuando las bibliotecas grandes con muchas plantillas o el código de utilidades genéricas dominen el mapa.
- Las funciones con demasiadas rutas acíclicas pueden omitirse con AFL++; las advertencias durante la compilación indican que el objetivo necesita allowlisting o un nivel menos estricto.
- La cobertura de llamadores + rutas admite una sola profundidad de llamador. No la combines con pilas de contexto más profundas.
- Los ID de ruta pueden cambiar entre versiones principales de LLVM. Mantén fija la cadena de herramientas durante la campaña y no sincronices corpus basados en PATH como si sus ID de características fueran estables entre compilaciones.
- Esta retroalimentación complementa `CMPLOG`: el trazado de comparaciones resuelve **qué valor supera una guarda**, mientras que la retroalimentación de rutas/llamadores conserva **qué ruta y combinación de ramas la alcanzaron**.

## Fuzzing con estado: las secuencias son seeds

En **protocolos**, **flujos de trabajo autenticados** y **analizadores sintácticos de varias etapas**, la unidad de interés suele ser una **secuencia de mensajes**, no un único blob. Concatenar toda la transcripción en un archivo y mutarla a ciegas suele ser ineficiente, porque el fuzzer muta cada paso por igual, aunque solo el mensaje posterior alcance el estado vulnerable.<sup>[[4]](#references)</sup>

Un patrón más eficaz consiste en tratar la **secuencia misma como el seed** y usar el **estado observable** (códigos de respuesta, estados del protocolo, fases del analizador sintáctico, tipos de objetos devueltos) como retroalimentación adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor en respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere mutar o combinar mensajes individuales en vez de mutar toda la transcripción serializada como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, úsalos como un **oráculo de estado barato** para priorizar las secuencias que avanzan más.

Por la misma razón, los bugs autenticados, las transiciones ocultas o los bugs de analizadores sintácticos que aparecen «solo después del handshake» suelen pasar inadvertidos con el fuzzing convencional basado en archivos: el fuzzer debe preservar **el orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de drivers con varios clientes

Una cobertura de aristas alta todavía puede pasar por alto bugs del driver IPC, porque la cobertura no describe **la propiedad de los objetos, los recuentos de referencias, los mensajes pendientes, el orden de limpieza ni los intercalados entre hilos**. La página sobre [los componentes internos de Android Binder IPC](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) describe el modelo de objetos del driver; este ejemplo se centra en el harness del fuzzer. Android Binder es un modelo útil: alcanzar tanto las rutas de asignación como las de liberación no basta si el fuzzer no puede hacer que varios procesos operen sobre el mismo objeto del kernel en el orden necesario.<sup>[[15]](#references)</sup>

#### Modela el protocolo, no buffers `ioctl` aislados

Representa cada caso de prueba como una gramática ordenada de **identidad del cliente + operación + argumentos estructurados**. El fuzzer Binder LKL usa protobuf y `libprotobuf-mutator`, con un cliente persistente de administrador de contexto y dos clientes ordinarios. Un harness semántico preserva así las relaciones que la mutación ciega de bytes destruiría.<sup>[[15]](#references)</sup>

- Guarda en caché los valores devueltos por operaciones anteriores. Por ejemplo, `BC_FREE_BUFFER` debe reutilizar un puntero al buffer de transacción devuelto por un `ioctl` anterior.
- Genera respuestas predeterminadas válidas para permitir que las transacciones síncronas finalicen y que se pueda llegar a operaciones posteriores.
- Rechaza transiciones imposibles, como transacciones a uno mismo o varias transacciones pendientes dirigidas al mismo destino.
- Mantén el estado de inicialización singleton fuera del reinicio por entrada. Binder permite solo un registro `BINDER_SET_CONTEXT_MGR` por arranque, por lo que destruir y recrear repetidamente ese cliente invalidaría las entradas posteriores.

Una plantilla útil para una condición de carrera de ciclo de vida consiste en hacer que un cliente transfiera un objeto, iniciar la limpieza de un hilo o proceso y, en paralelo, hacer que el cliente receptor libere el buffer de transacción. En el ejemplo de CVE-2020-0423, una transferencia de `BINDER_TYPE_WEAK_BINDER` seguida de `BINDER_THREAD_EXIT` en competencia con `BC_FREE_BUFFER` podía liberar un `binder_work` integrado mientras la ruta de limpieza del hilo que salía aún lo utilizaba.<sup>[[15]](#references)</sup>

#### Reintroduce intercalados controlados en un kernel de espacio de usuario

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) enlaza el código real del kernel en un harness de espacio de usuario y expone su interfaz de llamadas al sistema mediante `lkl_syscall`. Esto facilita coordinar el estado de protobuf, la cobertura y KASAN en un mismo proceso. Sin embargo, LKL normalmente ejecuta una llamada al sistema sin que otro hilo del kernel la interrumpa. Para campañas de condiciones de carrera, inserta puntos `schedule()` cerca de límites seleccionados de bloqueo/desbloqueo y de ciclo de vida, y deja que el harness elija aleatoriamente el siguiente cliente en cada cesión. Mantén estos puntos bien delimitados, porque cada uno multiplica el espacio de búsqueda de planificación. El planificador aleatorio descrito por los investigadores **no** forma parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila y reproduce seeds de regresión serializados

El harness upstream fija una versión compatible de `libprotobuf-mutator`, habilita la instrumentación de fuzzing de LKL y KASAN con `LKL_FUZZING=1`, y habilita `CONFIG_MMU` para Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Tras descargar una revisión deliberadamente vulnerable o aplicar los parches de reversión documentados upstream, una semilla serializada puede reproducir toda la transición de estado de varios clientes sin tener que reconstruirla en una prueba de concepto ad hoc en C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trata el use-after-free de KASAN resultante como confirmación de que el seed llegó a la ruta vulnerable del ciclo de vida. **No** demuestra las primitivas posteriores necesarias para ejecutar código en el kernel o escalar privilegios.<sup>[[16]](#references)</sup>

## Truco de diversidad en una sola máquina (estilo Jackalope)

Una forma práctica de combinar la **novedad generativa** con el **reaprovechamiento de coverage** es **reiniciar workers de corta duración** contra un servidor persistente. Cada worker empieza con un corpus vacío, sincroniza después de `T` segundos, ejecuta durante otros `T` segundos con el corpus combinado, vuelve a sincronizar y luego termina. Esto produce **estructuras nuevas en cada generación** y, a la vez, aprovecha la coverage acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` aproxima una **sincronización retrasada** (primero novedades, después reutilización).
- En el modo de fuzzing con gramáticas, la **sincronización inicial con el servidor se omite de forma predeterminada** (no hace falta `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del objetivo**; suele funcionar mejor cambiarlo cuando el worker ya ha encontrado la mayor parte de la cobertura «fácil».

## Snapshot Fuzzing Para Objetivos Difíciles De Instrumentar

Cuando el código que quieres probar solo se vuelve accesible **después de un costoso proceso de preparación** (arrancar una VM, completar un inicio de sesión, recibir un paquete, analizar un contenedor, inicializar un servicio), una alternativa útil es **snapshot fuzzing**: capturar el estado del proceso o la VM ya preparados, inyectar cada caso de prueba en la ruta de entrada del objetivo, ejecutar hasta que ocurra un crash o timeout y restaurar el snapshot. Así se evita repetir la inicialización o los prefijos del protocolo, y es útil para **servicios de red**, **firmware**, **superficies de ataque posteriores a la autenticación** y **objetivos solo binarios**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el objetivo hasta que esté listo el estado de interés.
2. Guarda un snapshot de la **memoria + los registros** en ese momento.
3. Para cada caso de prueba, escribe la entrada modificada directamente en el búfer pertinente del guest o del proceso.
4. Ejecuta hasta que ocurra un crash, timeout o reset.
5. Restaura el snapshot; para objetivos VM, restaura solo las **páginas modificadas** cuando sea posible y repite.

Coloca el snapshot lo más cerca posible del primer paso costoso de análisis o despacho, por ejemplo, después de un punto `recv`/`read` o de deserialización de paquetes, y registra el búfer de entrada que utiliza el objetivo. Esto sigue el principio de ubicación adaptativa: mover el snapshot más adentro del procesamiento de entrada para evitar repetir trabajo.<sup>[[11]](#references)</sup>

## Exploración De Carreras Del Kernel De Linux Con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) convierte las carreras sensibles a la temporización del kernel de Linux en secuencias repetibles de accesos a memoria. Puede enumerar automáticamente ejecuciones **A-B-A** de dos contextos o permitir que un analista imponga restricciones de orden en una interfaz de terminal o gráfica. Es una herramienta de investigación experimental, no un fuzzer de concurrencia completo: actualmente requiere LLVM 23+ y el kernel parcheado del proyecto; las herramientas de línea de comandos admiten dos hilos de prueba, y la capa propuesta de fuzzing en espacio de usuario aún no está implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Recopilar puntos de comunicación entre contextos

Compila el kernel instrumentado con callbacks outline de KASAN y el soporte parcheado de KCOV para registrar accesos a memoria. El README del proyecto también recomienda deshabilitar la optimización de llamadas a hermanos para que las pilas de llamadas sigan siendo útiles.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

El modo outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convierte los accesos instrumentados en llamadas a funciones auxiliares. Los parches del kernel MAccConc desactivan `asan-opt-same-temp` para que los accesos consecutivos no se fusionen; desactiva también la optimización `asan-opt-globals` cuando sea necesario que las carreras en variables globales sean visibles. KCOV lleva los registros resultantes al espacio de usuario. Compara los accesos de distintos contextos de ejecución y conserva los pares cuyos rangos de bytes se solapan y en los que al menos uno escribe; modela `kfree()` como una escritura para que las transiciones de ciclo de vida también sean candidatas.<sup>[[17]](#references)</sup>

Para el trabajo que continúa fuera de la tarea que lo inicia, como el procesamiento de paquetes o las callbacks de RCU, el subsistema debe propagar un identificador de cobertura remota de KCOV. KCOV remoto en upstream es opt-in y no está disponible automáticamente para cualquier trabajo en segundo plano, por lo que la falta de propagación puede hacer invisible una interacción real.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificar el mismo acceso dinámico en cada ejecución

No reproduzcas la ejecución usando una dirección concreta del heap, que puede cambiar tras cada asignación, ni solo una dirección de instrucción, que resulta ambigua dentro de funciones auxiliares como `memcpy()` y `spin_lock()`. MAccConc usa una **traza de pila aumentada con contadores**: cada frame identifica una función llamada y el contador de invocaciones dentro de su llamador, y el elemento final identifica la instrucción de acceso a memoria. Los registros de entrada y salida de funciones de SanitizerCoverage permiten al espacio de usuario reconstruir este identificador dinámico, que permanece estable pese a los cambios de dirección y al ruido de flujo de control no relacionado.<sup>[[17]](#references)</sup>

### Convertir pares candidatos en planificaciones forzadas

El ioctl parcheado `KCOV_SET_DI` asocia un identificador de acceso aumentado con contadores a una acción sobre una flag compartida.<sup>[[17]](#references)</sup>

| Acción | Semántica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Establece la flag *N* inmediatamente antes del acceso seleccionado. |
| `DI_STACK_WAIT` | Antes del acceso seleccionado, espera en un bucle hasta que se establezca la flag *N* o se agote el límite configurado. |
| `DI_STACK_WAKE_POST` | Establece la flag *N* inmediatamente después del acceso seleccionado. |

Para una restricción parcial **A-happens-before-B**, asigna `DI_STACK_WAKE_POST` a A y `DI_STACK_WAIT` a B usando la misma flag. Para una planificación de dos contextos completamente especificada, inicia B bloqueado; luego haz que A despierte a B y espere en el primer punto de transferencia. B realiza la operación inversa en la siguiente transferencia. Esto actúa como un cambio de contexto determinista y es lo que usa el explorador automático A-B-A.<sup>[[17]](#references)</sup>

Una campaña mínima consiste en compilar el caso de prueba de cuatro hooks (`test_setup`, dos funciones de hilo y `test_end`) como biblioteca compartida, recopilar una traza sin restricciones y, después, enumerar candidatos A-B-A o añadir restricciones manuales alrededor de los accesos sospechosos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta los timeouts por separado de los reordenamientos exitosos: el orden solicitado podría ser imposible porque un bloqueo o una dependencia de inicialización/publicación impide que el segundo contexto llegue a su punto de inyección. Ten en cuenta también los puntos ciegos de KASAN: los accesos directos a la pila normalmente no se instrumentan, salvo que puedan quedar fuera de límites; las variables globales se omiten con la optimización predeterminada; y los compiladores actuales no pueden emitir simultáneamente hooks de ASAN y TSAN. Además, el prototipo pierde su búfer de KCOV cuando el guest sufre un panic, así que conserva una consola/oráculo de fallos independiente.<sup>[[17]](#references)</sup>

Para el fuzzing guiado por concurrencia en el futuro, registra resúmenes de accesos a memoria por entrada o syscall, empareja operaciones que formarían puntos de comunicación entre contextos y luego explora solo esas combinaciones. Las instantáneas de VM estabilizan el estado global y las direcciones; sin instantáneas, los metadatos del sitio de asignación pueden abstraer objetos entre ejecuciones. Esta es una extensión propuesta, no una función de las herramientas userspace actuales de MAccConc.<sup>[[17]](#references)</sup>

## Introspección del harness: detecta pronto los fuzzers superficiales

Cuando una campaña se estanca, a menudo el problema no es el mutator, sino el **harness**. Usa la **introspección de alcanzabilidad/cobertura** para encontrar funciones que son estáticamente alcanzables desde tu fuzz target, pero que rara vez o nunca se cubren dinámicamente. Esas funciones suelen indicar uno de estos tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el target demasiado tarde o demasiado pronto.
- Al corpus de seeds le falta toda una familia de funcionalidades.
- El target realmente necesita un **segundo harness**, en lugar de un único harness sobredimensionado que “lo haga todo”.

Si usas flujos de trabajo al estilo de OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la alcanzabilidad estática con la cobertura en tiempo de ejecución y generar informes a partir de una ejecución cronometrada o de un corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa el informe para decidir si añadir un nuevo harness para una ruta del parser sin probar, ampliar el corpus para una función específica o dividir un harness monolítico en varios puntos de entrada.

## Selección de objetivos de fuzzing basada primero en grafos y triaje de mutaciones

Si ya tienes **hallazgos de análisis estático**, **mutantes supervivientes** y **informes de cobertura**, no los clasifiques como listas independientes. Primero, crea un **grafo de llamadas**, anota los nodos con **complejidad ciclomática**, **alcanzabilidad desde entrypoints/entradas no confiables** y cualquier hallazgo externo; luego, plantea preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde entradas no confiables?
- ¿Qué mutantes supervivientes están en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **radio de impacto** inusualmente amplio?

Esto suele sacar a la luz mejores objetivos de fuzzing que fijarse solo en la «menor cobertura». Un parser/decoder con **alta complejidad** y **alcanzabilidad externa** confirmada es mejor candidato para un harness que una función auxiliar interna aislada, con poca cobertura pero sin una ruta controlada por un atacante.

### Flujo de trabajo práctico de triaje

1. Crea un **grafo de código** a partir del codebase y extrae métricas de complejidad/ramas por función.
2. Enumera los **entrypoints** que aceptan entradas controladas por un atacante: request handlers, decoders, importers, parsers de protocolos y lectores de CLI/archivos.
3. Ejecuta consultas de rutas desde esos entrypoints hasta las funciones candidatas para separar la superficie de ataque alcanzable del código muerto o solo interno.
4. Da prioridad a los nodos que combinen:
   - alta **complejidad ciclomática**
   - **alcanzabilidad desde entradas no confiables** confirmada
   - alto **radio de impacto** o muchos dependientes posteriores
   - evidencia corroborante, como hallazgos **SARIF**, notas de auditoría o mutantes supervivientes
5. Escribe harnesses enfocados para los nodos con mejor puntuación, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Mutantes supervivientes: equivalentes frente a accionables

Las pruebas de mutación suelen producir una lista ruidosa de mutantes supervivientes. Antes de considerar cada superviviente una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un entrypoint controlado por un atacante?
- ¿Todas las rutas de llamada están limitadas por invariantes más estrictas que la comprobación mutada?
- ¿El nodo está en código muerto, lógica que solo afecta al formato o una ruta de aritmética/parser de alto impacto?

Los mutantes supervivientes que siguen siendo inalcanzables o están limitados estructuralmente suelen ser **mutantes equivalentes**. Los que siguen siendo **alcanzables** y afectan a **condiciones de límite**, **rutas de overflow/carry** o **aritmética/parsing críticos para la seguridad** deberían promoverse a:

- nuevos harnesses de fuzzing
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlacionar los hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo usando **archivo + rango de líneas** y utiliza el grafo para ampliar el análisis del impacto.<sup>[[6]](#references)</sup>

- calcula el **radio de impacto** de la función señalada
- comprueba si el hallazgo está en alguna ruta desde un entrypoint
- agrupa los hallazgos cercanos que confluyen en el mismo punto de estrangulamiento

Esto es útil al decidir si dedicar tiempo de fuzzing a una función específica: un nodo **alcanzable**, **complejo** y con **hallazgos de SAST** suele ser mejor objetivo que un nodo meramente complejo sin una ruta accesible para un atacante.

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

La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir los objetivos de fuzzing con mayor valor de seguridad esperado y, después, usa los mutantes supervivientes para decidir qué límites e invariantes debe poner a prueba tu harness.<sup>[[5]](#references)</sup>

## Fuzzing en Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo de `testing.F`, una forma práctica de mejorarlo es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain de Go bifurcada que conserva `go test -fuzz`, pero cambia el backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Esto resulta útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con uso intensivo de parsers**. La metodología no cambia:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con la planificación y mutación de LibAFL y mejores detectores complementarios.

### Convierte los fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en las evaluaciones de Go es que los comportamientos peligrosos a menudo **no** provocan un crash de forma predeterminada. Con gosentry, puedes convertir varias clases de estados «malos pero silenciosos» en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que las rutas seleccionadas de logging/error se comporten como crashes (útil para rutas de código del estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las entradas recién descubiertas de la cola con el detector de carreras de Go.
- `--catch-leaks=true` para volver a ejecutar las nuevas entradas de la cola con `goleak` y detenerse ante fugas de goroutines.
- La gestión de bloqueos de LibAFL para conservar los **bucles infinitos / las entradas muy lentas** como hallazgos de fuzzing, en lugar de dejar que desaparezcan como timeouts.
- Comprobaciones integradas de desbordamiento aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto resulta especialmente valioso para objetivos cuyo impacto en la seguridad consiste en un **fallo de parser sin panic**, un **bug de concurrencia** o un **bloqueo que solo provoca DoS**, en lugar de corrupción de memoria.

### Fuzzing consciente de structs para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente valores escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede aplicar fuzzing directamente a **valores compuestos** (structs, slices, arrays, pointers) y, al mismo tiempo, mutar los bytes subyacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usar esto al construir un formato wire falso solo para fuzzing ocultaría errores de lógica detrás de código de parsing exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y analiza los datos dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolos

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **fuzzing de gramáticas Nautilus** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre la metodología:

- Usa el modo de gramática cuando las mutaciones a nivel de byte suelen fallar en las primeras comprobaciones sintácticas.
- Mantén la gramática centrada en el **subconjunto de seguridad relevante** del lenguaje/protocolo, en lugar de modelar la especificación completa.
- Usa valores límite grandes en terminales/no terminales para poner a prueba los límites de enteros, longitudes y máquinas de estados.
- El modo de gramática mantiene las entradas válidas según la gramática, pero el objetivo sigue recibiendo **bytes/cadenas**, así que el análisis y las comprobaciones semánticas siguen ejecutándose dentro del código instrumentado.

### Fuzzing diferencial: comparar implementaciones, no solo fallos

Un patrón sólido para los ecosistemas Go es el **fuzzing diferencial basado en gramáticas**: generar entradas estructuradas válidas y proporcionárselas a dos analizadores, clientes o motores de transición de estados.<sup>[[7]](#references)[[8]](#references)</sup>

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
- discrepancias entre entradas aceptadas y rechazadas
- árboles de análisis u objetos decodificados diferentes
- transiciones de estado, nonces, balances o raíces de estado divergentes

Esta es una forma práctica de encontrar **discrepancias de consenso**, **ambigüedad del parser** y **desviaciones entre la especificación y la implementación** que el fuzzing de fallos puros suele pasar por alto.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutilizar el corpus de la campaña para generar informes de cobertura

Después de una campaña, vuelve a ejecutar el corpus de la cola guardado para generar un informe de cobertura de Go sin exportar manualmente un corpus aparte.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Ejecuta el comando desde el **mismo paquete** y con el mismo objetivo `-fuzz` para que gosentry resuelva el estado de campaña almacenado en caché correcto.



## References

- [1] [Fuzzing con gramáticas mutacionales](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing de AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte el código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [A Go fuzzing le faltaba la mitad del kit de herramientas. Bifurcamos la cadena de herramientas para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática, no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptables y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentación LLVM de AFL++: cobertura de rutas y de llamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predictivo sensible al contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de seguridad ofensiva de Android: fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer de Binder de LKL para Android: documentación de compilación y semillas de regresión](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: exploración de condiciones de carrera del kernel de Linux con intercalados controlados de accesos a memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
