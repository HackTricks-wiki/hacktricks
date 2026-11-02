# Metodología de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing con gramáticas mutacionales: cobertura frente a semántica

En el **fuzzing con gramáticas mutacionales**, las entradas se mutan sin dejar de ser **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como semillas del corpus las muestras que generan **nueva cobertura**. En los **objetivos de lenguaje** (analizadores, intérpretes, motores), esto puede pasar por alto errores que requieren **cadenas semánticas o de flujo de datos**, donde la salida de una construcción se convierte en la entrada de otra.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra semillas que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no conserva el flujo de datos encadenado**, así que descarta la muestra «más cercana al error» porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria resulta costosa y la retroalimentación de cobertura no orienta la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **combinar las fases mutacionales y generativas** o sesgar la generación hacia patrones de **encadenamiento de funciones** (no solo hacia la cobertura).<sup>[[1]](#references)</sup>

## Problemas de diversidad del corpus

La mutación guiada por cobertura es **codiciosa**: una muestra con nueva cobertura se guarda de inmediato y suele conservar grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, así que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene al alcanzar un umbral mínimo de tokens** (reduce el ruido y conserva suficiente estructura circundante para facilitar las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para el corpus de fuzzing mutacional es: **preferir un conjunto pequeño de semillas estructuralmente distintas que maximice la cobertura** antes que una gran cantidad de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empieza con **muestras del mundo real** (corpus públicos, rastreo, tráfico capturado, conjuntos de archivos del ecosistema objetivo).
- Depúralas mediante **minimización del corpus basada en cobertura** en vez de conservar todas las muestras válidas.
- Mantén las semillas **lo bastante pequeñas** para que las mutaciones afecten campos significativos, en lugar de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Vuelve a ejecutar la minimización del corpus después de cambios importantes en el harness o la instrumentación, porque el «mejor» corpus cambia cuando cambia la alcanzabilidad.

## Mutación consciente de las comparaciones para valores mágicos

Una razón común por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, cadenas de enumeración, checksums o valores de despacho del analizador protegidos por `memcmp`, tablas `switch` o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos objetivos, usa **trazado de comparaciones** (por ejemplo, flujos de trabajo de tipo AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y orientar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>

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

- Esto resulta especialmente útil cuando el objetivo protege la lógica interna tras **firmas de archivo**, **verbos de protocolo**, **etiquetas de tipo** o **bits de funciones dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o registros de depuración. Un diccionario pequeño con tokens gramaticales, nombres de bloques, verbos y delimitadores suele ser más valioso que una lista genérica enorme.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “mágicas” iniciales y luego vuelve a minimizar el corpus resultante para que las etapas posteriores comiencen con prefijos ya válidos.

## Fuzzing de APIs de archivos que ocultan un lenguaje de nombres de archivo

Un parámetro llamado `filename`, `path` o `URL` puede ser un punto de entrada a un intérprete en lugar de una búsqueda literal de archivo. Por ejemplo, CFITSIO Extended Filename Syntax (EFS) evalúa selectores entre corchetes, expresiones de filas/píxeles, columnas calculadas, histogramas y transformaciones antes de devolver el objeto abierto; algunas formas también crean copias temporales. Durante el mapeo de la superficie de ataque, clasifica cada API de apertura/importación como **ruta literal** o **ruta interpretada** y luego haz fuzzing del punto de entrada de producción que realmente llaman las aplicaciones.<sup>[[20]](#references)[[22]](#references)</sup>

Para conocer las primitivas resultantes de SSRF, copia de archivos y manejadores de protocolo —y las API más seguras para rutas literales—, consulta [Mini lenguajes de nombres de archivo como primitivas de SSRF/archivos](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantén el objeto de respaldo separado del programa sometido a fuzzing

Cuando la gramática reside en un sufijo del nombre de archivo, mutar solo los bytes del archivo referenciado no alcanza al analizador. En su lugar, un pequeño arnés puede leer un caso de prueba como cadena y pasárselo a la API de apertura interpretada; la campaña de CFITSIO llegó a la mayoría de los analizadores y evaluadores de EFS llamando a `fits_open_file()` en modo de solo lectura. Mantén disponibles por separado los archivos de respaldo válidos para que las mutaciones se centren en el lenguaje de selectores/expresiones, en vez de estropear continuamente la ruta base.<sup>[[22]](#references)</sup>

Usa seeds que alcancen cada una una familia gramatical distinta y luego deriva un diccionario compacto tanto de la especificación como del código fuente del lexer/analizador. Si la cobertura se estanca mientras las entradas fallan repetidamente en la misma ruta de error sintáctico, conserva los prefijos válidos y añade delimitadores, operadores, palabras clave, nombres de funciones y nombres de campos representativos, en vez de limitarte a aumentar el tiempo de mutación aleatoria.<sup>[[22]](#references)</sup>

Ejecuta el arnés con el diccionario gramatical, por ejemplo:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contener los efectos secundarios del harness «read-only»

Una marca de biblioteca «read-only» no garantiza que un testcase no tenga efectos secundarios: el lenguaje de nombres de archivo puede reescribir la entrada, crear archivos de salida o materializar objetos temporales. La campaña de CFITSIO destruyó inicialmente archivos de seed y dejó archivos inesperados en el sistema de archivos, por lo que fue necesario limpiar y aislar.<sup>[[22]](#references)</sup>

- Asigna a cada worker un directorio de trabajo desechable y un directorio temporal privado.
- Expón copias de los archivos canónicos de respaldo; nunca permitas que el target modifique la única copia del corpus.
- Deshabilita el acceso a la red, salvo que los backends remotos sean el objetivo previsto, y limita las rutas con permisos de escritura mediante un contenedor, un namespace de montaje o un sandbox equivalente.
- Restablece el directorio tras cada ejecución o lote de workers y trata los cambios inesperados en el sistema de archivos como hallazgos adicionales.

### Ciclo de crash a parche y fuzzing

Agrupa los crashes antes de corregirlos para que miles de artefactos no se conviertan en miles de tareas de parcheo. En la evaluación de CFITSIO, AFLTriage redujo el conjunto inicial de crashes a unas pocas causas raíz; el aviso resultante muestra distintos fallos, como comprobaciones incorrectas del tamaño del destino, punteros obsoletos tras `realloc()`, errores aritméticos y rutas inseguras de limpieza del parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiza una entrada representativa de cada grupo y reprodúcela con AddressSanitizer.
2. Registra el acceso exacto que falla, la ubicación en el código fuente, el historial de asignación/liberación y el estado del parser que provocó que el invariante dejara de cumplirse.
3. Aplica un parche candidato de alcance limitado y vuelve a compilar con la misma instrumentación de cobertura y sanitizadores.
4. Reproduce el caso original **y todas las entradas de su grupo**; activa también la detección de leaks, ya que una corrección de seguridad de memoria puede romper la gestión de propiedad en una ruta de error.
5. Ejecuta pruebas funcionales con archivos reales y luego reanuda desde la cola acumulada (o vuelve a importarla si el engine requiere un directorio de salida nuevo tras modificar el binario).
6. Repite el proceso: eliminar el primer crash superficial suele permitir que los seeds existentes avancen a un estado más profundo del parser.

Un LLM puede acelerar el paso 2 y redactar una propuesta para el paso 3 si recibe la entrada que provoca el crash, el informe del sanitizador, el harness y el código fuente pertinente, pero su parche sigue siendo poco fiable. La reproducción con el sanitizador y los controles de regresión —no la explicación del modelo— determinan si se acepta la reparación.<sup>[[22]](#references)</sup>

## Comentarios más completos cuando la cobertura de edges no distingue rutas diferentes

La cobertura normal de edges no permite distinguir dos ejecuciones que recorren el mismo helper desde distintos callers o toman combinaciones de ramas distintas dentro de una función. Esto importa en decoders compartidos, despachadores de protocolos y helpers de intérpretes, donde la **ruta** hasta un edge determina el estado activo. Rastrear ingenuamente todos los contextos de llamada también es peligroso: el mapa de cobertura y la cola pueden crecer sin control. Por ello, la investigación sobre fuzzing sensible al contexto recomienda refinar solo los contextos prometedores, en lugar de tratar todo el grafo de llamadas como sensible al contexto.<sup>[[14]](#references)</sup>

Las versiones recientes de AFL++ ofrecen **cobertura de rutas por función de Ball-Larus**, además de la cobertura normal de edges. Asigna una feature a cada ruta acíclica de una función; se eliminan los back-edges de los bucles, por lo que esta retroalimentación distingue combinaciones de ramas, pero **no el número de iteraciones del bucle**. Empieza con el nivel relajado `1` y luego limita los modos más estrictos al código sospechoso de parsers y máquinas de estado, porque el número de rutas puede crecer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para un helper llamado desde muchos sitios relevantes para la seguridad, el modo LTO puede combinar cada ruta de función con su sitio de llamada inmediato:<sup>[[13]](#references)</sup>

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

**Recomendaciones para la campaña:** aplica feedback más completo con prudencia y supervisa el coste en el mapa de cobertura y la cola.<sup>[[13]](#references)[[14]](#references)</sup>

- Ejecuta en paralelo una instancia normal con cobertura de aristas; el feedback más completo solo es útil si el coste adicional de cola/mapa no reduce demasiado las ejecuciones por segundo.
- Usa `AFL_LLVM_ALLOWLIST` para limitar la instrumentación de rutas/llamadores cuando las bibliotecas con muchas plantillas o el código de utilidades genéricas dominen el mapa.
- Las funciones con demasiadas rutas acíclicas pueden omitirse en AFL++; las advertencias durante la compilación indican que el objetivo necesita una allowlist o un nivel menos estricto.
- La cobertura de llamadores + rutas solo admite un nivel de llamador. No la combines con pilas de contexto más profundas.
- Los identificadores de ruta pueden cambiar entre versiones principales de LLVM. Mantén fija la cadena de herramientas durante una campaña y no sincronices corpus basados en PATH como si sus identificadores de características fueran estables entre compilaciones.
- Este feedback complementa `CMPLOG`: el trazado de comparaciones resuelve **qué valor supera una guarda**, mientras que el feedback de rutas/llamadores conserva **qué ruta y combinación de ramas permitieron llegar a ella**.

## Fuzzing con estado: las secuencias son seeds

Para **protocolos**, **flujos de trabajo autenticados** y **parsers de varias etapas**, la unidad interesante no suele ser un único blob, sino una **secuencia de mensajes**. Concatenar toda la transcripción en un solo archivo y mutarla a ciegas suele ser ineficiente, porque el fuzzer muta cada paso por igual, aunque solo el mensaje posterior llegue al estado vulnerable.<sup>[[4]](#references)</sup>

Un patrón más eficaz consiste en tratar la **secuencia misma como el seed** y usar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser, tipos de objetos devueltos) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes válidos de prefijo** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor en respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere mutaciones/empalmes por mensaje en lugar de mutar toda la transcripción serializada como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, úsalos como un **oráculo de estado económico** para priorizar las secuencias que avanzan más.

Por la misma razón, el fuzzing de archivos convencional suele pasar por alto bugs autenticados, transiciones ocultas o bugs de parser que aparecen “solo después del handshake”: el fuzzer debe preservar **el orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver con varios clientes

Una cobertura de aristas alta aún puede pasar por alto bugs del driver IPC, porque la cobertura no describe **la propiedad de los objetos, los recuentos de referencias, los mensajes pendientes, el orden de limpieza ni los entrelazados de hilos**. La página sobre [los componentes internos de Android Binder IPC](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) explica el modelo de objetos del driver; este ejemplo se centra en el harness del fuzzer. Android Binder es un modelo útil: alcanzar tanto las rutas de asignación como las de liberación no basta si el fuzzer no puede hacer que varios procesos operen sobre el mismo objeto del kernel en el orden necesario.<sup>[[15]](#references)</sup>

#### Modela el protocolo, no buffers `ioctl` aislados

Representa cada caso de prueba como una gramática ordenada de **identidad del cliente + operación + argumentos estructurados**. El fuzzer LKL de Binder usa protobuf y `libprotobuf-mutator`, con un cliente persistente de gestor de contexto y dos clientes ordinarios. Luego, un harness semántico preserva las relaciones que la mutación ciega de bytes destruiría.<sup>[[15]](#references)</sup>

- Guarda en caché los valores devueltos por operaciones anteriores. Por ejemplo, `BC_FREE_BUFFER` debe reutilizar un puntero al buffer de transacción devuelto por un `ioctl` anterior.
- Genera respuestas predeterminadas válidas para que las transacciones síncronas puedan completarse y las operaciones posteriores sigan siendo alcanzables.
- Rechaza transiciones imposibles, como las transacciones a uno mismo o varias transacciones pendientes dirigidas al mismo destino.
- Mantén el estado de inicialización singleton fuera del reinicio por entrada. Binder solo permite un registro `BINDER_SET_CONTEXT_MGR` por arranque, por lo que destruir y volver a crear ese cliente repetidamente invalidaría las entradas posteriores.

Una plantilla útil para provocar una race de ciclo de vida consiste en hacer que un cliente transfiera un objeto, iniciar la limpieza de un hilo o proceso y, al mismo tiempo, hacer que el cliente receptor libere el buffer de transacción. En el ejemplo de CVE-2020-0423, una transferencia de `BINDER_TYPE_WEAK_BINDER` seguida de una race entre `BINDER_THREAD_EXIT` y `BC_FREE_BUFFER` podía liberar un `binder_work` integrado mientras la ruta de limpieza del hilo que salía aún lo usaba.<sup>[[15]](#references)</sup>

#### Reintroduce entrelazados controlados en un kernel de espacio de usuario

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) enlaza el código real del kernel en un harness de espacio de usuario y expone su interfaz de llamadas al sistema mediante `lkl_syscall`. Así resulta sencillo coordinar el estado de protobuf, la cobertura y KASAN en un único proceso. Sin embargo, normalmente LKL ejecuta una llamada al sistema sin que otro hilo del kernel la interrumpa. Para las campañas de race, inserta puntos `schedule()` alrededor de límites seleccionados de bloqueo/desbloqueo y ciclo de vida; después, permite que el harness elija aleatoriamente el siguiente cliente en cada cesión. Mantén estos puntos bien delimitados, porque cada uno multiplica el espacio de búsqueda de planificación. El planificador aleatorio descrito por los investigadores **no** forma parte del fuzzer de Binder upstream.<sup>[[15]](#references)</sup>

#### Compila y reproduce seeds de regresión serializados

El harness upstream fija una versión compatible de `libprotobuf-mutator`, habilita la instrumentación de fuzzing de LKL y KASAN con `LKL_FUZZING=1`, y habilita `CONFIG_MMU` para Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Tras comprobar una revisión deliberadamente vulnerable o aplicar los parches de reversión documentados en el upstream, una semilla serializada puede reproducir toda la transición de estado entre varios clientes sin tener que reconstruirla en una prueba de concepto ad hoc en C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trata el use-after-free de KASAN resultante como confirmación de que la seed llegó a la ruta vulnerable del ciclo de vida. **No** demuestra las primitivas posteriores necesarias para ejecutar código en el kernel o escalar privilegios.<sup>[[16]](#references)</sup>

## Truco de diversidad en una sola máquina (estilo Jackalope)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de cobertura** es **reiniciar workers de corta duración** contra un servidor persistente. Cada worker empieza con un corpus vacío, sincroniza después de `T` segundos, ejecuta durante otros `T` segundos sobre el corpus combinado, vuelve a sincronizar y luego termina. Esto genera **estructuras nuevas en cada generación** y, al mismo tiempo, aprovecha la cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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
- En el modo de fuzzing gramatical, la **sincronización inicial con el servidor se omite de forma predeterminada** (no hace falta `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del objetivo**; suele funcionar mejor cambiarlo cuando el worker ya ha encontrado la mayor parte de la cobertura “fácil”.

## Snapshot Fuzzing Para Objetivos Difíciles De Instrumentar

Cuando el código que quieres probar solo es accesible **después de un proceso de preparación costoso** (arrancar una VM, completar un inicio de sesión, recibir un paquete, analizar un contenedor, inicializar un servicio), una alternativa útil es **snapshot fuzzing**: capturar el estado del proceso o la VM ya preparado, inyectar cada caso de prueba en la ruta de entrada del objetivo, ejecutar hasta que se produzca un crash o un timeout y restaurar el snapshot. Así se evita repetir la inicialización o los prefijos del protocolo, y resulta útil para **servicios de red**, **firmware**, **superficies de ataque posteriores a la autenticación** y **objetivos solo binarios**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el objetivo hasta que el estado de interés esté listo.
2. Crea un snapshot de la **memoria + los registros** en ese punto.
3. Para cada caso de prueba, escribe la entrada modificada directamente en el búfer pertinente del proceso o guest.
4. Ejecuta hasta que se produzca un crash, un timeout o un reinicio.
5. Restaura el snapshot; para objetivos en VM, restaura solo las **páginas modificadas** cuando sea posible y repite.

Coloca el snapshot tan cerca como sea práctico del primer paso costoso de análisis o despacho, por ejemplo, después de un `recv`/`read` o del punto de deserialización del paquete, y registra el búfer de entrada que usa el objetivo. Esto sigue el principio de ubicación adaptativa: mover el snapshot más adentro del procesamiento de la entrada para evitar repetir trabajo.<sup>[[11]](#references)</sup>

## Exploración De Condiciones De Carrera En El Kernel De Linux Con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) convierte las condiciones de carrera sensibles a los tiempos de ejecución en el kernel de Linux en secuencias repetibles de accesos a memoria. Puede enumerar automáticamente ejecuciones **A-B-A** de dos contextos o permitir que un analista imponga restricciones de orden mediante una interfaz de terminal o GUI. Es una herramienta de investigación experimental, no un fuzzer de concurrencia completo: actualmente requiere LLVM 23+ y el kernel parcheado del proyecto; las herramientas de línea de comandos admiten dos hilos de prueba, y la capa de fuzzing en espacio de usuario propuesta aún no está implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Recopilar puntos de comunicación entre contextos

Compila el kernel instrumentado con callbacks outline de KASAN y la compatibilidad parcheada de KCOV para registrar accesos a memoria. El README del proyecto también recomienda desactivar la optimización de llamadas entre hermanos para que las pilas de llamadas sigan siendo útiles.<sup>[[17]](#references)[[18]](#references)</sup>

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

El modo outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convierte los accesos instrumentados en llamadas auxiliares. Los parches del kernel MAccConc desactivan `asan-opt-same-temp` para que los accesos consecutivos no se fusionen; desactiva también la optimización `asan-opt-globals` cuando sea necesario que las carreras entre variables globales sean visibles. KCOV lleva los registros resultantes al espacio de usuario. Compara los accesos de distintos contextos de ejecución y conserva los pares cuyos rangos de bytes se solapan y en los que al menos uno escribe; modela `kfree()` como una escritura para que las transiciones del ciclo de vida también sean candidatas.<sup>[[17]](#references)</sup>

Para el trabajo que continúa fuera de la tarea que lo inicia, como el procesamiento de paquetes o las devoluciones de llamada RCU, el subsistema debe propagar un handle de cobertura remota de KCOV. La cobertura remota de KCOV upstream es optativa y no está disponible automáticamente para cualquier trabajo en segundo plano, por lo que la falta de propagación puede hacer invisible una interacción real.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificar el mismo acceso dinámico en cada ejecución

No repitas la ejecución usando una dirección concreta del heap, que puede cambiar tras cada asignación, ni solo una dirección de instrucción, que es ambigua dentro de helpers como `memcpy()` y `spin_lock()`. MAccConc usa una **traza de pila aumentada con contadores**: cada frame identifica una función llamada más el número de invocación dentro de su llamador, y el elemento final identifica la instrucción de acceso a memoria. Los registros de entrada y salida de funciones de SanitizerCoverage permiten al espacio de usuario reconstruir este identificador dinámico, que permanece estable pese a los cambios de dirección y al ruido de flujo de control no relacionado.<sup>[[17]](#references)</sup>

### Convertir los pares candidatos en planificaciones forzadas

El ioctl `KCOV_SET_DI` parcheado asocia un identificador de acceso aumentado con contadores a una acción sobre una bandera compartida.<sup>[[17]](#references)</sup>

| Acción | Semántica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Establece la bandera *N* justo antes del acceso seleccionado. |
| `DI_STACK_WAIT` | Antes del acceso seleccionado, espera en bucle hasta que se establezca la bandera *N* o venza el límite configurado. |
| `DI_STACK_WAKE_POST` | Establece la bandera *N* justo después del acceso seleccionado. |

Para una restricción parcial de **A ocurre antes que B**, asigna `DI_STACK_WAKE_POST` a A y `DI_STACK_WAIT` a B usando la misma bandera. Para una planificación de dos contextos completamente especificada, inicia B bloqueado; luego, haz que A despierte a B y espera en el primer punto de transferencia. B realiza la operación inversa en la siguiente transferencia. Esto funciona como un cambio de contexto determinista y es lo que utiliza el explorador automático A-B-A.<sup>[[17]](#references)</sup>

Una campaña mínima consiste en compilar el caso de prueba de cuatro hooks (`test_setup`, dos funciones de hilo y `test_end`) como una biblioteca compartida, recopilar una traza sin restricciones y, después, enumerar candidatos A-B-A o añadir restricciones manuales alrededor de los accesos sospechosos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta los timeouts por separado de los reordenamientos exitosos: el orden solicitado puede ser imposible porque un bloqueo o una dependencia de inicialización/publicación impide que el segundo contexto llegue a su punto de inyección. Ten en cuenta también los puntos ciegos de KASAN: los accesos directos a la pila normalmente no se instrumentan, salvo que puedan estar fuera de límites; las variables globales se omiten con la optimización predeterminada; y los compiladores actuales no pueden emitir hooks de ASAN y TSAN simultáneamente. Por último, el prototipo pierde su búfer de KCOV cuando un guest sufre un panic, así que conserva una consola/oráculo de fallos independiente.<sup>[[17]](#references)</sup>

Para el fuzzing guiado por concurrencia futuro, registra resúmenes de accesos a memoria por entrada o syscall, empareja operaciones que formarían puntos de comunicación entre contextos y, después, explora solo esas combinaciones. Las snapshots de VM estabilizan el estado global y las direcciones; sin snapshots, los metadatos del sitio de asignación pueden abstraer objetos entre ejecuciones. Esta es una extensión propuesta, no una función de las herramientas de espacio de usuario actuales de MAccConc.<sup>[[17]](#references)</sup>

## Introspección del harness: detecta fuzzers superficiales pronto

Cuando una campaña se estanca, a menudo el problema no es el mutador, sino el **harness**. Usa la **introspección de alcanzabilidad/cobertura** para encontrar funciones que son alcanzables estáticamente desde tu objetivo de fuzzing, pero que rara vez —o nunca— se cubren dinámicamente. Esas funciones suelen indicar uno de estos tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el objetivo demasiado pronto o demasiado tarde.
- Al corpus de semillas le falta toda una familia de funciones.
- El objetivo realmente necesita un **segundo harness** en lugar de un único harness sobredimensionado que “lo haga todo”.

Si usas flujos de trabajo al estilo de OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la alcanzabilidad estática con la cobertura en tiempo de ejecución y generar informes a partir de una ejecución cronometrada o de un corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa el informe para decidir si añadir un nuevo harness para una ruta del parser que no se haya probado, ampliar el corpus para una función específica o dividir un harness monolítico en varios puntos de entrada.

## Selección de objetivos de fuzzing basada primero en el grafo y triaje de mutaciones

Si ya tienes **hallazgos de análisis estático**, **supervivientes de mutation testing** e **informes de cobertura**, no los evalúes como listas independientes. Primero, crea un **grafo de llamadas**, anota los nodos con **complejidad ciclomática**, **alcanzabilidad desde entrypoints/entradas no confiables** y cualquier hallazgo externo; después, plantea preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde entradas no confiables?
- ¿Qué supervivientes de mutación están en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **radio de impacto** inusualmente amplio?

Esto suele revelar mejores objetivos de fuzzing que fijarse solo en la «menor cobertura». Un parser/decoder con **alta complejidad** y **alcanzabilidad externa** confirmada es mejor candidato para un harness que un helper interno aislado con poca cobertura pero sin una ruta controlada por un atacante.

### Flujo de trabajo práctico de triaje

1. Crea un **grafo de código** a partir del código base y extrae métricas de complejidad/ramas por función.
2. Enumera los **entrypoints** que aceptan entradas controladas por un atacante: request handlers, decoders, importers, protocol parsers y lectores de CLI/archivos.
3. Ejecuta consultas de rutas desde esos entrypoints hasta las funciones candidatas para separar la superficie de ataque alcanzable del código muerto o solo interno.
4. Prioriza los nodos que combinen:
   - alta **complejidad ciclomática**
   - **alcanzabilidad desde entradas no confiables** confirmada
   - alto **radio de impacto** o muchos dependientes posteriores
   - pruebas que lo corroboren, como hallazgos **SARIF**, notas de auditoría o supervivientes de mutación
5. Escribe primero harnesses específicos para los nodos con mejor puntuación, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Supervivientes de mutación: equivalentes o accionables

Mutation testing suele generar una lista ruidosa de supervivientes. Antes de tratar cada superviviente como una brecha de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un entrypoint controlado por un atacante?
- ¿Todas las rutas de llamada están restringidas por invariantes más estrictas que la comprobación mutada?
- ¿El nodo está en código muerto, lógica que solo afecta al formato o una ruta de aritmética/parser de alto impacto?

Los supervivientes que siguen siendo inalcanzables o están estructuralmente restringidos suelen ser **mutantes equivalentes**. Los supervivientes que siguen siendo **alcanzables** y afectan a **condiciones de límite**, **rutas de overflow/carry** o **aritmética/parsing críticos para la seguridad** deberían convertirse en:

- nuevos fuzz harnesses
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlacionar hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, asigna los hallazgos a los nodos del grafo mediante **archivo + rango de líneas** y usa el grafo para ampliar el análisis del impacto.<sup>[[6]](#references)</sup>

- calcula el **radio de impacto** de la función marcada
- comprueba si el hallazgo está en alguna ruta desde un entrypoint
- agrupa los hallazgos cercanos que convergen en el mismo punto de estrangulamiento

Esto resulta útil para decidir si dedicar tiempo de fuzzing a una función concreta: un nodo **alcanzable**, **complejo** y con **hallazgos de SAST** suele ser mejor objetivo que un nodo simplemente complejo sin una ruta controlada por un atacante.

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

La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir objetivos de fuzzing con el mayor valor de seguridad esperado y, después, usa los mutantes que sobreviven para decidir qué límites e invariantes debe poner a prueba tu harness.<sup>[[5]](#references)</sup>

## Fuzzing diferencial de codificaciones de claves criptográficas

Empieza con claves serializadas válidas o vectores de prueba estándar. Muta los campos codificados sin alterar la longitud ni la estructura necesarias para alcanzar las rutas de importación y operación; después, envía los mismos bytes a implementaciones independientes. Compara la aceptación y los errores. Las firmas y los textos cifrados aleatorizados requieren oráculos de corrección, no comparaciones byte por byte: verifica las firmas o compara los secretos compartidos de una ronda de encapsulación/decapsulación. Los vectores de prueba establecen la conformidad para casos conocidos; la mutación diferencial sondea codificaciones malformadas que van más allá de esos casos.<sup>[[23]](#references)[[26]](#references)</sup>

Para estos formatos de clave, usa oráculos específicos para cada formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Claves de firma expandidas ML-DSA:** altera los coeficientes `s1` o `s2` empaquetados para que queden fuera de `[-η, η]`, manteniendo la clave procesable. Comprueba si la importación o la firma la rechazan y si alguna firma resultante se verifica. Las diferencias en la aceptación por sí solas no constituyen incumplimientos de los estándares, porque FIPS 204 no exige comprobaciones adicionales de las claves privadas. Consulta el [mecanismo de filtración condicional](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pares de claves ML-KEM:** distingue las comprobaciones obligatorias de la clave de encapsulación y de la entrada de decapsulación de la comprobación opcional de consistencia por pares (PCT) de un par importado. Encapsula con su clave pública, decapsula con su clave privada y compara los secretos compartidos; una discrepancia puede interrumpir la comunicación cifrada incluso cuando las claves individuales superan las comprobaciones de entrada. Comprueba si la API valida las entradas durante la operación o mediante una llamada independiente; libcrux expone `validate_public_key(pk)` y `validate_private_key(sk, ct)`, que no sustituyen a una PCT.
- **Claves XMSS/XMSSMT sin procesar:** prueba los ciclos de serialización de claves de **firma y verificación** en distintos conjuntos de parámetros, no solo las operaciones con claves en memoria. XMSS y XMSSMT tienen espacios de nombres OID de cuatro bytes separados, por lo que un analizador que solo comprueba el OID y prueba primero XMSS puede clasificar erróneamente una clave XMSSMT cuyo OID coincida y rechazar su importación. El analizador de RustCrypto descrito ilustra un fallo de interoperabilidad/disponibilidad, no una falsificación de firmas.

## Fuzzing en Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo `testing.F`, una forma práctica de mejorarlo es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una cadena de herramientas de Go bifurcada que mantiene `go test -fuzz`, pero cambia el backend a **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Esto resulta útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con muchos requisitos de análisis**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para la callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con la planificación y las mutaciones de LibAFL y mejores detectores complementarios.

### Convierte los fallos silenciosos en hallazgos del fuzzing

Un problema recurrente en las evaluaciones de Go es que el comportamiento peligroso a menudo **no provoca un crash** de forma predeterminada. Con gosentry, puedes convertir varias clases de estados «malos, pero silenciosos» en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que determinadas rutas de logging o error se comporten como crashes (útil para rutas de código del estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las nuevas entradas descubiertas de la queue con el detector de race de Go.
- `--catch-leaks=true` para volver a ejecutar las nuevas entradas de la queue con `goleak` y detenerse si se detectan leaks de goroutines.
- Gestión de hangs de LibAFL para conservar los **bucles infinitos / las entradas muy lentas** como hallazgos del fuzzing, en lugar de dejar que desaparezcan como timeouts.
- Comprobaciones integradas de desbordamiento aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto es especialmente valioso para objetivos cuyo impacto en la seguridad consiste en un **fallo de parser sin panic**, un **bug de concurrencia** o un **hang que solo provoca DoS**, en lugar de corrupción de memoria.

### Fuzzing consciente de structs para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede fuzzear **valores compuestos** directamente (structs, slices, arrays, pointers) y seguir mutando los bytes subyacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usar un formato de intercambio falso solo para fuzzing ocultaría errores lógicos detrás de código de análisis exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y analiza los datos dentro del callback.

### Fuzzing basado en gramáticas para analizadores y entradas de protocolos

Para analizadores, formatos y lenguajes de entrada, gosentry puede ejecutar **fuzzing gramatical Nautilus** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas de metodología:

- Usa el modo de gramática cuando las mutaciones a nivel de byte suelen fallar en las primeras comprobaciones de sintaxis.
- Mantén la gramática centrada en el **subconjunto del lenguaje/protocolo relevante para la seguridad**, en lugar de modelar toda la especificación.
- Usa valores límite grandes en terminales/no terminales para poner a prueba los límites de enteros, longitudes y máquinas de estados.
- El modo de gramática mantiene las entradas válidas según la gramática, pero el objetivo sigue recibiendo **bytes/cadenas**, por lo que el análisis sintáctico y las comprobaciones semánticas siguen dentro del código instrumentado.

### Fuzzing diferencial: compara implementaciones, no solo fallos

Un patrón sólido en los ecosistemas de Go es el **fuzzing diferencial basado en gramáticas**: generar entradas estructuradas válidas y proporcionárselas a dos analizadores, clientes o motores de transición de estados.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considera los siguientes casos como hallazgos:

- una implementación provoca un panic mientras que la otra rechaza la entrada correctamente
- discrepancias entre entradas aceptadas y rechazadas
- árboles de análisis u objetos decodificados diferentes
- transiciones de estado, nonces, saldos o raíces de estado divergentes

Esta es una forma práctica de encontrar **desajustes de consenso**, **ambigüedades del parser** y **divergencias entre la especificación y la implementación** que las pruebas de fuzzing centradas únicamente en los crashes suelen pasar por alto.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutiliza el corpus de la campaña para generar informes de cobertura

Después de una campaña, vuelve a ejecutar el corpus de la cola guardado para generar un informe de cobertura de Go sin tener que exportar manualmente un corpus aparte.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Ejecuta el comando desde el **mismo paquete** y con el **mismo destino `-fuzz`** para que gosentry resuelva el estado de campaña almacenado en caché correcto.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing de AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [A Go fuzzing le faltaba la mitad del kit de herramientas. Creamos un fork de la cadena de herramientas para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado que usa snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptables y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentación LLVM de AFL++: cobertura de rutas y callers](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predictivo sensible al contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de seguridad ofensiva de Android: fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer de Binder de LKL para Android: documentación de compilación y seeds de regresión](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: explorar condiciones de carrera del kernel de Linux con intercalaciones controladas de accesos a memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaxis de nombres de archivo extendidos de CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Aviso de Doyensec: CFITSIO, cuarto trimestre de 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing de la sintaxis de nombres de archivo extendidos de CFITSIO: 16 vulnerabilidades de seguridad de memoria y triaje asistido por Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing diferencial para criptografía](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: estándar de mecanismo de encapsulación de claves basado en retículos modulares](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Error de análisis de OID de XMSSMT: issue #1442 de RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Estado de las implementaciones de criptografía poscuántica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
