# Metodología de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing mutacional con gramáticas: cobertura vs. semántica

En el **fuzzing mutacional con gramáticas**, las entradas se mutan sin dejar de ser **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como semillas del corpus las muestras que generan **nueva cobertura**. En los **objetivos de lenguaje** (parsers, intérpretes, motores), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos**, en las que la salida de una construcción se convierte en la entrada de otra.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra semillas que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no conserva el flujo de datos encadenado**, por lo que se descarta la muestra «más cercana al bug» porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria resulta costosa y la retroalimentación de cobertura no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **combinar las fases mutacional y generativa** o dar prioridad a patrones de **encadenamiento de funciones** (no solo a la cobertura).<sup>[[1]](#references)</sup>

## Problemas de diversidad del corpus

La mutación guiada por cobertura es **codiciosa**: una muestra que añade cobertura se guarda de inmediato y suele conservar grandes regiones sin cambios. Con el tiempo, los corpus se llenan de **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, así que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene al alcanzar un umbral mínimo de tokens** (reduce el ruido sin eliminar tanta estructura circundante como para dificultar las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para los corpus de fuzzing mutacional es: **preferir un conjunto pequeño de semillas estructuralmente diferentes que maximicen la cobertura** antes que un montón de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empieza con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema del objetivo).
- Depúralas mediante **minimización del corpus basada en cobertura**, en lugar de conservar todas las muestras válidas.
- Mantén las semillas **lo bastante pequeñas** para que las mutaciones afecten campos relevantes, en vez de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Vuelve a minimizar el corpus tras cambios importantes en el harness o la instrumentación, porque el corpus «óptimo» cambia cuando cambia la alcanzabilidad.

## Mutación guiada por comparaciones para valores mágicos

Una razón habitual por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, cadenas de enumeración, sumas de verificación o valores de despacho del parser protegidos por `memcmp`, tablas `switch` o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte por byte.

Para estos objetivos, usa **trazado de comparaciones** (por ejemplo, los flujos de trabajo de estilo Redqueen o `CMPLOG` de AFL++) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y orientar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>

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

- Esto resulta especialmente útil cuando el objetivo oculta lógica compleja tras **firmas de archivos**, **verbos de protocolo**, **etiquetas de tipo** o **bits de características dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolos o registros de depuración. Un diccionario pequeño con tokens de gramática, nombres de fragmentos, verbos y delimitadores suele ser más valioso que una lista de palabras genérica enorme.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las primeras comparaciones de “magic” y luego vuelve a minimizar el corpus resultante para que las etapas posteriores comiencen con prefijos ya válidos.

## Fuzzing de APIs de archivos que ocultan un lenguaje de nombres de archivo

Un parámetro llamado `filename`, `path` o `URL` puede ser un punto de entrada a un intérprete, no una búsqueda literal de archivo. Por ejemplo, CFITSIO Extended Filename Syntax (EFS) evalúa selectores entre corchetes, expresiones de filas/píxeles, columnas calculadas, histogramas y transformaciones antes de devolver el objeto abierto; algunas formas también crean copias temporales. Durante el mapeo de la superficie de ataque, clasifica cada API de apertura/importación como **ruta literal** o **ruta interpretada** y luego aplica fuzzing al punto de entrada de producción que realmente usan las aplicaciones.<sup>[[20]](#references)[[22]](#references)</sup>

Para conocer las primitivas SSRF, de copia de archivos y de manejadores de protocolo resultantes —y las APIs de ruta literal más seguras—, consulta [Minilenguajes de nombres de archivo como primitivas SSRF/de archivos](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantén separado el objeto de respaldo del programa sometido a fuzzing

Cuando la gramática reside en un sufijo del nombre de archivo, modificar únicamente los bytes del archivo referenciado no llega al parser. En su lugar, un harness pequeño puede leer un testcase como cadena y pasárselo a la API de apertura interpretada; la campaña de CFITSIO alcanzó la mayoría de los parsers y evaluadores de EFS llamando a `fits_open_file()` en modo de solo lectura. Mantén disponibles por separado archivos de respaldo válidos para que las mutaciones se centren en el lenguaje de selectores/expresiones, en vez de estropear continuamente la ruta base.<sup>[[22]](#references)</sup>

Usa seeds que alcancen cada una una familia gramatical distinta y luego deriva un diccionario compacto tanto de la especificación como del código fuente del lexer/parser. Si la cobertura se estanca mientras las entradas fallan repetidamente en la misma ruta de error de sintaxis, conserva los prefijos válidos y añade delimitadores, operadores, palabras clave, nombres de funciones y nombres de campos representativos, en lugar de limitarte a aumentar el tiempo de mutación aleatoria.<sup>[[22]](#references)</sup>

Ejecuta el harness con el diccionario de gramática; por ejemplo:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contener los efectos secundarios del harness «read-only»

Una marca de biblioteca read-only no garantiza que un testcase no tenga efectos secundarios: el lenguaje de nombres de archivo puede reescribir la entrada, crear archivos de salida o materializar objetos temporales. La campaña de CFITSIO inicialmente destruyó archivos semilla y dejó archivos inesperados por todo el sistema de archivos, por lo que fue necesario limpiar y aislar.<sup>[[22]](#references)</sup>

- Asigna a cada worker un directorio de trabajo desechable y un directorio temporal privado.
- Expón copias de los archivos de respaldo canónicos; nunca permitas que el objetivo modifique la única copia del corpus.
- Desactiva el acceso a la red, salvo que los backends remotos sean el objetivo previsto, y restringe las rutas de escritura con un contenedor, un namespace de montaje o un sandbox equivalente.
- Restablece el directorio después de cada ejecución o lote de workers y trata los cambios inesperados en el sistema de archivos como hallazgos adicionales.

### Ciclo de crash a parche y fuzzing

Agrupa los crashes antes de repararlos para que miles de artefactos no se conviertan en miles de tareas de parcheo. En la evaluación de CFITSIO, AFLTriage redujo el conjunto inicial de crashes a unas pocas causas raíz; el aviso resultante muestra fallos distintos, incluidos checks incorrectos del tamaño del destino, punteros obsoletos tras `realloc()`, errores aritméticos y rutas inseguras de limpieza del parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiza una entrada representativa de cada grupo y reprodúcela con AddressSanitizer.
2. Registra el acceso exacto que falla, la ubicación en el código fuente, el historial de asignación y liberación, y el estado del parser que hizo que el invariante dejara de cumplirse.
3. Aplica un parche candidato de alcance reducido y recompila con la misma instrumentación de cobertura y sanitización.
4. Vuelve a reproducir el caso original **y todas las entradas de su grupo**; activa también la detección de leaks, porque una corrección de seguridad de memoria puede romper la gestión de la propiedad en una ruta de error.
5. Ejecuta pruebas funcionales con archivos reales y luego reanuda desde la cola acumulada (o vuelve a importar esa cola si el motor requiere un directorio de salida nuevo después de cambiar el binario).
6. Repite: eliminar el primer crash superficial suele permitir que las semillas existentes avancen a un estado más profundo del parser.

Un LLM puede acelerar el paso 2 y redactar una propuesta para el paso 3 si recibe la entrada que provoca el crash, el informe del sanitizer, el harness y el código fuente pertinente, pero su parche sigue sin ser de confianza. La reproducción con el sanitizer y los controles de regresión —no la explicación del modelo— determinan si se acepta la reparación.<sup>[[22]](#references)</sup>

## Más riqueza de feedback cuando la cobertura de edges agrupa rutas distintas

La cobertura normal de edges no permite distinguir dos ejecuciones que atraviesan el mismo helper desde distintos callers o que toman combinaciones diferentes de ramas dentro de una función. Esto importa en decoders compartidos, despachadores de protocolos y helpers de intérpretes, donde la **ruta** hasta un edge determina el estado activo. Rastrear ingenuamente cada contexto de llamada también es peligroso: el mapa de cobertura y la cola pueden crecer desmesuradamente. Por eso, la investigación sobre fuzzing sensible al contexto recomienda refinar solo los contextos prometedores, en vez de tratar todo el grafo de llamadas como sensible al contexto.<sup>[[14]](#references)</sup>

Las versiones recientes de AFL++ ofrecen **cobertura de rutas por función de Ball-Larus**, además de la cobertura normal de edges. Asigna una feature a cada ruta acíclica de una función; se eliminan las aristas de retorno de los bucles, por lo que este feedback distingue combinaciones de ramas, pero **no la cantidad de iteraciones del bucle**. Empieza con el nivel flexible `1` y luego limita los modos más estrictos al código sospechoso del parser o de la máquina de estados, porque la cantidad de rutas puede crecer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para una función auxiliar llamada desde muchos puntos relevantes para la seguridad, el modo LTO puede combinar cada ruta de función con su sitio de llamada inmediato:<sup>[[13]](#references)</sup>

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

**Guía para campañas:** aplica feedback más rico con moderación y supervisa el costo en el mapa de cobertura y la cola.<sup>[[13]](#references)[[14]](#references)</sup>

- Ejecuta en paralelo una instancia normal con cobertura de bordes; el feedback más rico solo es útil si el costo adicional de cola/mapa no reduce las ejecuciones por segundo.
- Usa `AFL_LLVM_ALLOWLIST` para restringir la instrumentación de rutas/llamadores cuando las bibliotecas grandes con muchas plantillas o el código de utilidades genéricas dominen el mapa.
- AFL++ puede omitir funciones con demasiadas rutas acíclicas; las advertencias durante la compilación indican que el objetivo necesita una allowlist o un nivel menos estricto.
- La cobertura de llamadores + rutas admite una sola profundidad de llamador. No la combines con pilas de contexto más profundas.
- Los IDs de rutas pueden cambiar entre versiones principales de LLVM. Mantén fija la cadena de herramientas durante una campaña y no sincronices corpus basados en PATH como si sus IDs de características fueran estables entre compilaciones.
- Este feedback complementa `CMPLOG`: el trazado de comparaciones resuelve **qué valor supera una guarda**, mientras que el feedback de rutas/llamadores conserva **qué ruta y combinación de ramas permitió llegar a ella**.

## Fuzzing con estado: las secuencias son seeds

Para **protocolos**, **flujos de trabajo autenticados** y **parsers de varias etapas**, la unidad interesante suele ser una **secuencia de mensajes**, no un único blob. Concatenar toda la transcripción en un archivo y mutarla a ciegas suele ser ineficiente, porque el fuzzer muta todos los pasos por igual, incluso cuando solo el mensaje posterior alcanza el estado frágil.<sup>[[4]](#references)</sup>

Un patrón más eficaz es tratar la **secuencia en sí como el seed** y usar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser, tipos de objetos devueltos) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Almacena en caché los identificadores y valores generados por el servidor que devuelven respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere mutar y combinar mensajes individuales en lugar de mutar toda la transcripción serializada como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, úsalos como un **oráculo de estado económico** para priorizar las secuencias que avanzan más.

Por eso, a menudo el fuzzing vanilla al estilo de archivos no detecta bugs autenticados, transiciones ocultas o bugs de parser que aparecen “solo después del handshake”: el fuzzer debe preservar el **orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de drivers con varios clientes

Una alta cobertura de bordes aún puede pasar por alto bugs del driver IPC porque la cobertura no describe **la propiedad de los objetos, los recuentos de referencias, los mensajes pendientes, el orden de limpieza ni las intercalaciones de hilos**. La página sobre los [aspectos internos de Android Binder IPC](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) describe el modelo de objetos del driver; este ejemplo se centra en el harness del fuzzer. Android Binder es un modelo útil: alcanzar tanto las rutas de asignación como las de liberación no basta si el fuzzer no puede hacer que varios procesos operen sobre el mismo objeto del kernel en el orden requerido.<sup>[[15]](#references)</sup>

#### Modela el protocolo, no buffers `ioctl` aislados

Representa un caso de prueba como una gramática ordenada de **identidad del cliente + operación + argumentos estructurados**. El fuzzer Binder LKL usa protobuf y `libprotobuf-mutator`, con un cliente persistente de gestor de contexto y dos clientes ordinarios. Después, un harness semántico preserva las relaciones que la mutación ciega de bytes destruiría.<sup>[[15]](#references)</sup>

- Almacena en caché los valores que devuelven operaciones anteriores. Por ejemplo, `BC_FREE_BUFFER` debe reutilizar un puntero a un buffer de transacción devuelto por un `ioctl` anterior.
- Genera respuestas predeterminadas válidas para que las transacciones síncronas puedan completarse y las operaciones posteriores sigan siendo alcanzables.
- Rechaza transiciones imposibles, como transacciones a uno mismo o varias transacciones pendientes dirigidas al mismo destino.
- Mantén el estado singleton de inicialización fuera del reinicio por entrada. Binder permite un solo registro `BINDER_SET_CONTEXT_MGR` por arranque, así que destruir y recrear ese cliente repetidamente invalidaría las entradas posteriores.

Una plantilla útil para carreras de ciclo de vida consiste en hacer que un cliente transfiera un objeto, iniciar la limpieza de un hilo o proceso y, en paralelo, hacer que el cliente receptor libere el buffer de transacción. En el ejemplo CVE-2020-0423, una transferencia `BINDER_TYPE_WEAK_BINDER` seguida de una carrera entre `BINDER_THREAD_EXIT` y `BC_FREE_BUFFER` podía liberar un `binder_work` integrado mientras la ruta de limpieza del hilo que salía todavía lo usaba.<sup>[[15]](#references)</sup>

#### Reintroduce intercalaciones controladas en un kernel en espacio de usuario

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) enlaza el código real del kernel en un harness de espacio de usuario y expone su interfaz de llamadas al sistema mediante `lkl_syscall`. Esto facilita coordinar protobuf, la cobertura y KASAN en un solo proceso. Sin embargo, LKL normalmente ejecuta una llamada al sistema sin que otro hilo del kernel la interrumpa. Para campañas de carreras, inserta puntos `schedule()` alrededor de límites seleccionados de bloqueo/desbloqueo y del ciclo de vida; luego, permite que el harness elija aleatoriamente el siguiente cliente en cada cesión. Mantén estos puntos bien delimitados, porque cada uno multiplica el espacio de búsqueda de planificación. El planificador aleatorio descrito por los investigadores **no** forma parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila y reproduce seeds de regresión serializados

El harness upstream fija una versión compatible de `libprotobuf-mutator`, habilita la instrumentación de fuzzing de LKL y KASAN con `LKL_FUZZING=1`, y habilita `CONFIG_MMU` para Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Después de revisar una revisión deliberadamente vulnerable o aplicar los parches de reversión documentados upstream, una semilla serializada puede reproducir toda la transición de estado de varios clientes sin reconstruirla en una prueba de concepto ad hoc en C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trata el use-after-free de KASAN resultante como confirmación de que la seed alcanzó la ruta vulnerable del ciclo de vida. **No** demuestra las primitivas posteriores necesarias para ejecutar código en el kernel o escalar privilegios.<sup>[[16]](#references)</sup>

## Truco de diversidad en una sola máquina (estilo Jackalope)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de cobertura** es **reiniciar workers de corta duración** contra un servidor persistente. Cada worker comienza con un corpus vacío, sincroniza después de `T` segundos, se ejecuta otros `T` segundos con el corpus combinado, vuelve a sincronizar y luego termina. Esto produce **estructuras nuevas en cada generación** y, a la vez, aprovecha la cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` aproxima una **sincronización diferida** (primero novedades y luego reutilización).
- En el modo de fuzzing de gramáticas, la **sincronización inicial con el servidor se omite de forma predeterminada** (no es necesario usar `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del objetivo**; suele funcionar mejor cambiarlo cuando el worker ya ha encontrado la mayor parte de la cobertura «fácil».

## Snapshot Fuzzing Para Objetivos Difíciles De Preparar

Cuando el código que quieres probar solo se vuelve accesible **tras un gran coste de preparación** (arrancar una VM, completar un inicio de sesión, recibir un paquete, analizar un contenedor, inicializar un servicio), una alternativa útil es el **snapshot fuzzing**: capturar el estado del proceso o la VM preparado, inyectar cada caso de prueba en la ruta de entrada del objetivo, ejecutar hasta que se produzca un crash o un timeout y restaurar el snapshot. Así se evita repetir la inicialización o los prefijos del protocolo, y resulta útil para **servicios de red**, **firmware**, **superficies de ataque posteriores a la autenticación** y **objetivos solo binarios**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el objetivo hasta que esté listo el estado de interés.
2. Toma un snapshot de la **memoria + los registros** en ese punto.
3. Para cada caso de prueba, escribe la entrada modificada directamente en el búfer pertinente del guest o del proceso.
4. Ejecuta hasta que se produzca un crash, un timeout o un reinicio.
5. Restaura el snapshot; en objetivos de VM, restaura solo las **páginas modificadas** cuando sea posible y repite.

Coloca el snapshot lo más cerca posible del primer paso costoso de análisis o despacho, por ejemplo, después de un `recv`/`read` o del punto de deserialización de paquetes, y registra el búfer de entrada que usa el objetivo. Esto sigue el principio de ubicación adaptativa: mover el snapshot más adentro del procesamiento de entrada para evitar repetir trabajo.<sup>[[11]](#references)</sup>

## Exploración De Condiciones De Carrera Del Kernel De Linux Con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) convierte las condiciones de carrera sensibles a la temporización del kernel de Linux en secuencias repetibles de accesos a memoria. Puede enumerar automáticamente ejecuciones **A-B-A** de dos contextos o permitir que un analista imponga restricciones de orden mediante una interfaz de terminal o GUI. Es una herramienta de investigación experimental, no un fuzzer de concurrencia completo: actualmente requiere LLVM 23+ y el kernel parcheado del proyecto, las herramientas de línea de comandos admiten dos hilos de prueba y la capa propuesta de fuzzing en espacio de usuario no está implementada.<sup>[[17]](#references)[[18]](#references)</sup>

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

El modo outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convierte los accesos instrumentados en llamadas a funciones auxiliares. Los parches del kernel MAccConc desactivan `asan-opt-same-temp` para que los accesos consecutivos no se fusionen; desactiva también la optimización `asan-opt-globals` cuando sea necesario que las carreras en variables globales sean visibles. KCOV lleva los registros resultantes al espacio de usuario. Compara los accesos de distintos contextos de ejecución y conserva los pares cuyos rangos de bytes se solapan y en los que al menos uno de los lados escribe; modela `kfree()` como una escritura para que las transiciones del ciclo de vida también sean candidatas.<sup>[[17]](#references)</sup>

Para el trabajo que continúa fuera de la tarea que lo inició, como el procesamiento de paquetes o las devoluciones de llamada de RCU, el subsistema debe propagar un identificador de cobertura remota de KCOV. El KCOV remoto upstream es opcional y no está disponible automáticamente para cualquier trabajo en segundo plano, por lo que la falta de propagación puede hacer que una interacción real pase inadvertida.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificar el mismo acceso dinámico en cada ejecución

No reproduzcas las pruebas usando una dirección concreta del heap, que puede cambiar después de cada asignación, ni solo una dirección de instrucción, que resulta ambigua dentro de funciones auxiliares como `memcpy()` y `spin_lock()`. MAccConc usa un **rastro de pila aumentado con contadores**: cada marco identifica una función llamada junto con el número de invocación dentro de su llamador, y el elemento final identifica la instrucción de acceso a memoria. Los registros de entrada/salida de funciones de SanitizerCoverage permiten que el espacio de usuario reconstruya este identificador dinámico, que permanece estable aunque cambien las direcciones y haya ruido de flujo de control no relacionado.<sup>[[17]](#references)</sup>

### Convertir pares candidatos en planificaciones forzadas

El ioctl `KCOV_SET_DI` con parches asocia un identificador de acceso aumentado con contadores con una acción sobre un indicador compartido.<sup>[[17]](#references)</sup>

| Acción | Semántica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Establece el indicador *N* justo antes del acceso seleccionado. |
| `DI_STACK_WAIT` | Antes del acceso seleccionado, espera en un bucle hasta que se establezca el indicador *N* o venza el límite configurado. |
| `DI_STACK_WAKE_POST` | Establece el indicador *N* justo después del acceso seleccionado. |

Para una restricción parcial **A ocurre antes que B**, asigna `DI_STACK_WAKE_POST` a A y `DI_STACK_WAIT` a B usando el mismo indicador. Para una planificación completamente especificada entre dos contextos, inicia B bloqueado; luego, haz que A despierte a B y espere en el primer punto de transferencia. En el siguiente punto de transferencia, B realiza la operación inversa. Esto funciona como un cambio de contexto determinista y es lo que usa el explorador automático A-B-A.<sup>[[17]](#references)</sup>

Una campaña mínima consiste en compilar el caso de prueba de cuatro hooks (`test_setup`, dos funciones de hilo y `test_end`) como una biblioteca compartida, recopilar un rastro sin restricciones y, después, enumerar candidatos A-B-A o añadir restricciones manuales alrededor de accesos sospechosos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta los timeouts por separado de los reordenamientos exitosos: el orden solicitado puede ser imposible porque un lock o una dependencia de inicialización/publicación impide que el segundo contexto llegue a su punto de inyección. Ten en cuenta también los puntos ciegos de KASAN: los accesos directos a la pila normalmente no se instrumentan, salvo que puedan salirse de los límites; las variables globales se omiten con la optimización predeterminada; y los compiladores actuales no pueden emitir hooks de ASAN y TSAN simultáneamente. Por último, el prototipo pierde su búfer de KCOV cuando un guest entra en pánico, así que conserva una consola/oráculo de fallos independiente.<sup>[[17]](#references)</sup>

Para el fuzzing guiado por concurrencia en el futuro, registra resúmenes de accesos a memoria por entrada o syscall, empareja operaciones que formarían puntos de comunicación entre contextos y luego explora solo esas combinaciones. Las snapshots de VM estabilizan el estado global y las direcciones; sin snapshots, los metadatos del sitio de asignación pueden abstraer objetos entre ejecuciones. Esta es una extensión propuesta, no una función de las herramientas de espacio de usuario actuales de MAccConc.<sup>[[17]](#references)</sup>

## Introspección del harness: detecta pronto los fuzzers superficiales

Cuando una campaña se estanca, el problema suele estar en el **harness**, no en el mutador. Usa la **introspección de alcanzabilidad/cobertura** para encontrar funciones que son estáticamente alcanzables desde el objetivo de fuzzing, pero que rara vez o nunca se cubren dinámicamente. Esas funciones suelen indicar uno de estos tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el objetivo demasiado tarde o demasiado pronto.
- Al corpus de semillas le falta toda una familia de funcionalidades.
- El objetivo realmente necesita un **segundo harness**, en lugar de un único harness enorme que «lo haga todo».

Si usas flujos de trabajo del estilo de OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la alcanzabilidad estática con la cobertura en tiempo de ejecución y generar informes a partir de una ejecución cronometrada o de un corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa el informe para decidir si añadir un nuevo harness para una ruta del parser que no se haya probado, ampliar el corpus para una característica específica o dividir un harness monolítico en puntos de entrada más pequeños.

## Selección de objetivos de fuzzing y triaje de mutaciones basados primero en el grafo

Si ya tienes **hallazgos de análisis estático**, **mutantes supervivientes de las pruebas de mutación** e **informes de cobertura**, no los clasifiques como listas independientes. Primero, crea un **grafo de llamadas**, anota los nodos con **complejidad ciclomática**, **alcance desde puntos de entrada/datos no confiables** y cualquier hallazgo externo; después, plantea preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde datos no confiables?
- ¿Qué mutantes supervivientes están en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **radio de impacto** inusualmente amplio?

Esto suele revelar mejores objetivos de fuzzing que basarse únicamente en la «cobertura más baja». Un parser/decoder con **alta complejidad** y **alcance externo** confirmado es mejor candidato para un harness que una función auxiliar interna aislada con poca cobertura, pero sin una ruta controlada por un atacante.

### Flujo de trabajo práctico para el triaje

1. Construye un **grafo de código** a partir del código base y extrae métricas de complejidad/ramas por función.
2. Enumera los **puntos de entrada** que aceptan datos controlados por un atacante: handlers de solicitudes, decoders, importadores, parsers de protocolos, lectores de CLI/archivos.
3. Ejecuta consultas de rutas desde esos puntos de entrada hasta las funciones candidatas para distinguir la superficie de ataque alcanzable del código muerto o solo interno.
4. Prioriza los nodos que combinan:
   - alta **complejidad ciclomática**
   - **alcance desde datos no confiables** confirmado
   - un **radio de impacto** amplio o muchos dependientes posteriores
   - evidencia corroborante, como hallazgos de **SARIF**, notas de auditoría o mutantes supervivientes
5. Escribe primero harnesses enfocados en los nodos con mejor puntuación, especialmente para **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Mutantes supervivientes: equivalentes o accionables

Las pruebas de mutación suelen producir una lista ruidosa de mutantes supervivientes. Antes de tratar cada superviviente como una brecha de seguridad, usa el grafo para plantearte lo siguiente:

- ¿Es posible alcanzar la función mutada desde un punto de entrada controlado por un atacante?
- ¿Todas las rutas de llamada están limitadas por invariantes más estrictas que la comprobación mutada?
- ¿El nodo está en código muerto, lógica que solo afecta al formato o una ruta de alto impacto relacionada con aritmética/parsing?

Los supervivientes que siguen siendo inalcanzables o están limitados estructuralmente suelen ser **mutantes equivalentes**. Los que siguen siendo **alcanzables** y afectan a **condiciones límite**, **rutas de desbordamiento/acarreo** o **aritmética/parsing críticos para la seguridad** deberían promoverse a:

- nuevos harnesses de fuzzing
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlacionar los hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo usando **archivo + rango de líneas** y utiliza el grafo para ampliar el análisis del impacto.<sup>[[6]](#references)</sup>

- calcula el **radio de impacto** de la función marcada
- comprueba si el hallazgo está en alguna ruta desde un punto de entrada
- agrupa hallazgos cercanos que convergen en el mismo punto de estrangulamiento

Esto resulta útil para decidir si dedicar tiempo de fuzzing a una función concreta: un nodo **alcanzable**, **complejo** y que ya presenta **hallazgos de SAST** suele ser mejor objetivo que un nodo meramente complejo sin una ruta accesible para un atacante.

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

La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir los objetivos de fuzzing con mayor valor de seguridad esperado y, después, usa las mutaciones supervivientes para decidir qué límites e invariantes debe poner a prueba tu harness.<sup>[[5]](#references)</sup>

## Fuzzing en Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo `testing.F`, una vía práctica de mejora es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una toolchain de Go derivada que conserva `go test -fuzz`, pero cambia el backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Esto es útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con muchos parsers**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con planificación y mutación de LibAFL, y mejores detectores complementarios.

### Convierte los fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en las evaluaciones de Go es que los comportamientos peligrosos a menudo **no** provocan un crash por defecto. Con gosentry, puedes convertir varias clases de estados «malos pero silenciosos» en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que las rutas seleccionadas de logging/error se comporten como crashes (útil para rutas de código de estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las nuevas entradas descubiertas en la cola con el detector de race de Go.
- `--catch-leaks=true` para volver a ejecutar las nuevas entradas de la cola con `goleak` y detenerse ante fugas de goroutines.
- La gestión de hangs de LibAFL para conservar **bucles infinitos / entradas muy lentas** como hallazgos de fuzzing, en lugar de dejar que desaparezcan como timeouts.
- Comprobaciones integradas de desbordamiento aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación de estilo go-panikint.

Esto es especialmente valioso para objetivos cuyo impacto en la seguridad es un **fallo de parser sin panic**, un **bug de concurrencia** o un **hang que solo causa DoS**, en lugar de corrupción de memoria.

### Fuzzing consciente de structs para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede aplicar fuzzing directamente a **valores compuestos** (structs, slices, arrays, pointers) mientras sigue mutando los bytes subyacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usar esto al crear un formato wire falso solo para fuzzing ocultaría errores lógicos detrás del código de análisis exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y analiza los datos dentro del callback.

### Fuzzing basado en gramáticas para analizadores y entradas de protocolos

Para analizadores, formatos y lenguajes de entrada, gosentry puede ejecutar **fuzzing gramatical de Nautilus** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería recibir un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre la metodología:

- Usa el modo de gramática cuando las mutaciones a nivel de byte suelen fallar en las primeras comprobaciones sintácticas.
- Mantén la gramática enfocada en el **subconjunto del lenguaje/protocolo relevante para la seguridad**, en lugar de modelar toda la especificación.
- Usa valores límite grandes en terminales/no terminales para poner a prueba los límites de enteros, longitudes y máquinas de estado.
- El modo de gramática mantiene las entradas válidas según la gramática, pero el objetivo sigue recibiendo **bytes/cadenas**, así que el análisis y las comprobaciones semánticas siguen dentro del código instrumentado.

### Differential fuzzing: compara implementaciones, no solo fallos

Un patrón eficaz para los ecosistemas Go es el **grammar-based differential fuzzing**: generar entradas estructuradas válidas y enviarlas a dos analizadores, clientes o motores de transición de estado.<sup>[[7]](#references)[[8]](#references)</sup>

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
- transiciones de estado, nonces, saldos o raíces de estado divergentes

Esta es una forma práctica de encontrar **discrepancias de consenso**, **ambigüedad del parser** y **desviaciones entre la especificación y la implementación** que las pruebas de fuzzing enfocadas únicamente en fallos suelen pasar por alto.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutilizar el corpus de la campaña para generar informes de cobertura

Después de una campaña, vuelve a ejecutar el corpus guardado de la cola para generar un informe de cobertura de Go sin exportar manualmente un corpus aparte.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Ejecuta el comando desde el **mismo paquete** y con el mismo destino `-fuzz` para que gosentry resuelva el estado de campaña almacenado en caché correcto.



## References

- [1] [Fuzzing con gramáticas mutacionales](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing de AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte el código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [A Go fuzzing le faltaba la mitad del conjunto de herramientas. Hicimos un fork de la toolchain para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptables y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentación LLVM de AFL++: cobertura de rutas y callers](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predictivo sensible al contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de seguridad ofensiva de Android - Fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer de Binder de LKL Android: documentación de compilación y semillas de regresión](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: exploración de las condiciones de carrera del kernel de Linux con intercalaciones controladas de accesos a memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaxis de nombres de archivo extendidos de CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Aviso de Doyensec: CFITSIO Q4 de 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing de la sintaxis de nombres de archivo extendidos de CFITSIO: 16 vulnerabilidades de seguridad de memoria y triaje asistido por Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
