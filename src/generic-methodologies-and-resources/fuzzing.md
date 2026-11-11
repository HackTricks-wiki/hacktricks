# Metodología de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: cobertura vs. semántica

En **mutational grammar fuzzing**, las entradas se mutan sin dejar de ser **válidas según la gramática**. En el modo guiado por cobertura, solo se guardan como seeds del corpus las muestras que generan **nueva cobertura**. En los **targets de lenguajes** (parsers, intérpretes, engines), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos** en las que la salida de una construcción se convierte en la entrada de otra.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra seeds que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no conserva el flujo de datos encadenado**, por lo que se descarta la muestra “más cercana al bug” porque no añade cobertura. Con **3 o más pasos dependientes**, la recombinación aleatoria resulta costosa y la retroalimentación de cobertura no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **combinar fases mutacionales y generativas** o sesgar la generación hacia patrones de **encadenamiento de funciones** (no solo hacia la cobertura).<sup>[[1]](#references)</sup>

## Problemas de diversidad del corpus

La mutación guiada por cobertura es **codiciosa**: una muestra que genera nueva cobertura se guarda de inmediato y suele conservar grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, así que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene al alcanzar un umbral mínimo de tokens** (reduce el ruido y conserva suficiente estructura circundante para facilitar las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para los corpus de mutational fuzzing es: **preferir un conjunto pequeño de seeds estructuralmente diferentes que maximice la cobertura** antes que una gran cantidad de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empieza con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema del target).
- Depúralas mediante **minimización del corpus basada en cobertura**, en vez de conservar todas las muestras válidas.
- Mantén las seeds **lo suficientemente pequeñas** para que las mutaciones afecten campos significativos, en vez de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Vuelve a ejecutar la minimización del corpus después de cambios importantes en el harness o la instrumentación, porque el corpus “mejor” cambia cuando cambia la alcanzabilidad.

## Programas generados grandes y sesgo hacia los timeouts

En el fuzzing de compiladores e intérpretes, puede que una entrada tenga que superar un **umbral de tamaño del código generado**, en vez de activar una nueva rama del parser. En el [ejemplo del offset del manejador de excepciones de V8](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size), un testcase válido necesitaba más de 256 MiB de bytecode para que importara el offset truncado del manejador. Los constructos `yield*` repetidos podían alcanzar ese límite, pero compilar el testcase tardaba varios segundos en una build de debug. La preferencia por entradas pequeñas y los timeouts de ejecución cortos pueden desfavorecer esta clase de casos, incluso cuando la cobertura de la gramática es alta. Al auditar offsets empaquetados u otros metadatos sensibles a la longitud, considera por separado los umbrales de tamaño y la política de timeouts; este consejo para la campaña es una inferencia basada en el modo de fallo descrito.<sup>[[29]](#references)</sup>

## Mutación consciente de las comparaciones para valores mágicos

Una razón habitual por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, cadenas de enum, checksums o valores de despacho del parser protegidos por `memcmp`, tablas `switch` o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos targets, utiliza **trazado de comparaciones** (por ejemplo, flujos de trabajo de tipo AFL++ `CMPLOG` / Redqueen) para que el fuzzer pueda observar los operandos de las comparaciones fallidas y orientar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>

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

- Esto es especialmente útil cuando el objetivo oculta la lógica profunda tras **firmas de archivo**, **verbos de protocolo**, **etiquetas de tipo** o **bits de funcionalidad dependientes de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolo o registros de depuración. Un diccionario pequeño con tokens gramaticales, nombres de bloques, verbos y delimitadores suele ser más valioso que una wordlist genérica enorme.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las primeras comparaciones «mágicas» y luego vuelve a minimizar el corpus resultante para que las etapas posteriores partan de prefijos ya válidos.

## Fuzzing de API de archivos que ocultan un lenguaje de nombres de archivo

Un parámetro llamado `filename`, `path` o `URL` puede ser un punto de entrada para un intérprete, en lugar de una búsqueda literal de archivos. Por ejemplo, CFITSIO Extended Filename Syntax (EFS) evalúa selectores entre corchetes, expresiones de filas/píxeles, columnas calculadas, histogramas y transformaciones antes de devolver el objeto abierto; algunas formas también crean copias temporales. Al mapear la superficie de ataque, clasifica cada API de apertura/importación como **ruta literal** o **ruta interpretada** y luego aplica fuzzing al punto de entrada de producción que realmente llama la aplicación.<sup>[[20]](#references)[[22]](#references)</sup>

Para ver las primitivas SSRF, de copia de archivos y de controladores de protocolo resultantes —y las API de ruta literal más seguras—, consulta [Minilenguajes de nombres de archivo como primitivas SSRF/de archivos](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantén separado el objeto de respaldo del programa sometido a fuzzing

Cuando la gramática reside en un sufijo del nombre de archivo, mutar solo los bytes del archivo referenciado no llega al parser. En su lugar, un harness pequeño puede leer un caso de prueba como cadena y pasarlo a la API de apertura interpretada; la campaña de CFITSIO alcanzó la mayoría de los parsers y evaluadores de EFS llamando a `fits_open_file()` en modo de solo lectura. Mantén disponibles por separado los archivos de respaldo válidos para que las mutaciones se centren en el lenguaje de selectores/expresiones, en lugar de romper continuamente la ruta base.<sup>[[22]](#references)</sup>

Usa semillas que alcancen cada una una familia gramatical distinta y luego deriva un diccionario compacto tanto de la especificación como del código fuente del lexer/parser. Si la cobertura se estanca mientras las entradas fallan repetidamente en la misma ruta de error de sintaxis, conserva los prefijos válidos y añade delimitadores, operadores, palabras clave, nombres de funciones y nombres de campo representativos, en lugar de limitarte a aumentar el tiempo de mutación aleatoria.<sup>[[22]](#references)</sup>

Ejecuta el harness con el diccionario gramatical, por ejemplo:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contener los efectos secundarios del harness de «solo lectura»

Una flag de biblioteca de solo lectura no garantiza que un caso de prueba esté libre de efectos secundarios: el lenguaje de nombres de archivo puede reescribir la entrada, crear archivos de salida o materializar objetos temporales. La campaña de CFITSIO inicialmente destruyó archivos seed y dejó archivos inesperados por todo el sistema de archivos, por lo que fue necesario limpiar y aislar.<sup>[[22]](#references)</sup>

- Asigna a cada worker un directorio de trabajo desechable y un directorio temporal privado.
- Expón copias de los archivos de respaldo canónicos; nunca permitas que el target modifique la única copia del corpus.
- Desactiva el acceso a la red, salvo que los backends remotos sean el objetivo, y limita las rutas con permisos de escritura mediante un contenedor, un namespace de montajes o un sandbox equivalente.
- Restablece el directorio después de cada ejecución o lote de workers y trata los cambios inesperados en el sistema de archivos como hallazgos adicionales.

### Ciclo de crash a patch y fuzzing

Agrupa los crashes antes de repararlos para evitar que miles de artefactos se conviertan en miles de tareas de patching. En la evaluación de CFITSIO, AFLTriage redujo el conjunto inicial de crashes a unas pocas causas raíz; el aviso resultante muestra fallos distintos, como comprobaciones incorrectas del tamaño de destino, punteros obsoletos después de `realloc()`, errores aritméticos y rutas inseguras de limpieza del parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiza una entrada representativa de cada grupo y reprodúcela con AddressSanitizer.
2. Registra el acceso exacto que falla, la ubicación en el código fuente, el historial de asignaciones y liberaciones, y el estado del parser que provocó que el invariante dejara de cumplirse.
3. Aplica un patch candidato de alcance limitado y recompila con la misma instrumentación de cobertura y sanitizadores.
4. Reproduce el caso original **y cada entrada de su grupo**; habilita también la detección de leaks, porque una corrección de seguridad de memoria puede romper la gestión de ownership en una ruta de error.
5. Ejecuta pruebas funcionales con archivos reales y luego reanuda desde la cola acumulada (o vuelve a importar esa cola si el motor requiere un directorio de salida nuevo después de cambiar el binario).
6. Repite: eliminar el primer crash superficial suele permitir que los seeds existentes avancen a un estado más profundo del parser.

Un LLM puede acelerar el paso 2 y redactar un borrador del paso 3 si recibe la entrada que provoca el crash, el informe del sanitizer, el harness y el código fuente pertinente, pero su patch sigue sin ser de confianza. La reproducción con el sanitizer y las comprobaciones de regresión —no la explicación del modelo— determinan si se acepta la reparación.<sup>[[22]](#references)</sup>

## Comentarios más ricos cuando la cobertura de aristas no distingue distintas rutas

La cobertura normal de aristas no puede distinguir dos ejecuciones que recorren el mismo helper desde distintos callers o que toman combinaciones de ramas diferentes dentro de una función. Esto importa en decodificadores compartidos, despachadores de protocolos y helpers de intérpretes, donde la **ruta** hasta una arista determina el estado activo. Hacer un seguimiento ingenuo de cada contexto de llamada también es peligroso: el mapa de cobertura y la cola pueden crecer desmesuradamente. Por eso, la investigación sobre fuzzing sensible al contexto recomienda refinar solo los contextos prometedores, en lugar de tratar todo el grafo de llamadas como sensible al contexto.<sup>[[14]](#references)</sup>

Las versiones recientes de AFL++ ofrecen **cobertura de rutas por función de Ball-Larus**, además de la cobertura normal de aristas. Asigna una característica a cada ruta acíclica de una función; se eliminan las aristas de retorno de los bucles, por lo que este feedback distingue combinaciones de ramas, pero **no la cantidad de iteraciones de los bucles**. Empieza con el nivel relajado `1` y luego aplica modos más estrictos solo al código sospechoso del parser o de la máquina de estados, porque la cantidad de rutas puede crecer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para un helper invocado desde muchos sitios relevantes para la seguridad, el modo LTO puede combinar cada ruta de función con su sitio de llamada inmediato:<sup>[[13]](#references)</sup>

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

**Guía para campañas:** aplica feedback más rico con moderación y supervisa su costo en el mapa de cobertura y la cola.<sup>[[13]](#references)[[14]](#references)</sup>

- Ejecuta en paralelo una instancia normal de cobertura de aristas; el feedback más rico solo es útil si el costo adicional en la cola y el mapa no reduce demasiado las ejecuciones por segundo.
- Usa `AFL_LLVM_ALLOWLIST` para restringir la instrumentación de rutas/llamadores cuando las bibliotecas con muchas plantillas o el código de utilidades genéricas dominen el mapa.
- Las funciones con demasiadas rutas acíclicas pueden omitirse en AFL++; las advertencias durante la compilación indican que el objetivo necesita allowlisting o un nivel menos estricto.
- La cobertura de llamadores + rutas solo admite un nivel de profundidad de llamador. No la combines con pilas de contexto más profundas.
- Los ID de ruta pueden cambiar entre versiones principales de LLVM. Mantén fija la cadena de herramientas durante una campaña y no sincronices corpus basados en PATH como si sus ID de características fueran estables entre compilaciones.
- Este feedback complementa `CMPLOG`: el trazado de comparaciones resuelve **qué valor supera una guarda**, mientras que el feedback de rutas/llamadores conserva **qué ruta y combinación de ramas permitió llegar hasta ella**.

## Fuzzing con estado: las secuencias son semillas

Para **protocolos**, **flujos de trabajo autenticados** y **parsers de varias etapas**, la unidad interesante a menudo no es un único blob, sino una **secuencia de mensajes**. Concatenar toda la transcripción en un archivo y mutarla a ciegas suele ser ineficiente, porque el fuzzer muta todos los pasos por igual, aunque solo el mensaje posterior alcance el estado frágil.<sup>[[4]](#references)</sup>

Un patrón más eficaz consiste en tratar la **secuencia en sí como la semilla** y usar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser, tipos de objetos devueltos) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor que se reciban en respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere mutar o empalmar mensajes individuales en lugar de mutar toda la transcripción serializada como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, úsalos como un **oráculo de estado barato** para priorizar las secuencias que avanzan más.

Por esta misma razón, los bugs autenticados, las transiciones ocultas o los bugs de parser que aparecen “solo después del handshake” suelen pasar inadvertidos con el fuzzing convencional basado en archivos: el fuzzer debe preservar el **orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing de drivers con varios clientes

Una alta cobertura de aristas aún puede pasar por alto bugs en drivers IPC, porque la cobertura no describe **la propiedad de los objetos, los conteos de referencias, los mensajes pendientes, el orden de limpieza ni los intercalados de hilos**. La página [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) cubre el modelo de objetos del driver; este ejemplo se centra en el harness del fuzzer. Android Binder es un modelo útil: alcanzar tanto las rutas de asignación como las de liberación no basta si el fuzzer no puede hacer que varios procesos operen sobre el mismo objeto del kernel en el orden requerido.<sup>[[15]](#references)</sup>

#### Modela el protocolo, no buffers `ioctl` aislados

Representa un caso de prueba como una gramática ordenada de **identidad del cliente + operación + argumentos estructurados**. El fuzzer Binder LKL usa protobuf y `libprotobuf-mutator`, con un cliente persistente de context manager y dos clientes normales. Un harness semántico conserva las relaciones que la mutación ciega de bytes destruiría.<sup>[[15]](#references)</sup>

- Guarda en caché los valores devueltos por operaciones anteriores. Por ejemplo, `BC_FREE_BUFFER` debe reutilizar un puntero al buffer de transacción devuelto por un `ioctl` anterior.
- Genera respuestas predeterminadas válidas para que las transacciones síncronas puedan completarse y las operaciones posteriores sigan siendo alcanzables.
- Rechaza transiciones imposibles, como las transacciones a sí mismo o varias transacciones pendientes al mismo destino.
- Mantén el estado de inicialización singleton fuera del reinicio por entrada. Binder permite solo un registro `BINDER_SET_CONTEXT_MGR` por arranque, así que destruir y volver a crear ese cliente repetidamente invalidaría las entradas posteriores.

Una plantilla útil para una carrera de ciclo de vida consiste en hacer que un cliente transfiera un objeto, iniciar la limpieza de un hilo o proceso y, en paralelo, hacer que el cliente receptor libere el buffer de transacción. En el ejemplo de CVE-2020-0423, una transferencia `BINDER_TYPE_WEAK_BINDER` seguida de `BINDER_THREAD_EXIT` en carrera con `BC_FREE_BUFFER` podía liberar un `binder_work` integrado mientras la ruta de limpieza del hilo que salía aún lo usaba.<sup>[[15]](#references)</sup>

#### Reintroduce intercalados controlados en un kernel de espacio de usuario

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) enlaza el código real del kernel en un harness de espacio de usuario y expone su interfaz de llamadas al sistema mediante `lkl_syscall`. Esto facilita coordinar el estado de protobuf, la cobertura y KASAN en un solo proceso. Sin embargo, LKL normalmente ejecuta una llamada al sistema sin que otro hilo del kernel la interrumpa. Para campañas de carreras, inserta puntos `schedule()` alrededor de límites seleccionados de bloqueo/desbloqueo y ciclo de vida; luego deja que el harness elija al azar el siguiente cliente en cada cesión. Mantén estos puntos acotados, ya que cada uno multiplica el espacio de búsqueda de planificación. El planificador aleatorio descrito por los investigadores **no** forma parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila y reproduce semillas de regresión serializadas

El harness upstream fija una versión compatible de `libprotobuf-mutator`, habilita la instrumentación de fuzzing de LKL y KASAN con `LKL_FUZZING=1`, y habilita `CONFIG_MMU` para Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Tras revisar una revisión deliberadamente vulnerable o aplicar los parches de reversión documentados upstream, una semilla serializada puede reproducir toda la transición de estado de varios clientes sin tener que reconstruirla en una prueba de concepto ad hoc en C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trata el use-after-free de KASAN resultante como confirmación de que el seed llegó a la ruta vulnerable del ciclo de vida. **No** demuestra las primitivas posteriores necesarias para ejecutar código en el kernel o escalar privilegios.<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de cobertura** es **reiniciar workers de corta duración** contra un servidor persistente. Cada worker empieza con un corpus vacío, sincroniza después de `T` segundos, se ejecuta otros `T` segundos con el corpus combinado, vuelve a sincronizar y luego termina. Así se obtienen **estructuras nuevas en cada generación** y, al mismo tiempo, se aprovecha la cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

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
- `-server_update_interval T` aproxima una **sincronización retrasada** (primero la novedad, después la reutilización).
- En el modo de fuzzing de gramática, la **sincronización inicial con el servidor se omite de forma predeterminada** (no hace falta `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del objetivo**; suele funcionar mejor cambiarlo cuando el worker ya ha encontrado la mayor parte de la cobertura «fácil».

## Snapshot Fuzzing para objetivos difíciles de preparar

Cuando el código que quieres probar solo es accesible **tras un coste elevado de preparación** (arrancar una VM, completar un inicio de sesión, recibir un paquete, analizar un contenedor, inicializar un servicio), una alternativa útil es **snapshot fuzzing**: capturar el estado listo del proceso o la VM, inyectar cada caso de prueba en la ruta de entrada del objetivo, ejecutar hasta que se produzca un crash o un timeout y restaurar el snapshot. Así se evita repetir la inicialización o los prefijos del protocolo. Es útil para **servicios de red**, **firmware**, **superficies de ataque posteriores a la autenticación** y **objetivos solo binarios**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el objetivo hasta que el estado de interés esté listo.
2. Captura **la memoria y los registros** en ese momento.
3. Para cada caso de prueba, escribe la entrada modificada directamente en el búfer pertinente del guest o del proceso.
4. Ejecuta hasta que se produzca un crash, un timeout o un reinicio.
5. Restaura el snapshot; para objetivos VM, restaura solo las **páginas modificadas** cuando sea posible y repite.

Coloca el snapshot lo más cerca posible del primer paso costoso de análisis o distribución, por ejemplo, después de un `recv`/`read` o del punto de deserialización del paquete, y registra el búfer de entrada que usa el objetivo. Esto sigue el principio de ubicación adaptativa: mover el snapshot más adentro del procesamiento de entrada para evitar repetir trabajo.<sup>[[11]](#references)</sup>

### Snapshots incrementales para estados del protocolo

Un snapshot fijo evita el coste de preparación, pero por sí solo no explora transiciones que requieren varios mensajes válidos. Un harness de LibAFL-Qemu puede vigilar las escrituras en un campo de estado del protocolo y guardar un snapshot nuevo cuando cambia el estado. En el [harness TCP de libslirp](https://github.com/quarkslab/slirp_snapshots_stateful), vigila `tcpcb.t_state`, calcula hashes del estado y de las flags de respuesta para deduplicar snapshots y almacena las páginas modificadas con respecto a un snapshot padre. Antes de modificar el siguiente mensaje estructurado, restaura el snapshot seleccionado mediante su cadena de padres. El testcase conserva un `SnapshotId` y los bytes de entrada generados (`gen_bytes`); el administrador de snapshots realiza un seguimiento de la relación con el padre necesaria para la reproducción.<sup>[[27]](#references)[[28]](#references)</sup>

El `SnapshotModule` de modo usuario de LibAFL-Qemu guarda los mappings y la memoria del objetivo, pero no los registros de la CPU; consérvalos por separado cuando sea necesario. El administrador descrito admite un árbol de snapshots raíz y no puede compartir IDs de snapshot entre workers. Su modo de múltiples snapshots tampoco puede reutilizar directamente el estado shadow de QASAN. Para el análisis offline, reconstruye la cadena de entrada en un proceso instrumentado independiente. Al usar `AsanHostModule` y `DrCovModule`, `fuzzer.evaluate_input` ejecuta las callbacks necesarias de `pre_exec`/`post_exec`; `qemu.run` por sí solo no lo hace.<sup>[[27]](#references)[[28]](#references)</sup>

### Detectar lecturas fuera de los límites lógicos de un búfer circular

Una lectura más allá del *recuento de datos válidos* de un búfer puede permanecer dentro de la asignación de memoria del host y pasar inadvertida para ASAN convencional. El [ejemplo de datos urgentes de libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) también provoca un underflow en un recuento de bytes sin signo. Si se dispone del código fuente, la instrumentación para detectar desbordamientos de enteros con signo o sin signo puede detectar ese efecto secundario; distingue el wrap intencional de los números de secuencia TCP antes de suprimir informes. Un oracle propuesto más sólido consiste en envenenar la asignación del búfer circular personalizado, quitar el envenenamiento solo de los rangos válidos a medida que avanza su asignador interno y volver a envenenar los rangos liberados. LibAFL-Qemu ofrece una API de envenenamiento ASAN para objetivos en los que la instrumentación del código fuente no resulta práctica.<sup>[[27]](#references)</sup>

## Exploración de carreras en el kernel de Linux con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) convierte las carreras del kernel de Linux sensibles al tiempo en secuencias reproducibles de accesos a memoria. Puede enumerar automáticamente ejecuciones **A-B-A** en dos contextos o permitir que un analista imponga restricciones de orden desde una UI/GUI de terminal. Es una herramienta de investigación experimental, no un fuzzer de concurrencia completo: actualmente necesita LLVM 23+ y el kernel parcheado del proyecto, las herramientas de línea de comandos admiten dos threads de prueba y la capa propuesta de fuzzing en espacio de usuario no está implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Recopilar puntos de comunicación entre contextos

Compila el kernel instrumentado con callbacks de KASAN outline y el soporte parcheado de registros de memoria de KCOV. El README del proyecto también recomienda desactivar la optimización de llamadas a hermanos para que las pilas de llamadas sigan siendo útiles.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN en modo outline (`asan-instrumentation-with-call-threshold=0`) convierte los accesos instrumentados en llamadas a funciones auxiliares. Los parches del kernel MAccConc desactivan `asan-opt-same-temp` para que los accesos consecutivos no se fusionen; desactiva también la optimización `asan-opt-globals` cuando sea necesario detectar las carreras en variables globales. KCOV lleva los registros resultantes al espacio de usuario. Compara los accesos de distintos contextos de ejecución y conserva los pares cuyos rangos de bytes se solapan y en los que al menos uno escribe; modela `kfree()` como una escritura para que las transiciones del ciclo de vida también sean candidatas.<sup>[[17]](#references)</sup>

Para el trabajo que se ejecuta fuera de la tarea que lo inició, como el procesamiento de paquetes o las callbacks de RCU, el subsistema debe propagar un identificador de cobertura KCOV remoto. KCOV remoto upstream es opt-in y no está disponible automáticamente para cualquier trabajo en segundo plano, por lo que la falta de propagación puede hacer que una interacción real no sea visible.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificar el mismo acceso dinámico en cada ejecución

No reproduzcas la ejecución usando una dirección concreta del heap, que puede cambiar después de cada asignación, ni únicamente una dirección de instrucción, que resulta ambigua dentro de funciones auxiliares como `memcpy()` y `spin_lock()`. MAccConc usa una **traza de pila aumentada con contadores**: cada frame identifica una función llamada y el número de invocación dentro de su función llamadora, y el elemento final identifica la instrucción de acceso a memoria. Los registros de entrada/salida de funciones de SanitizerCoverage permiten al espacio de usuario reconstruir este identificador dinámico, que se mantiene estable a pesar de los cambios de dirección y del ruido de flujo de control no relacionado.<sup>[[17]](#references)</sup>

### Convertir pares candidatos en planificaciones forzadas

El ioctl parcheado `KCOV_SET_DI` asocia un identificador de acceso aumentado con contadores a una acción sobre una flag compartida.<sup>[[17]](#references)</sup>

| Acción | Semántica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Establece la flag *N* justo antes del acceso seleccionado. |
| `DI_STACK_WAIT` | Antes del acceso seleccionado, espera en un bucle hasta que se establezca la flag *N* o se agote el límite configurado. |
| `DI_STACK_WAKE_POST` | Establece la flag *N* justo después del acceso seleccionado. |

Para una restricción parcial **A-happens-before-B**, asigna `DI_STACK_WAKE_POST` a A y `DI_STACK_WAIT` a B usando la misma flag. Para una planificación completamente especificada de dos contextos, inicia B bloqueado; después, haz que A despierte a B y espere en el primer punto de transferencia. B realiza la operación inversa en la siguiente transferencia. Esto funciona como un cambio de contexto determinista y es lo que usa el explorador automático A-B-A.<sup>[[17]](#references)</sup>

Una campaña mínima consiste en compilar el caso de prueba de cuatro hooks (`test_setup`, dos funciones de hilo y `test_end`) como una biblioteca compartida, recopilar una traza sin restricciones y, luego, enumerar candidatos A-B-A o añadir restricciones manuales alrededor de accesos sospechosos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta los timeouts por separado de los reordenamientos exitosos: el orden solicitado puede ser imposible porque un bloqueo o una dependencia de inicialización/publicación impide que el segundo contexto llegue a su punto de inyección. Ten en cuenta también los puntos ciegos de KASAN: los accesos directos a la pila normalmente no se instrumentan, salvo que puedan salirse de los límites; las variables globales se omiten con la optimización predeterminada, y los compiladores actuales no pueden emitir hooks de ASAN y TSAN simultáneamente. Por último, el prototipo pierde su búfer de KCOV cuando un guest entra en pánico, así que conserva una consola/oráculo de fallos independiente.<sup>[[17]](#references)</sup>

Para el fuzzing guiado por concurrencia en el futuro, registra resúmenes de accesos a memoria por entrada o syscall, empareja operaciones que formarían puntos de comunicación entre contextos y luego explora solo esas combinaciones. Las snapshots de VM estabilizan el estado global y las direcciones; sin snapshots, los metadatos del sitio de asignación pueden abstraer objetos entre ejecuciones. Esta es una extensión propuesta, no una funcionalidad de las herramientas userspace actuales de MAccConc.<sup>[[17]](#references)</sup>

## Introspección del harness: detecta pronto los fuzzers superficiales

Cuando una campaña se estanca, a menudo el problema no es el mutador, sino el **harness**. Usa la **introspección de alcanzabilidad/cobertura** para encontrar funciones que sean estáticamente alcanzables desde tu objetivo de fuzzing, pero que rara vez se cubran dinámicamente o no se cubran nunca. Esas funciones suelen indicar uno de estos tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el objetivo demasiado tarde o demasiado pronto.
- Al corpus de seeds le falta toda una familia de funcionalidades.
- El objetivo realmente necesita un **segundo harness**, en vez de un único harness sobredimensionado que «lo haga todo».

Si usas flujos de trabajo del estilo de OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la alcanzabilidad estática con la cobertura en tiempo de ejecución y generar informes a partir de una ejecución programada o de un corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa el informe para decidir si añadir un nuevo harness para una ruta del parser no probada, ampliar el corpus para una característica específica o dividir un harness monolítico en puntos de entrada más pequeños.

## Selección de objetivos de fuzzing priorizando el grafo y triaje de mutaciones

Si ya tienes **hallazgos de análisis estático**, **mutantes supervivientes de pruebas de mutación** e **informes de cobertura**, no los clasifiques como listas independientes. Primero construye un **grafo de llamadas**, anota los nodos con **complejidad ciclomática**, **alcanzabilidad desde puntos de entrada/datos no confiables** y cualquier hallazgo externo; luego, plantea preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son alcanzables desde datos no confiables?
- ¿Qué mutantes supervivientes están en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos críticos arquitectónicos con un **radio de impacto** inusualmente amplio?

Esto suele revelar mejores objetivos de fuzzing que limitarse a elegir los de «menor cobertura». Un parser/decoder con **alta complejidad** y **alcanzabilidad externa** confirmada es mejor candidato para un harness que una función auxiliar interna aislada, con poca cobertura, pero sin una ruta controlada por un atacante.

### Flujo de trabajo práctico para el triaje

1. Construye un **grafo de código** a partir del codebase y extrae métricas de complejidad/ramas por función.
2. Enumera los **puntos de entrada** que aceptan datos controlados por un atacante: request handlers, decoders, importers, parsers de protocolos y lectores de CLI/archivos.
3. Ejecuta consultas de rutas desde esos puntos de entrada hasta las funciones candidatas para separar la superficie de ataque alcanzable del código muerto o solo interno.
4. Prioriza los nodos que combinen:
   - alta **complejidad ciclomática**
   - **alcanzabilidad desde datos no confiables** confirmada
   - un **radio de impacto** amplio o muchos dependientes posteriores
   - evidencia que lo corrobore, como hallazgos **SARIF**, notas de auditoría o mutantes supervivientes
5. Escribe primero harnesses específicos para los nodos con mejor puntuación, especialmente **parsers/codecs** como decoders de hex/Base64/IP/mensajes.

### Mutantes supervivientes: equivalentes frente a accionables

Las pruebas de mutación suelen producir una lista ruidosa de mutantes supervivientes. Antes de considerar cada uno un fallo de seguridad, usa el grafo para preguntar:

- ¿La función mutada es alcanzable desde un punto de entrada controlado por un atacante?
- ¿Todas las rutas de llamada están limitadas por invariantes más fuertes que la comprobación mutada?
- ¿El nodo está en código muerto, lógica que solo afecta al formato o una ruta de aritmética/parser de alto impacto?

Los mutantes que siguen siendo inalcanzables o están limitados estructuralmente suelen ser **mutantes equivalentes**. Los mutantes que siguen siendo **alcanzables** y afectan a **condiciones de límite**, **rutas de overflow/carry** o **aritmética/parsing críticos para la seguridad** deberían convertirse en:

- nuevos fuzz harnesses
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlacionar hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, asigna los hallazgos a los nodos del grafo por **archivo + rango de líneas** y usa el grafo para ampliar el análisis del impacto.<sup>[[6]](#references)</sup>

- calcula el **radio de impacto** de la función señalada
- comprueba si el hallazgo está en alguna ruta desde un punto de entrada
- agrupa los hallazgos cercanos que convergen en el mismo punto crítico

Esto resulta útil al decidir si dedicar tiempo de fuzzing a una función específica: un nodo **alcanzable**, **complejo** y que ya tiene **hallazgos de SAST** suele ser mejor objetivo que un nodo meramente complejo sin ninguna ruta accesible para un atacante.

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

La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir los objetivos de fuzzing con el mayor valor de seguridad esperado y, después, usa las mutaciones que sobreviven para decidir qué límites e invariantes debe poner a prueba tu harness.<sup>[[5]](#references)</sup>

## Fuzzing diferencial de codificaciones de claves criptográficas

Empieza con claves serializadas válidas o vectores de prueba estándar. Modifica los campos codificados sin alterar la longitud y la estructura necesarias para llegar a las rutas de importación y operación; luego, envía los mismos bytes a implementaciones independientes. Compara la aceptación y los errores. Las firmas y los textos cifrados aleatorizados necesitan oráculos de corrección, no comparaciones byte por byte: verifica las firmas o compara los secretos compartidos de una ronda de encapsulación y desencapsulación. Los vectores de prueba establecen la conformidad para casos conocidos; la mutación diferencial explora codificaciones malformadas que van más allá de esos casos.<sup>[[23]](#references)[[26]](#references)</sup>

Para estos formatos de clave, usa oráculos específicos para cada formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Claves de firma expandidas ML-DSA:** modifica los coeficientes empaquetados de `s1` o `s2` para que queden fuera de `[-η, η]`, pero mantén la clave analizable. Comprueba si la importación o la firma los rechaza y si alguna firma resultante se verifica. Las diferencias de aceptación por sí solas no constituyen infracciones de los estándares, porque FIPS 204 no exige comprobaciones adicionales de claves privadas. Consulta el [mecanismo de filtración condicional](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pares de claves ML-KEM:** distingue las comprobaciones obligatorias de la clave de encapsulación y de la entrada de desencapsulación de la comprobación opcional de consistencia por pares (PCT) en un par importado. Encapsula con su clave pública, desencapsula con su clave privada y compara los secretos compartidos; una discrepancia puede interrumpir la comunicación cifrada aunque las claves individuales superen las comprobaciones de entrada. Comprueba si la API valida las entradas durante la operación o mediante una llamada aparte; libcrux expone `validate_public_key(pk)` y `validate_private_key(sk, ct)`, que no sustituyen una PCT.
- **Claves sin procesar XMSS/XMSSMT:** prueba las rondas de serialización y deserialización de claves de **firma y verificación** entre conjuntos de parámetros, no solo las operaciones con claves en memoria. XMSS y XMSSMT tienen espacios de nombres OID de cuatro bytes separados, por lo que un analizador que solo comprueba el OID y prueba primero XMSS puede clasificar erróneamente una clave XMSSMT con un OID coincidente y rechazar su importación. El analizador de RustCrypto descrito ilustra un fallo de interoperabilidad/disponibilidad, no una falsificación de firma.

## Fuzzing en Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo `testing.F`, una ruta práctica de actualización es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una cadena de herramientas de Go bifurcada que conserva `go test -fuzz`, pero cambia el backend por **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Esto resulta útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con muchos parsers**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con planificación y mutación de LibAFL, y mejores detectores complementarios.

### Convierte los fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en las evaluaciones de Go es que, por defecto, el comportamiento peligroso a menudo **no** provoca un fallo. Con gosentry, puedes convertir varias clases de estados «incorrectos, pero silenciosos» en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para hacer que determinadas rutas de registro de logs y errores se comporten como fallos (útil para rutas de código del estilo de `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las nuevas entradas descubiertas de la cola con el detector de carreras de Go.
- `--catch-leaks=true` para volver a ejecutar las nuevas entradas de la cola con `goleak` y detenerse ante fugas de goroutines.
- La gestión de bloqueos de LibAFL para conservar los **bucles infinitos / las entradas muy lentas** como hallazgos de fuzzing, en lugar de permitir que desaparezcan como timeouts.
- Comprobaciones integradas de desbordamiento aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto es especialmente valioso para objetivos cuyo impacto en la seguridad consiste en un **fallo del parser sin panic**, un **error de concurrencia** o un **bloqueo que solo causa DoS**, en lugar de corrupción de memoria.

### Fuzzing de structs para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede aplicar fuzzing directamente a **valores compuestos** (structs, slices, arrays, punteros) y seguir mutando los bytes subyacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usa esto cuando crear un formato wire falso solo para fuzzing oculte errores de lógica detrás de código de parsing exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y realiza el parsing dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolos

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **fuzzing gramatical Nautilus** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre la metodología:

- Usa el modo de gramática cuando las mutaciones a nivel de byte suelen fallar en las primeras comprobaciones de sintaxis.
- Mantén la gramática centrada en el **subconjunto del lenguaje/protocolo relevante para la seguridad**, en lugar de modelar toda la especificación.
- Usa valores límite grandes en terminales/no terminales para poner a prueba los límites de enteros, longitudes y máquinas de estado.
- El modo de gramática mantiene las entradas válidas según la gramática, pero el objetivo sigue recibiendo **bytes/cadenas**, por lo que el análisis sintáctico y las comprobaciones semánticas siguen ejecutándose dentro del código bajo prueba.

### Fuzzing diferencial: comparar implementaciones, no solo fallos

Un patrón sólido en los ecosistemas Go es el **fuzzing diferencial basado en gramáticas**: generar entradas estructuradas válidas y proporcionárselas a dos parsers, clientes o motores de transición de estados.<sup>[[7]](#references)[[8]](#references)</sup>

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

- una implementación entra en pánico mientras que la otra rechaza la entrada limpiamente
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

Ejecuta el comando desde el **mismo paquete** y con el mismo objetivo `-fuzz` para que gosentry resuelva el estado de campaña en caché correcto.

## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing con AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: sobre fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [A Go fuzzing le faltaba la mitad del conjunto de herramientas. Bifurcamos la cadena de herramientas para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptables y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentación LLVM de AFL++: cobertura de rutas y llamadas](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predictivo sensible al contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de seguridad ofensiva de Android: fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer de Binder de LKL para Android: documentación de compilación y semillas de regresión](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: exploración de condiciones de carrera en el kernel de Linux mediante intercalaciones controladas de accesos a memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaxis de nombres de archivo extendida de CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Aviso de Doyensec: CFITSIO, cuarto trimestre de 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing de la sintaxis de nombres de archivo extendida de CFITSIO: 16 vulnerabilidades de seguridad de memoria y clasificación asistida por Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing diferencial para criptografía](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: estándar de mecanismo de encapsulación de claves basado en retículos modulares](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Error de análisis de OID en XMSSMT: incidencia #1442 de RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Estado de las implementaciones de criptografía poscuántica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Cómo llegamos a CVE-2026-9539 mediante snapshots](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [slirp_snapshots_stateful de Quarkslab](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero: fuzzers contra IA: comparación de Fuzzilli y BigSleep en motores JavaScript](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
