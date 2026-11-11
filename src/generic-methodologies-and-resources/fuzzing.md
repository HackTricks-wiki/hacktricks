# Metodología de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing gramatical mutacional: cobertura vs. semántica

En el **fuzzing gramatical mutacional**, las entradas se mutan y se mantienen **válidas según la gramática**. En el modo guiado por coverage, solo se guardan como seeds del corpus las muestras que activan **coverage nueva**. Para los **targets de lenguajes** (parsers, intérpretes, motores), esto puede pasar por alto bugs que requieren **cadenas semánticas/de flujo de datos**, en las que la salida de una construcción se convierte en la entrada de otra.<sup>[[1]](#references)</sup>

**Modo de fallo:** el fuzzer encuentra seeds que ejercitan individualmente `document()` y `generate-id()` (o primitivas similares), pero **no preserva el flujo de datos encadenado**, así que descarta la muestra «más cercana al bug» porque no añade coverage. Con **3 o más pasos dependientes**, la recombinación aleatoria resulta costosa y la retroalimentación de coverage no guía la búsqueda.<sup>[[1]](#references)</sup>

**Implicación:** para gramáticas con muchas dependencias, considera **combinar fases mutacionales y generativas** o sesgar la generación hacia patrones de **encadenamiento de funciones** (no solo hacia coverage).<sup>[[1]](#references)</sup>

## Problemas de diversidad del corpus

La mutación guiada por coverage es **codiciosa**: una muestra que activa coverage nueva se guarda de inmediato y suele conservar grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **casi duplicados** con poca diversidad estructural. Una minimización agresiva puede eliminar contexto útil, por lo que un compromiso práctico es la **minimización consciente de la gramática**, que **se detiene al alcanzar un umbral mínimo de tokens** (reduce el ruido y conserva suficiente estructura circundante para facilitar las mutaciones).<sup>[[1]](#references)</sup>

Una regla práctica para el corpus del fuzzing mutacional es: **preferir un conjunto pequeño de seeds estructuralmente diferentes que maximicen la coverage** antes que una gran colección de casi duplicados. En la práctica, esto suele implicar lo siguiente.<sup>[[1]](#references)[[3]](#references)</sup>

- Empieza con **muestras del mundo real** (corpus públicos, crawling, tráfico capturado, conjuntos de archivos del ecosistema del target).
- Depúralas con **minimización del corpus basada en coverage**, en lugar de conservar todas las muestras válidas.
- Mantén las seeds **lo bastante pequeñas** para que las mutaciones afecten campos significativos, en vez de dedicar la mayoría de los ciclos a bytes irrelevantes.
- Vuelve a ejecutar la minimización del corpus después de cambios importantes en el harness o la instrumentación, porque el «mejor» corpus cambia cuando cambia la alcanzabilidad.

## Mutación consciente de comparaciones para valores mágicos

Una razón habitual por la que los fuzzers se estancan no es la sintaxis, sino las **comparaciones estrictas**: bytes mágicos, comprobaciones de longitud, cadenas de enum, checksums o valores de dispatch del parser protegidos por `memcmp`, tablas `switch` o comparaciones encadenadas. La mutación puramente aleatoria desperdicia ciclos intentando adivinar estos valores byte a byte.

Para estos targets, usa **trazado de comparaciones** (por ejemplo, flujos de trabajo al estilo de AFL++ `CMPLOG` / Redqueen), para que el fuzzer pueda observar los operandos de las comparaciones fallidas y sesgar las mutaciones hacia valores que las satisfagan.<sup>[[3]](#references)</sup>

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

- Esto resulta especialmente útil cuando el objetivo protege la lógica profunda detrás de **firmas de archivo**, **verbos de protocolo**, **etiquetas de tipo** o **bits de funciones que dependen de la versión**.
- Combínalo con **diccionarios** extraídos de muestras reales, especificaciones de protocolo o registros de depuración. Un diccionario pequeño con tokens de gramática, nombres de bloques, verbos y delimitadores suele ser más valioso que una enorme lista genérica de palabras.
- Si el objetivo realiza muchas comprobaciones secuenciales, resuelve primero las comparaciones “mágicas” iniciales y vuelve a minimizar el corpus resultante para que las etapas posteriores partan de prefijos que ya son válidos.

## Fuzzing de APIs de archivos que ocultan un lenguaje de nombres de archivo

Un parámetro llamado `filename`, `path` o `URL` puede ser un punto de entrada de un intérprete, no una búsqueda literal de archivo. Por ejemplo, CFITSIO Extended Filename Syntax (EFS) evalúa selectores entre corchetes, expresiones de filas/píxeles, columnas calculadas, histogramas y transformaciones antes de devolver el objeto abierto; algunas formas también crean copias temporales. Al mapear la superficie de ataque, clasifica cada API de apertura/importación como **ruta literal** o **ruta interpretada** y luego aplica fuzzing al punto de entrada de producción que las aplicaciones realmente llaman.<sup>[[20]](#references)[[22]](#references)</sup>

Para las primitivas resultantes de SSRF, copia de archivos y manejadores de protocolo —y para APIs de ruta literal más seguras—, consulta [Mini-lenguajes de nombres de archivo como primitivas de SSRF/copia de archivos](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Mantén separado el objeto de respaldo del programa sometido a fuzzing

Cuando la gramática está en un sufijo del nombre de archivo, modificar únicamente los bytes del archivo referenciado no alcanza el parser. En su lugar, un pequeño harness puede leer un caso de prueba como cadena y pasarlo a la API de apertura interpretada; la campaña de CFITSIO llegó a la mayoría de los parsers y evaluadores de EFS llamando a `fits_open_file()` en modo de solo lectura. Mantén disponibles por separado archivos de respaldo válidos para que las mutaciones puedan centrarse en el lenguaje de selectores/expresiones en lugar de romper continuamente la ruta base.<sup>[[22]](#references)</sup>

Usa seeds que lleguen cada uno a una familia de gramática distinta y luego deriva un diccionario compacto tanto de la especificación como del código fuente del lexer/parser. Si la cobertura se estanca y las entradas fallan repetidamente en la misma ruta de error de sintaxis, conserva los prefijos válidos y añade delimitadores, operadores, palabras clave, nombres de funciones y nombres de campos representativos, en vez de limitarte a aumentar el tiempo de mutación aleatoria.<sup>[[22]](#references)</sup>

Ejecuta el harness con el diccionario de gramática, por ejemplo:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contener los efectos secundarios del harness «read-only»

Un flag «read-only» de una biblioteca no garantiza que un caso de prueba no tenga efectos secundarios: el lenguaje de nombres de archivo puede reescribir la entrada, crear archivos de salida o materializar objetos temporales. La campaña de CFITSIO inicialmente destruyó archivos seed y dejó archivos inesperados por todo el sistema de archivos, por lo que fue necesario limpiar y aislar.<sup>[[22]](#references)</sup>

- Asigna a cada worker un directorio de trabajo desechable y un directorio temporal privado.
- Expón copias de los archivos canónicos de respaldo; nunca permitas que el target modifique la única copia del corpus.
- Deshabilita el acceso a la red, salvo que los backends remotos sean el objetivo previsto, y limita las rutas con permisos de escritura mediante un contenedor, un espacio de nombres de montaje o un sandbox equivalente.
- Restablece el directorio después de cada ejecución o lote de workers y trata los cambios inesperados en el sistema de archivos como hallazgos adicionales.

### Ciclo de crash a parche y fuzzing

Agrupa los crashes antes de repararlos para evitar que miles de artefactos se conviertan en miles de tareas de parcheo. En la evaluación de CFITSIO, AFLTriage redujo el conjunto inicial de crashes a unas pocas causas raíz; el aviso resultante muestra fallos distintos, como comprobaciones incorrectas del tamaño del destino, punteros obsoletos tras `realloc()`, errores aritméticos y rutas inseguras de limpieza del parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiza una entrada representativa de cada grupo y reprodúcela con AddressSanitizer.
2. Registra el acceso exacto que falla, la ubicación en el código fuente, el historial de asignaciones/liberaciones y el estado del parser que provocó que la invariante dejara de cumplirse.
3. Aplica un parche candidato de alcance limitado y recompila con la misma instrumentación de cobertura y sanitización.
4. Reproduce el caso original **y todas las entradas de su grupo**; activa también la detección de fugas, ya que una corrección de seguridad de memoria puede romper la gestión de recursos en una ruta de error.
5. Ejecuta pruebas funcionales con archivos reales y luego reanuda desde la queue acumulada (o vuelve a importarla si el engine requiere un directorio de salida nuevo tras cambiar el binario).
6. Repite: eliminar el primer crash superficial suele permitir que las seeds existentes avancen a un estado más profundo del parser.

Un LLM puede acelerar el paso 2 y redactar una propuesta para el paso 3 si recibe la entrada que provoca el crash, el informe del sanitizer, el harness y el código fuente relevante, pero el parche sigue sin ser confiable. La reproducción con el sanitizer y los controles de regresión —no la explicación del modelo— determinan si se acepta la reparación.<sup>[[22]](#references)</sup>

## Más información de feedback cuando la cobertura de aristas fusiona rutas distintas

La cobertura normal de aristas no distingue dos ejecuciones que atraviesan el mismo helper desde distintos callers o toman distintas combinaciones de ramas dentro de una función. Esto importa en decodificadores compartidos, despachadores de protocolos y helpers de intérpretes, donde la **ruta** hacia una arista determina el estado activo. También es peligroso rastrear ingenuamente cada contexto de llamada: el mapa de cobertura y la queue pueden crecer desmesuradamente. Por eso, la investigación sobre fuzzing sensible al contexto recomienda refinar solo los contextos prometedores, en lugar de tratar todo el grafo de llamadas como sensible al contexto.<sup>[[14]](#references)</sup>

Las versiones recientes de AFL++ ofrecen **cobertura de rutas por función Ball-Larus**, además de la cobertura normal de aristas. Asigna una característica a cada ruta acíclica que atraviesa una función; se eliminan las aristas de retorno de los bucles, por lo que este feedback distingue combinaciones de ramas, pero **no el número de iteraciones del bucle**. Empieza con el nivel relajado `1` y luego aplica modos más estrictos solo al código sospechoso del parser o de la máquina de estados, ya que el número de rutas puede crecer exponencialmente.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Para un helper al que se llama desde muchos sitios relevantes para la seguridad, el modo LTO puede combinar cada ruta de función con su sitio de llamada inmediato:<sup>[[13]](#references)</sup>

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

**Guía para campañas:** aplica feedback más rico con moderación y vigila su costo en el mapa de cobertura/cola.<sup>[[13]](#references)[[14]](#references)</sup>

- Ejecuta en paralelo una instancia normal de cobertura de bordes; el feedback más rico solo es útil si el costo adicional de cola/mapa no reduce las ejecuciones por segundo.
- Usa `AFL_LLVM_ALLOWLIST` para restringir la instrumentación de rutas/llamadores cuando las bibliotecas grandes con muchas plantillas o el código de utilidades genéricas dominen el mapa.
- AFL++ puede omitir funciones con demasiadas rutas acíclicas; las advertencias durante la compilación indican que el objetivo necesita una allowlist o un nivel menos estricto.
- La cobertura de llamador + ruta solo admite un nivel de profundidad del llamador. No la combines con pilas de contexto más profundas.
- Los ID de ruta pueden cambiar entre versiones principales de LLVM. Mantén fija la cadena de herramientas durante una campaña y no sincronices corpus basados en PATH como si sus ID de características fueran estables entre compilaciones.
- Este feedback complementa `CMPLOG`: el trazado de comparaciones resuelve **qué valor supera una guarda**, mientras que el feedback de ruta/llamador conserva **qué ruta y combinación de ramas llegaron hasta ella**.

## Fuzzing con estado: las secuencias son seeds

Para **protocolos**, **flujos de trabajo autenticados** y **parsers de varias etapas**, a menudo la unidad interesante no es un único blob, sino una **secuencia de mensajes**. Concatenar toda la transcripción en un archivo y mutarla a ciegas suele ser ineficiente, porque el fuzzer muta cada paso por igual, aunque solo el mensaje posterior alcance el estado frágil.<sup>[[4]](#references)</sup>

Un patrón más eficaz es tratar la **propia secuencia como seed** y usar el **estado observable** (códigos de respuesta, estados del protocolo, fases del parser, tipos de objetos devueltos) como feedback adicional.<sup>[[4]](#references)</sup>

- Mantén estables los **mensajes de prefijo válidos** y centra las mutaciones en el mensaje que **impulsa la transición**.
- Guarda en caché los identificadores y valores generados por el servidor de respuestas anteriores cuando el siguiente paso dependa de ellos.
- Prefiere mutar o combinar mensajes individuales en lugar de mutar toda la transcripción serializada como un blob opaco.
- Si el protocolo expone códigos de respuesta significativos, úsalos como un **oráculo de estado económico** para priorizar las secuencias que avanzan más.

Por la misma razón, los bugs autenticados, las transiciones ocultas o los bugs de parser que aparecen “solo después del handshake” suelen pasar desapercibidos con el fuzzing convencional basado en archivos: el fuzzer debe preservar **el orden, el estado y las dependencias**, no solo la estructura.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing del driver con varios clientes

Una alta cobertura de bordes aún puede pasar por alto bugs del driver IPC, porque la cobertura no describe **la propiedad de los objetos, los recuentos de referencias, los mensajes pendientes, el orden de limpieza ni los intercalados entre hilos**. La página [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) describe el modelo de objetos del driver; este ejemplo se centra en el harness del fuzzer. Android Binder es un modelo útil: alcanzar tanto las rutas de asignación como las de liberación no basta si el fuzzer no puede hacer que varios procesos operen sobre el mismo objeto del kernel en el orden requerido.<sup>[[15]](#references)</sup>

#### Modela el protocolo, no buffers `ioctl` aislados

Representa un caso de prueba como una gramática ordenada de **identidad del cliente + operación + argumentos estructurados**. El fuzzer LKL de Binder usa protobuf y `libprotobuf-mutator`, con un cliente administrador de contexto persistente y dos clientes normales. Luego, un harness semántico preserva las relaciones que la mutación ciega de bytes destruiría.<sup>[[15]](#references)</sup>

- Guarda en caché los valores devueltos por operaciones anteriores. Por ejemplo, `BC_FREE_BUFFER` debe reutilizar un puntero al buffer de transacción devuelto por un `ioctl` anterior.
- Genera respuestas predeterminadas válidas para que las transacciones síncronas puedan finalizar y las operaciones posteriores sigan siendo alcanzables.
- Rechaza transiciones imposibles, como transacciones a uno mismo o varias transacciones pendientes al mismo destino.
- Mantén el estado de inicialización singleton fuera del reinicio por entrada. Binder solo permite un registro `BINDER_SET_CONTEXT_MGR` por arranque, así que destruir y recrear repetidamente ese cliente invalidaría las entradas posteriores.

Una plantilla útil para provocar una condición de carrera de ciclo de vida consiste en hacer que un cliente transfiera un objeto, iniciar la limpieza de un hilo o proceso y, al mismo tiempo, hacer que el cliente receptor libere el buffer de transacción. En el ejemplo de CVE-2020-0423, una transferencia `BINDER_TYPE_WEAK_BINDER` seguida de una carrera entre `BINDER_THREAD_EXIT` y `BC_FREE_BUFFER` podía liberar un `binder_work` integrado mientras la ruta de limpieza del hilo que salía aún lo utilizaba.<sup>[[15]](#references)</sup>

#### Reintroduce intercalados controlados en un kernel de espacio de usuario

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) enlaza el código real del kernel en un harness de espacio de usuario y expone su interfaz de llamadas al sistema mediante `lkl_syscall`. Así resulta fácil coordinar el estado de protobuf, la cobertura y KASAN en un solo proceso. Sin embargo, LKL normalmente ejecuta una llamada al sistema sin que otro hilo del kernel la interrumpa. Para campañas de condiciones de carrera, inserta puntos `schedule()` alrededor de límites seleccionados de bloqueo/desbloqueo y ciclo de vida, y deja que el harness elija aleatoriamente el siguiente cliente en cada cesión. Mantén estos puntos acotados, porque cada uno multiplica el espacio de búsqueda de planificación. El planificador aleatorio descrito por los investigadores **no** forma parte del fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compila y reproduce seeds de regresión serializadas

El harness upstream fija una versión compatible de `libprotobuf-mutator`, habilita la instrumentación de fuzzing de LKL y KASAN con `LKL_FUZZING=1`, y habilita `CONFIG_MMU` para Binder con `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Después de hacer checkout de una revisión deliberadamente vulnerable o aplicar los parches de reversión documentados upstream, una semilla serializada puede reproducir toda la transición de estado multi-cliente sin tener que reconstruirla en una prueba de concepto ad hoc en C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Trata el use-after-free de KASAN resultante como confirmación de que la seed alcanzó la ruta vulnerable del ciclo de vida. **No** demuestra las primitivas posteriores necesarias para ejecutar código en el kernel o escalar privilegios.<sup>[[16]](#references)</sup>

## Truco de diversidad en una sola máquina (al estilo Jackalope)

Una forma práctica de combinar la **novedad generativa** con la **reutilización de cobertura** es **reiniciar workers de corta duración** contra un servidor persistente. Cada worker comienza con un corpus vacío, sincroniza tras `T` segundos, ejecuta durante otros `T` segundos con el corpus combinado, vuelve a sincronizar y luego sale. Esto genera **estructuras nuevas en cada generación** y, a la vez, aprovecha la cobertura acumulada.<sup>[[1]](#references)[[2]](#references)</sup>

**Servidor:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers secuenciales (bucle de ejemplo):**

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
- `-server_update_interval T` aproxima una **sincronización retrasada** (primero novedades, después reutilización).
- En el modo de fuzzing con gramáticas, la **sincronización inicial con el servidor se omite de forma predeterminada** (no hace falta `-skip_initial_server_sync`).
- El valor óptimo de `T` **depende del objetivo**; suele funcionar mejor cambiarlo después de que el worker haya encontrado la mayor parte de la cobertura «fácil».

## Snapshot Fuzzing Para Objetivos Difíciles De Preparar

Cuando el código que quieres probar solo puede alcanzarse **después de un costoso proceso de preparación** (arrancar una VM, completar un inicio de sesión, recibir un paquete, analizar un contenedor, inicializar un servicio), una alternativa útil es **snapshot fuzzing**: capturar el estado listo del proceso o la VM, inyectar cada caso de prueba en la ruta de entrada del objetivo, ejecutarlo hasta que se produzca un crash o un timeout y restaurar el snapshot. Así se evita repetir la inicialización o los prefijos del protocolo, y resulta útil para **servicios de red**, **firmware**, **superficies de ataque posteriores a la autenticación** y **objetivos de solo binario**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Ejecuta el objetivo hasta que el estado de interés esté listo.
2. Guarda un snapshot de la **memoria + registros** en ese punto.
3. Para cada caso de prueba, escribe la entrada modificada directamente en el búfer pertinente del proceso o guest.
4. Ejecuta hasta que se produzca un crash, un timeout o un reset.
5. Restaura el snapshot; para objetivos VM, restaura solo las **páginas modificadas** cuando sea compatible y repite.

Coloca el snapshot tan cerca como sea práctico del primer paso costoso de análisis o despacho, por ejemplo, después de un `recv`/`read` o del punto de deserialización del paquete, y registra el búfer de entrada que utiliza el objetivo. Esto sigue el principio de ubicación adaptativa: mover el snapshot más adentro del procesamiento de entrada para evitar repetir trabajo.<sup>[[11]](#references)</sup>

### Snapshots incrementales para estados del protocolo

Un snapshot fijo evita el costo de preparación, pero no explora por sí solo las transiciones que requieren varios mensajes válidos. Un harness de LibAFL-Qemu puede observar las escrituras en un campo de estado del protocolo y guardar un snapshot nuevo cuando cambia el estado. En el [harness TCP de libslirp](https://github.com/quarkslab/slirp_snapshots_stateful), observa `tcpcb.t_state`, calcula hashes del estado y de las flags de respuesta para deduplicar snapshots, y almacena las páginas modificadas con respecto a un elemento padre. Antes de modificar el siguiente mensaje estructurado, restaura el snapshot seleccionado mediante su cadena de elementos padre. El testcase conserva un `SnapshotId` y los bytes de entrada generados (`gen_bytes`); el gestor de snapshots registra la relación con el elemento padre necesaria para la reproducción.<sup>[[27]](#references)[[28]](#references)</sup>

El `SnapshotModule` de modo usuario de LibAFL-Qemu guarda los mappings y la memoria del objetivo, pero no los registros de la CPU; consérvalos por separado cuando sea necesario. El gestor descrito admite un único árbol de snapshots raíz y no puede compartir IDs de snapshots entre workers. Su modo de múltiples snapshots tampoco puede reutilizar directamente el estado shadow de QASAN. Para el análisis offline, reconstruye la cadena de entrada en un proceso instrumentado aparte. Al usar `AsanHostModule` y `DrCovModule`, `fuzzer.evaluate_input` ejecuta las callbacks `pre_exec`/`post_exec` necesarias; `qemu.run` por sí solo no lo hace.<sup>[[27]](#references)[[28]](#references)</sup>

### Detectar lecturas fuera de los límites lógicos de un búfer circular

Una lectura más allá del *recuento de datos válidos* de un búfer puede permanecer dentro de la asignación del host y pasar inadvertida para ASAN convencional. El [ejemplo de datos urgentes de libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) también produce un underflow en un recuento de bytes sin signo. Si se dispone del código fuente, la instrumentación de desbordamiento de enteros con signo/sin signo puede detectar ese efecto secundario; distingue el wrap intencional del número de secuencia TCP antes de suprimir los informes. Un oráculo propuesto más sólido consiste en envenenar la asignación del búfer circular personalizado, quitar el envenenamiento solo de los rangos válidos a medida que avanza su asignador interno y volver a envenenar los rangos liberados. LibAFL-Qemu ofrece una API de envenenamiento de ASAN para objetivos en los que la instrumentación del código fuente no es práctica.<sup>[[27]](#references)</sup>

## Exploración De Carreras En El Kernel De Linux Con MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) convierte las carreras del kernel de Linux sensibles a la temporización en secuencias reproducibles de accesos a memoria. Puede enumerar automáticamente ejecuciones **A-B-A** de dos contextos o permitir que un analista imponga restricciones de orden en una interfaz de terminal o GUI. Es una herramienta de investigación experimental, no un fuzzer completo de concurrencia: actualmente necesita LLVM 23 o posterior y el kernel modificado del proyecto; las herramientas de línea de comandos admiten dos threads de prueba, y la capa propuesta de fuzzing en espacio de usuario aún no está implementada.<sup>[[17]](#references)[[18]](#references)</sup>

### Recopilar puntos de comunicación entre contextos

Compila el kernel instrumentado con callbacks de KASAN outline y el soporte modificado de KCOV para registrar memoria. El README del proyecto también recomienda deshabilitar la optimización de llamadas a hermanos para que las pilas de llamadas sigan siendo útiles.<sup>[[17]](#references)[[18]](#references)</sup>

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

El modo outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convierte los accesos instrumentados en llamadas a funciones auxiliares. Los parches de kernel de MAccConc desactivan `asan-opt-same-temp` para que los accesos consecutivos no se fusionen; desactiva también la optimización `asan-opt-globals` cuando deban poder detectarse las carreras en variables globales. KCOV lleva los registros resultantes al espacio de usuario. Compara los accesos de distintos contextos de ejecución y conserva los pares cuyos rangos de bytes se superponen y en los que al menos uno escribe; modela `kfree()` como una escritura para que las transiciones de vida útil también puedan ser candidatas.<sup>[[17]](#references)</sup>

Para el trabajo que se ejecuta fuera de la tarea que lo inició, como el procesamiento de paquetes o las callbacks de RCU, el subsistema debe propagar un identificador de cobertura remota de KCOV. La cobertura remota de KCOV upstream es opt-in y no está disponible automáticamente para cualquier trabajo en segundo plano, por lo que la falta de propagación puede hacer que una interacción real pase inadvertida.<sup>[[17]](#references)[[19]](#references)</sup>

### Identificar el mismo acceso dinámico en cada ejecución

No reproduzcas la ejecución usando una dirección concreta del heap, que puede cambiar después de cada asignación, ni solo una dirección de instrucción, que resulta ambigua dentro de funciones auxiliares como `memcpy()` y `spin_lock()`. MAccConc usa una **traza de pila aumentada con contadores**: cada marco identifica una función llamada y el número de veces que se la invocó desde su llamador, y el elemento final identifica la instrucción de acceso a memoria. Los registros de entrada y salida de funciones de SanitizerCoverage permiten al espacio de usuario reconstruir este identificador dinámico, que se mantiene estable aunque cambien las direcciones y haya ruido de flujo de control no relacionado.<sup>[[17]](#references)</sup>

### Convertir pares candidatos en planificaciones forzadas

El ioctl parcheado `KCOV_SET_DI` asocia un identificador de acceso aumentado con contadores con una acción sobre un indicador compartido.<sup>[[17]](#references)</sup>

| Acción | Semántica |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Establece el indicador *N* inmediatamente antes del acceso seleccionado. |
| `DI_STACK_WAIT` | Antes del acceso seleccionado, espera en un bucle hasta que se establezca el indicador *N* o se agote el límite configurado. |
| `DI_STACK_WAKE_POST` | Establece el indicador *N* inmediatamente después del acceso seleccionado. |

Para una restricción parcial **A-happens-before-B**, asigna `DI_STACK_WAKE_POST` a A y `DI_STACK_WAIT` a B usando el mismo indicador. Para una planificación completamente especificada de dos contextos, inicia B bloqueado; luego haz que A despierte a B y espera en el primer punto de transferencia. En el siguiente punto de transferencia, B realiza la operación inversa. Esto funciona como un cambio de contexto determinista y es lo que usa el explorador automático A-B-A.<sup>[[17]](#references)</sup>

Una campaña mínima consiste en compilar el caso de prueba con cuatro hooks (`test_setup`, dos funciones de hilo y `test_end`) como biblioteca compartida, recopilar una traza sin restricciones y, después, enumerar candidatos A-B-A o añadir restricciones manuales alrededor de accesos sospechosos.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpreta los timeouts por separado de los reordenamientos exitosos: el orden solicitado puede ser imposible porque un bloqueo o una dependencia de inicialización/publicación impide que el segundo contexto llegue a su punto de inyección. Ten en cuenta también los puntos ciegos de KASAN: los accesos directos a la pila normalmente no se instrumentan, salvo que puedan estar fuera de límites; las variables globales se omiten con la optimización predeterminada; y los compiladores actuales no pueden emitir hooks de ASAN y TSAN simultáneamente. Por último, el prototipo pierde su búfer de KCOV cuando una máquina virtual invitada sufre un panic, así que conserva una consola/oráculo de crashes independiente.<sup>[[17]](#references)</sup>

Para el fuzzing guiado por concurrencia en el futuro, registra resúmenes de accesos a memoria por entrada o syscall, empareja operaciones que formarían puntos de comunicación entre contextos y, a continuación, explora solo esas combinaciones. Las instantáneas de VM estabilizan el estado global y las direcciones; sin instantáneas, los metadatos del sitio de asignación pueden abstraer objetos entre ejecuciones. Esta es una extensión propuesta, no una función de las herramientas userspace actuales de MAccConc.<sup>[[17]](#references)</sup>

## Introspección del harness: detecta pronto los fuzzers superficiales

Cuando una campaña se estanca, el problema a menudo no es el mutator, sino el **harness**. Usa la **introspección de alcanzabilidad/cobertura** para encontrar funciones que son alcanzables estáticamente desde tu objetivo de fuzzing, pero que rara vez o nunca se cubren dinámicamente. Esas funciones suelen indicar uno de estos tres problemas.<sup>[[12]](#references)</sup>

- El harness entra en el objetivo demasiado tarde o demasiado pronto.
- Al corpus de seeds le falta una familia completa de funcionalidades.
- El objetivo realmente necesita un **segundo harness** en lugar de un único harness sobredimensionado que «lo haga todo».

Si usas flujos de trabajo al estilo de OSS-Fuzz / ClusterFuzz, Fuzz Introspector puede comparar la alcanzabilidad estática con la cobertura en tiempo de ejecución y generar informes a partir de una ejecución cronometrada o de un corpus público.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Usa el informe para decidir si añadir un nuevo harness para una ruta del parser no probada, ampliar el corpus para una característica concreta o dividir un harness monolítico en varios puntos de entrada más pequeños.

## Selección de objetivos de fuzzing basada primero en grafos y clasificación de mutaciones

Si ya tienes **hallazgos de análisis estático**, **mutantes supervivientes de las pruebas de mutación** e **informes de cobertura**, no los clasifiques como listas independientes. Primero crea un **grafo de llamadas**, anota los nodos con la **complejidad ciclomática**, el **alcance desde puntos de entrada/datos no confiables** y cualquier hallazgo externo, y luego plantea preguntas sobre el grafo.<sup>[[5]](#references)[[6]](#references)</sup>

- ¿Qué funciones de alta complejidad son accesibles desde datos no confiables?
- ¿Qué mutantes supervivientes están en rutas desde parsers/handlers hasta código crítico para la seguridad?
- ¿Qué funciones son puntos de estrangulamiento arquitectónicos con un **radio de impacto** inusualmente grande?

Esto suele revelar mejores objetivos de fuzzing que limitarse a buscar la «menor cobertura». Un parser/decoder con **alta complejidad** y **accesibilidad externa** confirmada es un candidato más sólido para crear un harness que una función auxiliar interna aislada, con poca cobertura, pero sin una ruta controlada por un atacante.

### Flujo de trabajo práctico para la clasificación

1. Crea un **grafo del código** a partir del codebase y extrae métricas de complejidad/ramas para cada función.
2. Enumera los **puntos de entrada** que aceptan datos controlados por un atacante: request handlers, decoders, importers, parsers de protocolos y lectores de CLI/archivos.
3. Ejecuta consultas de rutas desde esos puntos de entrada hasta las funciones candidatas para separar la superficie de ataque accesible del código inactivo o solo interno.
4. Da prioridad a los nodos que combinan:
   - alta **complejidad ciclomática**
   - **accesibilidad confirmada desde datos no confiables**
   - alto **radio de impacto** o muchos dependientes posteriores
   - indicios que lo corroboren, como hallazgos de **SARIF**, notas de auditoría o mutantes supervivientes
5. Escribe harnesses enfocados primero para los nodos con mejor puntuación, especialmente **parsers/codecs**, como decoders de hex/Base64/IP/mensajes.

### Mutantes supervivientes: equivalentes frente a accionables

Las pruebas de mutación suelen producir una lista ruidosa de mutantes supervivientes. Antes de tratar cada superviviente como una brecha de seguridad, usa el grafo para preguntar:

- ¿Es la función mutada accesible desde un punto de entrada controlado por un atacante?
- ¿Todas las rutas de llamada están restringidas por invariantes más fuertes que la comprobación mutada?
- ¿El nodo está en código inactivo, lógica que solo afecta al formato o en una ruta aritmética/parser de gran impacto?

Los mutantes que siguen siendo inaccesibles o están restringidos estructuralmente suelen ser **mutantes equivalentes**. Los que siguen siendo **accesibles** y afectan a **condiciones límite**, **rutas de overflow/carry** o **aritmética/parsing crítico para la seguridad** deberían convertirse en:

- nuevos harnesses de fuzzing
- pruebas directas de propiedades/invariantes
- vectores específicos para casos límite

### Correlaciona los hallazgos externos con el grafo

Si tu pipeline de SAST exporta **SARIF**, proyecta los hallazgos sobre los nodos del grafo usando **archivo + rango de líneas** y usa el grafo para ampliar el análisis del impacto.<sup>[[6]](#references)</sup>

- calcula el **radio de impacto** de la función señalada
- comprueba si el hallazgo está en alguna ruta desde un punto de entrada
- agrupa los hallazgos cercanos que convergen en el mismo punto de estrangulamiento

Esto resulta útil para decidir si conviene dedicar tiempo de fuzzing a una función concreta: un nodo **accesible**, **complejo** y que ya tiene **hallazgos de SAST** suele ser un objetivo mejor que un nodo meramente complejo, sin ninguna ruta accesible para un atacante.

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

La metodología importante es la intersección: **complejidad x exposición x impacto**. Usa el gráfico para elegir los objetivos de fuzzing con el mayor valor de seguridad esperado y, después, usa las mutaciones que sobrevivan para decidir qué límites e invariantes debe poner a prueba tu harness.<sup>[[5]](#references)</sup>

## Fuzzing diferencial de codificaciones de claves criptográficas

Empieza con claves serializadas válidas o vectores de prueba estándar. Modifica los campos codificados sin romper la longitud ni la estructura necesarias para alcanzar las rutas de importación y operación; después, envía los mismos bytes a implementaciones independientes. Compara la aceptación y los errores. Las firmas y los textos cifrados aleatorizados necesitan oráculos de corrección, no comparaciones byte por byte: verifica las firmas o compara los secretos compartidos de un ciclo de encapsulación/decapsulación. Los vectores de prueba establecen la conformidad para casos conocidos; las mutaciones diferenciales sondean codificaciones malformadas que van más allá de ellos.<sup>[[23]](#references)[[26]](#references)</sup>

Para estos formatos de claves, usa oráculos específicos para cada formato:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Claves de firma expandidas ML-DSA:** modifica los coeficientes empaquetados `s1` o `s2` para que queden fuera de `[-η, η]`, sin dejar de mantener la clave analizable. Comprueba si la importación o la firma los rechazan y si alguna firma resultante se verifica. Las diferencias en la aceptación por sí solas no constituyen infracciones de los estándares, porque FIPS 204 no exige comprobaciones adicionales de claves privadas. Consulta el [mecanismo de filtración condicional](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pares de claves ML-KEM:** distingue las comprobaciones obligatorias de la clave de encapsulación y de la entrada de decapsulación de la comprobación opcional de coherencia por pares (PCT) de un par importado. Encapsula con su clave pública, decapsula con su clave privada y compara los secretos compartidos; una discrepancia puede interrumpir la comunicación cifrada aunque cada clave supere las comprobaciones de entrada individuales. Comprueba si la API valida las entradas durante la operación o mediante una llamada independiente; libcrux ofrece `validate_public_key(pk)` y `validate_private_key(sk, ct)`, que no sustituyen a una PCT.
- **Claves sin procesar XMSS/XMSSMT:** prueba los ciclos de ida y vuelta de claves serializadas de **firma y verificación** en distintos conjuntos de parámetros, no solo las operaciones con claves en memoria. XMSS y XMSSMT tienen espacios de OID de cuatro bytes separados, por lo que un analizador de OID que pruebe primero XMSS puede clasificar erróneamente una clave XMSSMT con un OID coincidente y rechazar su importación. El analizador de RustCrypto descrito ilustra un fallo de interoperabilidad/disponibilidad, no una falsificación de firmas.

## Fuzzing en Go con gosentry: motor más potente, entradas tipadas y comprobaciones diferenciales

Si un objetivo de Go ya tiene un harness nativo `testing.F`, una forma práctica de actualizarlo es ejecutar el mismo harness con [gosentry](https://github.com/trailofbits/gosentry), una bifurcación de la cadena de herramientas de Go que mantiene `go test -fuzz`, pero cambia el backend a **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Esto es útil cuando el fuzzer nativo de Go se atasca con **comparaciones difíciles**, **entradas tipadas** o **formatos con parsers complejos**. La metodología sigue siendo la misma:

- Sigue usando `f.Add(...)` para las semillas y `f.Fuzz(...)` para el callback.
- Reutiliza el mismo harness, pero ejecútalo con el binario `go` de gosentry en lugar de con la toolchain estándar.
- Trata la campaña resultante como una ejecución normal guiada por cobertura, pero con la planificación y las mutaciones de LibAFL, y mejores detectores complementarios.

### Convierte los fallos silenciosos en hallazgos de fuzzing

Un problema recurrente en las evaluaciones de Go es que el comportamiento peligroso a menudo **no** provoca un crash de forma predeterminada. Con gosentry, puedes convertir varias clases de estados «incorrectos pero silenciosos» en hallazgos.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` para que determinadas rutas de logging/error se comporten como crashes (útil para rutas de código del estilo `log.Fatal` que, de otro modo, solo registran el error y continúan).
- `--catch-races=true` para volver a ejecutar las entradas nuevas descubiertas en la cola con el detector de carreras de Go.
- `--catch-leaks=true` para volver a ejecutar las entradas nuevas de la cola con `goleak` y detener la ejecución si hay fugas de goroutines.
- La gestión de bloqueos de LibAFL, para conservar los **bucles infinitos / las entradas muy lentas** como hallazgos de fuzzing, en lugar de descartarlos como timeouts.
- Comprobaciones integradas de overflow aritmético de forma predeterminada, además de comprobaciones opcionales de truncamiento mediante instrumentación al estilo de go-panikint.

Esto es especialmente valioso para los objetivos cuyo impacto en la seguridad es un **fallo de parser sin panic**, un **bug de concurrencia** o un **bloqueo que solo provoca un DoS**, en lugar de corrupción de memoria.

### Fuzzing consciente de estructuras para APIs tipadas de Go

El fuzzing nativo de Go espera principalmente escalares como `[]byte`, `string` y números. Si el código bajo prueba consume objetos tipados, gosentry puede hacer fuzzing directamente de **valores compuestos** (structs, slices, arrays, pointers), y seguir mutando los bytes subyacentes.<sup>[[7]](#references)[[8]](#references)</sup>

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

Usar un formato de protocolo falso solo para fuzzing ocultaría errores lógicos detrás de código de parsing exclusivo del harness. Para campañas diferenciales o basadas en gramáticas, mantén la entrada del harness como un único `[]byte` o `string` y realiza el parsing dentro del callback.

### Fuzzing basado en gramáticas para parsers y entradas de protocolos

Para parsers, formatos y lenguajes de entrada, gosentry puede ejecutar **fuzzing de gramáticas Nautilus** sobre LibAFL. La gramática es un array JSON de reglas de producción, y el harness normalmente debería aceptar un único argumento `[]byte` o `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notas sobre la metodología:

- Usa el modo de gramática cuando las mutaciones a nivel de byte suelen fallar en las primeras comprobaciones de sintaxis.
- Mantén la gramática centrada en el **subconjunto del lenguaje/protocolo relevante para la seguridad**, en lugar de modelar toda la especificación.
- Usa valores límite grandes en terminales/no terminales para poner a prueba los límites de enteros, longitudes y máquinas de estado.
- El modo de gramática mantiene las entradas válidas según la gramática, pero el objetivo sigue recibiendo **bytes/cadenas**, por lo que el análisis y las comprobaciones semánticas siguen ejecutándose dentro del código instrumentado.

### Fuzzing diferencial: comparar implementaciones, no solo buscar fallos

Un patrón eficaz para los ecosistemas Go es el **grammar-based differential fuzzing**: generar entradas estructuradas válidas y proporcionárselas a dos analizadores, clientes o motores de transición de estado.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considere los siguientes casos como hallazgos:

- una implementación entra en pánico mientras que la otra rechaza la entrada correctamente
- discrepancias entre entradas aceptadas y rechazadas
- árboles de análisis u objetos decodificados diferentes
- transiciones de estado, nonces, saldos o raíces de estado divergentes

Esta es una forma práctica de encontrar **discrepancias de consenso**, **ambigüedad del parser** y **desviaciones entre la especificación y la implementación** que el fuzzing de crashes puro suele pasar por alto.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Reutilizar el corpus de la campaña para generar informes de cobertura

Después de una campaña, vuelva a ejecutar el corpus de cola guardado para generar un informe de cobertura de Go sin tener que exportar manualmente un corpus separado.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Ejecuta el comando desde el **mismo paquete** y con el mismo objetivo `-fuzz` para que gosentry resuelva el estado de la campaña almacenado en caché correcto.

## References

- [1] [Fuzzing de gramática mutacional](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing de AFL++ en profundidad](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinco años después: fuzzing de protocolos guiado por cobertura](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark convierte el código en grafos](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [A Go fuzzing le faltaba la mitad del conjunto de herramientas. Creamos un fork de la toolchain para solucionarlo.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: un fuzzer greybox rápido para protocolos de red con estado mediante snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Sin gramática no hay problema: hacia el fuzzing del kernel de Linux sin descripciones de llamadas al sistema](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: fuzzing eficiente con snapshots adaptables y mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentación LLVM de AFL++: cobertura de rutas y llamadores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing predictivo sensible al contexto](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog de seguridad ofensiva de Android: fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer de Binder de Android para LKL: documentación de compilación y semillas de regresión](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: exploración de condiciones de carrera del kernel de Linux con intercalados controlados de accesos a memoria](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: cobertura de código para fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Sintaxis de nombres de archivo extendidos de CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Aviso de Doyensec: CFITSIO, cuarto trimestre de 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing de la sintaxis de nombres de archivo extendidos de CFITSIO: 16 vulnerabilidades de seguridad de memoria y triaje asistido por Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing diferencial para criptografía](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: estándar del mecanismo de encapsulación de claves basado en retículos modulares](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Error de análisis de OID de XMSSMT: issue #1442 de RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Estado de las implementaciones de criptografía poscuántica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Cómo llegamos a CVE-2026-9539 mediante snapshots](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
