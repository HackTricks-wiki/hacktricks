# Volcado de memoria de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos de memoria

### Archivos de swap

Los archivos de swap, como `/private/var/vm/swapfile0`, funcionan como **cachés cuando la memoria física está llena**. Cuando no queda espacio en la memoria física, sus datos se transfieren a un archivo de swap y luego se devuelven a la memoria física según sea necesario. Puede haber varios archivos de swap, con nombres como swapfile0, swapfile1, etc.

### Imagen de hibernación

El archivo ubicado en `/private/var/vm/sleepimage` es crucial durante el **modo de hibernación**. **Los datos de la memoria se almacenan en este archivo cuando OS X hiberna**. Cuando el ordenador se activa, el sistema recupera los datos de la memoria desde este archivo, lo que permite al usuario continuar desde donde lo dejó.

Cabe destacar que, en los sistemas MacOS modernos, este archivo suele estar cifrado por motivos de seguridad, lo que dificulta su recuperación.

- Para comprobar si el cifrado está habilitado para sleepimage, se puede ejecutar el comando `sysctl vm.swapusage`. Esto mostrará si el archivo está cifrado.

### Registros de presión de memoria

Otro archivo importante relacionado con la memoria en los sistemas MacOS es el **registro de presión de memoria**. Estos registros se encuentran en `/var/log` y contienen información detallada sobre el uso de la memoria del sistema y los eventos de presión. Pueden ser especialmente útiles para diagnosticar problemas relacionados con la memoria o comprender cómo el sistema administra la memoria con el tiempo.

## Volcado de memoria con osxpmem

Para volcar la memoria de un equipo con MacOS, puedes usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Actualmente, este es principalmente un **flujo de trabajo legacy**. `osxpmem` depende de la carga de una extensión del kernel, el proyecto [Rekall](https://github.com/google/rekall) está archivado, la última versión se publicó en **2017** y el binario publicado está dirigido a equipos **Intel**. En las versiones actuales de macOS, especialmente en **Apple Silicon**, la adquisición de RAM completa basada en kext suele estar bloqueada por las restricciones modernas de las extensiones del kernel, SIP y los requisitos de firma de la plataforma. En la práctica, en los sistemas modernos normalmente terminarás realizando un **volcado limitado a un proceso** en lugar de obtener una imagen de toda la RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si encuentras este error: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`, puedes solucionarlo haciendo lo siguiente:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Otros errores** podrían solucionarse **permitiendo la carga del kext** en "Security & Privacy --> General"; simplemente haz clic en **allow**.

También puedes usar este **oneliner** para descargar la aplicación, cargar el kext y volcar la memoria:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Volcado de procesos en vivo con LLDB

En **versiones recientes de macOS**, el enfoque más práctico suele ser volcar la memoria de un **proceso específico** en lugar de intentar crear una imagen de toda la memoria física.

LLDB puede guardar un archivo core Mach-O de un objetivo activo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
De forma predeterminada, esto suele crear un **skinny core**. Para forzar a LLDB a incluir toda la memoria mapeada del proceso:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandos útiles de seguimiento antes del dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Esto suele ser suficiente cuando el objetivo es recuperar:

- Blobs de configuración descifrados
- Tokens, cookies o credenciales en memoria
- Secretos en texto plano que solo están protegidos en reposo
- Páginas Mach-O descifradas después de unpacking / JIT / runtime patching

Si el objetivo está protegido por el **hardened runtime**, o si `taskgated` deniega el attach, normalmente necesitas una de estas condiciones:

- El objetivo contiene **`get-task-allow`**
- Tu debugger está firmado con el **debugger entitlement** adecuado
- Eres **root** y el objetivo es un proceso de terceros que no usa hardened runtime

Para obtener más información sobre cómo obtener un task port y qué se puede hacer con él:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Comprobaciones rápidas antes del attach

Antes de invertir tiempo en LLDB/Frida, verifica rápidamente si el objetivo es realmente **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
En la práctica, esto suele significar:

- Una app de terceros distribuida con **`get-task-allow`** suele poder volcarse directamente con LLDB, y el dump resultante puede exponer datos protegidos por TCC a los que la app ya haya accedido.<sup>[[1]](#references)</sup>
- Un target **hardened** sin `get-task-allow` normalmente rechazará los attaches, incluso como `root`, a menos que controles los entitlements del debugger relevantes o la ruta de policy.
- Los procesos de terceros no hardened siguen siendo el lugar más sencillo para usar `lldb`, `vmmap`, Frida o readers personalizados basados en `task_for_pid`/`vm_read`.

### Busca helpers anidados dumpables

Las investigaciones recientes sobre apps de macOS notarizadas siguen encontrando **`get-task-allow`** en helpers anidados en lugar de en el binario principal de la GUI. Cuando una app de nivel superior parece hardened, enumera sus **servicios XPC**, **login items**, **helper tools** y CLIs incluidos antes de rendirte:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Un ejecutable anidado con `get-task-allow` suele ser el lugar más sencillo para conectarse con `lldb`, hacer dump de un core o extraer memoria con un cliente personalizado de `task_for_pid`, incluso cuando la aplicación principal está mejor protegida.

## Dumps selectivos con Frida o lectores de userland

Cuando un core completo contiene demasiado ruido, hacer dump únicamente de los **rangos legibles interesantes** suele ser más rápido. Frida resulta especialmente útil porque funciona bien para la **extracción dirigida** una vez que puedes conectarte al proceso.

Enfoque básico:

1. Enumerar los rangos legibles/escribibles
2. Filtrar por módulo, heap, stack o memoria anónima
3. Hacer dump únicamente de las regiones que contengan strings candidatos, keys, protobufs, blobs plist/XML o código/datos descifrados

Ejemplo mínimo de Frida para hacer dump de todos los rangos anónimos legibles:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Esto es útil cuando quieres evitar archivos core gigantes y recopilar únicamente:

- Fragmentos del heap de la app que contienen secretos
- Regiones anónimas creadas por packers o loaders personalizados
- Páginas de código JIT / unpacked después de cambiar las protecciones

Cuando el objetivo sigue **asignando / liberando** memoria mientras realizas el dump, prefiere la primitiva **`readVolatile()`** de Frida en lugar de **`readByteArray()`** para rangos inestables. Es más lenta, pero evita terminar el objetivo si una página deja de ser legible a mitad de la lectura. Para adquisiciones grandes, también puede ser más limpio transmitir los fragmentos de vuelta con `send(..., data)` y comprimirlos en el lado del controller en lugar de crear miles de archivos pequeños dentro del objetivo.

También existen herramientas userland más antiguas, como [`readmem`](https://github.com/gdbinit/readmem), pero son principalmente útiles como **referencias del código fuente** para realizar dumps directamente mediante `task_for_pid`/`vm_read` y no reciben un buen mantenimiento para los workflows modernos con Apple Silicon.

## Snapshots del heap / VM con `.memgraph`

Si te interesan principalmente los **objetos del heap**, la **procedencia de las asignaciones** o un snapshot que puedas mover a otra máquina, un `.memgraph` suele ser más práctico que un core Mach-O gigante. Las herramientas de `leaks` pueden generar uno a partir de un proceso activo:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Luego, realiza su triage offline con las herramientas estándar de Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` es la razón principal para conservar una captura `-fullContent`, porque las etiquetas que describen el contenido de la memoria se omiten en un `.memgraph` mínimo.

Esto es especialmente útil cuando:

- Quieres una **snapshot más pequeña y fácil de compartir** en lugar de un core completo
- `MallocStackLogging` estaba habilitado y quieres **allocation backtraces**
- Ya conoces una **dirección de heap interesante** y quieres pivotar con `malloc_history`
- Necesitas un **desglose rápido de VM/heap** antes de decidir si vale la pena el ruido de un volcado completo

### Triage diferencial de memgraph

Si controlas la forma en que se inicia el target, habilita el **historical allocation logging** antes del lanzamiento para que las snapshots posteriores conserven backtraces útiles de alloc/free:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Luego captura snapshots alrededor de la acción de interés y compáralos offline:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Esta es una forma práctica de aislar **objetos post-autenticación**, **buffers `CFData` grandes** o **regiones de VM anónimas** que solo aparecen después de una etapa de descifrado, desempaquetado u obtención de secretos.

## Objetivos con mucho Swift: `swift-inspect`

En aplicaciones que mantienen datos de alto valor dentro de **objetos del runtime de Swift**, `swift-inspect` puede ser un buen complemento para LLDB o Frida. En lugar de volcarlo todo primero, puedes consultar estructuras específicas del runtime de Swift desde un proceso activo:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Esto resulta útil para identificar:

- Grandes arrays de Swift que almacenan datos interesantes
- Asignaciones de metadata que revelan tipos cargados en runtime
- Estado de concurrencia de Swift (`Task`, relaciones entre actores y threads) antes de realizar un dump más específico

Para realizar un triage a nivel de objeto una vez que ya puedas inspeccionar el proceso, consulta [la página dedicada a los objetos en memoria](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Notas rápidas de triage

- `sysctl vm.swapusage` sigue siendo una forma rápida de comprobar el **uso de swap** y si swap está **cifrado**.
- `sleepimage` sigue siendo relevante principalmente en escenarios de **hibernate/safe sleep**, pero los sistemas modernos suelen protegerlo, por lo que debe tratarse como una **fuente de artefactos que conviene comprobar**, no como una vía de adquisición fiable.
- En versiones recientes de macOS, el **dumping a nivel de proceso** suele ser más realista que la **creación de una imagen completa de la memoria física**, a menos que controles la política de arranque, el estado de SIP y la carga de kexts.

## Referencias

- [1] [To Allow or Not to get-task-allow: Análisis de seguridad de macOS](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [página man de leaks(1)](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
