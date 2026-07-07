# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Los swap files, como `/private/var/vm/swapfile0`, sirven como **caches cuando la memoria física está llena**. Cuando ya no queda espacio en la memoria física, sus datos se transfieren a un swap file y luego se vuelven a traer a la memoria física según sea necesario. Puede haber múltiples swap files, con nombres como swapfile0, swapfile1, y así sucesivamente.

### Hibernate Image

El archivo ubicado en `/private/var/vm/sleepimage` es crucial durante el **modo de hibernación**. **Los datos de la memoria se almacenan en este archivo cuando OS X entra en hibernación**. Al despertar el equipo, el sistema recupera los datos de memoria desde este archivo, permitiendo al usuario continuar donde lo dejó.

Cabe señalar que en los sistemas MacOS modernos, este archivo suele estar cifrado por razones de seguridad, lo que dificulta su recuperación.

- Para comprobar si el cifrado está habilitado para el sleepimage, se puede ejecutar el comando `sysctl vm.swapusage`. Esto mostrará si el archivo está cifrado.

### Memory Pressure Logs

Otro archivo importante relacionado con la memoria en sistemas MacOS es el **memory pressure log**. Estos logs se encuentran en `/var/log` y contienen información detallada sobre el uso de memoria del sistema y los eventos de presión. Pueden ser especialmente útiles para diagnosticar problemas relacionados con la memoria o para entender cómo el sistema gestiona la memoria con el tiempo.

## Dumping memory with osxpmem

Para volcar la memoria en una máquina MacOS puedes usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Esto es en su mayoría un **legacy workflow** ahora. `osxpmem` depende de cargar una kernel extension, el proyecto [Rekall](https://github.com/google/rekall) está archivado, la última versión es de **2017**, y el binario publicado está orientado a **Intel Macs**. En las versiones actuales de macOS, especialmente en **Apple Silicon**, la adquisición completa de RAM basada en kext suele estar bloqueada por las restricciones modernas de kernel-extension, SIP y los requisitos de firma de plataforma. En la práctica, en sistemas modernos normalmente acabarás haciendo un **process-scoped dump** en lugar de una imagen de toda la RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si encuentras este error: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Puedes solucionarlo haciendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Otros errores** podrían corregirse **permitiendo la carga del kext** en "Security & Privacy --> General", solo **permítelo**.

También puedes usar este **oneliner** para descargar la aplicación, cargar el kext y volcar la memoria:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Volcado de procesos en vivo con LLDB

Para **versiones recientes de macOS**, el enfoque más práctico suele ser volcar la memoria de un **proceso específico** en lugar de intentar generar una imagen de toda la memoria física.

LLDB puede guardar un archivo core Mach-O desde un objetivo en vivo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Por defecto, esto normalmente crea un **skinny core**. Para forzar a LLDB a incluir toda la memoria mapeada del proceso:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Comandos útiles de seguimiento antes de volcar:
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
- Secretos en texto claro que solo están protegidos en reposo
- Páginas Mach-O descifradas después de unpacking / JIT / runtime patching

Si el objetivo está protegido por el **hardened runtime**, o si `taskgated` deniega el attach, normalmente necesitas una de estas condiciones:

- El objetivo incluye **`get-task-allow`**
- Tu debugger está firmado con el **debugger entitlement** correcto
- Eres **root** y el objetivo es un proceso de terceros no hardened

Para más contexto sobre cómo obtener un task port y qué se puede hacer con él:

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
Operativamente, esto suele significar:

- Una app de terceros enviada con **`get-task-allow`** suele poder volcarse directamente con LLDB, y el volcado resultante puede exponer datos protegidos por TCC que la app ya accedió.
- Un objetivo **hardened** sin `get-task-allow` normalmente rechazará los attachments, incluso como `root`, a menos que controles los entitlements / la ruta de política del debugger correspondiente.
- Los procesos de terceros sin hardening siguen siendo el lugar más fácil para usar `lldb`, `vmmap`, Frida o lectores personalizados de `task_for_pid`/`vm_read`.

## Volcados selectivos con Frida o lectores de userland

Cuando un core completo es demasiado ruidoso, volcar solo **rangos legibles interesantes** suele ser más rápido. Frida es especialmente útil porque funciona bien para la **extracción dirigida** una vez que puedes adjuntarte al proceso.

Enfoque de ejemplo:

1. Enumerar rangos legibles/escribibles
2. Filtrar por módulo, heap, stack o memoria anónima
3. Volcar solo las regiones que contengan cadenas candidatas, keys, protobufs, blobs plist/XML o código/datos descifrados

Ejemplo mínimo de Frida para volcar todos los rangos anónimos legibles:
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
Esto es útil cuando quieres evitar archivos core gigantes y solo recopilar:

- Fragmentos del heap de la app que contienen secretos
- Regiones anónimas creadas por packers o loaders personalizados
- Páginas de código JIT / desempaquetado después de cambiar protecciones

También existen herramientas antiguas de userland como [`readmem`](https://github.com/gdbinit/readmem), pero principalmente son útiles como **referencias de código fuente** para dumping directo estilo `task_for_pid`/`vm_read` y no están bien mantenidas para flujos de trabajo modernos de Apple Silicon.

## Snapshots de heap / VM con `.memgraph`

Si principalmente te interesan los **objetos del heap**, el **origen de las asignaciones** o un snapshot que pueda moverse a otra máquina, un `.memgraph` suele ser más práctico que un enorme core Mach-O. La herramienta `leaks` puede generar uno desde un proceso en vivo:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Luego clasifícalo offline con las herramientas estándar de Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` es la razón principal para conservar una captura `-fullContent`, porque las etiquetas que describen el contenido de la memoria se omiten de un `.memgraph` mínimo.

Esto es especialmente útil cuando:

- Quieres una **instantánea más pequeña y compartible** en lugar de un core completo
- `MallocStackLogging` estaba habilitado y quieres **backtraces de asignación**
- Ya conoces una **dirección interesante de heap** y quieres pivotar con `malloc_history`
- Necesitas un **desglose rápido de VM/heap** antes de decidir si un volcado completo merece el ruido

## Objetivos con mucho Swift: `swift-inspect`

Para aplicaciones que guardan datos de alto valor dentro de **objetos del runtime de Swift**, `swift-inspect` puede ser un buen complemento de LLDB o Frida. En lugar de volcar todo primero, puedes consultar estructuras específicas del runtime de Swift desde un proceso en vivo:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Esto es útil para identificar:

- Grandes arrays de Swift que almacenan datos interesantes
- Asignaciones de metadata que revelan tipos cargados en tiempo de ejecución
- Estado de concurrencia de Swift (`Task`, actor, relaciones de thread) antes de hacer un volcado más específico

Para un triage a nivel de objetos en runtime una vez que ya puedes inspeccionar el proceso, consulta [la página dedicada sobre objetos en memoria](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Notas rápidas de triage

- `sysctl vm.swapusage` sigue siendo una forma rápida de comprobar el **uso de swap** y si swap está **cifrado**.
- `sleepimage` sigue siendo relevante principalmente para escenarios de **hibernate/safe sleep**, pero los sistemas modernos suelen protegerlo, así que debe tratarse como una **fuente de artefactos a revisar**, no como una vía de adquisición fiable.
- En versiones recientes de macOS, el **volcado a nivel de proceso** suele ser más realista que la **imagen completa de memoria física** a menos que controles la política de arranque, el estado de SIP y la carga de kext.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
