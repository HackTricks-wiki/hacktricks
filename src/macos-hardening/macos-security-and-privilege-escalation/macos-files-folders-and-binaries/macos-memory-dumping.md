# Volcado de memoria en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos de memoria

### Archivos de intercambio

Los archivos de intercambio, como `/private/var/vm/swapfile0`, actúan como **cachés cuando la memoria física está llena**. Cuando ya no queda espacio en la memoria física, sus datos se transfieren a un archivo de intercambio y luego se cargan de nuevo en la memoria física según se necesite. Pueden existir múltiples archivos de intercambio, con nombres como swapfile0, swapfile1, etc.

### Imagen de hibernación

El archivo ubicado en `/private/var/vm/sleepimage` es crucial durante el **modo de hibernación**. **Los datos de la memoria se almacenan en este archivo cuando OS X entra en hibernación**. Al despertar el equipo, el sistema recupera los datos de memoria de este archivo, permitiendo al usuario continuar donde lo dejó.

Cabe destacar que en los sistemas macOS modernos, este archivo suele estar cifrado por razones de seguridad, lo que dificulta su recuperación.

- Para comprobar si el cifrado está habilitado para el sleepimage, se puede ejecutar el comando `sysctl vm.swapusage`. Esto mostrará si el archivo está cifrado.

### Registros de presión de memoria

Otro archivo importante relacionado con la memoria en sistemas macOS es el **registro de presión de memoria**. Estos registros se encuentran en `/var/log` y contienen información detallada sobre el uso de memoria del sistema y los eventos de presión de memoria. Pueden ser especialmente útiles para diagnosticar problemas relacionados con la memoria o para comprender cómo el sistema gestiona la memoria a lo largo del tiempo.

## Volcado de memoria con osxpmem

Para volcar la memoria en una máquina macOS puedes usar [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Nota**: Esto es, en su mayoría, un **flujo de trabajo legado** ahora. `osxpmem` depende de cargar una kernel extension, el proyecto [Rekall](https://github.com/google/rekall) está archivado, la última release es de **2017**, y el binario publicado apunta a **Intel Macs**. En las versiones actuales de macOS, especialmente en **Apple Silicon**, la adquisición de RAM completa basada en kext suele estar bloqueada por las restricciones modernas de kernel-extension, SIP y los requisitos de firma de la plataforma. En la práctica, en sistemas modernos acabarás con más frecuencia haciendo un **volcado a nivel de proceso** en lugar de una imagen de toda la RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Si encuentras este error: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` puedes solucionarlo haciendo:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Otros errores** podrían solucionarse permitiendo la carga del kext en "Security & Privacy --> General"; simplemente **allow**.

También puedes usar este **oneliner** para descargar la aplicación, cargar el kext y volcar la memoria:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Volcado de procesos en vivo con LLDB

Para **versiones recientes de macOS**, el enfoque más práctico suele ser volcar la memoria de un **proceso específico** en lugar de intentar crear una imagen de toda la memoria física.

LLDB puede guardar un Mach-O core file desde un objetivo en vivo:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Por defecto, esto normalmente crea un **skinny core**. Para forzar a LLDB a incluir toda la memoria mapeada del proceso:
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

- El objetivo lleva **`get-task-allow`**
- Tu debugger está firmado con el **debugger entitlement** adecuado
- Eres **root** y el objetivo es un proceso de terceros no hardened

Para más contexto sobre cómo obtener un task port y lo que se puede hacer con él:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Volcados selectivos con Frida o userland readers

Cuando un core completo es demasiado ruidoso, volcar solo los **rangos legibles interesantes** suele ser más rápido. Frida es especialmente útil porque funciona bien para la **extracción dirigida** una vez que puedes attacharte al proceso.

Enfoque de ejemplo:

1. Enumerar rangos legibles/escribibles
2. Filtrar por módulo, heap, stack, o memoria anónima
3. Volcar solo las regiones que contengan cadenas candidatas, claves, protobufs, blobs plist/XML, o código/datos descifrados

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

- App heap chunks que contienen secretos
- Anonymous regions creadas por custom packers o loaders
- Páginas de código JIT / unpacked después de cambiar las protecciones

Older userland tools such as [`readmem`](https://github.com/gdbinit/readmem) also exist, but they are mainly useful as **referencias de origen** para volcados estilo directo `task_for_pid`/`vm_read` y no están bien mantenidas para los flujos de trabajo modernos de Apple Silicon.

## Notas rápidas de triaje

- `sysctl vm.swapusage` sigue siendo una forma rápida de comprobar el **uso de swap** y si el swap está **cifrado**.
- `sleepimage` sigue siendo relevante principalmente para escenarios de **hibernate/safe sleep**, pero los sistemas modernos suelen protegerlo, por lo que debe tratarse como una **fuente de artefactos a comprobar**, no como una ruta de adquisición fiable.
- En versiones recientes de macOS, el **volcado a nivel de proceso** suele ser más realista que la **imagen completa de memoria física**, a menos que controles la política de arranque, el estado de SIP y la carga de kexts.

## Referencias

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
