# Quick Look Generators у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Quick Look — це **framework попереднього перегляду файлів** у macOS. Коли користувач вибирає файл у Finder, натискає пробіл, наводить на нього вказівник або переглядає директорію з увімкненими мініатюрами, Quick Look **автоматично завантажує plugin-генератор** для аналізу файлу та створення його візуального попереднього перегляду.<sup>[[1]](#references)</sup>

Quick Look generators — це **bundles** (`.qlgenerator`), зареєстровані для певних **Uniform Type Identifiers (UTIs)**. Коли macOS потребує попереднього перегляду файлу, що відповідає цьому UTI, вона завантажує generator у sandboxed helper process (`QuickLookSatellite` або `qlmanage`) і викликає його generator function.

### Чому це важливо для безпеки

> [!WARNING]
> Quick Look generators запускаються **лише через вибір або перегляд файлу** — дія "Open" не потрібна. Це робить їх потужним **пасивним вектором exploitation**: користувачеві достатньо перейти до директорії, що містить malicious file.

**Поверхня атаки:**
- Generators **аналізують довільний вміст файлів** із диска, завантажень, email attachments або network shares
- Створений спеціальним чином файл може використати **вразливості аналізу** (buffer overflows, format strings, type confusion) у коді generator
- Рендеринг попереднього перегляду відбувається **автоматично** — достатньо відкрити папку Downloads, куди потрапив malicious file
- Quick Look працює в **sandboxed helper**, але escape з sandbox у цьому контексті вже демонстрували

## Архітектура
```
User selects file in Finder
↓
Finder → QuickLookSatellite (sandboxed helper)
↓
Generator plugin loaded (.qlgenerator bundle)
↓
Plugin parses file content → Returns preview image/HTML
↓
Preview displayed to user
```
## Перерахування

### Список встановлених генераторів
```bash
# List all Quick Look generators with their UTI registrations
qlmanage -m plugins 2>&1

# Find generator bundles on the system
find / -name "*.qlgenerator" -type d 2>/dev/null

# Common locations
ls /Library/QuickLook/
ls ~/Library/QuickLook/
ls /System/Library/QuickLook/

# Check a generator's Info.plist for UTI registrations
defaults read /path/to/Generator.qlgenerator/Contents/Info.plist 2>/dev/null
```
### Використання сканера
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Сценарії атак

### Експлуатація на основі файлів

Сторонній Quick Look generator, який обробляє складні формати файлів (3D-моделі, наукові дані, формати архівів), є чудовою ціллю:
```bash
# 1. Identify a third-party generator and its UTI
qlmanage -m plugins 2>&1 | grep -v "com.apple" | head -20

# 2. Find what file types it handles
defaults read /Library/QuickLook/SomeGenerator.qlgenerator/Contents/Info.plist \
CFBundleDocumentTypes 2>/dev/null

# 3. Craft a malicious file matching that UTI
# (fuzzer output or hand-crafted malformed file)

# 4. Place the file where the user will preview it
cp malicious.xyz ~/Downloads/

# 5. When user opens Downloads in Finder → preview triggers → exploit fires
```
### Drive-By через Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Заміна стороннього генератора

Якщо bundle Quick Look generator встановлено у **локації, доступній для запису користувачем** (`~/Library/QuickLook/`), його можна замінити:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Віддалений запуск Quick Look
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Особливості sandbox

Генератори Quick Look запускаються всередині допоміжного процесу в sandbox. Профіль sandbox обмежує:
- Доступ до файлової системи (переважно лише читання файлу, для якого створюється попередній перегляд)
- Доступ до мережі (обмежений)
- IPC (обмежений `mach-lookup`)

Однак sandbox має відомі вектори обходу:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE з реального світу<sup>[[2]](#references)</sup>

| CVE | Опис |
|---|---|
| CVE-2019-8741 | Пошкодження пам'яті під час попереднього перегляду Quick Look через спеціально створений файл |
| CVE-2018-4293 | Обхід sandbox генератора Quick Look |
| CVE-2020-9963 | Розкриття інформації під час обробки попереднього перегляду Quick Look |
| CVE-2021-30876 | Пошкодження пам'яті під час створення мініатюр |

## Fuzzing генераторів Quick Look
```bash
# Basic fuzzing approach for a Quick Look generator:

# 1. Identify the target generator and its file format
qlmanage -m plugins 2>&1 | grep "target-uti"

# 2. Collect seed corpus of valid files
find / -name "*.targetext" -size -1M 2>/dev/null | head -100

# 3. Mutate files and trigger preview
for f in /tmp/fuzz_corpus/*; do
# Mutate the file (using radamsa, honggfuzz, etc.)
radamsa "$f" > /tmp/fuzz_input.targetext

# Trigger Quick Look (with timeout to catch hangs)
timeout 5 qlmanage -t /tmp/fuzz_input.targetext 2>&1

# Check if QuickLookSatellite crashed
log show --last 5s --predicate 'process == "QuickLookSatellite" AND eventMessage CONTAINS "crash"' 2>/dev/null
done
```
## References

- [1] [Apple Developer — Посібник з програмування Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — CVE для Quick Look](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
