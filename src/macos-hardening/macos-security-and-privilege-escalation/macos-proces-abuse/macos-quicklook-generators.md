# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Quick Look — це macOS'ний **file preview framework**. Коли користувач вибирає файл у Finder, натискає Space, наводить на нього курсор або переглядає теку з увімкненими мініатюрами, Quick Look **автоматично завантажує генератор-плагін**, щоб проаналізувати файл і відобразити візуальний попередній перегляд.

Quick Look generators — це **bundles** (`.qlgenerator`), які реєструються для конкретних **Uniform Type Identifiers (UTIs)**. Коли macOS потребує прев'ю для файлу, що відповідає цьому UTI, воно завантажує генератор у ізольований допоміжний процес (`QuickLookSatellite` or `qlmanage`) і викликає його generator-функцію.

### Чому це важливо для безпеки

> [!WARNING]
> Quick Look generators запускаються просто при **виборі або перегляді файлу** — не потрібно жодної дії "Open". Це робить їх потужним **пасивним вектором експлуатації**: користувачеві достатньо перейти до теки, що містить шкідливий файл.

**Поверхня атаки:**
- Генератори **аналізують довільний вміст файлів** з диска, завантажень, вкладень електронної пошти або мережевих ресурсів
- Сфабрикований файл може використати **вразливості при розборі** (buffer overflows, format strings, type confusion) у коді генератора
- Рендеринг прев'ю відбувається **автоматично** — достатньо переглянути теку Downloads, куди потрапив шкідливий файл
- Quick Look запускається в **ізольованому допоміжному процесі**, проте були продемонстровані способи обходу обмежень sandbox у цьому контексті

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

### Файлова експлуатація

Сторонній Quick Look generator, який розбирає складні формати файлів (3D models, scientific data, archive formats), є основною ціллю:
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
### Drive-By через папку Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Заміна стороннього генератора

Якщо бандл генератора Quick Look встановлений у **каталозі, доступному для запису користувача** (`~/Library/QuickLook/`), його можна замінити:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Запустити Quick Look віддалено
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Питання щодо sandbox

Quick Look generators запускаються всередині допоміжного процесу, обмеженого sandbox. Профіль sandbox обмежує:
- Доступ до файлової системи (здебільшого лише для читання до файлу, що переглядається)
- Доступ до мережі (обмежений)
- IPC (обмежений mach-lookup)

Однак sandbox має відомі вектори обходу:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Реальні CVE

| CVE | Опис |
|---|---|
| CVE-2019-8741 | Пошкодження пам'яті у Quick Look preview через спеціально створений файл |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | Розкриття інформації під час обробки Quick Look preview |
| CVE-2021-30876 | Пошкодження пам'яті під час генерації мініатюр |

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
## Посилання

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objectivesee.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
