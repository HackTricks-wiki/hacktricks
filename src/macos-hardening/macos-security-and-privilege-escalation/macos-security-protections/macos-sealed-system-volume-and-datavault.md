# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Основна інформація

Починаючи з **macOS Big Sur (11.0)**, системний том криптографічно запечатується за допомогою **хеш-дерева знімка APFS**. Це називається **Sealed System Volume (SSV)**. Системний розділ монтується **лише для читання**, і будь-яка модифікація порушує печатку, що перевіряється під час завантаження.<sup>[[11]](#references)</sup>

SSV забезпечує:
- **Виявлення втручання** — будь-яка модифікація системних бінарних файлів або фреймворків змінює корінь дерева Меркла та робить недійсною печатку, підписану Apple
- **Автентифікацію під час завантаження** — ланцюжок завантаження перевіряє вибраний системний знімок, перш ніж він стане кореневою файловою системою
- **Захист від rootkit** — навіть root не може постійно замінити файли в автентифікованому системному знімку без вимкнення authenticated root або компрометації авторизованого шляху оновлення

SSV захищає том **System**, але не доступний для запису том **Data**, пов’язаний із ним. Firmlinks об’єднують обидва томи в простір імен, видимий у `/`, тому шлях, який виглядає доступним для запису, не доводить, що відповідний об’єкт належить запечатаному знімку. FileVault і Data Protection забезпечують конфіденційність даних у стані спокою; вони є окремими від забезпечення цілісності SSV.<sup>[[11]](#references)</sup>

### Перевірка стану SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```
### Актуальне представлення системи: SSV + Cryptex grafts

У нових версіях macOS не кожен виконуваний файл, видимий у `/System`, обов’язково походить зі snapshot завантаженого SSV. **Cryptexes** — це окремо автентифіковані дискові образи APFS, вміст яких накладається на вибрані каталоги; тому Rapid Security Responses можуть замінювати компоненти, важливі для безпеки, без перебудови базового SSV. Під час аналізу persistence або порівняння системного коду перевіряйте активні монтування та сховище Preboot Cryptex замість хешування лише базового snapshot:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Деталі boot-chain і Rapid Security Response описано в [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); у цьому розділі розглядається безпосередньо межа SSV.

### Entitlements для запису в SSV

Деякі системні бінарні файли Apple мають entitlements, які дають їм змогу змінювати sealed system volume або керувати ним:

| Entitlement | Призначення |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Повернути system volume до попереднього snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Створити новий sealed snapshot після оновлень системи |
| `com.apple.rootless.install.heritable` | Виконувати запис до шляхів, захищених SIP (успадковується дочірніми процесами) |
| `com.apple.rootless.install` | Виконувати запис до шляхів, захищених SIP |

### Пошук SSV Writers
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### Сценарії атак

#### Атака відкату snapshot

Якщо зловмисник скомпрометує бінарний файл із `com.apple.private.apfs.revert-to-snapshot`, він зможе **відкотити системний том до стану до оновлення**, відновивши відомі вразливості:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Відкат snapshot фактично **скасовує оновлення безпеки**, відновлюючи раніше виправлені вразливості kernel і системи. Це одна з найнебезпечніших операцій, можливих у сучасній macOS.

#### Заміна системного бінарного файла

За наявності обходу SIP + можливості запису до SSV зловмисник може:

1. Змонтувати системний том у режимі read-write
2. Замінити системний daemon або бібліотеку framework на троянську версію
3. Повторно запечатати snapshot (або прийняти пошкоджений seal, якщо SIP уже ослаблено)
4. Rootkit зберігається після перезавантажень і невидимий для інструментів виявлення на рівні userland

### Реальні CVE

| CVE | Опис |
|---|---|
| CVE-2021-30892 | **Shrootless** — обхід SIP через зловживання entitlement `com.apple.rootless.install.heritable` у `system_installd`, що дає змогу запускати довільні post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Обхід SIP: `system_installd` розміщував post-install script у захищеній SIP папці в `/tmp`, але сам `/tmp` не захищений SIP, тому папку можна було підмінити, змонтувавши поверх неї image ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition під час copy-on-write у XNU, що дає змогу записувати дані до доступних лише для читання файлів, власником яких є root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Основна інформація

**DataVault** — це захист файлової системи для конфіденційних файлів і директорій, доступ до якого регулюється entitlement. BSD-прапорець `UF_DATAVAULT` (`0x00000080`) позначає об’єкт як такий, що потребує entitlement і для читання, і для запису; на відміну від звичайного DAC, просте отримання прав **root** або Full Disk Access не задовольняє цю перевірку, доки захист активний.<sup>[[4]](#references)[[13]](#references)</sup>

Не використовуйте “DataVault” як синонім для будь-якої захищеної бази даних. Бази даних TCC регулюються політиками TCC/FDA і SIP (див. [macOS TCC](macos-tcc/README.md)), тоді як доступ до елементів keychain також залежить від ACL keychain і cryptographic protection (див. [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Фактичні приклади DataVault зазвичай трапляються у сховищах, що належать сервісам, у `/private/var/folders/.../0/`, наприклад у сховищі Screen Time; цей прапорець відображається як `datavault` у BSD file flags, якщо батьківський об’єкт можна перевірити через `stat`.

### Entitlements контролерів DataVault

| Entitlement | Межа |
|---|---|
| `com.apple.rootless.datavault.controller` | Доступ до об’єктів `UF_DATAVAULT` і керування ними<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Керування рішеннями TCC; це споріднена, але окрема privacy boundary |
| `com.apple.private.tcc.allow` | Обхід вибраних TCC-сервісів, зазначених у значенні entitlement |
| `com.apple.rootless.storage.TCC` | Запис до захищеного SIP сховища TCC |

Процес, який поєднує entitlement контролера DataVault із FDA, backup, indexing або IPC-функціональністю, є особливо цікавим: шукайте primitive confused deputy, який копіює захищений об’єкт до звичайного шляху, замість спроби безпосередньо відкрити vault.<sup>[[14]](#references)</sup>

### Пошук контролерів DataVault
```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### Сценарії атак

#### Пряма модифікація бази даних TCC (окремий кордон TCC)

Якщо attacker компрометує процес TCC manager (наприклад, через code injection у процес, що має `com.apple.private.tcc.manager`), він може **безпосередньо змінити базу даних TCC**, щоб надати будь-якому застосунку будь-який дозвіл TCC:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Модифікація бази даних TCC — це **остаточний обхід захисту приватності**: вона непомітно надає будь-який дозвіл без запиту користувача чи видимого індикатора. Історично кілька ланцюжків підвищення привілеїв у macOS завершувалися записом до бази даних TCC як фінальним payload.

#### Доступ до бази даних Keychain

Прямий доступ до бази даних, що зберігає Keychain, не є еквівалентом доступу до секретів у відкритому вигляді. Якщо інша межа привілеїв дає зловмиснику змогу скопіювати базу даних, усе одно потрібно атакувати матеріал ключів і ACL елементів; дивіться окрему сторінку [macOS Keychain](../../macos-red-teaming/macos-keychain.md), а не припускайте, що entitlement DataVault-controller є достатнім.

#### Межа копії резервної копії: Time Machine

Аналіз 2026 року продемонстрував корисну загальну закономірність: `backupd` має одночасно `com.apple.rootless.datavault.controller` і Full Disk Access, щоб копіювати захищені сховища. У протестованій конфігурації `/private/var/folders` входив до Time Machine, а змонтована копія резервної копії не застосовувала активну межу DataVault. Дослідник використав це, щоб знайти сховище Screen Time SQLite і прочитати його PIN-код обмежень у відкритому вигляді, не відкриваючи активне сховище. Розглядайте це як **атаку на межу копії**: перевіряйте deputies для резервного копіювання, експорту, міграції, індексації та діагностики, які можуть матеріалізувати дані сховища під слабшим монтуванням або шляхом.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Ця поведінка залежить від версії та структури резервних копій. Перевірте її на цільовій збірці та пам'ятайте, що зашифроване призначення Time Machine захищає копію лише доки воно заблоковане; після монтування його засоби контролю доступу стають частиною attack surface.

### Реальні CVE, пов'язані з DataVault/TCC Bypass

| CVE | Опис |
|---|---|
| CVE-2024-44131 | FileProvider symlink race, що дозволяє привілейованому helper отримати доступ до захищених TCC даних ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Як root, **створити нового користувача, чий `NFSHomeDirectory` вказує на контрольований атакувальником `TCC.db`**; під час входу `tccd` використовує його, і дозволи застосовуються, забезпечуючи доступ до даних інших користувачів ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": зміна домашнього каталогу користувача для розміщення контрольованого атакувальником TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Недолік у визначенні bundle, що дозволяє застосунку **успадкувати дозволи TCC донорського bundle** без запиту; у wild його використовувала **XCSSET** для створення знімків екрана робочого столу ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` формував шлях до DB на основі `$HOME`, тому `launchctl setenv HOME` перенаправляв його на контрольований атакувальником `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` мав `com.apple.private.tcc.manager` **і** вимкнену перевірку бібліотек, тому HAL plug-in, розміщений у `/Library/Audio/Plug-Ins/HAL`, міг надавати довільні права TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft виявила нову вразливість macOS Shrootless, яка могла обійти System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Технічний аналіз: CVE-2022-22583 — Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow — Варто робити погано](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Захист даних](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs — CVE-2024-44131: TCC bypass викрадає дані з iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji — Виявлення malware для macOS: обхід TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Нова вразливість macOS, "powerdir", могла призвести до несанкціонованого доступу до даних користувача](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [У malware XCSSET виявлено zero-day обхід TCC](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: обхід macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Відтворення музики та обхід TCC, також відомий як CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Кошмар оновлень Apple OTA (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — експлуатація TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Як обійти власний код-пароль Screen Time — аналіз коду та Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
