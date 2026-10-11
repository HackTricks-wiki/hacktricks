# macOS Sealed System Volume і DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Основна інформація

Починаючи з **macOS Big Sur (11.0)**, системний том криптографічно запечатується за допомогою **дерева хешів знімка APFS**. Це називається **Sealed System Volume (SSV)**. Системний розділ монтується **лише для читання**, а будь-яка його зміна порушує печатку, яка перевіряється під час завантаження.<sup>[[11]](#references)</sup>

SSV забезпечує:
- **Виявлення підміни** — будь-яка зміна системних бінарних файлів або фреймворків змінює корінь дерева Merkle і робить недійсною печатку, підписану Apple
- **Автентифікацію під час завантаження** — ланцюжок завантаження перевіряє вибраний системний знімок, перш ніж він стане кореневою файловою системою
- **Стійкість до руткітів** — навіть root не може постійно замінити файли в автентифікованому системному знімку, не вимкнувши authenticated root або не скомпрометувавши авторизований шлях оновлення

SSV захищає том **System**, а не пов’язаний із ним доступний для запису том **Data**. Firmlinks об’єднують обидва томи в простір імен, видимий у `/`, тому шлях, який виглядає доступним для запису, не доводить, що відповідний об’єкт належить до запечатаного знімка. FileVault і Data Protection забезпечують конфіденційність даних у стані спокою; вони не пов’язані із цілісністю SSV.<sup>[[11]](#references)</sup>

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

### Ефективне системне подання: SSV + Cryptex grafts

У новіших випусках macOS не кожен виконуваний файл, видимий у `/System`, обов’язково походить із завантаженого знімка SSV. **Cryptexes** — це окремо автентифіковані образи дисків APFS, вміст яких монтується поверх вибраних каталогів; тому Rapid Security Responses можуть замінювати чутливі до безпеки компоненти без перебудови базового SSV. Під час аналізу persistence або порівняння системного коду перевіряйте активні точки монтування та сховище Preboot Cryptex, а не лише обчислюйте хеш базового знімка:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Завантажувальний ланцюжок і Rapid Security Response описані в [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); у цьому розділі розглядається лише межа SSV.

### Entitlements для запису в SSV

Деякі системні бінарні файли Apple мають entitlements, які дають їм змогу змінювати запечатаний системний том або керувати ним:

| Entitlement | Призначення |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Повернути системний том до попереднього snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Створити новий запечатаний snapshot після оновлення системи |
| `com.apple.rootless.install.heritable` | Записувати в захищені SIP шляхи (успадковується дочірніми процесами) |
| `com.apple.rootless.install` | Записувати в захищені SIP шляхи |

### Пошук процесів, що записують у SSV

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

#### Атака з відкатом знімка

Якщо зловмисник скомпрометує двійковий файл із `com.apple.private.apfs.revert-to-snapshot`, він зможе **відкотити системний том до стану до оновлення**, відновивши відомі вразливості:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Відкат snapshot фактично **скасовує оновлення безпеки**, відновлюючи раніше виправлені вразливості ядра та системи. Це одна з найнебезпечніших операцій, можливих у сучасній macOS.

#### Заміна системних бінарних файлів

За наявності обходу SIP і можливості запису до SSV зловмисник може:

1. Змонтувати системний том для читання й запису
2. Замінити системний daemon або бібліотеку framework на троянізовану версію
3. Повторно запечатати snapshot (або прийняти порушення seal, якщо SIP уже ослаблено)
4. Rootkit зберігається після перезавантажень і невидимий для інструментів виявлення в userland

### CVE з реального світу

| CVE | Опис |
|---|---|
| CVE-2021-30892 | **Shrootless** — обхід SIP, що зловживає entitlement `com.apple.rootless.install.heritable` процесу `system_installd` для запуску довільних post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Обхід SIP: `system_installd` розміщував post-install script у захищеній SIP папці всередині `/tmp`, але сам `/tmp` не захищений SIP, тому папку можна було підмінити, змонтувавши поверх неї образ ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write в XNU, що дозволяє записувати у файли лише для читання, власником яких є root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Основна інформація

**DataVault** — це захист файлової системи для конфіденційних файлів і каталогів, доступ до яких контролюється entitlement. Прапорець BSD `UF_DATAVAULT` (`0x00000080`) позначає об’єкт як такий, для читання й запису якого потрібен entitlement; на відміну від звичайного DAC, саме лише отримання прав **root** або Full Disk Access не задовольняє цю перевірку, доки захист активний.<sup>[[4]](#references)[[13]](#references)</sup>

Не використовуйте «DataVault» як синонім будь-якої захищеної бази даних. Бази даних TCC регулюються політиками TCC/FDA та SIP (див. [macOS TCC](macos-tcc/README.md)), а доступ до елементів keychain також залежить від ACL Keychain і криптографічного захисту (див. [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Реальні приклади DataVault часто трапляються у сховищах, що належать сервісам, у каталогах `/private/var/folders/.../0/`, наприклад у сховищі Screen Time; прапорець відображається як `datavault` у прапорцях файлів BSD, якщо батьківський каталог доступний для `stat`.

### Entitlements контролера DataVault

| Entitlement | Межа |
|---|---|
| `com.apple.rootless.datavault.controller` | Доступ до об’єктів `UF_DATAVAULT` і керування ними<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Керування рішеннями TCC; це пов’язана, але окрема межа конфіденційності |
| `com.apple.private.tcc.allow` | Обхід вибраних сервісів TCC, указаних у значенні entitlement |
| `com.apple.rootless.storage.TCC` | Запис до захищеного SIP сховища TCC |

Процес, що поєднує entitlement контролера DataVault із функціями FDA, резервного копіювання, індексування або IPC, становить особливий інтерес: шукайте confused-deputy primitive, який копіює захищений об’єкт у звичайний шлях, замість того щоб намагатися відкрити сховище безпосередньо.<sup>[[14]](#references)</sup>

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

#### Безпосередня модифікація бази даних TCC (окрема межа TCC)

Якщо зловмисник скомпрометує процес-менеджер TCC (наприклад, за допомогою code injection у процес, що має `com.apple.private.tcc.manager`), він може **безпосередньо змінити базу даних TCC**, щоб надати будь-якому застосунку будь-який дозвіл TCC:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> Модифікація бази даних TCC — це **найрадикальніший спосіб обійти захист приватності**: вона непомітно надає будь-який дозвіл без запиту користувача чи видимого індикатора. Історично кілька ланцюжків підвищення привілеїв у macOS завершувалися записом у базу даних TCC як фінальним payload.

#### Доступ до бази даних Keychain

Доступ безпосередньо до бази даних, що використовується Keychain, не рівнозначний доступу до секретів у відкритому вигляді. Навіть якщо інша межа привілеїв дає зловмиснику змогу скопіювати базу даних, ключовий матеріал і ACL елементів усе одно потрібно атакувати; дивіться спеціальну сторінку про [macOS Keychain](../../macos-red-teaming/macos-keychain.md), а не вважайте, що entitlement контролера DataVault достатній.

#### Межа резервної копії: Time Machine

Аналіз 2026 року продемонстрував корисний загальний підхід: `backupd` має і `com.apple.rootless.datavault.controller`, і Full Disk Access, щоб копіювати захищені сховища. У протестованій конфігурації `/private/var/folders` входив до резервної копії Time Machine, а змонтована копія резервної копії не дотримувалася межі DataVault, що діє для активного сховища. Дослідник використав це, щоб знайти сховище SQLite Screen Time і прочитати PIN-код обмежень у відкритому вигляді, не відкриваючи активне сховище. Розглядайте це як **атаку на межу копіювання**: перевіряйте резервне копіювання, експорт, міграцію, індексацію та діагностичні служби, які можуть матеріалізувати дані сховища у слабше захищеній точці монтування чи за іншим шляхом.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Ця поведінка залежить від версії та структури резервної копії. Перевірте її на цільовій збірці й пам’ятайте: зашифроване сховище Time Machine захищає копію лише тоді, коли воно заблоковане; після монтування його засоби контролю доступу стають частиною поверхні атаки.

### Реальні CVE, пов’язані з обходом DataVault/TCC

| CVE | Опис |
|---|---|
| CVE-2024-44131 | Symlink race у FileProvider дає привілейованому helper змогу отримати доступ до даних, захищених TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Від імені root **створити нового користувача, чий `NFSHomeDirectory` вказує на контрольований зловмисником `TCC.db`**; під час входу `tccd` використовує його, застосовує дозволи й отримує доступ до даних інших користувачів ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | «powerdir»: змінити домашній каталог користувача, щоб підкласти контрольований зловмисником TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Помилка визначення bundle дає застосунку змогу **успадкувати дозволи TCC від донорського bundle** без запиту; у реальних атаках її використовувала **XCSSET** для створення знімків екрана робочого стола ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` формував шлях до DB на основі `$HOME`, тож `launchctl setenv HOME` перенаправляв його на контрольований зловмисником `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` мав `com.apple.private.tcc.manager` **і** вимкнену перевірку бібліотек, тому HAL-плагін, розміщений у `/Library/Audio/Plug-Ins/HAL`, міг надавати будь-які дозволи TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft виявила нову вразливість macOS Shrootless, яка може обійти System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Технічний аналіз: CVE-2022-22583 — Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow — Варто робити погано](https://worthdoingbadly.com/macdirtycow/)
- [4] [Безпека платформ Apple — захист даних](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs — CVE-2024-44131: обхід TCC викрадає дані з iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji — Виявлення шкідливого ПЗ для macOS: обхід TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Нова вразливість macOS «powerdir» може призвести до несанкціонованого доступу до даних користувачів](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [У шкідливому ПЗ XCSSET виявлено zero-day обхід TCC](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: обхід фреймворку macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Увімкніть музику й обійдіть TCC, або CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Жах оновлень Apple OTA (знімки APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — експлуатація TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Як обійти власний пароль Screen Time — аналіз вихідного коду та Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
