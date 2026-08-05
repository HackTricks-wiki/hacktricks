# Sealed System Volume і DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Основна інформація

Починаючи з **macOS Big Sur (11.0)**, системний том криптографічно запечатується за допомогою **хеш-дерева знімка APFS**. Це називається **Sealed System Volume (SSV)**. Системний розділ монтується **лише для читання**, і будь-яка модифікація порушує seal, що перевіряється під час завантаження.

SSV забезпечує:
- **Виявлення втручання** — будь-яку модифікацію системних бінарних файлів або фреймворків можна виявити за порушеним криптографічним seal
- **Захист від відкату** — процес завантаження перевіряє цілісність системного знімка
- **Запобігання rootkit** — навіть root не може постійно змінювати файли на системному томі (без порушення seal)

### Перевірка стану SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### Права доступу записувачів SSV

Певні системні бінарні файли Apple мають права доступу, які дають їм змогу змінювати або керувати sealed system volume:

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Повернення системного тому до попереднього snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Створення нового sealed snapshot після оновлень системи |
| `com.apple.rootless.install.heritable` | Запис до шляхів, захищених SIP (успадковується дочірніми процесами) |
| `com.apple.rootless.install` | Запис до шляхів, захищених SIP |

### Пошук записувачів SSV
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

#### Snapshot Rollback Attack

Якщо зловмисник отримує контроль над бінарним файлом із `com.apple.private.apfs.revert-to-snapshot`, він може **відкотити системний том до стану до оновлення**, відновивши відомі вразливості:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Відкат snapshot фактично **скасовує оновлення безпеки**, відновлюючи раніше виправлені вразливості kernel і системи. Це одна з найнебезпечніших операцій, можливих у сучасній macOS.

#### Заміна системних бінарних файлів

Маючи bypass SIP + можливість запису до SSV, attacker може:

1. Змонтувати системний том у режимі read-write
2. Замінити системний daemon або framework library на троянську версію
3. Повторно запечатати snapshot (або прийняти зламаний seal, якщо SIP уже degraded)
4. Rootkit зберігається після перезавантажень і невидимий для інструментів виявлення у userland

### Реальні CVE

| CVE | Опис |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass SIP через зловживання entitlement `com.apple.rootless.install.heritable` у `system_installd` для запуску довільних post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | Bypass SIP: `system_installd` розміщував post-install script у захищеній SIP папці під `/tmp`, але сам `/tmp` не захищений SIP, тому папку можна було підмінити, змонтувавши поверх неї image ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write у XNU, що дозволяє записувати дані до read-only файлів, власником яких є root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Основна інформація

**DataVault** — це рівень захисту Apple для чутливих системних баз даних. Навіть **root не може отримати доступ до файлів, захищених DataVault** — читати або змінювати їх можуть лише процеси з певними entitlements.<sup>[1]</sup> До захищених сховищ належать:

| Захищена база даних | Шлях | Вміст |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Загальносистемні рішення щодо приватності TCC |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Рішення щодо приватності TCC для окремого користувача |
| Keychain (system) | `/Library/Keychains/System.keychain` | Системний keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Користувацький keychain |

Захист DataVault застосовується на **рівні файлової системи** за допомогою extended attributes і прапорців захисту тома, які перевіряються kernel.

### Entitlements контролера DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Пошук контролерів DataVault
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
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

#### Пряма модифікація бази даних TCC

Якщо attacker компрометує бінарний файл-контролер DataVault (наприклад, через code injection у process із `com.apple.private.tcc.manager`), він може **безпосередньо модифікувати базу даних TCC**, щоб надати будь-якому застосунку будь-який дозвіл TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Модифікація бази даних TCC — це **остаточний обхід захисту приватності**: вона безшумно надає будь-які дозволи, без будь-якого запиту до користувача чи видимого індикатора. Історично численні ланцюжки підвищення привілеїв у macOS завершувалися записом до бази даних TCC як фінальним payload.

#### Доступ до бази даних Keychain

DataVault також захищає файли backing keychain. Скомпрометований контролер DataVault може:

1. Прочитати необроблені файли бази даних keychain
2. Видобути зашифровані елементи keychain
3. Спробувати офлайн-розшифрування за допомогою пароля користувача або відновлених ключів

### Реальні CVE, пов'язані з обходом DataVault/TCC

| CVE | Опис |
|---|---|
| CVE-2024-44131 | Symlink race у FileProvider, що дозволяє привілейованому helper отримати доступ до даних, захищених TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Від імені root **створити нового користувача, чий `NFSHomeDirectory` вказує на контрольовану атакером `TCC.db`**; під час входу `tccd` використовує її, і дозволи застосовуються, відкриваючи доступ до даних інших користувачів ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": змінення домашнього каталогу користувача для розміщення контрольованої атакером TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Помилка у визначенні bundle, що дозволяє застосунку **успадкувати дозволи TCC донорського bundle** без запиту; у реальних атаках використовувалася **XCSSET** для створення знімків екрана робочого столу ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` формував шлях до DB на основі `$HOME`, тому `launchctl setenv HOME` перенаправляв його до контрольованої атакером `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` мав `com.apple.private.tcc.manager` **і** вимкнену перевірку бібліотек, тому HAL plug-in, розміщений у `/Library/Audio/Plug-Ins/HAL`, міг надати довільні права TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Посилання

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
