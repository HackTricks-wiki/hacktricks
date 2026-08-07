# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Основна інформація

Починаючи з **macOS Big Sur (11.0)**, системний том криптографічно запечатується за допомогою **APFS snapshot hash tree**. Це називається **Sealed System Volume (SSV)**. Системний розділ монтується **лише для читання**, і будь-яка модифікація порушує seal, що перевіряється під час завантаження.<sup>[[11]](#references)</sup>

SSV забезпечує:
- **Виявлення втручання** — будь-яку модифікацію системних бінарних файлів або фреймворків можна виявити через порушений криптографічний seal
- **Захист від відкату** — процес завантаження перевіряє цілісність системного snapshot
- **Запобігання rootkit** — навіть root не може постійно змінювати файли на системному томі (не порушивши seal)

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
### Entitlements для запису до SSV

Певні системні бінарні файли Apple мають entitlements, які дають їм змогу змінювати або керувати sealed system volume:

| Entitlement | Призначення |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Повернути системний том до попереднього snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Створити новий sealed snapshot після системних оновлень |
| `com.apple.rootless.install.heritable` | Записувати до шляхів, захищених SIP (успадковується дочірніми процесами) |
| `com.apple.rootless.install` | Записувати до шляхів, захищених SIP |

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

#### Атака з відкатом snapshot

Якщо зловмисник скомпрометує binary із `com.apple.private.apfs.revert-to-snapshot`, він може **відкотити системний том до стану до оновлення**, відновивши відомі вразливості:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Відкат snapshot фактично **скасовує оновлення безпеки**, відновлюючи раніше виправлені вразливості ядра та системи. Це одна з найнебезпечніших операцій, можливих у сучасній macOS.

#### Заміна системного бінарного файлу

Маючи обхід SIP + можливість запису до SSV, зловмисник може:

1. Змонтувати системний том у режимі читання-запису
2. Замінити системний daemon або бібліотеку framework на троянську версію
3. Повторно підписати snapshot (або прийняти пошкоджений підпис, якщо SIP уже ослаблено)
4. Rootkit зберігається після перезавантажень і невидимий для інструментів виявлення на рівні userland

### Реальні CVE

| CVE | Опис |
|---|---|
| CVE-2021-30892 | **Shrootless** — обхід SIP із використанням entitlement `com.apple.rootless.install.heritable` процесу `system_installd` для запуску довільних post-install скриптів ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Обхід SIP: `system_installd` розміщував post-install скрипт у захищеній SIP папці в `/tmp`, але сам `/tmp` не захищений SIP, тому папку можна було підмінити, змонтувавши поверх неї образ ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition під час copy-on-write у XNU, що дає змогу записувати дані до доступних лише для читання файлів, власником яких є root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Основна інформація

**DataVault** — це рівень захисту Apple для чутливих системних баз даних. Навіть **root не може отримати доступ до файлів, захищених DataVault** — лише процеси з певними entitlements можуть читати або змінювати їх.<sup>[[4]](#references)</sup> До захищених сховищ належать:

| Захищена база даних | Шлях | Вміст |
|---|---|---|
| TCC (система) | `/Library/Application Support/com.apple.TCC/TCC.db` | Загальносистемні рішення щодо конфіденційності TCC |
| TCC (користувач) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Рішення щодо конфіденційності TCC для окремого користувача |
| Keychain (система) | `/Library/Keychains/System.keychain` | Системний Keychain |
| Keychain (користувач) | `~/Library/Keychains/login.keychain-db` | Keychain користувача |

Захист DataVault реалізується на **рівні файлової системи** за допомогою розширених атрибутів і прапорців захисту тому та перевіряється ядром.

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

Якщо зловмисник скомпрометує бінарний файл контролера DataVault (наприклад, за допомогою code injection у процес із `com.apple.private.tcc.manager`), він може **безпосередньо модифікувати базу даних TCC**, щоб надати будь-якому застосунку будь-який TCC-дозвіл:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Модифікація бази даних TCC — це **остаточний обхід захисту приватності** — вона непомітно надає будь-які дозволи, без запиту до користувача чи видимого індикатора. Історично декілька ланцюжків підвищення привілеїв у macOS завершувалися записом до бази даних TCC як фінальним payload.

#### Доступ до бази даних Keychain

DataVault також захищає backing-файли keychain. Скомпрометований контролер DataVault може:

1. Читати raw-файли бази даних keychain
2. Витягувати зашифровані елементи keychain
3. Виконувати спроби offline-розшифрування за допомогою пароля користувача або відновлених ключів

### Реальні CVE, пов'язані з обходом DataVault/TCC

| CVE | Опис |
|---|---|
| CVE-2024-44131 | Symlink race у FileProvider, що дає змогу privileged helper отримати доступ до даних, захищених TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Як root, **створити нового користувача, чий `NFSHomeDirectory` вказує на контрольовану attacker'ом `TCC.db`**; під час входу `tccd` використовує її, і дозволи застосовуються, надаючи доступ до даних інших користувачів ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": змінити home dir користувача, щоб розмістити контрольовану attacker'ом TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Дефект визначення bundle, що дає змогу застосунку **успадкувати дозволи TCC bundle-донора** без запиту; у wild ця вразливість експлуатувалася **XCSSET** для створення скриншотів робочого столу ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` формував шлях до DB на основі `$HOME`, тому `launchctl setenv HOME` перенаправляв його до контрольованої attacker'ом `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` мав **`com.apple.private.tcc.manager`** і **вимкнену library validation**, тому HAL plug-in, розміщений у `/Library/Audio/Plug-Ins/HAL`, міг надати довільні права TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## References

- [1] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Uncovering macOS Malware: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
