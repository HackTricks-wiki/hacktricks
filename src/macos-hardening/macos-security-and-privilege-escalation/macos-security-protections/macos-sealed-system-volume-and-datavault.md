# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Основна інформація

Починаючи з **macOS Big Sur (11.0)**, системний том криптографічно запечатаний з використанням **APFS snapshot hash tree**. Це називається **Sealed System Volume (SSV)**. Системний розділ монтується як **тільки для читання** і будь‑які модифікації руйнують печатку, яка перевіряється під час завантаження.

SSV забезпечує:
- **Tamper detection** — будь‑яка модифікація системних бінарних файлів/фреймворків виявляється через порушену криптографічну печатку
- **Rollback protection** — процес завантаження перевіряє цілісність системного snapshot
- **Rootkit prevention** — навіть root не може постійно змінювати файли на системному томі (без руйнування печатки)

### Перевірка статусу SSV
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
### Привілеї записувачів SSV

Деякі системні бінарні файли Apple мають entitlements (права доступу), які дозволяють їм змінювати або керувати запечатаним системним томом:

| Entitlement | Призначення |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Повернути системний том до попереднього знімка |
| `com.apple.private.apfs.create-sealed-snapshot` | Створити новий запечатаний знімок після оновлень системи |
| `com.apple.rootless.install.heritable` | Запис у шляхи, захищені SIP (успадковується дочірніми процесами) |
| `com.apple.rootless.install` | Запис у шляхи, захищені SIP |

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

Якщо зловмисник скомпрометує binary з `com.apple.private.apfs.revert-to-snapshot`, він може **відкотити системний том до стану перед оновленням**, відновивши відомі вразливості:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Відкат snapshot фактично **відміняє оновлення безпеки**, відновлюючи раніше виправлені уразливості ядра та системи. Це одна з найнебезпечніших операцій, які можливі в сучасному macOS.

#### Заміна системного бінарного файлу

При наявності SIP bypass та можливості запису в SSV, атакуючий може:

1. Вмонтувати системний том у режимі читання-запису
2. Замінити системний демон або бібліотеку фреймворку на троянську версію
3. Повторно запечатати snapshot (або прийняти порушену печатку, якщо SIP вже послаблено)
4. rootkit зберігається після перезавантажень і невидимий для userland detection tools

### Реальні CVE

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass, що дозволяє модифікацію SSV через `system_installd` |
| CVE-2022-22583 | SSV bypass через обробку snapshot у PackageKit |
| CVE-2022-46689 | Умова гонки, що дозволяє запис у файли, захищені SIP |

---

## DataVault

### Загальна інформація

**DataVault** — шар захисту Apple для чутливих системних баз даних. Навіть **root не може отримати доступ до файлів, захищених DataVault** — лише процеси з відповідними entitlements можуть читати або змінювати їх. Захищені сховища включають:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Загальносистемні рішення TCC щодо приватності |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Рішення TCC щодо приватності для користувача |
| Keychain (system) | `/Library/Keychains/System.keychain` | Системний keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Користувацький keychain |

Захист DataVault реалізується на **рівні файлової системи** за допомогою розширених атрибутів та прапорців захисту тома, що перевіряються ядром.

### Entitlements контролера DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Знаходження DataVault Controllers
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

#### Пряме змінення бази даних TCC

Якщо атакуючий скомпрометує двійковий файл контролера DataVault (наприклад, через ін'єкцію коду в процес з `com.apple.private.tcc.manager`), він може **безпосередньо змінити базу даних TCC**, щоб надати будь-якому додатку будь-який дозвіл TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Модифікація бази даних TCC є **ultimate privacy bypass** — вона надає будь‑які дозволи безшумно, без запиту користувача або видимого індикатора. Історично кілька macOS privilege escalation chains завершувалися записами в базу TCC як фінальним payload.

#### Доступ до бази даних Keychain

DataVault також захищає файли, що лежать в основі keychain. Скомпрометований контролер DataVault може:

1. Читати сирі файли бази даних keychain
2. Витягувати зашифровані елементи keychain
3. НамагаTися виконати офлайн-розшифрування з використанням пароля користувача або відновлених ключів

### Реальні CVE, пов'язані з DataVault/TCC bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## Посилання

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
