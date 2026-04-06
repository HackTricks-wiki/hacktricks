# macOS Sealed System Volume i DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Podstawowe informacje

Począwszy od **macOS Big Sur (11.0)**, wolumin systemowy jest kryptograficznie zapieczętowany przy użyciu **APFS snapshot hash tree**. Nazywa się to **Sealed System Volume (SSV)**. Partycja systemowa jest montowana jako **tylko do odczytu** i każda modyfikacja łamie pieczęć, która jest weryfikowana podczas rozruchu.

SSV zapewnia:
- **Wykrywanie manipulacji** — każda modyfikacja binarek/frameworków systemowych jest wykrywalna przez przerwanie pieczęci kryptograficznej
- **Ochrona przed rollback** — proces rozruchowy weryfikuje integralność migawki systemu
- **Zapobieganie rootkitom** — nawet root nie może trwale modyfikować plików na woluminie systemowym (bez złamania pieczęci)

### Sprawdzanie stanu SSV
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
### Uprawnienia SSV Writerów

Niektóre pliki binarne systemu Apple mają uprawnienia, które pozwalają im modyfikować lub zarządzać zabezpieczonym woluminem systemowym:

| Uprawnienie | Cel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Przywrócenie woluminu systemowego do poprzedniej migawki |
| `com.apple.private.apfs.create-sealed-snapshot` | Utworzenie nowej zapieczętowanej migawki po aktualizacjach systemu |
| `com.apple.rootless.install.heritable` | Zapisywanie do ścieżek chronionych przez SIP (dziedziczone przez procesy potomne) |
| `com.apple.rootless.install` | Zapisywanie do ścieżek chronionych przez SIP |

### Wyszukiwanie SSV Writerów
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
### Scenariusze ataku

#### Atak przywrócenia migawki

Jeżeli atakujący przejmie binarkę z `com.apple.private.apfs.revert-to-snapshot`, może **cofnąć wolumin systemowy do stanu sprzed aktualizacji**, przywracając znane podatności:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Przywrócenie snapshotu skutecznie **cofa aktualizacje bezpieczeństwa**, przywracając wcześniej załatane luki w jądrze i systemie. To jedna z najbardziej niebezpiecznych operacji na nowoczesnym macOS.

#### Zastępowanie binarek systemowych

Przy obejściu SIP i możliwości zapisu do SSV, atakujący może:

1. Zamontować wolumin systemowy w trybie odczytu i zapisu
2. Zastąpić demon systemowy lub bibliotekę frameworku wersją zawierającą trojana
3. Ponownie zapieczętować snapshot (lub zaakceptować uszkodzoną pieczęć, jeśli SIP jest już zdegradowany)
4. Rootkit utrzymuje się po rebootach i jest niewidoczny dla narzędzi wykrywających w warstwie użytkownika

### Rzeczywiste CVE

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — obejście SIP pozwalające na modyfikację SSV za pomocą `system_installd` |
| CVE-2022-22583 | Obejście SSV poprzez obsługę snapshotów w PackageKit |
| CVE-2022-46689 | Warunek wyścigu umożliwiający zapisy do plików chronionych przez SIP |

---

## DataVault

### Podstawowe informacje

**DataVault** jest warstwą ochronną Apple dla wrażliwych baz danych systemowych. Nawet **root nie może uzyskać dostępu do plików chronionych przez DataVault** — tylko procesy z określonymi uprawnieniami (entitlements) mogą je odczytywać lub modyfikować. Chronione zasoby obejmują:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Decyzje prywatności TCC obowiązujące systemowo |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Decyzje prywatności TCC dla użytkownika |
| Keychain (system) | `/Library/Keychains/System.keychain` | Pęk kluczy systemowy |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Pęk kluczy użytkownika |

Ochrona DataVault jest egzekwowana na poziomie **systemu plików** przy użyciu atrybutów rozszerzonych i flag ochrony woluminu, weryfikowanych przez jądro.

### Uprawnienia (entitlements) kontrolera DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Znajdowanie kontrolerów DataVault
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
### Scenariusze ataku

#### Bezpośrednia modyfikacja bazy danych TCC

Jeśli atakujący przejmie plik binarny kontrolera DataVault (np. poprzez wstrzyknięcie kodu do procesu z `com.apple.private.tcc.manager`), może **bezpośrednio modyfikować bazę danych TCC**, aby przyznać dowolnej aplikacji dowolne uprawnienie TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Modyfikacja bazy danych TCC to **ostateczne obejście prywatności** — przyznaje dowolne uprawnienie w sposób cichy, bez wyświetlenia monitu użytkownika ani widocznego wskaźnika. Historycznie wiele łańcuchów eskalacji uprawnień w macOS kończyło się zapisami do bazy danych TCC jako końcowym ładunkiem.

#### Keychain Database Access

DataVault również chroni pliki zaplecza Keychain. Skompromitowany kontroler DataVault może:

1. Odczytać surowe pliki bazy danych Keychain
2. Wyodrębnić zaszyfrowane elementy Keychain
3. Próbować odszyfrowania offline przy użyciu hasła użytkownika lub odzyskanych kluczy

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
