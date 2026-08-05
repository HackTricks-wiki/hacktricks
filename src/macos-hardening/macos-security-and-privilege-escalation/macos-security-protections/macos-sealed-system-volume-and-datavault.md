# Sealed System Volume i DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Podstawowe informacje

Począwszy od **macOS Big Sur (11.0)**, wolumin systemowy jest kryptograficznie zapieczętowany przy użyciu **drzewa hashy migawki APFS**. Nazywa się to **Sealed System Volume (SSV)**. Partycja systemowa jest montowana jako **read-only**, a każda modyfikacja narusza pieczęć, co jest weryfikowane podczas uruchamiania systemu.

SSV zapewnia:
- **Wykrywanie manipulacji** — każda modyfikacja plików binarnych systemu/frameworków jest wykrywalna dzięki naruszeniu pieczęci kryptograficznej
- **Ochronę przed rollbackiem** — proces uruchamiania weryfikuje integralność migawki systemu
- **Zapobieganie rootkitom** — nawet root nie może trwale modyfikować plików na woluminie systemowym (bez naruszenia pieczęci)

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

Niektóre systemowe pliki binarne Apple mają uprawnienia umożliwiające im modyfikowanie zapieczętowanego woluminu systemowego lub zarządzanie nim:

| Uprawnienie | Cel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Przywrócenie woluminu systemowego do poprzedniego snapshotu |
| `com.apple.private.apfs.create-sealed-snapshot` | Utworzenie nowego zapieczętowanego snapshotu po aktualizacjach systemu |
| `com.apple.rootless.install.heritable` | Zapis do ścieżek chronionych przez SIP (dziedziczony przez procesy potomne) |
| `com.apple.rootless.install` | Zapis do ścieżek chronionych przez SIP |

### Znajdowanie SSV Writerów
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

#### Snapshot Rollback Attack

Jeśli atakujący przejmie kontrolę nad plikiem binarnym z `com.apple.private.apfs.revert-to-snapshot`, może **przywrócić wolumin systemowy do stanu sprzed aktualizacji**, ponownie aktywując znane podatności:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Wycofanie snapshotu skutecznie **cofa aktualizacje zabezpieczeń**, przywracając wcześniej załatane luki w kernelu i systemie. Jest to jedna z najbardziej niebezpiecznych operacji możliwych we współczesnym macOS.

#### Zastępowanie binariów systemowych

Dzięki obejściu SIP i możliwości zapisu do SSV attacker może:

1. Zamontować wolumin systemowy w trybie odczytu i zapisu
2. Zastąpić systemowy daemon lub bibliotekę frameworka wersją zawierającą trojana
3. Ponownie zapieczętować snapshot (lub zaakceptować uszkodzoną pieczęć, jeśli SIP jest już osłabiony)
4. Rootkit pozostaje aktywny po ponownym uruchomieniu i jest niewidoczny dla narzędzi detekcyjnych userland

### CVE z realnego świata

| CVE | Opis |
|---|---|
| CVE-2021-30892 | **Shrootless** — obejście SIP wykorzystujące entitlement `com.apple.rootless.install.heritable` procesu `system_installd` do uruchamiania dowolnych skryptów post-install ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | Obejście SIP: `system_installd` umieszczał skrypt post-install w chronionym przez SIP folderze w `/tmp`, ale samo `/tmp` nie jest chronione przez SIP, więc folder można było podmienić, montując na nim obraz ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write w XNU umożliwiający zapis do plików tylko do odczytu należących do root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Podstawowe informacje

**DataVault** to warstwa ochrony Apple dla wrażliwych systemowych baz danych. Nawet **root nie może uzyskać dostępu do plików chronionych przez DataVault** — tylko procesy z określonymi entitlementami mogą je odczytywać lub modyfikować.<sup>[1]</sup> Chronione magazyny obejmują:

| Chroniona baza danych | Ścieżka | Zawartość |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Systemowe decyzje dotyczące prywatności TCC |
| TCC (użytkownik) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Decyzje dotyczące prywatności TCC dla poszczególnych użytkowników |
| Keychain (system) | `/Library/Keychains/System.keychain` | Systemowy keychain |
| Keychain (użytkownik) | `~/Library/Keychains/login.keychain-db` | Keychain użytkownika |

Ochrona DataVault jest wymuszana na **poziomie systemu plików** przy użyciu atrybutów rozszerzonych i flag ochrony woluminu, weryfikowanych przez kernel.

### Entitlementy kontrolera DataVault
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

Jeśli atakujący przejmie plik binarny kontrolera DataVault (np. za pomocą code injection do procesu z `com.apple.private.tcc.manager`), może **bezpośrednio modyfikować bazę danych TCC**, aby przyznać dowolnej aplikacji dowolne uprawnienie TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Modyfikacja bazy danych TCC to **ostateczne obejście ochrony prywatności** — przyznaje dowolne uprawnienia po cichu, bez żadnego monitu użytkownika ani widocznego wskaźnika. Historycznie wiele łańcuchów privilege escalation w macOS kończyło się zapisem do bazy danych TCC jako końcowym payloadem.

#### Dostęp do bazy danych keychain

DataVault chroni również pliki pomocnicze keychain. Przejęty kontroler DataVault może:

1. Odczytać surowe pliki bazy danych keychain
2. Wyodrębnić zaszyfrowane elementy keychain
3. Podjąć próbę odszyfrowania offline przy użyciu hasła użytkownika lub odzyskanych kluczy

### Rzeczywiste CVE związane z obejściem DataVault/TCC

| CVE | Opis |
|---|---|
| CVE-2024-44131 | Wyścig symlinków w FileProvider umożliwiający uprzywilejowanemu helperowi dostęp do danych chronionych przez TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Jako root można **utworzyć nowego użytkownika, którego `NFSHomeDirectory` wskazuje na kontrolowaną przez atakującego `TCC.db`**; podczas logowania `tccd` ją odczytuje, a uprawnienia zostają zastosowane, umożliwiając dostęp do danych innych użytkowników ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | „powerdir”: zmiana katalogu domowego użytkownika w celu umieszczenia kontrolowanej przez atakującego bazy TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Luka w wnioskowaniu bundle umożliwiająca aplikacji **odziedziczenie uprawnień TCC bundle źródłowego** bez monitu; wykorzystana w środowisku naturalnym przez **XCSSET** do wykonywania zrzutów ekranu pulpitu ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` tworzył ścieżkę do bazy danych na podstawie `$HOME`, więc `launchctl setenv HOME` przekierowywał go do kontrolowanej przez atakującego `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` posiadał `com.apple.private.tcc.manager` **i** miał wyłączoną walidację bibliotek, więc wtyczka HAL umieszczona w `/Library/Audio/Plug-Ins/HAL` mogła przyznać dowolne uprawnienia TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Referencje

- [1] [Apple Platform Security — ochrona danych](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [Koszmar aktualizacji OTA Apple (migawki APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — eksploatacja TCC](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
