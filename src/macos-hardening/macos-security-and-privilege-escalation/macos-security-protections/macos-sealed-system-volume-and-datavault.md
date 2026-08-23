# macOS Sealed System Volume i DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Podstawowe informacje

Począwszy od **macOS Big Sur (11.0)**, wolumin systemowy jest kryptograficznie zapieczętowany przy użyciu **drzewa hashy migawki APFS**. Nazywa się to **Sealed System Volume (SSV)**. Partycja systemowa jest montowana jako **tylko do odczytu**, a każda modyfikacja narusza pieczęć, co jest weryfikowane podczas uruchamiania systemu.<sup>[[11]](#references)</sup>

SSV zapewnia:
- **Wykrywanie manipulacji** — każda modyfikacja systemowych plików binarnych lub frameworków zmienia korzeń drzewa Merkle'a i unieważnia pieczęć podpisaną przez Apple
- **Uwierzytelnianie podczas uruchamiania** — łańcuch rozruchowy weryfikuje wybraną migawkę systemu, zanim stanie się ona głównym systemem plików
- **Odporność na rootkity** — nawet root nie może trwale zastąpić plików w uwierzytelnionej migawce systemu bez wyłączenia authenticated root lub naruszenia autoryzowanej ścieżki aktualizacji

SSV chroni wolumin **System**, a nie zapisywalny wolumin **Data** sparowany z nim. Firmlinks łączą oba woluminy w przestrzeni nazw widocznej pod `/`, dlatego ścieżka wyglądająca na zapisywalną nie dowodzi, że leżący u jej podstaw obiekt należy do zapieczętowanej migawki. FileVault i Data Protection zapewniają poufność danych w spoczynku; są niezależne od integralności SSV.<sup>[[11]](#references)</sup>

### Sprawdzanie stanu SSV
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
### Efektywny widok systemu: SSV + Cryptex grafts

W nowszych wydaniach macOS nie każdy plik wykonywalny widoczny w `/System` musi pochodzić z uruchomionego snapshotu SSV. **Cryptexes** to osobno uwierzytelniane obrazy dysków APFS, których zawartość jest nakładana na wybrane katalogi; Rapid Security Responses mogą więc zastępować komponenty istotne dla bezpieczeństwa bez przebudowy bazowego SSV. Podczas analizowania persistence lub porównywania kodu systemowego zinwentaryzuj aktywne mounty oraz magazyn Preboot Cryptex zamiast haszować wyłącznie bazowy snapshot:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Szczegóły dotyczące łańcucha rozruchowego i Rapid Security Response opisano w [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); ta sekcja koncentruje się na samej granicy SSV.

### Uprawnienia SSV Writers

Niektóre systemowe pliki binarne Apple mają uprawnienia, które pozwalają im modyfikować zarządzany, zapieczętowany wolumin systemowy:

| Uprawnienie | Cel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Przywrócenie woluminu systemowego do poprzedniego snapshotu |
| `com.apple.private.apfs.create-sealed-snapshot` | Utworzenie nowego zapieczętowanego snapshotu po aktualizacjach systemu |
| `com.apple.rootless.install.heritable` | Zapis do ścieżek chronionych przez SIP (dziedziczone przez procesy potomne) |
| `com.apple.rootless.install` | Zapis do ścieżek chronionych przez SIP |

### Znajdowanie SSV Writers
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
### Attack Scenarios

#### Snapshot Rollback Attack

Jeśli attacker przejmie binary z `com.apple.private.apfs.revert-to-snapshot`, może **wycofać system volume do stanu sprzed aktualizacji**, przywracając znane vulnerabilities:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Przywrócenie migawki skutecznie **cofa aktualizacje zabezpieczeń**, przywracając wcześniej załatane podatności kernela i systemu. Jest to jedna z najbardziej niebezpiecznych operacji możliwych we współczesnym macOS.

#### Zastępowanie plików binarnych systemu

Po ominięciu SIP i uzyskaniu możliwości zapisu do SSV attacker może:

1. Zamontować wolumin systemowy z prawem odczytu i zapisu
2. Zastąpić systemowego daemona lub bibliotekę frameworka wersją zawierającą trojana
3. Ponownie zapieczętować snapshot (lub zaakceptować uszkodzoną pieczęć, jeśli SIP jest już zdegradowane)
4. rootkit utrzymuje się po ponownym uruchomieniu i pozostaje niewidoczny dla narzędzi wykrywających działających w userlandzie

### CVE z realnego świata

| CVE | Opis |
|---|---|
| CVE-2021-30892 | **Shrootless** — ominięcie SIP wykorzystujące entitlement `com.apple.rootless.install.heritable` daemona `system_installd` do uruchamiania dowolnych skryptów post-install ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Ominięcie SIP: `system_installd` umieszczał skrypt post-install w chronionym przez SIP folderze w `/tmp`, ale samo `/tmp` nie jest chronione przez SIP, więc folder można było podmienić przez zamontowanie na nim obrazu ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition copy-on-write w XNU umożliwiająca zapis do plików tylko do odczytu należących do roota ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Podstawowe informacje

**DataVault** to ochrona systemu plików weryfikowana przez entitlement, przeznaczona dla poufnych plików i katalogów. Flaga BSD `UF_DATAVAULT` (`0x00000080`) oznacza obiekt wymagający entitlement zarówno do odczytu, jak i zapisu; w przeciwieństwie do normalnego DAC samo uzyskanie uprawnień **root** lub otrzymanie Full Disk Access nie spełnia tego warunku, gdy ochrona jest aktywna.<sup>[[4]](#references)[[13]](#references)</sup>

Nie używaj terminu „DataVault” jako synonimu każdej chronionej bazy danych. Bazy danych TCC podlegają zasadom TCC/FDA i SIP (zobacz [macOS TCC](macos-tcc/README.md)), natomiast dostęp do elementów keychaina zależy również od ACL keychaina i ochrony kryptograficznej (zobacz [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Rzeczywiste przykłady DataVault często występują jako magazyny należące do usług poniżej `/private/var/folders/.../0/`, takie jak magazyn Screen Time; flaga jest widoczna jako `datavault` w flagach plików BSD, gdy można wykonać `stat` na katalogu nadrzędnym.

### Entitlementy kontrolerów DataVault

| Entitlement | Granica |
|---|---|
| `com.apple.rootless.datavault.controller` | Dostęp do obiektów `UF_DATAVAULT` i zarządzanie nimi<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Zarządzanie decyzjami TCC; jest to powiązana, lecz odrębna granica prywatności |
| `com.apple.private.tcc.allow` | Omijanie wybranych usług TCC wymienionych w wartości entitlementu |
| `com.apple.rootless.storage.TCC` | Zapis do chronionego przez SIP magazynu TCC |

Proces łączący entitlement kontrolera DataVault z funkcjami FDA, backupu, indeksowania lub IPC jest szczególnie interesujący: szukaj prymitywu confused deputy, który kopiuje chroniony obiekt do zwykłej ścieżki, zamiast próbować bezpośrednio otworzyć vault.<sup>[[14]](#references)</sup>

### Znajdowanie kontrolerów DataVault
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
### Scenariusze ataku

#### Bezpośrednia modyfikacja bazy danych TCC (oddzielna granica TCC)

Jeśli atakujący przejmie proces zarządzający TCC (np. poprzez code injection do procesu posiadającego `com.apple.private.tcc.manager`), może **bezpośrednio zmodyfikować bazę danych TCC**, aby przyznać dowolnej aplikacji dowolne uprawnienie TCC:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Modyfikacja bazy danych TCC to **ostateczne obejście ochrony prywatności** — przyznaje dowolne uprawnienie po cichu, bez monitu użytkownika ani widocznego wskaźnika. Historycznie wiele łańcuchów eskalacji uprawnień w macOS kończyło się zapisem do bazy danych TCC jako końcowym payloadem.

#### Dostęp do bazy danych Keychain

Surowy dostęp do bazowej bazy danych keychain nie jest równoznaczny z dostępem do sekretów w postaci plaintextu. Jeśli inna granica uprawnień pozwala atakującemu skopiować bazę danych, nadal trzeba zaatakować materiał kluczowy i ACL elementów; zobacz dedykowaną stronę [macOS Keychain](../../macos-red-teaming/macos-keychain.md), zamiast zakładać, że entitlement kontrolera DataVault jest wystarczający.

#### Granica kopii zapasowej: Time Machine

Analiza z 2026 roku wykazała przydatny ogólny wzorzec: `backupd` posiada zarówno `com.apple.rootless.datavault.controller`, jak i Full Disk Access, dzięki czemu może kopiować chronione magazyny. W testowanej konfiguracji `/private/var/folders` było uwzględnione w Time Machine, a zamontowana kopia zapasowa nie egzekwowała granicy DataVault obowiązującej dla aktywnego systemu. Badacz wykorzystał to do zlokalizowania magazynu SQLite Screen Time i odczytania jego kodu PIN ograniczeń w plaintext, bez otwierania aktywnego vaultu. Traktuj to jako **atak na granicę kopii**: wyliczaj deputy odpowiedzialne za backup, eksport, migrację, indeksowanie i diagnostykę, które mogą materializować dane vaultu w ramach słabszego montowania lub pod słabszą ścieżką.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
To zachowanie zależy od wersji i układu kopii zapasowych. Zweryfikuj je w docelowej kompilacji i pamiętaj, że zaszyfrowane miejsce docelowe Time Machine chroni kopię tylko wtedy, gdy jest zablokowane; po zamontowaniu jego mechanizmy kontroli dostępu stają się częścią attack surface.

### Rzeczywiste CVE obejmujące DataVault/TCC Bypass

| CVE | Opis |
|---|---|
| CVE-2024-44131 | Wyścig symlinków w FileProvider umożliwiający uprzywilejowanemu helperowi dostęp do danych chronionych przez TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Jako root **utworzenie nowego użytkownika, którego `NFSHomeDirectory` wskazuje na kontrolowany przez attackera `TCC.db`**; podczas logowania `tccd` wykorzystuje ten plik, a uprawnienia zostają zastosowane, umożliwiając dostęp do danych innych użytkowników ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | „powerdir”: zmiana katalogu domowego użytkownika w celu umieszczenia kontrolowanego przez attackera TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Błąd w konkluzji bundle'a umożliwiający aplikacji **odziedziczenie uprawnień TCC donor bundle'a** bez monitu; wykorzystany w środowisku naturalnym przez **XCSSET** do wykonywania zrzutów ekranu pulpitu ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` tworzył ścieżkę do DB na podstawie `$HOME`, więc `launchctl setenv HOME` przekierowywało ją do kontrolowanego przez attackera `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` posiadał **`com.apple.private.tcc.manager`** i miał wyłączoną walidację bibliotek, więc wtyczka HAL umieszczona w `/Library/Audio/Plug-Ins/HAL` mogła przyznać dowolne uprawnienia TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft znajduje nową lukę w macOS, Shrootless, która mogła ominąć System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Analiza techniczna: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Ochrona danych](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass wykrada dane z iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Odkrywanie malware w macOS: omijanie TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nowa luka w macOS, „powerdir”, mogła prowadzić do nieautoryzowanego dostępu do danych użytkownika](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Ominięcie TCC typu zero-day odkryte w malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Omijanie frameworka Transparency, Consent, and Control (TCC) w macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Odtwarzaj muzykę i omiń TCC, czyli CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Koszmar aktualizacji OTA Apple (migawki APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Eksploatacja TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Jak ominąć własny kod Screen Time — analiza źródła oraz Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
