# Granice zaufania w automatycznych aktualizacjach Electron

{{#include ../../banners/hacktricks-training.md}}

## Powierzchnia ataku automatycznych aktualizacji Electron

Traktuj aktualizator jako granicę zdalnego wykonania kodu: pobiera on wykonywalną zawartość, decyduje, czy ta zawartość jest nowsza i zaufana, przygotowuje ją lokalnie i przekazuje instalatorowi. Przeanalizuj cały graf zaufania — indeks wydań, metadane poszczególnych wersji, artefakt, podpisy odłączone, osadzony klucz weryfikacyjny, cache, ścieżkę tymczasową i instalator — a nie tylko to, czy końcowy plik `.app` jest podpisany.<sup>[[1]](#references)[[2]](#references)</sup>

### Testy o wysokiej wartości

- **Rollback/replay:** odtwórz wcześniej poprawny manifest i powiązany z nim artefakt z nadal ważnym podpisem. Podpis uwierzytelnia dane wejściowe, ale nie zapewnia ich aktualności; klient musi odrzucać wersje niższe od trwale zapisanego monotonicznego minimum, chyba że uwierzytelniona polityka odzyskiwania jawnie zezwala na rollback.<sup>[[2]](#references)</sup>
- **Podmiana metadanych/artefaktu:** niezależnie zmień wersję, URL, oczekiwany hash, artefakt i podpis odłączony. Spróbuj też połączyć poprawną parę artefakt/podpis z jednego wydania z metadanymi innego. Jeśli metadane wydania nie są podpisane, TLS ani podpisany plik wykonywalny nie powstrzymają zaatakowanego originu/CDN przed zmianą logiki wyboru.<sup>[[1]](#references)[[2]](#references)</sup>
- **Pomylenie kanałów podpisanych kompilacji:** udostępnij w produkcyjnym feedzie poprawnie podpisaną kompilację alpha, beta, development lub debug. Ponowne użycie tego samego klucza i polityki w różnych środowiskach pozwala artefaktowi przejść kontrolę opartą wyłącznie na signerze; tożsamość/kanał produkcyjny muszą być częścią uwierzytelnionej polityki albo należy użyć oddzielnego root of trust.<sup>[[2]](#references)</sup>
- **TOCTOU pliku tymczasowego:** ustal, czy weryfikacja otwiera ścieżkę, a instalacja później otwiera ją ponownie. Jeśli lokalny atakujący może zmienić nazwę, podmienić lub przekierować przygotowany obiekt między tymi operacjami, instalator może użyć bajtów, które nigdy nie zostały zweryfikowane. Katalog przygotowawczy z uprawnieniami `0700` ogranicza dostęp, ale nie zapewnia atomowości obu operacji.<sup>[[2]](#references)</sup>

Analiza statyczna i triage podczas działania mogą szybko wskazać te granice.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Podczas autoryzowanego testu przechwyć sprawdzanie dostępności aktualizacji, archiwizuj każdą odpowiedź i modyfikuj po jednym polu naraz. Następnie sprawdź właściciela i uprawnienia katalogu stagingowego oraz śledź otwieranie plików od pobrania do instalacji. W systemie macOS kontynuuj testowanie granicy zaufania instalatora [installer trust-boundary testing](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md), jeśli przepływ dociera do uprzywilejowanego helpera, i przeanalizuj [code-signing weaknesses](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md), zamiast traktować „podpisano” jako pełną weryfikację tożsamości.<sup>[[2]](#references)</sup>

### Oczekiwane powiązanie i zasady

Możliwy do obrony projekt uwierzytelnia zarówno metadane wyboru, jak i bajty artefaktu. Referencyjny projekt SafeUpdater pokazuje osadzony klucz publiczny Ed25519, podpisane manifesty i artefakty, podpisaną wiadomość utworzoną na podstawie `SHA-256(file)` oraz wersji, a także skrót artefaktu SHA-512 zapisany w podpisanych metadanych; jest to wyraźnie referencyjne rozwiązanie badawcze, a nie pakiet gotowy do użycia produkcyjnego.<sup>[[1]](#references)[[2]](#references)</sup>

Sprawdź, czy rozwiązanie docelowe zapewnia dodatkowo następujące właściwości.<sup>[[1]](#references)[[2]](#references)</sup>

- używa jednoznacznej, podpisanej reprezentacji, która wiąże skrót artefaktu z jego kanoniczną wersją i środowiskiem wydania;
- domyślnie wyłącza downgrade i wymusza minimalną akceptowaną wersję przy autoryzowanym rollbacku;
- rozdziela produkcję od środowisk nieprodukcyjnych za pomocą odrębnych kluczy/kanałów lub uwierzytelnionych danych zasad wydania; oraz
- instaluje już zweryfikowany otwarty plik (lub równoważny niezmienny uchwyt/obiekt), zamiast ponownie rozwiązywać tę samą ścieżkę.

## References

- [1] [Implementacja referencyjna Doyensec ElectronSafeUpdater](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: projektowanie bezpiecznego mechanizmu automatycznych aktualizacji Electron](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
