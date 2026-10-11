# Lokalny magazyn w chmurze

{{#include ../../../banners/hacktricks-training.md}}

## Lokalne emulatory magazynu i klucze kont

Emulator Blob zgodny z Azure, działający w kontenerze, może być dostępny z hosta lub sieci mostkowej, nawet jeśli usługa magazynu nie jest wystawiona na zewnątrz. Sprawdź czytelne lokalne pliki konfiguracyjne i metadane plików kopii zapasowych pod kątem nazwy konta i klucza, ale nie wyświetlaj klucza podczas rutynowego przeglądu. [Azurite obsługuje niestandardowe lokalne klucze kont](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [autoryzacja Shared Key](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) może zapewnić szeroki dostęp do danych powiązanych z danym kontem. Sam plik klucza nie potwierdza możliwości eskalacji: sprawdź, czy endpoint jest osiągalny, konto i klucz są akceptowane oraz czy konkretny blob faktycznie zawiera użyteczne dane uwierzytelniające tożsamości o wyższych uprawnieniach. Jeśli zawiera prywatny klucz SSH, odpowiedni klucz publiczny musi być również autoryzowany dla tej tożsamości, a dostęp SSH musi być dozwolony. Po potwierdzeniu ujawnienia zabezpiecz klucz i zmień go.

## OneDrive

W systemie Windows folder OneDrive znajduje się w `\Users\<username>\AppData\Local\Microsoft\OneDrive`. W folderze `logs\Personal` można znaleźć plik `SyncDiagnostics.log`, który zawiera interesujące dane dotyczące synchronizowanych plików:<sup>[[3]](#references)</sup>

- Rozmiar w bajtach
- Data utworzenia
- Data modyfikacji
- Liczba plików w chmurze
- Liczba plików w folderze
- **CID**: unikatowy identyfikator użytkownika OneDrive
- Czas wygenerowania raportu
- Rozmiar dysku HD systemu operacyjnego

Po znalezieniu CID zaleca się **wyszukanie plików zawierających ten identyfikator**. Możesz znaleźć pliki o nazwach _**\<CID>.ini**_ i _**\<CID>.dat**_, które mogą zawierać interesujące informacje, takie jak nazwy plików synchronizowanych z OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

W systemie Windows główny folder Google Drive znajduje się w `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ten folder zawiera plik Sync_log.log, w którym rejestrowane są sesje synchronizacji klienta Google Drive oraz zdarzenia tworzenia, modyfikacji i usuwania plików.<sup>[[4]](#references)[[6]](#references)</sup>

Plik **`Cloud_graph\Cloud_graph.db`** to baza danych sqlite.<sup>[[6]](#references)</sup> Zawiera tabelę **`cloud_graph_entry`**. W tej tabeli można znaleźć **nazwy** **synchronizowanych** **plików**, czas modyfikacji, rozmiar i sumę kontrolną MD5 plików.

Powiązana baza danych **`snapshot.db`**, a konkretnie jej tabela **`cloud_entry`**, może zachowywać usunięte wpisy z nazwami plików, znacznikami czasu, rozmiarami i sumami kontrolnymi.<sup>[[4]](#references)</sup>

Dane w tabeli bazy danych **`Sync_config.db`** zawierają adres e-mail konta, ścieżkę do udostępnionych folderów i wersję Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox używa **baz danych SQLite** do zarządzania plikami.<sup>[[2]](#references)</sup> W tym\
baz danych można szukać w folderach:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Główne bazy danych to:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Rozszerzenie „.dbx” oznacza, że **bazy danych** są **zaszyfrowane**. Dropbox używa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Aby lepiej zrozumieć szyfrowanie używane przez Dropbox, przeczytaj [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Najważniejsze informacje to:<sup>[[1]](#references)</sup>

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorytm**: PBKDF2
- **Liczba iteracji**: 1066

Oprócz tych informacji do odszyfrowania baz danych nadal potrzebujesz:<sup>[[2]](#references)</sup>

- **Zaszyfrowanego klucza DPAPI**: można go znaleźć w rejestrze pod `NTUSER.DAT\Software\Dropbox\ks\client` (wyeksportuj te dane w formacie binarnym)
- Gałęzi **`SYSTEM`** i **`SECURITY`**
- **Kluczy głównych DPAPI**: można je znaleźć w `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Nazwy użytkownika** i **hasła** użytkownika Windows

Następnie możesz użyć narzędzia [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Następnie możesz użyć narzędzia DataProtectionDecryptor](<../../../images/image (443).png>)

Jeśli wszystko pójdzie zgodnie z oczekiwaniami, narzędzie wskaże **klucz główny**, którego należy **użyć do odzyskania oryginalnego klucza**. Aby odzyskać oryginalny klucz, użyj tego [przepisu CyberChef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) i wstaw klucz główny jako „passphrase” w przepisie.

Uzyskany ciąg hex to ostateczny klucz używany do szyfrowania baz danych. Można je odszyfrować za pomocą:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

Baza danych **`config.dbx`** zawiera:

- **Email**: Adres e-mail użytkownika
- **usernamedisplayname**: Nazwa użytkownika
- **dropbox_path**: Ścieżka do folderu Dropbox
- **Host_id: Hash** używany do uwierzytelniania w chmurze. Można go unieważnić tylko w witrynie internetowej.
- **Root_ns**: Identyfikator użytkownika

Baza danych **`filecache.db`** zawiera informacje o wszystkich plikach i folderach synchronizowanych z Dropbox. Tabela `File_journal` zawiera najwięcej przydatnych informacji:<sup>[[5]](#references)</sup>

- **Server_path**: Ścieżka pliku na serwerze (jest poprzedzona wartością `host_id` klienta).
- **local_sjid**: Wersja pliku
- **local_mtime**: Data modyfikacji
- **local_ctime**: Data utworzenia

Pozostałe tabele w tej bazie danych zawierają więcej interesujących informacji:

- **block_cache**: Hashe wszystkich plików i folderów Dropbox
- **block_ref**: Łączy identyfikator hash z tabeli `block_cache` z identyfikatorem pliku w tabeli `file_journal`
- **mount_table**: Udostępnione foldery Dropbox
- **deleted_fields**: Usunięte pliki Dropbox
- **date_added**

## References

- [1] [Krytyczna analiza bezpieczeństwa oprogramowania Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Odświeżenie wiedzy o deszyfrowaniu DBX Dropbox](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Analiza kryminalistyczna pamięci masowej w chmurze (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Przypadek wycieku danych NIST CFReDS: odpowiedzi dotyczące wycieku](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Analiza kryminalistyczna Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefakty używania Google Drive w systemie Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
