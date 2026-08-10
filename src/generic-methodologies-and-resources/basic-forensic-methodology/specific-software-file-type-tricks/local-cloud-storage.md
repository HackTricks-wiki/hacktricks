# Lokalna pamięć masowa Cloud

## OneDrive

W Windows folder OneDrive można znaleźć w `\Users\<username>\AppData\Local\Microsoft\OneDrive`. W folderze `logs\Personal` można znaleźć plik `SyncDiagnostics.log`, który zawiera interesujące dane dotyczące zsynchronizowanych plików:<sup>[[3]](#references)</sup>

- Rozmiar w bajtach
- Data utworzenia
- Data modyfikacji
- Liczba plików w cloud
- Liczba plików w folderze
- **CID**: Unikalny identyfikator użytkownika OneDrive
- Czas wygenerowania raportu
- Rozmiar dysku HD systemu operacyjnego

Po znalezieniu identyfikatora CID zaleca się **wyszukanie plików zawierających ten identyfikator**. Możliwe, że uda się znaleźć pliki o nazwach: _**\<CID>.ini**_ i _**\<CID>.dat**_, które mogą zawierać interesujące informacje, takie jak nazwy plików zsynchronizowanych z OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

W Windows główny folder Google Drive można znaleźć w `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ten folder zawiera plik o nazwie Sync_log.log, który rejestruje sesje synchronizacji klienta Google Drive oraz zdarzenia tworzenia, modyfikowania i usuwania plików.<sup>[[4]](#references)[[6]](#references)</sup>

Plik **`Cloud_graph\Cloud_graph.db`** jest bazą danych sqlite.<sup>[[6]](#references)</sup> Zawiera tabelę **`cloud_graph_entry`**. W tej tabeli można znaleźć **nazwy** **zsynchronizowanych** **plików**, czas modyfikacji, rozmiar oraz sumę kontrolną MD5 plików.

Tabela **`cloud_entry`** powiązanej bazy danych **`snapshot.db`** może przechowywać usunięte rekordy wraz z nazwami plików, znacznikami czasu, rozmiarami i sumami kontrolnymi.<sup>[[4]](#references)</sup>

Dane tabeli bazy danych **`Sync_config.db`** zawierają adres email konta, ścieżkę folderów udostępnionych oraz wersję Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox używa **baz danych SQLite** do zarządzania plikami.<sup>[[2]](#references)</sup> W tym\
bazę danych można znaleźć w folderach:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Główne bazy danych to:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Rozszerzenie ".dbx" oznacza, że **bazy danych** są **zaszyfrowane**. Dropbox używa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Aby lepiej zrozumieć szyfrowanie używane przez Dropbox, można przeczytać [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Najważniejsze informacje to:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Oprócz tych informacji do odszyfrowania baz danych nadal potrzebne są:<sup>[[2]](#references)</sup>

- **Zaszyfrowany klucz DPAPI**: Można go znaleźć w rejestrze w `NTUSER.DAT\Software\Dropbox\ks\client` (wyeksportuj te dane jako binarne)
- Ule **`SYSTEM`** i **`SECURITY`**
- **Klucze główne DPAPI**: Można je znaleźć w `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Nazwa użytkownika** i **hasło** użytkownika Windows

Następnie można użyć narzędzia [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Następnie można użyć narzędzia DataProtectionDecryptor](<../../../images/image (443).png>)

Jeśli wszystko przebiegnie zgodnie z oczekiwaniami, narzędzie wskaże **klucz główny**, którego należy **użyć do odzyskania oryginalnego klucza**. Aby odzyskać oryginalny klucz, wystarczy użyć tej [receptury cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) i wprowadzić klucz główny jako "passphrase" w recepturze.

Wynikowy hex to końcowy klucz używany do szyfrowania baz danych, które można odszyfrować za pomocą:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Baza danych **`config.dbx`** zawiera:

- **Email**: Adres email użytkownika
- **usernamedisplayname**: Nazwa użytkownika
- **dropbox_path**: Ścieżka, w której znajduje się folder Dropbox
- **Host_id: Hash** używany do uwierzytelniania w cloud. Można go unieważnić wyłącznie z poziomu web.
- **Root_ns**: Identyfikator użytkownika

Baza danych **`filecache.db`** zawiera informacje o wszystkich plikach i folderach synchronizowanych z Dropbox. Tabela `File_journal` zawiera najbardziej przydatne informacje:<sup>[[5]](#references)</sup>

- **Server_path**: Ścieżka, pod którą plik znajduje się na serwerze (ścieżka ta jest poprzedzona wartością `host_id` klienta).
- **local_sjid**: Wersja pliku
- **local_mtime**: Data modyfikacji
- **local_ctime**: Data utworzenia

Inne tabele w tej bazie danych zawierają dodatkowe interesujące informacje:

- **block_cache**: Hash wszystkich plików i folderów Dropbox
- **block_ref**: Łączy hash ID tabeli `block_cache` z ID pliku w tabeli `file_journal`
- **mount_table**: Udostępnione foldery Dropbox
- **deleted_fields**: Usunięte pliki Dropbox
- **date_added**

## References

- [1] [Krytyczna analiza bezpieczeństwa software Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Odświeżenie wiedzy na temat deszyfrowania Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Analiza śledcza Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Przypadek wycieku danych NIST CFReDS: Odpowiedzi dotyczące wycieku](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Analiza śledcza Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Ślady użytkowania Google Drive w Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
