# Lokalna Chmura

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

W systemie Windows folder OneDrive można znaleźć w `\Users\<username>\AppData\Local\Microsoft\OneDrive`. A wewnątrz `logs\Personal` można znaleźć plik `SyncDiagnostics.log`, który zawiera interesujące dane dotyczące zsynchronizowanych plików:

- Rozmiar w bajtach
- Data utworzenia
- Data modyfikacji
- Liczba plików w chmurze
- Liczba plików w folderze
- **CID**: Unikalny identyfikator użytkownika OneDrive
- Czas generowania raportu
- Rozmiar dysku twardego systemu operacyjnego

Po znalezieniu CID zaleca się **wyszukiwanie plików zawierających ten identyfikator**. Możesz znaleźć pliki o nazwach: _**\<CID>.ini**_ i _**\<CID>.dat**_, które mogą zawierać interesujące informacje, takie jak nazwy plików zsynchronizowanych z OneDrive.

## Google Drive

W systemie Windows główny folder Google Drive można znaleźć w `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ten folder zawiera plik o nazwie Sync_log.log z informacjami takimi jak adres e-mail konta, nazwy plików, znaczniki czasu, hashe MD5 plików itp. Nawet usunięte pliki pojawiają się w tym pliku dziennika z odpowiadającym im MD5.

Plik **`Cloud_graph\Cloud_graph.db`** to baza danych sqlite, która zawiera tabelę **`cloud_graph_entry`**. W tej tabeli można znaleźć **nazwę** **zsynchronizowanych** **plików**, czas modyfikacji, rozmiar i sumę kontrolną MD5 plików.

Dane tabeli bazy danych **`Sync_config.db`** zawierają adres e-mail konta, ścieżkę do udostępnionych folderów oraz wersję Google Drive.

## Dropbox

Dropbox używa **baz danych SQLite** do zarządzania plikami. W tym\
Można znaleźć bazy danych w folderach:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

A główne bazy danych to:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Rozszerzenie ".dbx" oznacza, że **bazy danych** są **szyfrowane**. Dropbox używa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Aby lepiej zrozumieć szyfrowanie, które stosuje Dropbox, możesz przeczytać [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Jednak główne informacje to:

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Sól**: 0D638C092E8B82FC452883F95F355B8E
- **Algorytm**: PBKDF2
- **Iteracje**: 1066

Oprócz tych informacji, aby odszyfrować bazy danych, potrzebujesz jeszcze:

- **szyfrowanego klucza DPAPI**: Można go znaleźć w rejestrze w `NTUSER.DAT\Software\Dropbox\ks\client` (wyeksportuj te dane jako binarne)
- **hive'ów `SYSTEM`** i **`SECURITY`**
- **głównych kluczy DPAPI**: Które można znaleźć w `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **nazwa użytkownika** i **hasło** użytkownika systemu Windows

Następnie możesz użyć narzędzia [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (448).png>)

Jeśli wszystko pójdzie zgodnie z oczekiwaniami, narzędzie wskaże **klucz główny**, który musisz **użyć, aby odzyskać oryginalny**. Aby odzyskać oryginalny klucz, wystarczy użyć tego [przepisu cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) wstawiając klucz główny jako "hasło" w przepisie.

Ostateczny hex to klucz użyty do szyfrowania baz danych, który można odszyfrować za pomocą:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Baza danych **`config.dbx`** zawiera:

- **Email**: Email użytkownika
- **usernamedisplayname**: Nazwa użytkownika
- **dropbox_path**: Ścieżka, w której znajduje się folder dropbox
- **Host_id: Hash** używany do uwierzytelniania w chmurze. Może być odwołany tylko z poziomu sieci.
- **Root_ns**: Identyfikator użytkownika

Baza danych **`filecache.db`** zawiera informacje o wszystkich plikach i folderach zsynchronizowanych z Dropbox. Tabela `File_journal` zawiera najwięcej przydatnych informacji:

- **Server_path**: Ścieżka, w której plik znajduje się na serwerze (ta ścieżka jest poprzedzona `host_id` klienta).
- **local_sjid**: Wersja pliku
- **local_mtime**: Data modyfikacji
- **local_ctime**: Data utworzenia

Inne tabele w tej bazie danych zawierają bardziej interesujące informacje:

- **block_cache**: hash wszystkich plików i folderów Dropbox
- **block_ref**: Powiązanie identyfikatora hash z tabeli `block_cache` z identyfikatorem pliku w tabeli `file_journal`
- **mount_table**: Udostępnione foldery Dropbox
- **deleted_fields**: Usunięte pliki Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
