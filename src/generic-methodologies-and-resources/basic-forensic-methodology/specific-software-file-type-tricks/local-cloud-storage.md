# Lokalna pamięć masowa w chmurze

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

W systemie Windows folder OneDrive można znaleźć w `\Users\<username>\AppData\Local\Microsoft\OneDrive`. W folderze `logs\Personal` można znaleźć plik `SyncDiagnostics.log`, który zawiera interesujące dane dotyczące synchronizowanych plików:

- Rozmiar w bajtach
- Data utworzenia
- Data modyfikacji
- Liczba plików w chmurze
- Liczba plików w folderze
- **CID**: Unikalny identyfikator użytkownika OneDrive
- Czas wygenerowania raportu
- Rozmiar dysku HD systemu operacyjnego

Po znalezieniu CID zaleca się **wyszukanie plików zawierających ten identyfikator**. Możliwe, że znajdziesz pliki o nazwach: _**\<CID>.ini**_ i _**\<CID>.dat**_, które mogą zawierać interesujące informacje, takie jak nazwy plików synchronizowanych z OneDrive.

## Google Drive

W systemie Windows główny folder Google Drive można znaleźć w `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Folder ten zawiera plik o nazwie Sync_log.log z informacjami takimi jak adres e-mail konta, nazwy plików, znaczniki czasu, skróty MD5 plików itd. Nawet usunięte pliki pojawiają się w tym pliku dziennika wraz z odpowiadającymi im skrótami MD5.

Plik **`Cloud_graph\Cloud_graph.db`** to baza danych sqlite zawierająca tabelę **`cloud_graph_entry`**. W tej tabeli można znaleźć **nazwy** **synchronizowanych** **plików**, czas modyfikacji, rozmiar oraz sumę kontrolną MD5 plików.

Dane tabeli bazy danych **`Sync_config.db`** zawierają adres e-mail konta, ścieżkę udostępnionych folderów oraz wersję Google Drive.

## Dropbox

Dropbox używa **baz danych SQLite** do zarządzania plikami. W tym\
bazę danych można znaleźć w folderach:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Główne bazy danych to:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Rozszerzenie „.dbx” oznacza, że **bazy danych** są **zaszyfrowane**. Dropbox używa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Aby lepiej zrozumieć szyfrowanie używane przez Dropbox, możesz przeczytać [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Najważniejsze informacje to:<sup>[[1]](#references)</sup>

- **Entropia**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorytm**: PBKDF2
- **Liczba iteracji**: 1066

Poza tymi informacjami do odszyfrowania baz danych nadal potrzebujesz:<sup>[[2]](#references)</sup>

- **Zaszyfrowany klucz DPAPI**: Można go znaleźć w rejestrze w `NTUSER.DAT\Software\Dropbox\ks\client` (wyeksportuj te dane jako dane binarne)
- Uli **`SYSTEM`** i **`SECURITY`**
- **Klucze główne DPAPI**: Można je znaleźć w `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Nazwę użytkownika** i **hasło** użytkownika Windows

Następnie możesz użyć narzędzia [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Następnie możesz użyć narzędzia DataProtectionDecryptor](<../../../images/image (443).png>)

Jeśli wszystko przebiegnie zgodnie z oczekiwaniami, narzędzie wskaże **klucz główny**, którego należy **użyć do odzyskania oryginalnego klucza**. Aby odzyskać oryginalny klucz, użyj tego [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)>, wprowadzając klucz główny jako „passphrase” w receipt.

Wynikowy ciąg hex to końcowy klucz używany do szyfrowania baz danych, które można odszyfrować za pomocą:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Baza danych **`config.dbx`** zawiera:

- **Email**: Adres email użytkownika
- **usernamedisplayname**: Nazwa użytkownika
- **dropbox_path**: Ścieżka, w której znajduje się folder Dropbox
- **Host_id: Hash** używany do uwierzytelniania w cloud. Można go unieważnić tylko z poziomu web.
- **Root_ns**: Identyfikator użytkownika

Baza danych **`filecache.db`** zawiera informacje o wszystkich plikach i folderach synchronizowanych z Dropbox. Tabela `File_journal` zawiera najbardziej przydatne informacje:

- **Server_path**: Ścieżka, pod którą plik znajduje się na serwerze (przed tą ścieżką znajduje się `host_id` klienta).
- **local_sjid**: Wersja pliku
- **local_mtime**: Data modyfikacji
- **local_ctime**: Data utworzenia

Inne tabele w tej bazie danych zawierają bardziej interesujące informacje:

- **block_cache**: Hash wszystkich plików i folderów Dropbox
- **block_ref**: Łączy ID Hash z tabeli `block_cache` z ID pliku w tabeli `file_journal`
- **mount_table**: Udostępnione foldery Dropbox
- **deleted_fields**: Usunięte pliki Dropbox
- **date_added**

## Referencje

- [1] [Krytyczna analiza bezpieczeństwa oprogramowania Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Odświeżenie wiedzy na temat deszyfrowania Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
