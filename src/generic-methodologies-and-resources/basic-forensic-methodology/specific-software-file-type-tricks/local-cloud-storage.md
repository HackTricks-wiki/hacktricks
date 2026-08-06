# Lokalno cloud skladište

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

U Windows-u, OneDrive folder možete pronaći na putanji `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Unutar foldera `logs\Personal` moguće je pronaći fajl `SyncDiagnostics.log`, koji sadrži neke zanimljive podatke o sinhronizovanim fajlovima:

- Veličina u bajtovima
- Datum kreiranja
- Datum izmene
- Broj fajlova u cloud-u
- Broj fajlova u folderu
- **CID**: Jedinstveni ID OneDrive korisnika
- Vreme generisanja izveštaja
- Veličina HD-a operativnog sistema

Kada pronađete CID, preporučuje se da **pretražite fajlove koji sadrže ovaj ID**. Možda ćete pronaći fajlove sa imenima: _**\<CID>.ini**_ i _**\<CID>.dat**_, koji mogu sadržati zanimljive informacije, kao što su imena fajlova sinhronizovanih sa OneDrive-om.

## Google Drive

U Windows-u, glavni Google Drive folder možete pronaći na putanji `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ovaj folder sadrži fajl pod nazivom Sync_log.log, sa informacijama kao što su email adresa naloga, imena fajlova, vremenske oznake, MD5 hash-evi fajlova itd. Čak se i obrisani fajlovi pojavljuju u ovom log fajlu sa odgovarajućim MD5 hash-om.

Fajl **`Cloud_graph\Cloud_graph.db`** je sqlite baza podataka koja sadrži tabelu **`cloud_graph_entry`**. U ovoj tabeli možete pronaći **imena** **sinhronizovanih** **fajlova**, vreme izmene, veličinu i MD5 checksum fajlova.

Podaci tabele baze podataka **`Sync_config.db`** sadrže email adresu naloga, putanju deljenih foldera i verziju Google Drive-a.

## Dropbox

Dropbox koristi **SQLite baze podataka** za upravljanje fajlovima. U ovom\
možete pronaći baze podataka u folderima:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Glavne baze podataka su:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Ekstenzija ".dbx" znači da su **baze podataka** **šifrovane**. Dropbox koristi **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Da biste bolje razumeli enkripciju koju Dropbox koristi, možete pročitati [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Međutim, glavne informacije su:<sup>[[1]](#references)</sup>

- **Entropija**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritam**: PBKDF2
- **Iteracije**: 1066

Pored ovih informacija, za dešifrovanje baza podataka i dalje su vam potrebni:<sup>[[2]](#references)</sup>

- **Šifrovani DPAPI ključ**: Možete ga pronaći u registru unutar `NTUSER.DAT\Software\Dropbox\ks\client` (izvezite ove podatke kao binarne)
- Hive-ovi **`SYSTEM`** i **`SECURITY`**
- **DPAPI master ključevi**: Mogu se pronaći na putanji `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Korisničko ime** i **lozinka** Windows korisnika

Zatim možete koristiti alat [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Zatim možete koristiti alat DataProtectionDecryptor](<../../../images/image (443).png>)

Ako sve prođe kako je očekivano, alat će prikazati **primarni ključ** koji treba da **upotrebite za oporavak originalnog ključa**. Da biste oporavili originalni ključ, samo upotrebite ovaj [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) tako što ćete primarni ključ uneti kao "passphrase" unutar receipt-a.

Dobijeni hex je konačni ključ koji se koristi za enkripciju baza podataka i koji se može dešifrovati pomoću:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Baza podataka **`config.dbx`** sadrži:

- **Email**: Email korisnika
- **usernamedisplayname**: Ime korisnika
- **dropbox_path**: Putanja do lokacije Dropbox foldera
- **Host_id: Hash** koji se koristi za autentifikaciju na cloud. Ovo se može opozvati samo sa weba.
- **Root_ns**: Identifikator korisnika

Baza podataka **`filecache.db`** sadrži informacije o svim fajlovima i folderima sinhronizovanim sa Dropbox-om. Tabela `File_journal` sadrži najkorisnije informacije:

- **Server_path**: Putanja do lokacije fajla na serveru (ovoj putanji prethodi `host_id` klijenta).
- **local_sjid**: Verzija fajla
- **local_mtime**: Datum izmene
- **local_ctime**: Datum kreiranja

Druge tabele unutar ove baze podataka sadrže još zanimljivije informacije:

- **block_cache**: hash svih fajlova i foldera Dropbox-a
- **block_ref**: Povezuje ID hash-a iz tabele `block_cache` sa ID-om fajla u tabeli `file_journal`
- **mount_table**: Deljeni folderi Dropbox-a
- **deleted_fields**: Obrisani Dropbox fajlovi
- **date_added**

## Reference

- [1] [Kritička analiza bezbednosti Dropbox softvera (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Obnovite znanje o DBX dešifrovanju u Dropbox-u](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
