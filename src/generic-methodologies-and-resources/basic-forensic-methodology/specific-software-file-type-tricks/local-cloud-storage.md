# Lokalno Cloud skladište

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

U Windows-u, OneDrive folder možete pronaći na lokaciji `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Unutar foldera `logs\Personal` moguće je pronaći fajl `SyncDiagnostics.log`, koji sadrži zanimljive podatke o sinhronizovanim fajlovima:<sup>[[3]](#references)</sup>

- Veličina u bajtovima
- Datum kreiranja
- Datum izmene
- Broj fajlova u cloud-u
- Broj fajlova u folderu
- **CID**: Jedinstveni ID OneDrive korisnika
- Vreme generisanja izveštaja
- Veličina HD-a operativnog sistema

Kada pronađete CID, preporučuje se da **pretražite fajlove koji sadrže ovaj ID**. Možda ćete pronaći fajlove sa imenima: _**\<CID>.ini**_ i _**\<CID>.dat**_, koji mogu sadržati zanimljive informacije, kao što su imena fajlova sinhronizovanih sa OneDrive-om.<sup>[[3]](#references)</sup>

## Google Drive

U Windows-u, glavni Google Drive folder možete pronaći na lokaciji `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ovaj folder sadrži fajl pod nazivom Sync_log.log, koji beleži sesije sinhronizacije Google Drive klijenta, kao i događaje kreiranja, izmene i brisanja fajlova.<sup>[[4]](#references)[[6]](#references)</sup>

Fajl **`Cloud_graph\Cloud_graph.db`** je sqlite baza podataka.<sup>[[6]](#references)</sup> Sadrži tabelu **`cloud_graph_entry`**. U ovoj tabeli možete pronaći **naziv** **sinhronizovanih** **fajlova**, vreme izmene, veličinu i MD5 checksum fajlova.

Tabela **`cloud_entry`** povezane baze **`snapshot.db`** može zadržati uklonjene zapise sa imenima fajlova, vremenskim oznakama, veličinama i checksum-ovima.<sup>[[4]](#references)</sup>

Podaci tabele baze **`Sync_config.db`** sadrže email adresu naloga, putanju deljenih foldera i verziju Google Drive-a.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox koristi **SQLite baze podataka** za upravljanje fajlovima.<sup>[[2]](#references)</sup> U ovom\
folderu možete pronaći baze podataka:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Glavne baze podataka su:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Ekstenzija ".dbx" znači da su **baze podataka** **šifrovane**. Dropbox koristi **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Da biste bolje razumeli šifrovanje koje Dropbox koristi, možete pročitati [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Međutim, najvažnije informacije su:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Pored ovih informacija, za dešifrovanje baza podataka i dalje su vam potrebni:<sup>[[2]](#references)</sup>

- **Šifrovani DPAPI ključ**: Možete ga pronaći u registru, unutar `NTUSER.DAT\Software\Dropbox\ks\client` (izvezite ove podatke kao binarne)
- Hive-ovi **`SYSTEM`** i **`SECURITY`**
- **DPAPI master ključevi**: Mogu se pronaći na lokaciji `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Username** i **password** Windows korisnika

Zatim možete koristiti alat [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Zatim možete koristiti alat DataProtectionDecryptor](<../../../images/image (443).png>)

Ako sve prođe očekivano, alat će prikazati **primary key** koji treba da **upotrebite za oporavak originalnog ključa**. Da biste oporavili originalni ključ, samo upotrebite ovaj [cyber_chef recept](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) tako što ćete primary key uneti kao "passphrase" unutar recepta.

Dobijeni hex je finalni ključ koji se koristi za šifrovanje baza podataka, a koji se može dešifrovati pomoću:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Baza podataka **`config.dbx`** sadrži:

- **Email**: Email korisnika
- **usernamedisplayname**: Ime korisnika
- **dropbox_path**: Putanja do lokacije Dropbox foldera
- **Host_id: Hash** koji se koristi za autentifikaciju na cloud. Ovo se može opozvati samo sa weba.
- **Root_ns**: Identifikator korisnika

Baza podataka **`filecache.db`** sadrži informacije o svim fajlovima i folderima sinhronizovanim sa Dropbox-om. Tabela `File_journal` sadrži najkorisnije informacije:<sup>[[5]](#references)</sup>

- **Server_path**: Putanja do lokacije fajla na serveru (ovoj putanji prethodi `host_id` klijenta).
- **local_sjid**: Verzija fajla
- **local_mtime**: Datum izmene
- **local_ctime**: Datum kreiranja

Druge tabele unutar ove baze podataka sadrže dodatne zanimljive informacije:

- **block_cache**: Hash svih fajlova i foldera Dropbox-a
- **block_ref**: Povezuje hash ID tabele `block_cache` sa ID-jem fajla u tabeli `file_journal`
- **mount_table**: Deljeni folderi Dropbox-a
- **deleted_fields**: Obrisani fajlovi Dropbox-a
- **date_added**

## References

- [1] [Kritička analiza bezbednosti Dropbox softvera (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Obnavljanje znanja o Dropbox DBX dešifrovanju](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Forenzička analiza Cloud Storage-a (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS slučaj curenja podataka: odgovori o curenju](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox forenzika](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefakti korišćenja Google Drive-a u Windows-u](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
