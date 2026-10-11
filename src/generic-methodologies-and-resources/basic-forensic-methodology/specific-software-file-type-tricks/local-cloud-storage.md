# Lokalno skladište u oblaku

{{#include ../../../banners/hacktricks-training.md}}

## Lokalni emulatori skladišta i ključevi naloga

Azure-kompatibilan Blob emulator koji radi u kontejneru može biti dostupan sa hosta ili preko bridge mreže čak i kada servis za skladištenje nije izložen spolja. Pregledajte čitljive lokalne konfiguracije i metapodatke backup fajlova da biste pronašli ime naloga i ključ, ali nemojte ispisivati ključ tokom rutinske enumeracije. [Azurite podržava prilagođene ključeve lokalnih naloga](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key autorizacija](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) može omogućiti širok pristup podacima odgovarajućeg naloga. Sam fajl sa ključem ne potvrđuje eskalaciju: proverite da li je endpoint dostupan, da li su nalog i ključ prihvaćeni i da li konkretni blob zaista sadrži upotrebljiv credential za identitet sa višim privilegijama. Ako sadrži SSH privatni ključ, odgovarajući javni ključ takođe mora biti autorizovan za taj identitet, a SSH pristup mora biti dozvoljen. Zaštitite i rotirajte ključ kada potvrdite da je izložen.

## OneDrive

U Windowsu se OneDrive fascikla nalazi u `\Users\<username>\AppData\Local\Microsoft\OneDrive`. U fascikli `logs\Personal` može se pronaći fajl `SyncDiagnostics.log`, koji sadrži zanimljive podatke o sinhronizovanim fajlovima:<sup>[[3]](#references)</sup>

- Veličina u bajtovima
- Datum kreiranja
- Datum izmene
- Broj fajlova u oblaku
- Broj fajlova u fascikli
- **CID**: Jedinstveni ID OneDrive korisnika
- Vreme generisanja izveštaja
- Veličina HD-a operativnog sistema

Kada pronađete CID, preporučuje se da **pretražite fajlove koji sadrže ovaj ID**. Možda ćete pronaći fajlove pod nazivima _**\<CID>.ini**_ i _**\<CID>.dat**_, koji mogu sadržati zanimljive informacije, kao što su nazivi fajlova sinhronizovanih sa OneDrive-om.<sup>[[3]](#references)</sup>

## Google Drive

U Windowsu se glavna Google Drive fascikla nalazi u `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ova fascikla sadrži fajl pod nazivom Sync_log.log, koji beleži sesije sinhronizacije Google Drive klijenta i događaje kreiranja, izmene i brisanja fajlova.<sup>[[4]](#references)[[6]](#references)</sup>

Fajl **`Cloud_graph\Cloud_graph.db`** je sqlite baza podataka.<sup>[[6]](#references)</sup> Sadrži tabelu **`cloud_graph_entry`**. U ovoj tabeli možete pronaći **nazive** **sinhronizovanih** **fajlova**, vreme izmene, veličinu i MD5 checksum fajlova.

Povezana baza podataka **`snapshot.db`** može u tabeli **`cloud_entry`** zadržati obrisane zapise sa imenima fajlova, vremenskim oznakama, veličinama i checksum vrednostima.<sup>[[4]](#references)</sup>

Podaci u tabeli baze **`Sync_config.db`** sadrže adresu e-pošte naloga, putanju do deljenih fascikli i verziju Google Drive-a.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox koristi **SQLite baze podataka** za upravljanje fajlovima.<sup>[[2]](#references)</sup> U ovom slučaju, baze podataka možete pronaći u fasciklama:

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

- **Entropija**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritam**: PBKDF2
- **Broj iteracija**: 1066

Pored tih informacija, za dešifrovanje baza podataka i dalje su vam potrebni:<sup>[[2]](#references)</sup>

- **Šifrovani DPAPI ključ**: Možete ga pronaći u registru na lokaciji `NTUSER.DAT\Software\Dropbox\ks\client` (izvezite ove podatke kao binarne)
- Hive-ovi **`SYSTEM`** i **`SECURITY`**
- **DPAPI glavni ključevi**: Mogu se pronaći u `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Korisničko ime** i **lozinka** Windows korisnika

Zatim možete koristiti alat [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Zatim možete koristiti alat DataProtectionDecryptor](<../../../images/image (443).png>)

Ako sve prođe kako treba, alat će prikazati **primarni ključ** koji treba da **iskoristite za povraćaj originalnog ključa**. Da biste povratili originalni ključ, samo upotrebite ovaj [CyberChef recept](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) i unesite primarni ključ kao "passphrase" u recept.

Dobijena heksadecimalna vrednost je konačni ključ koji se koristi za šifrovanje baza podataka, a koje se mogu dešifrovati pomoću:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

Baza podataka **`config.dbx`** sadrži:

- **Email**: E-adresa korisnika
- **usernamedisplayname**: Ime korisnika
- **dropbox_path**: Putanja do Dropbox fascikle
- **Host_id: Hash** koji se koristi za autentifikaciju na cloud. Može se opozvati samo putem veba.
- **Root_ns**: Identifikator korisnika

Baza podataka **`filecache.db`** sadrži informacije o svim datotekama i fasciklama sinhronizovanim sa Dropbox-om. Tabela `File_journal` sadrži najkorisnije informacije:<sup>[[5]](#references)</sup>

- **Server_path**: Putanja do datoteke na serveru (ispred ove putanje nalazi se `host_id` klijenta).
- **local_sjid**: Verzija datoteke
- **local_mtime**: Datum izmene
- **local_ctime**: Datum kreiranja

Ostale tabele u ovoj bazi podataka sadrže još zanimljivih informacija:

- **block_cache**: Hash vrednosti svih datoteka i fascikli u Dropbox-u
- **block_ref**: Povezuje hash ID iz tabele `block_cache` sa ID-jem datoteke u tabeli `file_journal`
- **mount_table**: Deljene fascikle u Dropbox-u
- **deleted_fields**: Izbrisane Dropbox datoteke
- **date_added**

## References

- [1] [Kritička analiza bezbednosti Dropbox softvera (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Obnavljanje znanja o dešifrovanju Dropbox DBX-a](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Forenzička analiza cloud skladišta (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Slučaj NIST CFReDS o curenju podataka: odgovori o curenju](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox forenzika](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefakti korišćenja Google Drive-a u Windows-u](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
