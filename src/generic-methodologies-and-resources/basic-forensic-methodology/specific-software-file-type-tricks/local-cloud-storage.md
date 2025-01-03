# Hifadhi ya Wingu ya Mitaa

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Katika Windows, unaweza kupata folda ya OneDrive katika `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Na ndani ya `logs\Personal` inawezekana kupata faili `SyncDiagnostics.log` ambayo ina data za kuvutia kuhusu faili zilizohusishwa:

- Ukubwa kwa bytes
- Tarehe ya kuundwa
- Tarehe ya mabadiliko
- Idadi ya faili katika wingu
- Idadi ya faili katika folda
- **CID**: Kitambulisho cha kipekee cha mtumiaji wa OneDrive
- Wakati wa kuzalisha ripoti
- Ukubwa wa HD wa OS

Mara tu unapopata CID inashauriwa **kutafuta faili zinazohusisha kitambulisho hiki**. Unaweza kupata faili zenye jina: _**\<CID>.ini**_ na _**\<CID>.dat**_ ambazo zinaweza kuwa na taarifa za kuvutia kama majina ya faili zilizohusishwa na OneDrive.

## Google Drive

Katika Windows, unaweza kupata folda kuu ya Google Drive katika `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Folda hii ina faili inayoitwa Sync_log.log yenye taarifa kama anwani ya barua pepe ya akaunti, majina ya faili, alama za muda, MD5 hashes za faili, n.k. Hata faili zilizofutwa zinaonekana katika faili hiyo ya logi na MD5 inayohusiana.

Faili **`Cloud_graph\Cloud_graph.db`** ni database ya sqlite ambayo ina jedwali **`cloud_graph_entry`**. Katika jedwali hili unaweza kupata **jina** la **faili zilizohusishwa**, wakati wa mabadiliko, ukubwa, na MD5 checksum za faili.

Data za jedwali la database **`Sync_config.db`** zina anwani ya barua pepe ya akaunti, njia za folda zilizoshirikiwa na toleo la Google Drive.

## Dropbox

Dropbox hutumia **databases za SQLite** kusimamia faili. Katika hii\
Unaweza kupata databases katika folda:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Na databases kuu ni:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Kiambatisho ".dbx" kinamaanisha kwamba **databases** zime **siri**. Dropbox hutumia **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Ili kuelewa vizuri usimbuaji ambao Dropbox hutumia unaweza kusoma [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Hata hivyo, taarifa kuu ni:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Mbali na taarifa hizo, ili kufungua databases bado unahitaji:

- **funguo ya DPAPI iliyosimbwa**: Unaweza kuipata katika rejista ndani ya `NTUSER.DAT\Software\Dropbox\ks\client` (export data hii kama binary)
- **`SYSTEM`** na **`SECURITY`** hives
- **funguo kuu za DPAPI**: Ambazo zinaweza kupatikana katika `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **jina la mtumiaji** na **nenosiri** la mtumiaji wa Windows

Kisha unaweza kutumia chombo [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (443).png>)

Ikiwa kila kitu kinaenda kama inavyotarajiwa, chombo kitatoa **funguo kuu** ambayo unahitaji **kutumia ili kurejesha ile ya awali**. Ili kurejesha ile ya awali, tumia tu [mapishi ya cyber_chef](<https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) ukitumia funguo kuu kama "passphrase" ndani ya mapishi.

Hex inayotokana ni funguo ya mwisho inayotumika kusimbua databases ambazo zinaweza kufunguliwa na:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Hifadhidata ya **`config.dbx`** ina:

- **Email**: Barua pepe ya mtumiaji
- **usernamedisplayname**: Jina la mtumiaji
- **dropbox_path**: Njia ambapo folda ya dropbox iko
- **Host_id: Hash** inayotumika kuthibitisha kwenye wingu. Hii inaweza kufutwa tu kutoka kwenye wavuti.
- **Root_ns**: Kitambulisho cha mtumiaji

Hifadhidata ya **`filecache.db`** ina taarifa kuhusu faili na folda zote zilizoratibiwa na Dropbox. Jedwali la `File_journal` ndilo lenye taarifa zaidi muhimu:

- **Server_path**: Njia ambapo faili iko ndani ya seva (njia hii inatanguliwa na `host_id` ya mteja).
- **local_sjid**: Toleo la faili
- **local_mtime**: Tarehe ya mabadiliko
- **local_ctime**: Tarehe ya kuundwa

Jedwali mengine ndani ya hifadhidata hii yana taarifa zaidi za kuvutia:

- **block_cache**: hash ya faili na folda zote za Dropbox
- **block_ref**: Inahusisha ID ya hash ya jedwali `block_cache` na ID ya faili katika jedwali `file_journal`
- **mount_table**: Shiriki folda za dropbox
- **deleted_fields**: Faili zilizofutwa za Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
