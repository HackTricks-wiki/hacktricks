# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Katika Windows, unaweza kupata folda ya OneDrive kwenye `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Ndani ya `logs\Personal` inawezekana kupata faili `SyncDiagnostics.log` iliyo na data ya kuvutia kuhusu faili zilizosawazishwa:

- Ukubwa kwa bytes
- Tarehe ya kuundwa
- Tarehe ya kurekebishwa
- Idadi ya faili kwenye cloud
- Idadi ya faili kwenye folda
- **CID**: Kitambulisho cha kipekee cha mtumiaji wa OneDrive
- Muda wa kutengenezwa kwa ripoti
- Ukubwa wa HD ya OS

Baada ya kupata CID, inapendekezwa **kutafuta faili zilizo na ID hii**. Huenda ukaweza kupata faili zenye majina: _**\<CID>.ini**_ na _**\<CID>.dat**_ ambazo zinaweza kuwa na taarifa za kuvutia kama majina ya faili zilizosawazishwa na OneDrive.

## Google Drive

Katika Windows, unaweza kupata folda kuu ya Google Drive kwenye `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Folda hii ina faili inayoitwa Sync_log.log yenye taarifa kama anwani ya barua pepe ya account, majina ya faili, timestamps, MD5 hashes za faili, n.k. Hata faili zilizofutwa huonekana kwenye log file hiyo pamoja na MD5 yake inayolingana.

Faili **`Cloud_graph\Cloud_graph.db`** ni sqlite database iliyo na jedwali **`cloud_graph_entry`**. Katika jedwali hili unaweza kupata **majina** ya **faili** **zilizosawazishwa**, muda wa kurekebishwa, ukubwa, na MD5 checksum za faili.

Data ya jedwali ya database **`Sync_config.db`** ina anwani ya barua pepe ya account, path ya shared folders na toleo la Google Drive.

## Dropbox

Dropbox hutumia **SQLite databases** kudhibiti faili. Katika\
Unaweza kupata databases kwenye folda:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Na databases kuu ni:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Extension ya ".dbx" inamaanisha kuwa **databases** zime **encrypted**. Dropbox hutumia **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Ili kuelewa vizuri encryption inayotumiwa na Dropbox, unaweza kusoma [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Hata hivyo, taarifa kuu ni:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Mbali na taarifa hiyo, ili ku-decrypt databases bado unahitaji:<sup>[[2]](#references)</sup>

- **DPAPI key iliyosimbwa kwa njia fiche**: Unaweza kuipata kwenye registry ndani ya `NTUSER.DAT\Software\Dropbox\ks\client` (export data hii kama binary)
- Hives za **`SYSTEM`** na **`SECURITY`**
- **DPAPI master keys**: Zinaweza kupatikana kwenye `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Username** na **password** ya mtumiaji wa Windows

Kisha unaweza kutumia tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Kisha unaweza kutumia tool DataProtectionDecryptor](<../../../images/image (443).png>)

Ikiwa kila kitu kitaenda kama ilivyotarajiwa, tool itaonyesha **primary key** unayohitaji **kutumia kurejesha ile ya awali**. Ili kurejesha ile ya awali, tumia tu [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) ukiweka primary key kama "passphrase" ndani ya receipt.

Hex inayotokana ni key ya mwisho inayotumika ku-encrypt databases, ambazo zinaweza ku-decryptiwa kwa:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Hifadhidata ya **`config.dbx`** ina:

- **Email**: Barua pepe ya mtumiaji
- **usernamedisplayname**: Jina la mtumiaji
- **dropbox_path**: Njia ambapo folda ya Dropbox iko
- **Host_id: Hash** inayotumika kuthibitisha mtumiaji kwenye cloud. Hii inaweza kufutwa tu kupitia wavuti.
- **Root_ns**: Kitambulisho cha mtumiaji

Hifadhidata ya **`filecache.db`** ina taarifa kuhusu faili na folda zote zilizosawazishwa na Dropbox. Jedwali la `File_journal` ndilo lenye taarifa muhimu zaidi:

- **Server_path**: Njia ambapo faili iko ndani ya server (njia hii hutanguliwa na `host_id` ya client).
- **local_sjid**: Toleo la faili
- **local_mtime**: Tarehe ya marekebisho
- **local_ctime**: Tarehe ya kuundwa

Majedwali mengine ndani ya hifadhidata hii yana taarifa za kuvutia zaidi:

- **block_cache**: Hash ya faili na folda zote za Dropbox
- **block_ref**: Huunganisha kitambulisho cha hash cha jedwali la `block_cache` na kitambulisho cha faili katika jedwali la `file_journal`
- **mount_table**: Folda za Dropbox zilizoshirikiwa
- **deleted_fields**: Faili zilizofutwa za Dropbox
- **date_added**

## Marejeo

- [1] [Uchambuzi muhimu wa usalama wa software ya Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Pata uelewa bora kuhusu usimbuaji wa Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
