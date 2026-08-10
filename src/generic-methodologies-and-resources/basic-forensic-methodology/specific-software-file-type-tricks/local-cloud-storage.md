# Local Cloud Storage

## OneDrive

Katika Windows, unaweza kupata folda ya OneDrive katika `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Na ndani ya `logs\Personal` inawezekana kupata faili `SyncDiagnostics.log` ambayo ina data ya kuvutia kuhusu faili zilizosawazishwa:<sup>[[3]](#references)</sup>

- Ukubwa kwa bytes
- Tarehe ya kuundwa
- Tarehe ya kurekebishwa
- Idadi ya faili zilizo kwenye cloud
- Idadi ya faili zilizo kwenye folda
- **CID**: Kitambulisho cha kipekee cha mtumiaji wa OneDrive
- Muda wa kutengenezwa kwa ripoti
- Ukubwa wa HD ya OS

Baada ya kupata CID, inapendekezwa **kutafuta faili zilizo na ID hii**. Huenda ukaweza kupata faili zenye majina: _**\<CID>.ini**_ na _**\<CID>.dat**_ ambazo zinaweza kuwa na taarifa za kuvutia kama vile majina ya faili zilizosawazishwa na OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

Katika Windows, unaweza kupata folda kuu ya Google Drive katika `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Folda hii ina faili inayoitwa Sync_log.log ambayo huhifadhi sessions za usawazishaji za Google Drive client pamoja na matukio ya kuundwa, kurekebishwa na kufutwa kwa faili.<sup>[[4]](#references)[[6]](#references)</sup>

Faili **`Cloud_graph\Cloud_graph.db`** ni database ya sqlite.<sup>[[6]](#references)</sup> Ina table **`cloud_graph_entry`**. Katika table hii unaweza kupata **majina** ya **faili** **zilizosawazishwa**, muda wa kurekebishwa, ukubwa na MD5 checksum za faili.

Table **`cloud_entry`** ya database inayohusiana ya **`snapshot.db`** inaweza kuhifadhi records zilizoondolewa pamoja na majina ya faili, timestamps, ukubwa na checksums.<sup>[[4]](#references)</sup>

Data ya table ya database **`Sync_config.db`** ina anwani ya barua pepe ya account, path ya shared folders na version ya Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox hutumia **SQLite databases** kudhibiti faili.<sup>[[2]](#references)</sup> Katika\
Unaweza kupata databases katika folda:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Na databases kuu ni:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Extension ya ".dbx" inamaanisha kuwa **databases** zimefichwa kwa encryption. Dropbox hutumia **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Ili kuelewa vizuri encryption inayotumiwa na Dropbox, unaweza kusoma [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Hata hivyo, taarifa kuu ni:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Mbali na taarifa hiyo, ili ku-decrypt databases bado unahitaji:<sup>[[2]](#references)</sup>

- **DPAPI key iliyofichwa kwa encryption**: Unaweza kuipata kwenye registry ndani ya `NTUSER.DAT\Software\Dropbox\ks\client` (export data hii kama binary)
- Hives za **`SYSTEM`** na **`SECURITY`**
- **DPAPI master keys**: Ambazo zinaweza kupatikana katika `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Username** na **password** ya mtumiaji wa Windows

Kisha unaweza kutumia tool [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Kisha unaweza kutumia tool DataProtectionDecryptor](<../../../images/image (443).png>)

Ikiwa kila kitu kitaenda kama ilivyotarajiwa, tool itaonyesha **primary key** ambayo unahitaji **kutumia kurejesha ile ya awali**. Ili kurejesha ile ya awali, tumia tu hii [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) ukiweka primary key kama "passphrase" ndani ya receipt.

Hex itakayotokana ndiyo key ya mwisho inayotumika ku-encrypt databases, ambazo zinaweza ku-decryptiwa kwa kutumia:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** database ina:

- **Email**: Barua pepe ya mtumiaji
- **usernamedisplayname**: Jina la mtumiaji
- **dropbox_path**: Njia ambapo folda ya Dropbox iko
- **Host_id: Hash** inayotumiwa kuthibitisha kwenye cloud. Hii inaweza kubatilishwa tu kutoka kwenye web.
- **Root_ns**: Kitambulisho cha mtumiaji

**`filecache.db`** database ina taarifa kuhusu files na folders zote zilizosawazishwa na Dropbox. Jedwali `File_journal` ndilo lenye taarifa muhimu zaidi:<sup>[[5]](#references)</sup>

- **Server_path**: Njia ambapo file iko ndani ya server (njia hii hutanguliwa na `host_id` ya client).
- **local_sjid**: Toleo la file
- **local_mtime**: Tarehe ya urekebishaji
- **local_ctime**: Tarehe ya kuundwa

Majedwali mengine ndani ya database hii yana taarifa zinazovutia zaidi:

- **block_cache**: hash ya files na folders zote za Dropbox
- **block_ref**: Huunganisha hash ID ya jedwali `block_cache` na file ID kwenye jedwali `file_journal`
- **mount_table**: Folders za Dropbox zilizoshirikiwa
- **deleted_fields**: Files za Dropbox zilizofutwa
- **date_added**

## References

- [1] [Uchambuzi muhimu wa usalama wa software ya Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Kufanya mapitio ya Dropbox DBX decryption](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Uchambuzi wa kiforensiki wa Cloud Storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Kesi ya NIST CFReDS ya Data Leakage: Majibu ya Leakage](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Forensics ya Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artifacts za matumizi ya Google Drive kwenye Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
