# Hifadhi ya Wingu ya Ndani

{{#include ../../../banners/hacktricks-training.md}}

## Emulators za hifadhi ya ndani na funguo za akaunti

Emulator ya Blob inayooana na Azure inayoendeshwa kwenye container inaweza kufikiwa kutoka kwa host yake au bridge network hata kama huduma ya hifadhi haijawekwa wazi kwa mitandao ya nje. Kagua usanidi wa ndani unaoweza kusomeka na metadata ya faili za backup ili kupata jina la akaunti na key, bila kuchapisha key wakati wa ukaguzi wa kawaida. [Azurite inaruhusu kutumia funguo maalum za akaunti za ndani](https://learn.microsoft.com/en-us/azure/storage/common/storage-azurite); [Uidhinishaji wa Shared Key](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) unaweza kutoa ufikiaji mpana wa data ya akaunti inayolingana. Kupata faili ya key pekee hakuthibitishi kuongezeka kwa ruhusa: thibitisha kuwa endpoint inafikika, akaunti na key zinakubaliwa, na blob husika ina credential inayoweza kutumiwa kupata utambulisho wenye ruhusa za juu zaidi. Ikiwa ina private key ya SSH, public key inayolingana lazima pia iwe imeidhinishwa kwa utambulisho huo na ufikiaji wa SSH uruhusiwe. Linda na ubadilishe key mara tu mfichuko wake unapothibitishwa.

## OneDrive

Katika Windows, unaweza kupata folda ya OneDrive katika `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Ndani ya `logs\Personal` unaweza kupata faili ya `SyncDiagnostics.log` yenye data muhimu kuhusu faili zilizosawazishwa:<sup>[[3]](#references)</sup>

- Ukubwa kwa baiti
- Tarehe ya kuundwa
- Tarehe ya kurekebishwa
- Idadi ya faili kwenye cloud
- Idadi ya faili kwenye folda
- **CID**: Kitambulisho cha kipekee cha mtumiaji wa OneDrive
- Muda wa kutengenezwa kwa ripoti
- Ukubwa wa HD ya OS

Baada ya kupata CID, inapendekezwa **utafute faili zilizo na kitambulisho hiki**. Unaweza kupata faili zinazoitwa: _**\<CID>.ini**_ na _**\<CID>.dat**_ ambazo zinaweza kuwa na taarifa muhimu kama vile majina ya faili zilizosawazishwa na OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

Katika Windows, unaweza kupata folda kuu ya Google Drive katika `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Folda hii ina faili inayoitwa Sync_log.log inayorekodi vipindi vya usawazishaji vya client ya Google Drive, pamoja na matukio ya kuundwa, kurekebishwa na kufutwa kwa faili.<sup>[[4]](#references)[[6]](#references)</sup>

Faili ya **`Cloud_graph\Cloud_graph.db`** ni hifadhidata ya sqlite.<sup>[[6]](#references)</sup> Ina jedwali la **`cloud_graph_entry`**. Katika jedwali hili unaweza kupata **majina** ya **faili** **zilizosawazishwa**, muda wa kurekebishwa, ukubwa na checksum ya MD5 ya faili.

Jedwali la **`cloud_entry`** katika hifadhidata inayohusiana ya **`snapshot.db`** linaweza kuhifadhi rekodi zilizofutwa zenye majina ya faili, mihuri ya muda, ukubwa na checksum.<sup>[[4]](#references)</sup>

Data ya jedwali la hifadhidata ya **`Sync_config.db`** ina anwani ya barua pepe ya akaunti, njia ya folda zilizoshirikiwa na toleo la Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox hutumia **hifadhidata za SQLite** kudhibiti faili.<sup>[[2]](#references)</sup> Katika hili\
Unaweza kupata hifadhidata katika folda hizi:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Na hifadhidata kuu ni:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Kiendelezi cha ".dbx" kinamaanisha kuwa **hifadhidata** **zimesimbwa kwa njia fiche**. Dropbox hutumia **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Ili kuelewa vizuri usimbaji fiche unaotumiwa na Dropbox, unaweza kusoma [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Hata hivyo, taarifa kuu ni:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Mbali na taarifa hizo, bado unahitaji yafuatayo ili kusimbua hifadhidata:<sup>[[2]](#references)</sup>

- **Key ya DPAPI iliyosimbwa kwa njia fiche**: Unaweza kuipata kwenye registry ndani ya `NTUSER.DAT\Software\Dropbox\ks\client` (hamisha data hii kama binary)
- Hives za **`SYSTEM`** na **`SECURITY`**
- **Master keys za DPAPI**: Zinapatikana katika `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Jina la mtumiaji** na **nenosiri** la mtumiaji wa Windows

Kisha unaweza kutumia zana ya [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Kisha unaweza kutumia zana ya DataProtectionDecryptor](<../../../images/image (443).png>)

Ikiwa kila kitu kitaenda kama ilivyotarajiwa, zana itaonyesha **primary key** unayohitaji **kutumia kurejesha ile ya awali**. Ili kurejesha ile ya awali, tumia tu [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) na uweke primary key kama "passphrase" ndani ya receipt.

Hex inayotokana ndiyo key ya mwisho inayotumiwa kusimba hifadhidata kwa njia fiche, ambazo zinaweza kusimbuliwa kwa kutumia:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

Hifadhidata ya **`config.dbx`** ina:

- **Email**: Barua pepe ya mtumiaji
- **usernamedisplayname**: Jina la mtumiaji
- **dropbox_path**: Njia ya folda ya Dropbox
- **Host_id: Hash** inayotumika kuthibitisha utambulisho kwenye cloud. Hii inaweza kubatilishwa kupitia wavuti pekee.
- **Root_ns**: Kitambulisho cha mtumiaji

Hifadhidata ya **`filecache.db`** ina taarifa kuhusu faili na folda zote zilizosawazishwa na Dropbox. Jedwali la `File_journal` lina taarifa muhimu zaidi:<sup>[[5]](#references)</sup>

- **Server_path**: Njia ya faili ndani ya server (njia hii hutanguliwa na `host_id` ya mteja).
- **local_sjid**: Toleo la faili
- **local_mtime**: Tarehe ya kurekebishwa
- **local_ctime**: Tarehe ya kuundwa

Majedwali mengine ndani ya hifadhidata hii yana taarifa nyingine za kuvutia zaidi:

- **block_cache**: Hash ya faili na folda zote za Dropbox
- **block_ref**: Huunganisha kitambulisho cha hash cha jedwali la `block_cache` na kitambulisho cha faili kwenye jedwali la `file_journal`
- **mount_table**: Folda za Dropbox zilizoshirikiwa
- **deleted_fields**: Faili za Dropbox zilizofutwa
- **date_added**

## References

- [1] [Uchambuzi muhimu wa usalama wa programu ya Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Kujikumbusha kuhusu usimbuaji wa DBX za Dropbox](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Uchambuzi wa kiuchunguzi wa hifadhi ya cloud (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Kesi ya NIST CFReDS ya kuvuja kwa data: Majibu kuhusu kuvuja](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Uchunguzi wa kiuchunguzi wa Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Mabaki ya matumizi ya Google Drive kwenye Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
