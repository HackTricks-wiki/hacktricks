# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Windows में, आप OneDrive folder को `\Users\<username>\AppData\Local\Microsoft\OneDrive` में पा सकते हैं। और `logs\Personal` के अंदर `SyncDiagnostics.log` file मिल सकती है, जिसमें synchronized files से संबंधित कुछ महत्वपूर्ण data होता है:<sup>[[3]](#references)</sup>

- Bytes में size
- Creation date
- Modification date
- Cloud में files की संख्या
- Folder में files की संख्या
- **CID**: OneDrive user की unique ID
- Report generation time
- OS की HD का size

CID मिलने के बाद **इस ID वाली files को search करना** recommended है। आपको _**\<CID>.ini**_ और _**\<CID>.dat**_ नाम वाली files मिल सकती हैं, जिनमें OneDrive के साथ synchronized files के नाम जैसी महत्वपूर्ण information हो सकती है।<sup>[[3]](#references)</sup>

## Google Drive

Windows में, आप मुख्य Google Drive folder को `\Users\<username>\AppData\Local\Google\Drive\user_default`\
में पा सकते हैं। इस folder में Sync_log.log नाम की file होती है, जो Google Drive client synchronization sessions और file creation, modification तथा deletion events को record करती है।<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** file एक sqlite database है।<sup>[[6]](#references)</sup> इसमें **`cloud_graph_entry`** table होती है। इस table में आप **synchronized** **files** के **name**, modification time, size और files का MD5 checksum पा सकते हैं।

संबंधित **`snapshot.db`** database की **`cloud_entry`** table हटाए गए records को filenames, timestamps, sizes और checksums के साथ बनाए रख सकती है।<sup>[[4]](#references)</sup>

**`Sync_config.db`** database के table data में account का email address, shared folders का path और Google Drive version होता है।<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox files को manage करने के लिए **SQLite databases** का उपयोग करता है।<sup>[[2]](#references)</sup> इस\
में databases इन folders में मिल सकते हैं:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

और मुख्य databases हैं:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" extension का अर्थ है कि **databases** **encrypted** हैं। Dropbox **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)) का उपयोग करता है।<sup>[[1]](#references)</sup>

Dropbox द्वारा उपयोग की जाने वाली encryption को बेहतर ढंग से समझने के लिए आप [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) पढ़ सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

हालाँकि, मुख्य information यह है:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

इस information के अलावा, databases को decrypt करने के लिए आपको अभी भी इनकी आवश्यकता होगी:<sup>[[2]](#references)</sup>

- **encrypted DPAPI key**: आप इसे registry में `NTUSER.DAT\Software\Dropbox\ks\client` के अंदर पा सकते हैं (इस data को binary के रूप में export करें)
- **`SYSTEM`** और **`SECURITY`** hives
- **DPAPI master keys**: ये `\Users\<username>\AppData\Roaming\Microsoft\Protect` में मिल सकती हैं
- Windows user का **username** और **password**

फिर आप [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** tool का उपयोग कर सकते हैं:**

![Google Drive - Dropbox: फिर आप DataProtectionDecryptor tool का उपयोग कर सकते हैं](<../../../images/image (443).png>)

यदि सब कुछ अपेक्षित रूप से होता है, तो tool उस **primary key** को बताएगा जिसका उपयोग आपको **original key recover करने के लिए करना होगा**। Original key recover करने के लिए, इस [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) का उपयोग करें और receipt के अंदर primary key को "passphrase" के रूप में डालें।

प्राप्त hex databases को encrypt करने के लिए उपयोग की जाने वाली final key है, जिसे निम्नलिखित से decrypt किया जा सकता है:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** database में निम्नलिखित जानकारी होती है:

- **Email**: user का email
- **usernamedisplayname**: user का नाम
- **dropbox_path**: वह path जहाँ Dropbox folder स्थित है
- **Host_id: Hash** जिसका उपयोग cloud के साथ authenticate करने के लिए किया जाता है। इसे केवल web से revoke किया जा सकता है।
- **Root_ns**: User identifier

**`filecache.db`** database में Dropbox के साथ synchronized सभी files और folders की जानकारी होती है। `File_journal` table में सबसे अधिक उपयोगी जानकारी होती है:<sup>[[5]](#references)</sup>

- **Server_path**: वह path जहाँ file server के अंदर स्थित है (इस path के पहले client का `host_id` होता है)।
- **local_sjid**: File का version
- **local_mtime**: Modification date
- **local_ctime**: Creation date

इस database के अंदर मौजूद अन्य tables में अधिक उपयोगी जानकारी होती है:

- **block_cache**: Dropbox की सभी files और folders के hash
- **block_ref**: `block_cache` table की hash ID को `file_journal` table में मौजूद file ID से संबंधित करता है
- **mount_table**: Dropbox के shared folders
- **deleted_fields**: Dropbox की deleted files
- **date_added**

## References

- [1] [Dropbox software security का critical analysis (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX decryption पर जानकारी](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Cloud Storage Forensic Analysis (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: Leakage Answers](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Forensics](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows में Google Drive के उपयोग के Artifacts](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
