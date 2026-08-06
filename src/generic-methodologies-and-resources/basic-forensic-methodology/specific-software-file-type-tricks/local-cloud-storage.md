# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Windows में, OneDrive folder को `\Users\<username>\AppData\Local\Microsoft\OneDrive` में पाया जा सकता है। और `logs\Personal` के अंदर `SyncDiagnostics.log` file मिल सकती है, जिसमें synchronized files से संबंधित कुछ interesting data होता है:

- Bytes में size
- Creation date
- Modification date
- Cloud में files की संख्या
- Folder में files की संख्या
- **CID**: OneDrive user की Unique ID
- Report generation time
- OS की HD का size

CID मिलने के बाद **इस ID वाली files को search करने** की recommendation दी जाती है। आपको _**\<CID>.ini**_ और _**\<CID>.dat**_ नाम वाली files मिल सकती हैं, जिनमें OneDrive के साथ synchronized files के नाम जैसी interesting information हो सकती है।

## Google Drive

Windows में, मुख्य Google Drive folder को `\Users\<username>\AppData\Local\Google\Drive\user_default`\
में पाया जा सकता है। इस folder में Sync_log.log नाम की file होती है, जिसमें account का email address, filenames, timestamps, files के MD5 hashes आदि जैसी information होती है। Deleted files भी उस log file में अपने corresponding MD5 के साथ दिखाई देती हैं।

**`Cloud_graph\Cloud_graph.db`** file एक sqlite database है, जिसमें **`cloud_graph_entry`** table होती है। इस table में आप **synchronized** **files** के **name**, modified time, size और files का MD5 checksum पा सकते हैं।

**`Sync_config.db`** database के table data में account का email address, shared folders का path और Google Drive version होता है।

## Dropbox

Dropbox files को manage करने के लिए **SQLite databases** का उपयोग करता है। इसमें\
आप databases को इन folders में पा सकते हैं:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

और मुख्य databases हैं:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" extension का अर्थ है कि **databases** **encrypted** हैं। Dropbox **DPAPI** का उपयोग करता है ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Dropbox द्वारा उपयोग की जाने वाली encryption को बेहतर ढंग से समझने के लिए आप [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) पढ़ सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

हालाँकि, मुख्य information यह है:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

इस information के अलावा, databases को decrypt करने के लिए आपको अभी भी इनकी आवश्यकता होगी:<sup>[[2]](#references)</sup>

- **encrypted DPAPI key**: इसे registry में `NTUSER.DAT\Software\Dropbox\ks\client` के अंदर पाया जा सकता है (इस data को binary के रूप में export करें)
- **`SYSTEM`** और **`SECURITY`** hives
- **DPAPI master keys**: जिन्हें `\Users\<username>\AppData\Roaming\Microsoft\Protect` में पाया जा सकता है
- Windows user का **username** और **password**

इसके बाद आप [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** tool का उपयोग कर सकते हैं:**

![Google Drive - Dropbox: इसके बाद DataProtectionDecryptor tool का उपयोग करें](<../../../images/image (443).png>)

यदि सब कुछ अपेक्षा के अनुसार होता है, तो tool उस **primary key** को बताएगा जिसका उपयोग आपको **original key को recover करने के लिए करना** होगा। Original key recover करने के लिए, इस [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) का उपयोग करें और primary key को receipt के अंदर "passphrase" के रूप में डालें।

प्राप्त hex databases को encrypt करने के लिए उपयोग की जाने वाली final key है, जिसे इससे decrypt किया जा सकता है:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** database में निम्न जानकारी होती है:

- **Email**: user का email
- **usernamedisplayname**: user का नाम
- **dropbox_path**: वह path जहाँ Dropbox folder स्थित है
- **Host_id: Hash** जिसका उपयोग cloud के साथ authenticate करने के लिए किया जाता है। इसे केवल web से revoke किया जा सकता है।
- **Root_ns**: User identifier

**`filecache.db`** database में Dropbox के साथ synchronized सभी files और folders की जानकारी होती है। `File_journal` table में सबसे उपयोगी जानकारी होती है:

- **Server_path**: वह path जहाँ file server के अंदर स्थित है (इस path के पहले client का `host_id` होता है)।
- **local_sjid**: file का version
- **local_mtime**: modification date
- **local_ctime**: creation date

इस database के अन्य tables में अधिक उपयोगी जानकारी होती है:

- **block_cache**: Dropbox की सभी files और folders के hash
- **block_ref**: `block_cache` table की hash ID को `file_journal` table में मौजूद file ID से संबंधित करता है
- **mount_table**: Dropbox के shared folders
- **deleted_fields**: Dropbox की deleted files
- **date_added**

## References

- [1] [A critical analysis of Dropbox software security (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Brush up on Dropbox DBX decryption](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
