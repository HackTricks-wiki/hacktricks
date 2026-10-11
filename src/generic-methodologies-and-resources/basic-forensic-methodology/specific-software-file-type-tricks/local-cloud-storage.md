# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}

## Local storage emulators and account keys

कंटेनर में चल रहा Azure-compatible Blob emulator अपने host या bridge network से पहुँच योग्य हो सकता है, भले ही storage service बाहरी रूप से expose न की गई हो। पढ़ने योग्य local configuration और backup-file metadata में account name और key देखें, लेकिन सामान्य enumeration के दौरान key प्रिंट न करें। [Azurite custom local account keys को support करता है](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) matching account के data तक व्यापक access दे सकता है। केवल key file मिलने से privilege escalation साबित नहीं होता: पुष्टि करें कि endpoint पहुँच योग्य है, account और key स्वीकार किए जाते हैं, और उस specific blob में higher-privileged identity के लिए उपयोगी credential मौजूद है। यदि उसमें SSH private key है, तो उस identity के लिए संबंधित public key भी authorized होनी चाहिए और SSH access की अनुमति होनी चाहिए। Exposure की पुष्टि होने पर key को सुरक्षित रखें और rotate करें।

## OneDrive

Windows में, OneDrive folder `\Users\<username>\AppData\Local\Microsoft\OneDrive` में मिल सकता है। और `logs\Personal` के अंदर `SyncDiagnostics.log` file मिल सकती है, जिसमें synchronized files से जुड़ा कुछ दिलचस्प data होता है:<sup>[[3]](#references)</sup>

- Bytes में size
- Creation date
- Modification date
- Cloud में files की संख्या
- Folder में files की संख्या
- **CID**: OneDrive user की unique ID
- Report generation time
- OS की HD का size

CID मिलने के बाद, **इस ID वाली files खोजना** बेहतर है। आपको _**\<CID>.ini**_ और _**\<CID>.dat**_ नाम वाली files मिल सकती हैं, जिनमें OneDrive के साथ synchronized files के नाम जैसी दिलचस्प जानकारी हो सकती है।<sup>[[3]](#references)</sup>

## Google Drive

Windows में, Google Drive का main folder `\Users\<username>\AppData\Local\Google\Drive\user_default` में मिल सकता है।\
इस folder में `Sync_log.log` नाम की file होती है, जो Google Drive client के synchronization sessions और files बनाने, संशोधित करने तथा हटाने की घटनाओं को रिकॉर्ड करती है।<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** file एक sqlite database है।<sup>[[6]](#references)</sup> इसमें **`cloud_graph_entry`** table होती है। इस table में आप **synchronized** **files** के **नाम**, modified time, size और files का MD5 checksum पा सकते हैं।

संबंधित **`snapshot.db`** database की **`cloud_entry`** table में हटाए गए records के filenames, timestamps, sizes और checksums मौजूद रह सकते हैं।<sup>[[4]](#references)</sup>

**`Sync_config.db`** database की table में account का email address, shared folders के paths और Google Drive version होता है।<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox files को manage करने के लिए **SQLite databases** का उपयोग करता है।<sup>[[2]](#references)</sup> इसमें\
आप databases इन folders में पा सकते हैं:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

और main databases हैं:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" extension का मतलब है कि **databases** **encrypted** हैं। Dropbox **DPAPI** का उपयोग करता है ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Dropbox द्वारा इस्तेमाल किए जाने वाले encryption को बेहतर ढंग से समझने के लिए आप [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) पढ़ सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

हालाँकि, मुख्य जानकारी यह है:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

इस जानकारी के अलावा, databases को decrypt करने के लिए आपको अभी भी इनकी ज़रूरत होगी:<sup>[[2]](#references)</sup>

- **Encrypted DPAPI key**: यह registry में `NTUSER.DAT\Software\Dropbox\ks\client` के अंदर मिल सकती है (इस data को binary के रूप में export करें)
- **`SYSTEM`** और **`SECURITY`** hives
- **DPAPI master keys**: ये `\Users\<username>\AppData\Roaming\Microsoft\Protect` में मिल सकती हैं
- Windows user का **username** और **password**

इसके बाद आप [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** टूल का उपयोग कर सकते हैं:**

![Google Drive - Dropbox: इसके बाद आप DataProtectionDecryptor टूल का उपयोग कर सकते हैं](<../../../images/image (443).png>)

सब कुछ अपेक्षा के अनुसार होने पर, tool वह **primary key** बताएगा जिसका उपयोग **original key को recover करने के लिए** करना होगा। Original key recover करने के लिए, इस [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) का उपयोग करें और receipt में primary key को "passphrase" के रूप में डालें।

इससे मिलने वाला hex databases को encrypt करने के लिए इस्तेमाल की गई final key है, जिसे इस तरह decrypt किया जा सकता है:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

**`config.dbx`** डेटाबेस में ये शामिल हैं:

- **Email**: उपयोगकर्ता का ईमेल
- **usernamedisplayname**: उपयोगकर्ता का नाम
- **dropbox_path**: वह पथ जहाँ Dropbox फ़ोल्डर मौजूद है
- **Host_id: Hash**: Cloud से authenticate करने के लिए उपयोग किया जाता है। इसे केवल वेब से revoke किया जा सकता है।
- **Root_ns**: उपयोगकर्ता पहचानकर्ता

**`filecache.db`** डेटाबेस में Dropbox के साथ synchronized सभी फ़ाइलों और फ़ोल्डरों की जानकारी होती है। `File_journal` तालिका में सबसे उपयोगी जानकारी है:<sup>[[5]](#references)</sup>

- **Server_path**: सर्वर के अंदर फ़ाइल का पथ (इस पथ से पहले client का `host_id` होता है)।
- **local_sjid**: फ़ाइल का संस्करण
- **local_mtime**: संशोधन की तारीख
- **local_ctime**: निर्माण की तारीख

इस डेटाबेस की अन्य तालिकाओं में अधिक दिलचस्प जानकारी होती है:

- **block_cache**: Dropbox की सभी फ़ाइलों और फ़ोल्डरों का hash
- **block_ref**: `block_cache` तालिका के hash ID को `file_journal` तालिका के file ID से जोड़ता है
- **mount_table**: Dropbox के साझा फ़ोल्डर
- **deleted_fields**: Dropbox की हटाई गई फ़ाइलें
- **date_added**

## References

- [1] [Dropbox सॉफ़्टवेयर सुरक्षा का एक महत्वपूर्ण विश्लेषण (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX decryption की जानकारी ताज़ा करें](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Cloud Storage का Forensic Analysis (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage केस: Leakage के उत्तर](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Forensics](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows में Google Drive के उपयोग के Artifacts](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
