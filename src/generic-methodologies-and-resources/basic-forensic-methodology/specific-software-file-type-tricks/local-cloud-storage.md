# स्थानीय क्लाउड स्टोरेज

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Windows में, आप OneDrive फ़ोल्डर को `\Users\<username>\AppData\Local\Microsoft\OneDrive` में पा सकते हैं। और `logs\Personal` के अंदर, आप फ़ाइल `SyncDiagnostics.log` पा सकते हैं जिसमें समन्वयित फ़ाइलों के बारे में कुछ दिलचस्प डेटा होता है:

- बाइट्स में आकार
- निर्माण तिथि
- संशोधन तिथि
- क्लाउड में फ़ाइलों की संख्या
- फ़ोल्डर में फ़ाइलों की संख्या
- **CID**: OneDrive उपयोगकर्ता का अद्वितीय आईडी
- रिपोर्ट निर्माण समय
- OS का HD का आकार

एक बार जब आप CID पा लेते हैं, तो **इस ID वाले फ़ाइलों की खोज करना** अनुशंसित है। आप _**\<CID>.ini**_ और _**\<CID>.dat**_ नाम की फ़ाइलें पा सकते हैं जो OneDrive के साथ समन्वयित फ़ाइलों के नाम जैसी दिलचस्प जानकारी रख सकती हैं।

## Google Drive

Windows में, आप मुख्य Google Drive फ़ोल्डर को `\Users\<username>\AppData\Local\Google\Drive\user_default` में पा सकते हैं।\
इस फ़ोल्डर में एक फ़ाइल है जिसका नाम Sync_log.log है जिसमें खाते का ईमेल पता, फ़ाइल नाम, टाइमस्टैम्प, फ़ाइलों के MD5 हैश आदि जैसी जानकारी होती है। यहां तक कि हटाई गई फ़ाइलें भी उस लॉग फ़ाइल में अपने संबंधित MD5 के साथ दिखाई देती हैं।

फ़ाइल **`Cloud_graph\Cloud_graph.db`** एक sqlite डेटाबेस है जिसमें तालिका **`cloud_graph_entry`** होती है। इस तालिका में आप **समन्वयित** **फ़ाइलों** का **नाम**, संशोधित समय, आकार, और फ़ाइलों का MD5 चेकसम पा सकते हैं।

डेटाबेस **`Sync_config.db`** की तालिका डेटा में खाते का ईमेल पता, साझा फ़ोल्डरों का पथ और Google Drive का संस्करण होता है।

## Dropbox

Dropbox फ़ाइलों को प्रबंधित करने के लिए **SQLite डेटाबेस** का उपयोग करता है। इसमें\
आप डेटाबेस को निम्नलिखित फ़ोल्डरों में पा सकते हैं:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

और मुख्य डेटाबेस हैं:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" एक्सटेंशन का अर्थ है कि **डेटाबेस** **एन्क्रिप्टेड** हैं। Dropbox **DPAPI** का उपयोग करता है ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Dropbox द्वारा उपयोग की जाने वाली एन्क्रिप्शन को बेहतर ढंग से समझने के लिए आप पढ़ सकते हैं [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)।

हालांकि, मुख्य जानकारी है:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

उस जानकारी के अलावा, डेटाबेस को डिक्रिप्ट करने के लिए आपको अभी भी आवश्यकता है:

- **एन्क्रिप्टेड DPAPI कुंजी**: आप इसे रजिस्ट्री में `NTUSER.DAT\Software\Dropbox\ks\client` में पा सकते हैं (इस डेटा को बाइनरी के रूप में निर्यात करें)
- **`SYSTEM`** और **`SECURITY`** हाइव
- **DPAPI मास्टर कुंजी**: जो `\Users\<username>\AppData\Roaming\Microsoft\Protect` में पाई जा सकती हैं
- Windows उपयोगकर्ता का **उपयोगकर्ता नाम** और **पासवर्ड**

फिर आप टूल [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** का उपयोग कर सकते हैं:**

![](<../../../images/image (443).png>)

यदि सब कुछ अपेक्षित रूप से चलता है, तो टूल आपको **प्राथमिक कुंजी** बताएगा जिसका आपको **मूल कुंजी को पुनर्प्राप्त करने के लिए उपयोग करना है**। मूल कुंजी को पुनर्प्राप्त करने के लिए, बस इस [cyber_chef रेसिपी](<https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) का उपयोग करें, जिसमें प्राथमिक कुंजी को रेसिपी के अंदर "पासफ़्रेज़" के रूप में डालें।

परिणामी हेक्स अंतिम कुंजी है जिसका उपयोग डेटाबेस को एन्क्रिप्ट करने के लिए किया गया है जिसे डिक्रिप्ट किया जा सकता है:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** डेटाबेस में शामिल हैं:

- **Email**: उपयोगकर्ता का ईमेल
- **usernamedisplayname**: उपयोगकर्ता का नाम
- **dropbox_path**: वह पथ जहाँ ड्रॉपबॉक्स फ़ोल्डर स्थित है
- **Host_id: Hash** जो क्लाउड में प्रमाणीकरण के लिए उपयोग किया जाता है। इसे केवल वेब से रद्द किया जा सकता है।
- **Root_ns**: उपयोगकर्ता पहचानकर्ता

**`filecache.db`** डेटाबेस में ड्रॉपबॉक्स के साथ समन्वयित सभी फ़ाइलों और फ़ोल्डरों के बारे में जानकारी होती है। तालिका `File_journal` में अधिक उपयोगी जानकारी होती है:

- **Server_path**: वह पथ जहाँ फ़ाइल सर्वर के अंदर स्थित है (यह पथ क्लाइंट के `host_id` द्वारा पूर्ववर्ती होता है)।
- **local_sjid**: फ़ाइल का संस्करण
- **local_mtime**: संशोधन तिथि
- **local_ctime**: निर्माण तिथि

इस डेटाबेस के अंदर अन्य तालिकाएँ अधिक दिलचस्प जानकारी प्रदान करती हैं:

- **block_cache**: ड्रॉपबॉक्स की सभी फ़ाइलों और फ़ोल्डरों का हैश
- **block_ref**: तालिका `block_cache` के हैश आईडी को तालिका `file_journal` में फ़ाइल आईडी से संबंधित करता है
- **mount_table**: ड्रॉपबॉक्स के साझा फ़ोल्डर
- **deleted_fields**: ड्रॉपबॉक्स द्वारा हटाई गई फ़ाइलें
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
