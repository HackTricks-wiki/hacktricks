# Yerel Bulut Depolama

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Windows'ta OneDrive klasörünü `\Users\<username>\AppData\Local\Microsoft\OneDrive` konumunda bulabilirsiniz. `logs\Personal` içinde, senkronize edilen dosyalarla ilgili bazı ilginç veriler içeren `SyncDiagnostics.log` dosyasını bulmak mümkündür:<sup>[[3]](#references)</sup>

- Bayt cinsinden boyut
- Oluşturulma tarihi
- Değiştirilme tarihi
- Buluttaki dosya sayısı
- Klasördeki dosya sayısı
- **CID**: OneDrive kullanıcısının benzersiz kimliği
- Rapor oluşturma zamanı
- İşletim sistemi HD'sinin boyutu

CID'yi bulduktan sonra, **bu kimliği içeren dosyaları aramanız** önerilir. _**\<CID>.ini**_ ve _**\<CID>.dat**_ adlarına sahip, OneDrive ile senkronize edilen dosyaların adları gibi ilginç bilgiler içerebilecek dosyalar bulabilirsiniz.<sup>[[3]](#references)</sup>

## Google Drive

Windows'ta ana Google Drive klasörünü `\Users\<username>\AppData\Local\Google\Drive\user_default` konumunda bulabilirsiniz\
Bu klasör, Google Drive istemcisinin senkronizasyon oturumlarını ve dosya oluşturma, değiştirme ve silme olaylarını kaydeden Sync_log.log adlı bir dosya içerir.<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** dosyası bir sqlite veritabanıdır.<sup>[[6]](#references)</sup> Bu dosya **`cloud_graph_entry`** tablosunu içerir. Bu tabloda **senkronize edilmiş** **dosyaların** **adını**, değiştirilme zamanını, boyutunu ve dosyaların MD5 checksum değerini bulabilirsiniz.

İlgili **`snapshot.db`** veritabanının **`cloud_entry`** tablosu; dosya adları, zaman damgaları, boyutlar ve checksum değerleriyle birlikte kaldırılmış kayıtları tutabilir.<sup>[[4]](#references)</sup>

**`Sync_config.db`** veritabanının tablo verileri, hesabın e-posta adresini, paylaşılan klasörlerin yolunu ve Google Drive sürümünü içerir.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox, dosyaları yönetmek için **SQLite veritabanlarını** kullanır.<sup>[[2]](#references)</sup> Bu\
Veritabanlarını şu klasörlerde bulabilirsiniz:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Ana veritabanları şunlardır:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" uzantısı, **veritabanlarının** **şifrelenmiş** olduğu anlamına gelir. Dropbox, **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)) kullanır.<sup>[[1]](#references)</sup>

Dropbox'ın kullandığı şifrelemeyi daha iyi anlamak için [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) adresini okuyabilirsiniz.<sup>[[1]](#references)[[2]](#references)</sup>

Ancak temel bilgiler şunlardır:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Bu bilgilere ek olarak, veritabanlarının şifresini çözmek için hâlâ şunlara ihtiyacınız vardır:<sup>[[2]](#references)</sup>

- **Şifrelenmiş DPAPI anahtarı**: Bu anahtarı registry içinde `NTUSER.DAT\Software\Dropbox\ks\client` konumunda bulabilirsiniz (bu verileri binary olarak dışa aktarın)
- **`SYSTEM`** ve **`SECURITY`** hive'ları
- **DPAPI master key'leri**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` konumunda bulunabilirler
- Windows kullanıcısının **username** ve **password** bilgileri

Ardından [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** aracını kullanabilirsiniz:**

![Google Drive - Dropbox: Ardından DataProtectionDecryptor aracını kullanabilirsiniz](<../../../images/image (443).png>)

Her şey beklendiği gibi giderse araç, **asıl anahtarı kurtarmak için kullanmanız** gereken **primary key** değerini gösterecektir. Asıl anahtarı kurtarmak için bu [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) içindeki "passphrase" alanına primary key'i girmeniz yeterlidir.

Ortaya çıkan hex, veritabanlarını şifrelemek için kullanılan ve şu şekilde şifresi çözülebilen final key'dir:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** veritabanı şunları içerir:

- **Email**: Kullanıcının e-posta adresi
- **usernamedisplayname**: Kullanıcının adı
- **dropbox_path**: Dropbox klasörünün bulunduğu yol
- **Host_id: Hash**: Cloud üzerinde kimlik doğrulamak için kullanılır. Bu yalnızca web üzerinden iptal edilebilir.
- **Root_ns**: Kullanıcı tanımlayıcısı

**`filecache.db`** veritabanı, Dropbox ile senkronize edilen tüm dosya ve klasörler hakkında bilgi içerir. `File_journal` tablosu en faydalı bilgileri içeren tablodur:<sup>[[5]](#references)</sup>

- **Server_path**: Dosyanın server içinde bulunduğu yol (bu yolun başında istemcinin `host_id` değeri bulunur).
- **local_sjid**: Dosyanın sürümü
- **local_mtime**: Değiştirilme tarihi
- **local_ctime**: Oluşturulma tarihi

Bu veritabanındaki diğer tablolar daha ilginç bilgiler içerir:

- **block_cache**: Dropbox'taki tüm dosya ve klasörlerin hash değerleri
- **block_ref**: `block_cache` tablosundaki hash ID'sini `file_journal` tablosundaki dosya ID'siyle ilişkilendirir
- **mount_table**: Dropbox paylaşım klasörleri
- **deleted_fields**: Dropbox'tan silinen dosyalar
- **date_added**

## References

- [1] [Dropbox yazılım güvenliğinin kritik bir analizi (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX şifre çözme bilgilerinizi tazeleyin](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Cloud Storage Forensic Analysis (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: Leakage Answers](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Forensics](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows'ta Google Drive Kullanımına Ait Artifacts](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
