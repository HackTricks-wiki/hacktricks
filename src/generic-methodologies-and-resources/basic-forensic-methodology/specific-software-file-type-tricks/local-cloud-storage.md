# Yerel Cloud Depolama

{{#include ../../../banners/hacktricks-training.md}}

## Yerel depolama emülatörleri ve hesap anahtarları

Bir container içinde çalışan Azure uyumlu Blob emülatörüne, depolama hizmeti dışarıya açılmamış olsa bile ana makineden veya bridge ağından erişilebilir. Okunabilir yerel yapılandırma ve yedek dosyası meta verilerinde hesap adı ve anahtar arayın; rutin listeleme sırasında anahtarı yazdırmayın. [Azurite özel yerel hesap anahtarlarını destekler](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key yetkilendirmesi](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access), eşleşen hesabın verilerine geniş erişim sağlayabilir. Tek başına bir anahtar dosyası, ayrıcalık yükseltme olduğunu kanıtlamaz: endpoint'e erişilebildiğini, hesap ve anahtarın kabul edildiğini ve ilgili blob'un daha yüksek ayrıcalıklı bir kimlik için kullanılabilir bir kimlik bilgisi içerdiğini doğrulayın. Blob bir SSH private key içeriyorsa bu kimliğin ilgili public key'e de izin vermesi ve SSH erişimine müsaade edilmesi gerekir. Anahtarın açığa çıktığı doğrulanırsa anahtarı koruyun ve yenileyin.

## OneDrive

Windows'ta OneDrive klasörünü `\Users\<username>\AppData\Local\Microsoft\OneDrive` konumunda bulabilirsiniz. `logs\Personal` içinde eşitlenen dosyalarla ilgili bazı ilginç veriler içeren `SyncDiagnostics.log` dosyasını bulmak mümkündür:<sup>[[3]](#references)</sup>

- Bayt cinsinden boyut
- Oluşturulma tarihi
- Değiştirilme tarihi
- Cloud'daki dosya sayısı
- Klasördeki dosya sayısı
- **CID**: OneDrive kullanıcısının benzersiz ID'si
- Raporun oluşturulma zamanı
- OS'nin HD boyutu

CID'yi bulduğunuzda **bu ID'yi içeren dosyaları aramanız** önerilir. OneDrive ile eşitlenen dosyaların adları gibi ilginç bilgiler içerebilecek _**\<CID>.ini**_ ve _**\<CID>.dat**_ adlı dosyalar bulabilirsiniz.<sup>[[3]](#references)</sup>

## Google Drive

Windows'ta ana Google Drive klasörünü `\Users\<username>\AppData\Local\Google\Drive\user_default` konumunda bulabilirsiniz.\
Bu klasör, Google Drive istemcisinin eşitleme oturumlarını ve dosya oluşturma, değiştirme ve silme olaylarını kaydeden Sync_log.log adlı bir dosya içerir.<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** dosyası bir SQLite veritabanıdır.<sup>[[6]](#references)</sup> Bu dosyada **`cloud_graph_entry`** tablosu bulunur. Bu tabloda **eşitlenen** **dosyaların** **adını**, değiştirilme zamanını, boyutunu ve MD5 checksum değerini bulabilirsiniz.

İlişkili **`snapshot.db`** veritabanının **`cloud_entry`** tablosunda silinmiş kayıtlar; dosya adları, zaman damgaları, boyutlar ve checksum değerleriyle birlikte tutulabilir.<sup>[[4]](#references)</sup>

**`Sync_config.db`** veritabanının tablo verileri, hesabın e-posta adresini, paylaşılan klasörlerin yolunu ve Google Drive sürümünü içerir.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox, dosyaları yönetmek için **SQLite veritabanları** kullanır.<sup>[[2]](#references)</sup> Bu veritabanlarını şu klasörlerde bulabilirsiniz:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Ana veritabanları şunlardır:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" uzantısı **veritabanlarının** **şifreli** olduğu anlamına gelir. Dropbox, **DPAPI** kullanır ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Dropbox'ın kullandığı şifrelemeyi daha iyi anlamak için [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) yazısını okuyabilirsiniz.<sup>[[1]](#references)[[2]](#references)</sup>

Ancak temel bilgiler şunlardır:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Bu bilgilere ek olarak, veritabanlarının şifresini çözmek için şunlara da ihtiyacınız vardır:<sup>[[2]](#references)</sup>

- **Şifrelenmiş DPAPI key**: Bu anahtarı registry içinde `NTUSER.DAT\Software\Dropbox\ks\client` konumunda bulabilirsiniz (bu verileri binary olarak dışa aktarın)
- **`SYSTEM`** ve **`SECURITY`** hive'ları
- **DPAPI master key'leri**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` konumunda bulunabilirler
- Windows kullanıcısının **username** ve **password** bilgileri

Ardından [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** aracını kullanabilirsiniz:**

![Google Drive - Dropbox: Ardından DataProtectionDecryptor aracını kullanabilirsiniz](<../../../images/image (443).png>)

Her şey beklendiği gibi giderse araç, orijinal anahtarı kurtarmak için **kullanmanız gereken** **primary key**'i belirtir. Orijinal anahtarı kurtarmak için, primary key'i tarifteki "passphrase" alanına girerek bu [cyber_chef tarifi](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) kullanın.

Ortaya çıkan hex, veritabanlarını şifrelemek için kullanılan nihai anahtardır; veritabanlarının şifresi şu şekilde çözülebilir:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

**`config.dbx`** veritabanı şunları içerir:

- **Email**: Kullanıcının e-posta adresi
- **usernamedisplayname**: Kullanıcının adı
- **dropbox_path**: Dropbox klasörünün bulunduğu yol
- **Host_id: Hash**: Buluta kimlik doğrulaması yapmak için kullanılan hash. Bu yalnızca web üzerinden iptal edilebilir.
- **Root_ns**: Kullanıcı tanımlayıcısı

**`filecache.db`** veritabanı, Dropbox ile senkronize edilen tüm dosya ve klasörler hakkında bilgi içerir. `File_journal` tablosu en faydalı bilgileri barındırır:<sup>[[5]](#references)</sup>

- **Server_path**: Dosyanın sunucu içindeki konumu (bu yolun önünde istemcinin `host_id` değeri bulunur).
- **local_sjid**: Dosyanın sürümü
- **local_mtime**: Değiştirilme tarihi
- **local_ctime**: Oluşturulma tarihi

Bu veritabanındaki diğer tablolar daha ilginç bilgiler içerir:

- **block_cache**: Dropbox'taki tüm dosya ve klasörlerin hash değerleri
- **block_ref**: `block_cache` tablosundaki hash ID'sini `file_journal` tablosundaki dosya ID'siyle ilişkilendirir
- **mount_table**: Dropbox'ın paylaşılan klasörleri
- **deleted_fields**: Dropbox'tan silinen dosyalar
- **date_added**

## References

- [1] [Dropbox yazılım güvenliğinin eleştirel bir analizi (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX şifre çözme bilgilerini tazeleyin](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Bulut Depolama Adli Analizi (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Veri Sızıntısı Vakası: Sızıntı Yanıtları](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Adli İncelemesi](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows'ta Google Drive Kullanımına Ait İzler](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
