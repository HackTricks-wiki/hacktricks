# Yerel Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Windows'ta OneDrive klasörünü `\Users\<username>\AppData\Local\Microsoft\OneDrive` konumunda bulabilirsiniz. `logs\Personal` içinde, senkronize edilen dosyalarla ilgili bazı ilginç veriler içeren `SyncDiagnostics.log` dosyasını bulmak mümkündür:

- Bayt cinsinden boyut
- Oluşturulma tarihi
- Değiştirilme tarihi
- Cloud'daki dosya sayısı
- Klasördeki dosya sayısı
- **CID**: OneDrive kullanıcısının benzersiz kimliği
- Rapor oluşturma zamanı
- İşletim sisteminin bulunduğu HD'nin boyutu

CID'yi bulduktan sonra **bu kimliği içeren dosyaları aramanız** önerilir. _**\<CID>.ini**_ ve _**\<CID>.dat**_ adlarında, OneDrive ile senkronize edilen dosyaların adları gibi ilginç bilgiler içerebilecek dosyalar bulabilirsiniz.

## Google Drive

Windows'ta ana Google Drive klasörünü `\Users\<username>\AppData\Local\Google\Drive\user_default`\
konumunda bulabilirsiniz. Bu klasör, hesabın e-posta adresi, dosya adları, zaman damgaları, dosyaların MD5 hash'leri vb. bilgileri içeren Sync_log.log adlı bir dosya barındırır. Silinen dosyalar bile karşılık gelen MD5 değerleriyle birlikte bu log dosyasında görünür.

**`Cloud_graph\Cloud_graph.db`** dosyası, **`cloud_graph_entry`** tablosunu içeren bir sqlite veritabanıdır. Bu tabloda **senkronize edilmiş** **dosyaların** **adını**, değiştirilme zamanını, boyutunu ve dosyaların MD5 checksum değerini bulabilirsiniz.

**`Sync_config.db`** veritabanının tablo verileri, hesabın e-posta adresini, paylaşılan klasörlerin yolunu ve Google Drive sürümünü içerir.

## Dropbox

Dropbox, dosyaları yönetmek için **SQLite veritabanlarını** kullanır. Bu\
Veritabanlarını şu klasörlerde bulabilirsiniz:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Ana veritabanları şunlardır:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" uzantısı **veritabanlarının** **şifrelenmiş** olduğu anlamına gelir. Dropbox, **DPAPI** kullanır ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Dropbox'ın kullandığı şifrelemeyi daha iyi anlamak için [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) adresini okuyabilirsiniz.<sup>[[1]](#references)[[2]](#references)</sup>

Ancak temel bilgiler şunlardır:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Bu bilgilerin yanı sıra veritabanlarının şifresini çözmek için hâlâ şunlara ihtiyacınız vardır:<sup>[[2]](#references)</sup>

- **Şifrelenmiş DPAPI anahtarı**: Bunu registry içinde `NTUSER.DAT\Software\Dropbox\ks\client` konumunda bulabilirsiniz (bu verileri binary olarak dışa aktarın)
- **`SYSTEM`** ve **`SECURITY`** hive'ları
- **DPAPI master key'leri**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` konumunda bulunabilir
- Windows kullanıcısının **username** ve **password** bilgileri

Ardından [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** aracını kullanabilirsiniz:**

![Google Drive - Dropbox: Ardından DataProtectionDecryptor aracını kullanabilirsiniz](<../../../images/image (443).png>)

Her şey beklendiği gibi giderse araç, **asıl anahtarı kurtarmak için kullanmanız** gereken **primary key**'i gösterecektir. Asıl anahtarı kurtarmak için bu [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) dosyasını kullanın ve primary key'i receipt içindeki "passphrase" olarak girin.

Ortaya çıkan hex, veritabanlarını şifrelemek için kullanılan ve şu araçla şifresi çözülebilen nihai anahtardır:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** veritabanı şunları içerir:

- **Email**: Kullanıcının e-posta adresi
- **usernamedisplayname**: Kullanıcının adı
- **dropbox_path**: Dropbox klasörünün bulunduğu yol
- **Host_id: Hash**: Cloud'a authentication için kullanılan **Hash**. Bu yalnızca web üzerinden revoke edilebilir.
- **Root_ns**: Kullanıcı identifier'ı

**`filecache.db`** veritabanı, Dropbox ile synchronize edilen tüm dosya ve klasörler hakkında bilgiler içerir. `File_journal` tablosu en kullanışlı bilgileri içeren tablodur:

- **Server_path**: Dosyanın server içindeki bulunduğu yol (bu yolun önünde client'ın `host_id` değeri bulunur).
- **local_sjid**: Dosyanın sürümü
- **local_mtime**: Değiştirilme tarihi
- **local_ctime**: Oluşturulma tarihi

Bu veritabanındaki diğer tablolar daha ilginç bilgiler içerir:

- **block_cache**: Dropbox'taki tüm dosya ve klasörlerin **hash** değerleri
- **block_ref**: `block_cache` tablosundaki **hash ID** değerini `file_journal` tablosundaki dosya ID'siyle ilişkilendirir
- **mount_table**: Dropbox'ın paylaşılan klasörleri
- **deleted_fields**: Dropbox'tan silinen dosyalar
- **date_added**

## References

- [1] [Dropbox software security'nin kritik analizi (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX decryption bilgilerinizi tazeleyin](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
