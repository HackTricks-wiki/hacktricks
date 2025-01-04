# Yerel Bulut Depolama

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Windows'ta, OneDrive klasörünü `\Users\<username>\AppData\Local\Microsoft\OneDrive` içinde bulabilirsiniz. Ve `logs\Personal` içinde, senkronize edilmiş dosyalarla ilgili bazı ilginç verileri içeren `SyncDiagnostics.log` dosyasını bulmak mümkündür:

- Boyut (bayt cinsinden)
- Oluşturulma tarihi
- Değiştirilme tarihi
- Buluttaki dosya sayısı
- Klasördeki dosya sayısı
- **CID**: OneDrive kullanıcısının benzersiz kimliği
- Rapor oluşturma zamanı
- İşletim sisteminin HD boyutu

CID'yi bulduktan sonra, **bu kimliği içeren dosyaları aramanız önerilir**. _**\<CID>.ini**_ ve _**\<CID>.dat**_ gibi ilginç bilgiler içerebilecek dosyaları bulabilirsiniz; bu dosyalar OneDrive ile senkronize edilmiş dosyaların adlarını içerebilir.

## Google Drive

Windows'ta, ana Google Drive klasörünü `\Users\<username>\AppData\Local\Google\Drive\user_default` içinde bulabilirsiniz.\
Bu klasör, hesap e-posta adresi, dosya adları, zaman damgaları, dosyaların MD5 hash'leri gibi bilgileri içeren Sync_log.log adında bir dosya içerir. Silinmiş dosyalar bile bu günlük dosyasında ilgili MD5 ile görünmektedir.

**`Cloud_graph\Cloud_graph.db`** dosyası, **`cloud_graph_entry`** tablosunu içeren bir sqlite veritabanıdır. Bu tabloda, **senkronize** **dosyaların** **adı**, değiştirilme zamanı, boyut ve dosyaların MD5 kontrol toplamını bulabilirsiniz.

**`Sync_config.db`** veritabanının tablo verileri, hesap e-posta adresini, paylaşılan klasörlerin yolunu ve Google Drive sürümünü içerir.

## Dropbox

Dropbox, dosyaları yönetmek için **SQLite veritabanları** kullanır. Bu\
Veritabanlarını şu klasörlerde bulabilirsiniz:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Ve ana veritabanları şunlardır:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" uzantısı, **veritabanlarının** **şifreli** olduğunu gösterir. Dropbox, **DPAPI** kullanır ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Dropbox'un kullandığı şifrelemeyi daha iyi anlamak için [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html) adresini okuyabilirsiniz.

Ancak, ana bilgiler şunlardır:

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Bu bilgilere ek olarak, veritabanlarını şifrelerini çözmek için hala şunlara ihtiyacınız var:

- **şifreli DPAPI anahtarı**: Bunu `NTUSER.DAT\Software\Dropbox\ks\client` içinde kayıt defterinde bulabilirsiniz (bu veriyi ikili olarak dışa aktarın)
- **`SYSTEM`** ve **`SECURITY`** hives
- **DPAPI anahtarları**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` içinde bulunabilir
- Windows kullanıcısının **kullanıcı adı** ve **şifresi**

Sonra [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** aracını kullanabilirsiniz:**

![](<../../../images/image (448).png>)

Her şey beklendiği gibi giderse, araç, **orijinalini geri kazanmak için kullanmanız gereken anahtarı** gösterecektir. Orijinalini geri kazanmak için, bu [cyber_chef tarifi](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) kullanarak anahtarı tarifin "şifre" kısmına koyun.

Sonuçta elde edilen hex, veritabanlarını şifrelemek için kullanılan nihai anahtardır ve şu şekilde şifresi çözülebilir:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** veritabanı şunları içerir:

- **Email**: Kullanıcının e-posta adresi
- **usernamedisplayname**: Kullanıcının adı
- **dropbox_path**: Dropbox klasörünün bulunduğu yol
- **Host_id: Hash**: Buluta kimlik doğrulamak için kullanılan hash. Bu yalnızca web üzerinden iptal edilebilir.
- **Root_ns**: Kullanıcı tanımlayıcısı

**`filecache.db`** veritabanı, Dropbox ile senkronize edilen tüm dosyalar ve klasörler hakkında bilgi içerir. `File_journal` tablosu daha fazla yararlı bilgiye sahiptir:

- **Server_path**: Dosyanın sunucu içindeki bulunduğu yol (bu yol, istemcinin `host_id` ile önceden gelir).
- **local_sjid**: Dosyanın versiyonu
- **local_mtime**: Değiştirilme tarihi
- **local_ctime**: Oluşturulma tarihi

Bu veritabanındaki diğer tablolar daha ilginç bilgiler içerir:

- **block_cache**: Dropbox'ın tüm dosya ve klasörlerinin hash'i
- **block_ref**: `block_cache` tablosundaki hash ID'sini `file_journal` tablosundaki dosya ID'si ile ilişkilendirir
- **mount_table**: Dropbox'ın paylaşılan klasörleri
- **deleted_fields**: Dropbox'tan silinen dosyalar
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
