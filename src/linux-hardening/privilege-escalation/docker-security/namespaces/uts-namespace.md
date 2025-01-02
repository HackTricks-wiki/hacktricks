# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

UTS (UNIX Zaman Paylaşım Sistemi) ad alanı, iki sistem tanımlayıcısının **izolasyonunu** sağlayan bir Linux çekirdek özelliğidir: **hostname** ve **NIS** (Ağ Bilgi Servisi) alan adı. Bu izolasyon, her UTS ad alanının **kendi bağımsız hostname ve NIS alan adına** sahip olmasına olanak tanır; bu, her bir konteynerin kendi hostname'i ile ayrı bir sistem olarak görünmesi gereken konteynerleştirme senaryolarında özellikle faydalıdır.

### Nasıl çalışır:

1. Yeni bir UTS ad alanı oluşturulduğunda, **ebeveyn ad alanından hostname ve NIS alan adının bir kopyasıyla** başlar. Bu, oluşturulduğunda yeni ad alanının **ebeveyniyle aynı tanımlayıcıları paylaştığı** anlamına gelir. Ancak, ad alanı içindeki hostname veya NIS alan adı üzerindeki sonraki değişiklikler diğer ad alanlarını etkilemeyecektir.
2. UTS ad alanı içindeki süreçler, sırasıyla `sethostname()` ve `setdomainname()` sistem çağrılarını kullanarak **hostname ve NIS alan adını değiştirebilir**. Bu değişiklikler ad alanına özgüdür ve diğer ad alanlarını veya ana sistemini etkilemez.
3. Süreçler, `setns()` sistem çağrısını kullanarak ad alanları arasında geçiş yapabilir veya `CLONE_NEWUTS` bayrağı ile `unshare()` veya `clone()` sistem çağrılarını kullanarak yeni ad alanları oluşturabilir. Bir süreç yeni bir ad alanına geçtiğinde veya bir tane oluşturduğunda, o ad alanıyla ilişkili hostname ve NIS alan adını kullanmaya başlayacaktır.

## Laboratuvar:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Yeni bir `/proc` dosya sisteminin örneğini monte ederek `--mount-proc` parametresini kullanırsanız, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerini doğru ve izole bir şekilde görmesini** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Problem Açıklaması**:

- Linux çekirdeği, bir sürecin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanı oluşturma işlemini başlatan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmez; yalnızca onun çocuk süreçleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanındadır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, o ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:

- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluştururken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını sağlar. `/bin/bash` ve onun çocuk süreçleri bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ile alt süreçleri bellek tahsis hatası ile karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Tüm UTS ad alanlarını bul
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTS ad alanına girin
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
