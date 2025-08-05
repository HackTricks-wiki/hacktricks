# Zaman Ad Alanı

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Linux'taki zaman ad alanı, sistemin monotonik ve önyükleme zamanı saatlerine göre ad alanı başına ofsetler sağlar. Genellikle Linux konteynerlerinde, bir konteyner içindeki tarih/saatin değiştirilmesi ve bir kontrol noktasından veya anlık görüntüden geri yüklendikten sonra saatlerin ayarlanması için kullanılır.

## Laboratuvar:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresi ile monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerini doğru ve izole bir şekilde görmesini** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Sorun Açıklaması**:

- Linux çekirdeği, bir sürecin yeni ad alanları oluşturmasına `unshare` sistem çağrısı ile izin verir. Ancak, yeni bir PID ad alanı oluşturma işlemini başlatan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmez; yalnızca onun çocuk süreçleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanında kalır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, bu ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:

- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluşturulurken `alloc_pid` fonksiyonunun yeni bir PID tahsis etmesini engelleyerek "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğinin kullanılmasıyla çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını garanti eder. `/bin/bash` ve onun çocuk süreçleri bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ile alt süreçlerinin bellek tahsis hatası ile karşılaşmadan çalışmasına olanak tanır.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Tüm Zaman ad alanlarını Bulun
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Zaman ad alanına girin
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Zaman Ofsetlerini Manipüle Etme

Linux 5.6 ile birlikte, her zaman ad alanı için iki saat sanallaştırılabilir:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Her bir ad alanına ait farklar, `/proc/<PID>/timens_offsets` dosyası aracılığıyla açığa çıkar (ve değiştirilebilir):
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
Dosya, her bir saat için birer satır içermekte ve **nanosecond** cinsinden ofseti göstermektedir. **CAP_SYS_TIME** _zaman ad alanında_ bulunan süreçler bu değeri değiştirebilir:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
Eğer duvar saati (`CLOCK_REALTIME`) değişmesini istiyorsanız, yine klasik mekanizmalara (`date`, `hwclock`, `chronyd`, …) güvenmek zorundasınız; bu **ad alanı** değildir.


### `unshare(1)` yardımcı bayrakları (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
Uzun seçenekler, seçilen delta'ları `timens_offsets`'a otomatik olarak yazar, bu da manuel bir `echo` gerektirmez.

---

## OCI & Runtime desteği

* **OCI Runtime Specification v1.1** (Kasım 2023), konteyner motorlarının taşınabilir bir şekilde zaman sanallaştırması talep edebilmesi için özel bir `time` namespace türü ve `linux.timeOffsets` alanını ekledi.
* **runc >= 1.2.0**, spesifikasyonun bu kısmını uygular. Minimal bir `config.json` parçası şöyle görünür:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Sonra konteyneri `runc run <id>` ile çalıştırın.

>  NOT: runc **1.2.6** (Şubat 2025), bir "özel timens ile konteynere exec" hatasını düzeltti; bu hata bir takılmaya ve potansiyel DoS'a yol açabilirdi. Üretimde ≥ 1.2.6 sürümünde olduğunuzdan emin olun.

---

## Güvenlik hususları

1. **Gerekli yetki** – Bir işlemin, offset'leri değiştirmek için kullanıcı/zaman namespace'i içinde **CAP_SYS_TIME** yetkisine ihtiyacı vardır. Bu yetkinin konteynerde (Docker & Kubernetes'te varsayılan) düşürülmesi, müdahaleyi engeller.
2. **Duvar saati değişiklikleri yok** – `CLOCK_REALTIME` ana makine ile paylaşıldığı için, saldırganlar yalnızca timens aracılığıyla sertifika ömürlerini, JWT süresini vb. taklit edemez.
3. **Log / tespit kaçışı** – `CLOCK_MONOTONIC`'a (örneğin, çalışma süresine dayalı oran sınırlayıcılar) dayanan yazılımlar, namespace kullanıcısı offset'i ayarladığında karışıklık yaşayabilir. Güvenlik açısından önemli zaman damgaları için `CLOCK_REALTIME`'ı tercih edin.
4. **Kernel saldırı yüzeyi** – `CAP_SYS_TIME` kaldırılmış olsa bile, kernel kodu erişilebilir kalır; ana makineyi güncel tutun. Linux 5.6 → 5.12, bir dizi timens hata düzeltmesi aldı (NULL-deref, işaretleme sorunları).

### Güçlendirme kontrol listesi

* Konteyner çalışma zamanı varsayılan profilinizde `CAP_SYS_TIME`'ı kaldırın.
* Çalışma zamanlarını güncel tutun (runc ≥ 1.2.6, crun ≥ 1.12).
* `--monotonic/--boottime` yardımcılarına güveniyorsanız util-linux ≥ 2.38 sürümüne sabitleyin.
* Güvenlik kritik mantık için **uptime** veya **CLOCK_MONOTONIC** okuyan konteyner içi yazılımları denetleyin.

## Referanslar

* man7.org – Zaman namespace'leri kılavuz sayfası: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI blog – "OCI v1.1: yeni zaman ve RDT namespace'leri" (15 Kasım 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
