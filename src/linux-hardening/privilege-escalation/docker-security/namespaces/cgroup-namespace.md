# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Cgroup namespace, **bir namespace içinde çalışan süreçler için cgroup hiyerarşilerinin izolasyonunu sağlayan** bir Linux çekirdek özelliğidir. Cgroups, **kontrol grupları** için kısaltmadır ve süreçleri hiyerarşik gruplar halinde organize ederek **sistem kaynakları** üzerinde (CPU, bellek ve I/O gibi) **sınırlamalar** yönetmeyi ve uygulamayı sağlar.

Cgroup namespace'leri, daha önce tartıştığımız diğerleri gibi ayrı bir namespace türü olmasa da (PID, mount, network vb.), namespace izolasyonu kavramıyla ilişkilidir. **Cgroup namespace'leri, cgroup hiyerarşisinin görünümünü sanallaştırır**, böylece bir cgroup namespace içinde çalışan süreçler, ana makinede veya diğer namespace'lerde çalışan süreçlere kıyasla hiyerarşinin farklı bir görünümüne sahip olurlar.

### Nasıl çalışır:

1. Yeni bir cgroup namespace oluşturulduğunda, **oluşturan sürecin cgroup'una dayanan bir cgroup hiyerarşisi görünümü ile başlar**. Bu, yeni cgroup namespace içinde çalışan süreçlerin, yalnızca oluşturucu sürecin cgroup'unda köklenen cgroup alt ağacına sınırlı olan tüm cgroup hiyerarşisinin bir alt kümesini göreceği anlamına gelir.
2. Bir cgroup namespace içindeki süreçler, **kendi cgroup'larını hiyerarşinin kökü olarak göreceklerdir**. Bu, namespace içindeki süreçlerin bakış açısından, kendi cgroup'larının kök olarak göründüğü ve kendi alt ağaçlarının dışındaki cgroup'ları göremeyecekleri veya erişemeyecekleri anlamına gelir.
3. Cgroup namespace'leri doğrudan kaynak izolasyonu sağlamaz; **yalnızca cgroup hiyerarşisi görünümünün izolasyonunu sağlar**. **Kaynak kontrolü ve izolasyonu hala cgroup** alt sistemleri (örneğin, cpu, bellek vb.) tarafından uygulanmaktadır.

CGroups hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratuvar:

### Farklı Namespace'ler Oluşturun

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresi ile monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerine doğru ve izole bir bakış** sağlamış olursunuz.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Sorun Açıklaması**:

- Linux çekirdeği, bir sürecin yeni ad alanları oluşturmasına `unshare` sistem çağrısı ile izin verir. Ancak, yeni bir PID ad alanı oluşturma işlemini başlatan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmez; yalnızca onun çocuk süreçleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanındadır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, bu ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:

- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluştururken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını garanti eder. `/bin/bash` ve onun çocuk süreçleri bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ile alt süreçlerinin bellek tahsis hatası ile karşılaşmadan çalışmasına olanak tanır.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Tüm CGroup ad alanlarını bul
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### CGroup ad alanına girin
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Ayrıca, **başka bir işlem ad alanına yalnızca root iseniz girebilirsiniz**. Ve **başka bir ad alanına** **giremezsiniz** **onu işaret eden bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/cgroup`).

## Referanslar

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
