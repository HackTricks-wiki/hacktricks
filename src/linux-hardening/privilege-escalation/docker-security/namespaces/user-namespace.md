# User Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Bir kullanıcı ad alanı, **kullanıcı ve grup kimlik eşlemelerinin izolasyonunu sağlayan** bir Linux çekirdek özelliğidir ve her kullanıcı ad alanının **kendi kullanıcı ve grup kimlikleri setine** sahip olmasına olanak tanır. Bu izolasyon, farklı kullanıcı ad alanlarında çalışan süreçlerin **farklı ayrıcalıklara ve sahipliğe** sahip olmasını sağlar, hatta aynı kullanıcı ve grup kimliklerini sayısal olarak paylaşsalar bile.

Kullanıcı ad alanları, her bir konteynerin kendi bağımsız kullanıcı ve grup kimlikleri setine sahip olması gereken konteynerleştirmede özellikle faydalıdır ve bu, konteynerler ile ana sistem arasında daha iyi güvenlik ve izolasyon sağlar.

### Nasıl çalışır:

1. Yeni bir kullanıcı ad alanı oluşturulduğunda, **kullanıcı ve grup kimlik eşlemeleri için boş bir setle başlar**. Bu, yeni kullanıcı ad alanında çalışan herhangi bir sürecin **başlangıçta ad alanının dışındaki ayrıcalıklara sahip olmayacağı** anlamına gelir.
2. Yeni ad alanındaki kullanıcı ve grup kimlikleri ile ana (veya host) ad alanındaki kimlikler arasında eşlemeler kurulabilir. Bu, **yeni ad alanındaki süreçlerin ana ad alanındaki kullanıcı ve grup kimliklerine karşılık gelen ayrıcalıklara ve sahipliğe sahip olmasına olanak tanır**. Ancak, kimlik eşlemeleri belirli aralıklar ve alt kümelerle sınırlı tutulabilir, bu da yeni ad alanındaki süreçlere verilen ayrıcalıklar üzerinde ince ayar kontrolü sağlar.
3. Bir kullanıcı ad alanı içinde, **süreçler ad alanı içindeki işlemler için tam kök ayrıcalıklarına (UID 0) sahip olabilir**, aynı zamanda ad alanının dışındaki ayrıcalıkları sınırlı kalır. Bu, **konteynerlerin kendi ad alanlarında kök benzeri yeteneklerle çalışmasına olanak tanırken, ana sistemde tam kök ayrıcalıklarına sahip olmalarını engeller**.
4. Süreçler, `setns()` sistem çağrısını kullanarak ad alanları arasında geçiş yapabilir veya `CLONE_NEWUSER` bayrağı ile `unshare()` veya `clone()` sistem çağrılarını kullanarak yeni ad alanları oluşturabilir. Bir süreç yeni bir ad alanına geçtiğinde veya bir tane oluşturduğunda, o ad alanıyla ilişkili kullanıcı ve grup kimlik eşlemelerini kullanmaya başlayacaktır.

## Laboratuvar:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
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

- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluşturulurken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğinin kullanılmasıyla çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını sağlar. `/bin/bash` ve onun çocuk süreçleri bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştırılmasını sağlayarak, yeni PID ad alanının doğru bir şekilde korunmasını sağlarsınız, böylece `/bin/bash` ve alt süreçleri bellek tahsis hatası ile karşılaşmadan çalışabilir.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Kullanıcı ad alanını kullanmak için, Docker daemon'un **`--userns-remap=default`** ile başlatılması gerekir (Ubuntu 14.04'te, bu `/etc/default/docker` dosyasını değiştirerek ve ardından `sudo service docker restart` komutunu çalıştırarak yapılabilir).

### Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Docker konteynerinden kullanıcı haritasını kontrol etmek mümkündür:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ya da ana makineden:
```bash
cat /proc/<pid>/uid_map
```
### Tüm Kullanıcı ad alanlarını bul
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Kullanıcı ad alanına girin
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Ayrıca, **başka bir işlem ad alanına yalnızca root iseniz girebilirsiniz**. Ve **başka bir ad alanına** **giremezsiniz** **onu işaret eden bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/user`).

### Yeni Kullanıcı ad alanı oluşturun (eşlemelerle)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Yeteneklerin Kurtarılması

Kullanıcı ad alanları durumunda, **yeni bir kullanıcı ad alanı oluşturulduğunda, ad alanına giren işleme o ad alanı içinde tam bir yetenek seti verilir**. Bu yetenekler, işlemin **dosya sistemlerini** **monte etme**, cihazlar oluşturma veya dosyaların sahipliğini değiştirme gibi ayrıcalıklı işlemleri gerçekleştirmesine olanak tanır, ancak **yalnızca kendi kullanıcı ad alanı bağlamında**.

Örneğin, bir kullanıcı ad alanında `CAP_SYS_ADMIN` yeteneğine sahip olduğunuzda, genellikle bu yeteneği gerektiren işlemleri gerçekleştirebilirsiniz, örneğin dosya sistemlerini monte etme, ancak yalnızca kendi kullanıcı ad alanı bağlamında. Bu yetenekle gerçekleştirdiğiniz herhangi bir işlem, ana sistem veya diğer ad alanlarını etkilemeyecektir.

> [!WARNING]
> Bu nedenle, yeni bir Kullanıcı ad alanında yeni bir işlem almak **size tüm yeteneklerinizi geri verecektir** (CapEff: 000001ffffffffff), aslında **yalnızca ad alanı ile ilgili olanları kullanabilirsiniz** (örneğin monte etme) ama hepsini değil. Bu nedenle, bu kendi başına bir Docker konteynerinden kaçmak için yeterli değildir.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#include ../../../../banners/hacktricks-training.md}}
