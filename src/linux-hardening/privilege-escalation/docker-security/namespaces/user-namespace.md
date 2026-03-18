# Kullanıcı Namespace

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referanslar

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Temel Bilgiler

Bir kullanıcı namespace'i, **kullanıcı ve grup ID eşlemelerinin izolasyonunu sağlayan** bir Linux kernel özelliğidir; her kullanıcı namespace'inin **kendi kullanıcı ve grup ID setine** sahip olmasına izin verir. Bu izolasyon, farklı user namespace'lerde çalışan süreçlerin sayısal olarak aynı kullanıcı ve grup ID'lerini paylaşsalar bile **farklı ayrıcalıklara ve sahipliklere** sahip olmasını mümkün kılar.

Kullanıcı namespace'leri, her container'ın kendi bağımsız kullanıcı ve grup ID setine sahip olması gereken containerization ortamlarında özellikle yararlıdır; bu da container'lar ile host sistemi arasında daha iyi güvenlik ve izolasyon sağlar.

### Nasıl çalışır:

1. Yeni bir kullanıcı namespace'i oluşturulduğunda, **boş bir kullanıcı ve grup ID eşlemeleri seti ile başlar**. Bu, yeni namespace'te çalışan herhangi bir sürecin **başlangıçta namespace dışındaki hiçbir ayrıcalığa sahip olmayacağı** anlamına gelir.
2. Yeni namespace'teki kullanıcı ve grup ID'leri ile üst (veya host) namespace'teki ID'ler arasında eşlemeler kurulabilir. Bu, **yeni namespace'teki süreçlerin, üst namespace'teki kullanıcı ve grup ID'lerine karşı gelen ayrıcalık ve sahipliğe sahip olmasına** izin verir. Ancak, ID eşlemeleri belirli aralıklara ve ID alt kümelerine kısıtlanabilir; bu da yeni namespace'teki süreçlere verilen ayrıcalıklar üzerinde ince ayar yapılmasına olanak sağlar.
3. Bir user namespace içinde, **süreçler namespace içindeki operasyonlar için tam root ayrıcalıklarına (UID 0) sahip olabilir**, aynı zamanda namespace dışında sınırlı ayrıcalıklara sahip olmaya devam ederler. Bu, **container'ların kendi namespace'leri içinde root benzeri yeteneklerle çalışmasına, ancak host sistemde tam root ayrıcalıklarına sahip olmamasına** izin verir.
4. Süreçler `setns()` sistem çağrısını kullanarak namespace'ler arasında hareket edebilir veya `unshare()` ya da `clone()` sistem çağrılarını `CLONE_NEWUSER` bayrağı ile kullanarak yeni namespace'ler oluşturabilir. Bir süreç yeni bir namespace'e geçtiğinde veya bir tane oluşturduğunda, o namespace ile ilişkilendirilmiş kullanıcı ve grup ID eşlemelerini kullanmaya başlar.

## Lab:

### Farklı Namespace'ler Oluşturma

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Sorunun Açıklaması**:

- Linux kernel'i, bir sürecin `unshare` sistem çağrısını kullanarak yeni namespace'ler oluşturmasına izin verir. Ancak yeni bir PID namespace'inin oluşturulmasını başlatan süreç (\"unshare\" süreci olarak anılan) yeni namespace'e girmez; yalnızca onun alt süreçleri girer.
- Running %unshare -p /bin/bash% starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- Yeni namespace'te `/bin/bash`'in ilk alt süreci PID 1 olur. Bu süreç sonlandığında, eğer başka süreç yoksa namespace'in temizlenmesini tetikler; zira PID 1'in öksüz süreçleri devralma gibi özel bir rolü vardır. Linux kernel'i daha sonra o namespace'te PID tahsisini devre dışı bırakır.

2. **Sonuç**:

- Yeni bir namespace'te PID 1'in çıkışı `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu da yeni bir süreç oluşturulurken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine ve "Cannot allocate memory" hatasının oluşmasına neden olur.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğinin kullanılmasıyla çözülebilir. Bu seçenek, `unshare`'in yeni PID namespace'i oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- %unshare -fp /bin/bash% çalıştırılması, `unshare` komutunun kendisinin yeni namespace'te PID 1 olmasını sağlar. `/bin/bash` ve onun alt süreçleri bu yeni namespace içinde güvenle tutulur; böylece PID 1'in erken çıkışı engellenir ve normal PID tahsisi mümkün olur.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
user namespace kullanmak için, Docker daemon **`--userns-remap=default`** ile başlatılmalıdır (Ubuntu 14.04'te bu, `/etc/default/docker` dosyasını değiştirip sonra `sudo service docker restart` komutunu çalıştırarak yapılabilir)

### Sürecinizin hangi namespace içinde olduğunu kontrol edin
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
docker konteynerinden kullanıcı haritasını şu komutla kontrol etmek mümkündür:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Veya host'tan şu komutla:
```bash
cat /proc/<pid>/uid_map
```
### Tüm kullanıcı namespace'lerini bul
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Kullanıcı namespace'ine girin
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Ayrıca, sadece **root iseniz başka bir süreç namespace'ine girebilirsiniz**. Ve bir **tanımlayıcı** ona işaret etmeden (ör. `/proc/self/ns/user`) başka bir namespace'e **giremezsiniz**.

### Yeni User namespace oluştur (eşlemelerle)
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
### Ayrıcalı Olmayan UID/GID Eşleme Kuralları

`uid_map`/`gid_map`'e yazan süreç **ebeveyn user namespace'inde CAP_SETUID/CAP_SETGID'e sahip değilse**, çekirdek daha katı kurallar uygular: çağıranın etkili UID/GID'si için yalnızca **tek bir eşleme** izin verilir ve `gid_map` için `/proc/<pid>/setgroups` dosyasına `deny` yazarak `setgroups(2)`'yi **önce devre dışı bırakmalısınız**.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mounts bir mount'a bir user namespace eşlemesi ekler, bu nedenle o mount üzerinden erişildiğinde dosya sahipliği yeniden eşlenir. Bu, container runtimes (özellikle rootless) tarafından host yollarını recursive `chown` yapmadan paylaşmak için sık kullanılır; aynı zamanda user namespace'in UID/GID çevirimini uygular.

Ofansif açıdan, eğer bir mount namespace oluşturup user namespace'iniz içinde CAP_SYS_ADMIN'e sahipseniz ve filesystem ID-mapped mounts'ı destekliyorsa, bind mount'ların sahiplik *görünümlerini* yeniden eşleyebilirsiniz. Bu diskteki gerçek sahipliği değiştirmez; ancak namespace içinde, aksi takdirde yazılamayan dosyaların map'lenmiş UID/GID'niz tarafından sahiplenilmiş gibi görünmesini sağlayabilir.

### Recovering Capabilities

User namespaces durumunda, yeni bir user namespace oluşturulduğunda namespace'e giren sürece o namespace içinde tam bir yetki kümesi verilir. Bu yetkiler, sürecin dosya sistemlerini mount etme, device oluşturma veya dosya sahipliğini değiştirme gibi ayrıcalıklı işlemleri yapmasına izin verir; ancak sadece kendi user namespace bağlamında.

Örneğin, bir user namespace içinde CAP_SYS_ADMIN yetkisine sahipseniz, genellikle bu yetkiyi gerektiren işlemleri (dosya sistemlerini mount etmek gibi) gerçekleştirebilirsiniz; fakat yalnızca kendi user namespace bağlamında. Bu yetkiyle yaptığınız işlemler host sistemini veya diğer namespace'leri etkilemez.

> [!WARNING]
> Bu yüzden, yeni bir User namespace içine yeni bir process almak size tüm yetkileri geri verse bile (CapEff: 000001ffffffffff), aslında sadece namespace ile ilgili olanları (örneğin mount) kullanabilirsiniz, hepsini değil. Yani tek başına bu, bir Docker container'dan kaçmak için yeterli değildir.
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
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referanslar

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
