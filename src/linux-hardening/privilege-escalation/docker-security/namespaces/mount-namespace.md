# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Mount namespace, bir grup işlemin gördüğü dosya sistemi mount noktalarının izolasyonunu sağlayan bir Linux çekirdek özelliğidir. Her mount namespace'in kendi dosya sistemi mount noktaları seti vardır ve **bir namespace'deki mount noktalarındaki değişiklikler diğer namespace'leri etkilemez**. Bu, farklı mount namespace'lerinde çalışan süreçlerin dosya sistemi hiyerarşisinin farklı görünümlerine sahip olabileceği anlamına gelir.

Mount namespace'leri, her bir konteynerin diğer konteynerlerden ve ana sistemden izole edilmiş kendi dosya sistemi ve yapılandırmasına sahip olması gerektiği konteynerleştirmede özellikle faydalıdır.

### Nasıl çalışır:

1. Yeni bir mount namespace oluşturulduğunda, **ebeveyn namespace'inden mount noktalarının bir kopyasıyla başlatılır**. Bu, oluşturulduğunda yeni namespace'in ebeveyn ile aynı dosya sistemi görünümünü paylaştığı anlamına gelir. Ancak, namespace içindeki mount noktalarındaki sonraki değişiklikler ebeveyni veya diğer namespace'leri etkilemeyecektir.
2. Bir süreç, kendi namespace'i içinde bir mount noktasını değiştirdiğinde, örneğin bir dosya sistemini mount veya unmount ettiğinde, **değişiklik o namespace'e özeldir** ve diğer namespace'leri etkilemez. Bu, her namespace'in kendi bağımsız dosya sistemi hiyerarşisine sahip olmasını sağlar.
3. Süreçler, `setns()` sistem çağrısını kullanarak namespace'ler arasında geçiş yapabilir veya `CLONE_NEWNS` bayrağı ile `unshare()` veya `clone()` sistem çağrılarını kullanarak yeni namespace'ler oluşturabilir. Bir süreç yeni bir namespace'e geçtiğinde veya oluşturduğunda, o namespace ile ilişkili mount noktalarını kullanmaya başlayacaktır.
4. **Dosya tanımlayıcıları ve inode'lar namespace'ler arasında paylaşılır**, yani bir namespace'deki bir süreç, bir dosyaya işaret eden açık bir dosya tanımlayıcısına sahipse, bu dosya tanımlayıcısını başka bir namespace'deki bir sürece **geçirebilir** ve **her iki süreç de aynı dosyaya erişecektir**. Ancak, dosyanın yolu, mount noktalarındaki farklılıklar nedeniyle her iki namespace'de aynı olmayabilir.

## Laboratuvar:

### Farklı Namespace'ler Oluşturma

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresi ile monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerine doğru ve izole bir görünüm** sağladığınızı garanti edersiniz.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Problem Açıklaması**:

- Linux çekirdeği, bir sürecin yeni ad alanları oluşturmasına `unshare` sistem çağrısı ile izin verir. Ancak, yeni bir PID ad alanı oluşturan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmez; yalnızca onun çocuk süreçleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanındadır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, o ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:

- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluştururken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını garanti eder. `/bin/bash` ve onun çocuk süreçleri, bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştığından emin olarak, yeni PID ad alanı doğru bir şekilde korunur ve `/bin/bash` ile alt süreçlerinin bellek tahsis hatası ile karşılaşmadan çalışmasına olanak tanır.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Tüm Mount ad alanlarını bul
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Bir Mount ad alanına girin
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Ayrıca, **başka bir işlem ad alanına yalnızca root iseniz girebilirsiniz**. Ve **başka bir ad alanına** **giremezsiniz** **onu işaret eden bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/mnt`).

Yeni montajlar yalnızca ad alanı içinde erişilebilir olduğundan, bir ad alanının yalnızca oradan erişilebilen hassas bilgileri içermesi mümkündür.

### Bir şeyi monte et
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Referanslar

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
