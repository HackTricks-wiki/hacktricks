# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

IPC (Inter-Process Communication) namespace, mesaj kuyrukları, paylaşılan bellek segmentleri ve semaforlar gibi System V IPC nesnelerinin **izolasyonunu** sağlayan bir Linux çekirdek özelliğidir. Bu izolasyon, **farklı IPC namespace'lerinde bulunan süreçlerin birbirlerinin IPC nesnelerine doğrudan erişememesi veya bunları değiştirememesi** anlamına gelir ve süreç grupları arasında ek bir güvenlik ve gizlilik katmanı sağlar.

### Nasıl çalışır:

1. Yeni bir IPC namespace oluşturulduğunda, **tamamen izole bir System V IPC nesne seti** ile başlar. Bu, yeni IPC namespace'inde çalışan süreçlerin varsayılan olarak diğer namespace'lerdeki veya ana sistemdeki IPC nesnelerine erişemeyeceği veya bunlarla etkileşime giremeyeceği anlamına gelir.
2. Bir namespace içinde oluşturulan IPC nesneleri, yalnızca o namespace içindeki süreçler tarafından **görülebilir ve erişilebilir**. Her IPC nesnesi, kendi namespace'i içinde benzersiz bir anahtar ile tanımlanır. Anahtar farklı namespace'lerde aynı olabilir, ancak nesneler kendileri izole edilmiştir ve namespace'ler arasında erişilemez.
3. Süreçler, `setns()` sistem çağrısını kullanarak namespace'ler arasında geçiş yapabilir veya `CLONE_NEWIPC` bayrağı ile `unshare()` veya `clone()` sistem çağrılarını kullanarak yeni namespace'ler oluşturabilir. Bir süreç yeni bir namespace'e geçtiğinde veya bir tane oluşturduğunda, o namespace ile ilişkili IPC nesnelerini kullanmaya başlayacaktır.

## Laboratuvar:

### Farklı Namespace'ler Oluşturma

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresi ile monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerini doğru ve izole bir şekilde görmesini** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Sorun Açıklaması**:

- Linux çekirdeği, bir sürecin `unshare` sistem çağrısını kullanarak yeni ad alanları oluşturmasına izin verir. Ancak, yeni bir PID ad alanı oluşturma işlemini başlatan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmez; yalnızca onun çocuk süreçleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanındadır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, bu ad alanında PID tahsisini devre dışı bırakır.

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
### Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Tüm IPC ad alanlarını bulma
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### IPC ad alanına girin
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Ayrıca, **başka bir işlem ad alanına yalnızca root iseniz girebilirsiniz**. Ve **başka bir ad alanına** **giremezsiniz** **onu işaret eden bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/net`).

### IPC nesnesi oluşturun
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Referanslar

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
