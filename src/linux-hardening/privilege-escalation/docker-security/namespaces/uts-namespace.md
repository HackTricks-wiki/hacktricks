# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

A UTS (UNIX Time-Sharing System) namespace, iki sistem tanımlayıcısının **izolasyonunu** sağlayan bir Linux çekirdek özelliğidir: **hostname** ve **NIS** (Network Information Service) alan adı. Bu izolasyon, her UTS namespace'in kendi **bağımsız hostname ve NIS alan adına** sahip olmasına olanak tanır; bu durum, her container'ın kendi hostname'iyle ayrı bir sistemmiş gibi görünmesi gereken containerization senaryolarında özellikle kullanışlıdır.

### Nasıl çalışır:

1. Yeni bir UTS namespace oluşturulduğunda, parent namespace'inden **hostname ve NIS alan adının bir kopyasıyla başlar**. Bu, oluşturulma sırasında yeni namespace'in **üst namespace ile aynı tanımlayıcıları paylaşacağı** anlamına gelir. Ancak, namespace içinde yapılan sonraki herhangi bir hostname veya NIS alan adı değişikliği diğer namespace'leri etkilemez.
2. UTS namespace içindeki süreçler sırasıyla `sethostname()` ve `setdomainname()` system call'larını kullanarak **hostname ve NIS alan adını değiştirebilir**. Bu değişiklikler namespace'e özeldir ve diğer namespace'leri ya da host sistemini etkilemez.
3. Süreçler `setns()` system call'u ile namespace'ler arasında geçiş yapabilir veya `unshare()` ya da `clone()` system call'ları ile `CLONE_NEWUTS` bayrağını kullanarak yeni namespace'ler oluşturabilir. Bir süreç yeni bir namespace'e geçtiğinde veya bir tane oluşturduğunda, o namespace ile ilişkili hostname ve NIS alan adını kullanmaya başlar.

## Laboratuvar:

### Farklı Namespaces Oluşturma

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- Linux çekirdeği, bir işlemin `unshare` sistem çağrısını kullanarak yeni namespace'ler oluşturmasına izin verir. Ancak yeni bir PID namespace'inin oluşturulmasını başlatan süreç ("unshare" süreci olarak adlandırılan) yeni namespace'e girmez; sadece onun alt süreçleri girer.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- Yeni namespace'teki `/bin/bash`'in ilk alt süreci PID 1 olur. Bu süreç sonlandığında, eğer başka süreç yoksa namespace'in temizlenmesini tetikler; çünkü PID 1 yetim süreçleri devralma gibi özel bir role sahiptir. Linux çekirdeği daha sonra o namespace'de PID tahsisini devre dışı bırakır.

2. **Consequence**:

- Yeni namespace'te PID 1'in çıkışı `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluşturulurken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine ve "Cannot allocate memory" hatasının ortaya çıkmasına neden olur.

3. **Solution**:
- Sorun, `unshare` ile `-f` seçeneği kullanılarak çözülebilir. Bu seçenek, yeni PID namespace'i oluşturduktan sonra `unshare`'in yeni bir süreç fork etmesini sağlar.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### İşleminizin hangi namespace'te olduğunu kontrol edin
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Tüm UTS namespaces'lerini bulun
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Bir UTS namespace içine girin
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Host UTS paylaşımının kötüye kullanılması

Bir container `--uts=host` ile başlatılırsa, izole bir UTS namespace'i almak yerine host UTS namespace'ine katılır. `--cap-add SYS_ADMIN` gibi yetkilerle, container içindeki kod host'un hostname/NIS name'ini `sethostname()`/`setdomainname()` aracılığıyla değiştirebilir:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Host name'i değiştirmek logs/alerts üzerinde tahribata yol açabilir, cluster discovery'i yanıltabilir veya hostname'i pinleyen TLS/SSH konfigürasyonlarını bozabilir.

### Host ile UTS paylaşan containers'ları tespit et
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
