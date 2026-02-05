# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**iki sistem tanımlayıcısının izolasyonu**: the **hostname** and the **NIS** (Network Information Service) domain name. Bu izolasyon, her UTS namespace'inin kendi **bağımsız hostname ve NIS alan adına** sahip olmasını sağlar; bu, containerization senaryolarında, her container'ın kendi hostname'i ile ayrı bir sistem gibi görünmesi gerektiğinde özellikle kullanışlıdır.

### Nasıl çalışır:

1. Yeni bir UTS namespace oluşturulduğunda, üst namespace'inden **hostname ve NIS alan adının bir kopyasıyla** başlar. Bu, oluşturulma sırasında yeni namespace'in üstüyle s**aynı tanımlayıcıları paylaştığı** anlamına gelir. Ancak, namespace içindeki hostname veya NIS alan adındaki sonraki değişiklikler diğer namespace'leri etkilemez.
2. UTS namespace içindeki süreçler `sethostname()` ve `setdomainname()` system call'larını kullanarak sırasıyla **hostname ve NIS alan adını değiştirebilir**. Bu değişiklikler namespace'e yerel olup diğer namespace'leri veya host sistemini etkilemez.
3. Süreçler `setns()` system call'ını kullanarak namespace'ler arasında hareket edebilir veya `CLONE_NEWUTS` flag'i ile `unshare()` veya `clone()` system call'larıyla yeni namespace'ler oluşturabilir. Bir süreç yeni bir namespace'e geçtiğinde veya bir namespace oluşturduğunda, o namespace ile ilişkili hostname ve NIS alan adını kullanmaya başlar.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Hata: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Sorunun Açıklaması**:

- Linux kernel, bir işlemin `unshare` system call'u ile yeni namespace'ler oluşturmasına izin verir. Ancak yeni bir PID namespace'inin oluşturulmasını başlatan süreç ("unshare" süreci olarak adlandırılır) yeni namespace'e girmez; sadece onun alt süreçleri girer.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Sonuç**:

- Yeni namespace'te PID 1'in çıkışı `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Cannot allocate memory" hatasını üretir.

3. **Çözüm**:
- Bu sorun `unshare` ile `-f` seçeneği kullanılarak çözülebilir. Bu seçenek `unshare`'in yeni PID namespace'ini oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Hangi namespace'te olduğunuzu kontrol edin
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
### UTS namespace içine girin
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Host UTS paylaşımının kötüye kullanılması

Eğer bir container `--uts=host` ile başlatılırsa, izole bir UTS yerine host UTS namespace'ine katılır. `--cap-add SYS_ADMIN` gibi capabilities ile container içindeki kod host'un hostname/NIS adını `sethostname()`/`setdomainname()` aracılığıyla değiştirebilir:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Host name'i değiştirmek logs/alerts'lara müdahale edebilir, cluster discovery'yi karıştırabilir veya hostname'e sabitlenmiş TLS/SSH konfigürasyonlarını bozabilir.

### Host ile UTS paylaşan container'ları tespit et
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
