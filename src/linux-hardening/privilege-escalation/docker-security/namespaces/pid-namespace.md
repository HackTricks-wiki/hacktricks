# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

PID (Process IDentifier) namespace, Linux çekirdeğinde, bir grup sürecin diğer namespace'lerdeki PIDs'lerden ayrı olarak kendi benzersiz PID setine sahip olmasını sağlayarak süreç izolasyonu sunan bir özelliktir. Bu, süreç izolasyonunun güvenlik ve kaynak yönetimi için hayati olduğu konteynerleştirme alanında özellikle faydalıdır.

Yeni bir PID namespace oluşturulduğunda, o namespace içindeki ilk süreç PID 1 ile atanır. Bu süreç, yeni namespace'in "init" süreci haline gelir ve namespace içindeki diğer süreçleri yönetmekten sorumludur. Namespace içinde oluşturulan her bir sonraki süreç, o namespace içinde benzersiz bir PID alacak ve bu PIDs, diğer namespace'lerdeki PIDs'den bağımsız olacaktır.

Bir PID namespace içindeki bir süreç açısından, yalnızca aynı namespace içindeki diğer süreçleri görebilir. Diğer namespace'lerdeki süreçlerden haberdar değildir ve geleneksel süreç yönetim araçları (örneğin, `kill`, `wait`, vb.) kullanarak onlarla etkileşimde bulunamaz. Bu, süreçlerin birbirine müdahale etmesini önlemeye yardımcı olan bir izolasyon seviyesi sağlar.

### Nasıl çalışır:

1. Yeni bir süreç oluşturulduğunda (örneğin, `clone()` sistem çağrısı kullanılarak), süreç yeni veya mevcut bir PID namespace'ine atanabilir. **Yeni bir namespace oluşturulursa, süreç o namespace'in "init" süreci haline gelir**.
2. **Çekirdek**, **yeni namespace'deki PIDs ile ana namespace'deki karşılık gelen PIDs arasında bir eşleme** tutar (yani, yeni namespace'in oluşturulduğu namespace). Bu eşleme, **çekirdeğin gerekli olduğunda PIDs'leri çevirmesine olanak tanır**, örneğin, farklı namespace'lerdeki süreçler arasında sinyaller gönderirken.
3. **Bir PID namespace içindeki süreçler yalnızca aynı namespace içindeki diğer süreçleri görebilir ve onlarla etkileşimde bulunabilir**. Diğer namespace'lerdeki süreçlerden haberdar değillerdir ve PIDs'leri kendi namespace'leri içinde benzersizdir.
4. **Bir PID namespace yok edildiğinde** (örneğin, namespace'in "init" süreci çıktığında), **o namespace içindeki tüm süreçler sonlandırılır**. Bu, namespace ile ilişkili tüm kaynakların düzgün bir şekilde temizlenmesini sağlar.

## Laboratuvar:

### Farklı Namespace'ler Oluşturun

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Problem Açıklaması**:

- Linux çekirdeği, bir sürecin yeni ad alanları oluşturmasına `unshare` sistem çağrısı ile izin verir. Ancak, yeni bir PID ad alanı oluşturma işlemini başlatan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmez; yalnızca onun çocuk süreçleri girer.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanındadır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, bu ad alanında PID tahsisini devre dışı bırakır.

2. **Sonuç**:

- Yeni bir ad alanındaki PID 1'in çıkışı, `PIDNS_HASH_ADDING` bayrağının temizlenmesine yol açar. Bu, yeni bir süreç oluştururken `alloc_pid` fonksiyonunun yeni bir PID tahsis edememesine neden olur ve "Bellek tahsis edilemiyor" hatasını üretir.

3. **Çözüm**:
- Sorun, `unshare` ile `-f` seçeneğini kullanarak çözülebilir. Bu seçenek, `unshare`'in yeni PID ad alanını oluşturduktan sonra yeni bir süreç fork etmesini sağlar.
- `%unshare -fp /bin/bash%` komutunu çalıştırmak, `unshare` komutunun kendisinin yeni ad alanında PID 1 olmasını garanti eder. `/bin/bash` ve onun çocuk süreçleri, bu yeni ad alanında güvenli bir şekilde yer alır, PID 1'in erken çıkışını önler ve normal PID tahsisine izin verir.

`unshare`'in `-f` bayrağı ile çalıştırılmasını sağlayarak, yeni PID ad alanının doğru bir şekilde korunması sağlanır ve `/bin/bash` ile alt süreçlerinin bellek tahsis hatası ile karşılaşmadan çalışmasına olanak tanınır.

</details>

Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresini kullanarak monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerini doğru ve izole bir şekilde görmesini** sağlarsınız.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Tüm PID ad alanlarını bul
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Kök kullanıcısının başlangıç (varsayılan) PID ad alanından tüm süreçleri görebildiğini, hatta yeni PID ad alanlarındaki süreçleri bile görebildiğini unutmayın, bu yüzden tüm PID ad alanlarını görebiliyoruz.

### Bir PID ad alanına girin
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Bir PID ad alanına varsayılan ad alanından girdiğinizde, tüm süreçleri görebilirsiniz. Ve o PID ad alanındaki süreç, PID ad alanındaki yeni bash'i görebilecektir.

Ayrıca, **başka bir süreç PID ad alanına yalnızca root iseniz girebilirsiniz**. Ve **bir tanımlayıcı olmadan** **başka bir ad alanına giremezsiniz** (örneğin `/proc/self/ns/pid`)

## Referanslar

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
