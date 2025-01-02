# Ağ Ad Alanı

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Ağ ad alanı, **her ağ ad alanının kendi bağımsız ağ yapılandırmasına** sahip olmasını sağlayan, ağ yığınını izole eden bir Linux çekirdek özelliğidir; arayüzler, IP adresleri, yönlendirme tabloları ve güvenlik duvarı kuralları. Bu izolasyon, her konteynerin diğer konteynerlerden ve ana sistemden bağımsız olarak kendi ağ yapılandırmasına sahip olması gereken konteynerleştirme gibi çeşitli senaryolar için faydalıdır.

### Nasıl çalışır:

1. Yeni bir ağ ad alanı oluşturulduğunda, **tamamen izole bir ağ yığını** ile başlar; **loopback arayüzü** (lo) dışında **hiçbir ağ arayüzü** yoktur. Bu, yeni ağ ad alanında çalışan süreçlerin varsayılan olarak diğer ad alanlarındaki veya ana sistemdeki süreçlerle iletişim kuramayacağı anlamına gelir.
2. **Sanal ağ arayüzleri**, örneğin veth çiftleri, oluşturulabilir ve ağ ad alanları arasında taşınabilir. Bu, ad alanları arasında veya bir ad alanı ile ana sistem arasında ağ bağlantısı kurmayı sağlar. Örneğin, bir veth çiftinin bir ucu bir konteynerin ağ ad alanında yer alabilir ve diğer ucu ana ad alanındaki bir **köprüye** veya başka bir ağ arayüzüne bağlanarak konteynere ağ bağlantısı sağlayabilir.
3. Bir ad alanı içindeki ağ arayüzleri, diğer ad alanlarından bağımsız olarak **kendi IP adreslerine, yönlendirme tablolarına ve güvenlik duvarı kurallarına** sahip olabilir. Bu, farklı ağ ad alanlarındaki süreçlerin farklı ağ yapılandırmalarına sahip olmasını ve sanki ayrı ağ sistemlerinde çalışıyormuş gibi işlem yapmasını sağlar.
4. Süreçler, `setns()` sistem çağrısını kullanarak ad alanları arasında hareket edebilir veya `CLONE_NEWNET` bayrağı ile `unshare()` veya `clone()` sistem çağrılarını kullanarak yeni ad alanları oluşturabilir. Bir süreç yeni bir ad alanına geçtiğinde veya bir tane oluşturduğunda, o ad alanıyla ilişkili ağ yapılandırmasını ve arayüzlerini kullanmaya başlayacaktır.

## Laboratuvar:

### Farklı Ad Alanları Oluşturma

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Yeni bir `/proc` dosya sisteminin örneğini `--mount-proc` parametresi ile monte ederek, yeni montaj ad alanının **o ad alanına özgü süreç bilgilerini doğru ve izole bir şekilde görmesini** sağlarsınız.

<details>

<summary>Hata: bash: fork: Bellek tahsis edilemiyor</summary>

`unshare` komutu `-f` seçeneği olmadan çalıştırıldığında, Linux'un yeni PID (Process ID) ad alanlarını nasıl yönettiği nedeniyle bir hata ile karşılaşılır. Anahtar detaylar ve çözüm aşağıda özetlenmiştir:

1. **Sorun Açıklaması**:

- Linux çekirdeği, bir sürecin yeni ad alanları oluşturmasına `unshare` sistem çağrısı ile izin verir. Ancak, yeni bir PID ad alanı oluşturan süreç (bu süreç "unshare" süreci olarak adlandırılır) yeni ad alanına girmemektedir; yalnızca onun çocuk süreçleri girmektedir.
- `%unshare -p /bin/bash%` komutu, `/bin/bash`'i `unshare` ile aynı süreçte başlatır. Sonuç olarak, `/bin/bash` ve onun çocuk süreçleri orijinal PID ad alanındadır.
- Yeni ad alanındaki `/bin/bash`'in ilk çocuk süreci PID 1 olur. Bu süreç sona erdiğinde, başka süreç yoksa ad alanının temizlenmesini tetikler, çünkü PID 1, yetim süreçleri benimseme özel rolüne sahiptir. Linux çekirdeği, bu ad alanında PID tahsisini devre dışı bırakacaktır.

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
# Run ifconfig or ip -a
```
### &#x20;Hangi ad alanında olduğunuzu kontrol edin
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Tüm Ağ ad alanlarını Bulun
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Bir Ağ ad alanına girin
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Ayrıca, **başka bir işlem ad alanına yalnızca root iseniz girebilirsiniz**. Ve **başka bir ad alanına** **giremezsiniz** **onu işaret eden bir tanımlayıcı olmadan** (örneğin `/proc/self/ns/net`).

## Referanslar

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
