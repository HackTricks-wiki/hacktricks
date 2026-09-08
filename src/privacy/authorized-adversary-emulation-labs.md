# Yetkili Adversary-Emulation Lab'ları

{{#include ../banners/hacktricks-training.md}}

Bu alıştırmalar, yetkisiz compromise yerine **gözlemlenebilir mimariyi** yeniden oluşturur. Bunları Docker içeren, hassas kimlik bilgileri barındırmayan ve üçüncü taraf hedeflere route'u olmayan özel bir Linux lab host üzerinde çalıştırın. Teardown işleminin açıkça yapılabilmesi için adlar sabit tutulmuştur.

{% hint style="danger" %}
Aşağıdaki sahip olunan container'ları, AP'leri, router'ları, hesapları veya synthetic transaction'ları public proxy'ler, bir komşunun Wi-Fi'ı, kontrol etmediğiniz production CDN tenant'ı ya da gerçek illicit funds ile değiştirmeyin. Yazılı authorization her sistemi ve radio ortamını kapsamalıdır.
{% endhint %}

## Lab 1: sahip olunan ORB ve redirector chain

**Objective:** Bir target'ın yalnızca exit'i kaydettiğini, her relay'in ise kendisine bitişik hop'ları gördüğünü gösterin. Bu, compromised device'lar olmadan T1090.003/T1584 yapısını emüle eder.

**Requirements:** Docker Engine ve `ht-orb-` ile başlayan kullanılmayan container adları.

### Build
```bash
docker network create ht-orb-entry
docker network create ht-orb-transit
docker network create ht-orb-target

docker run -d --name ht-orb-target --network ht-orb-target nginx:alpine

docker run -d --name ht-orb-r2 --network ht-orb-transit \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-target:80
docker network connect ht-orb-target ht-orb-r2

docker run -d --name ht-orb-r1 --network ht-orb-entry \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-r2:8080
docker network connect ht-orb-transit ht-orb-r1

docker run --rm --network ht-orb-entry curlimages/curl:latest \
-sS http://ht-orb-r1:8080/ >/dev/null
```
### Görünürlük sınırlarını doğrulayın
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Beklenen sonuç: Nginx, tek seferlik istemciyi değil, `ht-orb-target` üzerindeki `ht-orb-r2` adresini kaydeder. Relay log'ları yalnızca bitişik ağlarından gelen bağlantıları gösterir. Docker control-plane incelemesi, sağlayıcı/controller kanıtlarına benzer şekilde tüm yolu yeniden oluşturur.

### Tespit deneyleri

1. İstekleri her 60 saniyede bir tekrarlayın ve istekler arası süreyi ve baytları grafik üzerinde gösterin.
2. `ht-orb-r2` yerine yeni adlandırılmış bir container/adres kullanın; ancak aynı ritmi ve uygulama isteğini koruyun. Yalnızca IP'ye dayalı bir kuralın zinciri kaybettiğini, davranışın ise hâlâ bağlantı kurduğunu doğrulayın.
3. Lab ana bilgisayarında `tcpdump` ile üç Docker bridge üzerinde yakalama yapın ve zaman damgalarını karşılaştırın.
4. `ht-orb-r2`'yi durdurun; entry'den target'a doğrudan bir fallback olmadığını doğrulayın.

### Temizleme
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Lab 2: SNI/Host mismatch ve redirector logging

**Objective:** domain fronting'in arkasındaki routing primitive'i özel bir yerel edge üzerinde yeniden üretin ve bunun nerede görünür olduğunu gösterin. Herhangi bir public CDN kullanılmaz.

### Yerel bir TLS edge oluşturun
```bash
ht_front_dir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
-subj '/CN=front.lab' \
-keyout "$ht_front_dir/key.pem" -out "$ht_front_dir/cert.pem"

cat >"$ht_front_dir/default.conf" <<'EOF'
log_format routing '$remote_addr sni=$ssl_server_name host=$host request="$request"';
server {
listen 443 ssl;
server_name front.lab;
ssl_certificate /etc/nginx/tls/cert.pem;
ssl_certificate_key /etc/nginx/tls/key.pem;
access_log /var/log/nginx/access.log routing;
location / {
if ($host != origin.lab) { return 404; }
proxy_pass http://ht-front-target:80;
}
}
EOF

docker network create ht-front-net
docker run -d --name ht-front-target --network ht-front-net nginx:alpine
docker run -d --name ht-front-edge --network ht-front-net -p 127.0.0.1:8443:443 \
-v "$ht_front_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
-v "$ht_front_dir:/etc/nginx/tls:ro" nginx:alpine
```
### Uyumsuzluğu gönderin ve gözlemleyin
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Beklenen log alanları arasında `sni=front.lab host=origin.lab` bulunur. ECH kullanılmıyorsa client-to-edge packet capture SNI'ı açığa çıkarır; HTTP Host bu bağlantı üzerinden şifrelenir. Terminating edge her ikisini de görür.

Şimdi normal bir istek gönderin ve policy'nin bunu reddettiğini doğrulayın:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Detection assertion

` sni != host` için yalnızca portları/büyük-küçük harf kullanımını normalize ettikten ve bilinen reverse-proxy istisnalarını kontrol ettikten sonra uyarı oluşturun. Severity atamadan önce process ve tenant/origin bağlamını ekleyin.

### Teardown
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Amaç:** güvenli bir low-TTL/multi-ASN-like DNS dataset oluşturmak ve bir analytic'i doğrulamak. Döndürülen RFC 5737 documentation adresleri bu amaçla routable değildir.

### Bir authoritative server çalıştırın
```bash
ht_dns_dir="$(mktemp -d)"
cat >"$ht_dns_dir/Corefile" <<'EOF'
.:53 {
log
errors
file /zones/db.lab lab
}
EOF

mkdir -p "$ht_dns_dir/zones"
cat >"$ht_dns_dir/zones/db.lab" <<'EOF'
$ORIGIN lab.
@ 60 IN SOA ns.lab. hostmaster.lab. 1 60 60 60 5
@ 60 IN NS ns.lab.
ns 60 IN A 192.0.2.53
flux 5 IN A 192.0.2.10
flux 5 IN A 198.51.100.20
flux 5 IN A 203.0.113.30
EOF

docker run -d --name ht-flux-dns -p 127.0.0.1:1053:53/udp \
-v "$ht_dns_dir/Corefile:/Corefile:ro" \
-v "$ht_dns_dir/zones:/zones:ro" coredns/coredns:latest -conf /Corefile

for query_number in 1 2 3 4 5; do
dig @127.0.0.1 -p 1053 flux.lab A +noall +answer
done
docker logs ht-flux-dns
```
Beklenen sonuç: her yanıt üç adet documentation IP ve 5 saniyelik bir TTL içerir. Gerçek fast flux ayrıca zaman içinde alt kümeleri de döndürür; birden fazla epoch oluşturmak için zone serial/addresses değerlerini değiştirin ve bu geçici sunucuyu yeniden başlatın.

### Analitik doğrulama

Beş dakikalık bir pencere için `median(TTL)`, benzersiz yanıtları, benzersiz sentetik ASN/coğrafya etiketlerini ve yanıt değişimini hesaplayın. En az iki şüpheli boyutun yanı sıra bir process/follow-on event gerektirin. Yanlış pozitifleri ölçmek için aynı analitiği bilinen bir CDN örneği üzerinde çalıştırın.

### Söküm
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Amaç:** Sahip olduğunuz iki “organization” ile APT28 boundary mismatch durumunu yeniden üretmek. Wi-Fi hardware/driver commands değişiklik gösterdiğinden, bu lab her radio için tek bir `hostapd` komutunun geçerli olduğunu varsaymak yerine doğrulanabilir roller ve kanıtlar tanımlar.

### Equipment

- İzole lab channels/SSIDs `HT-NEIGHBOR` ve `HT-TARGET` üzerinde size ait iki AP;
- yalnızca `HT-TARGET` üzerinden erişilebilen bir target service;
- her iki AP'ye association yapabilen, size ait dual-radio Linux pivot;
- `HT-NEIGHBOR` arkasında bulunan bir remote-control workstation;
- RADIUS/NAC veya AP association logs, DHCP logs ve pivot audit/process logs.

### Procedure

1. Kurulumu fiziksel olarak izole edin veya sinyali zayıflatın; böylece hiçbir SSID authorized area dışına çıkmasın. Bir survey ile doğrulayın.
2. `HT-TARGET` üzerinde bir exercise identity yapılandırın ve ilk çalıştırmada device-certificate/posture validation özelliğini bilerek devre dışı bırakın. Bunu test edilen koşul olarak kaydedin.
3. Pivot'un first interface'ını `HT-NEIGHBOR`'a, second interface'ını `HT-TARGET`'a bağlayın. Genel bir bridge'i etkinleştirmeyin; yalnızca target service/port trafiğine host firewall üzerinden izin verin.
4. Workstation'dan pivot'a authenticated tunnel açın ve target service'ı bu tunnel üzerinden isteyin.
5. Pivot process/interface creation olayını, her iki AP association'ını, target RADIUS event'ini, DHCP lease'ini ve target source address'ini kaydedin.
6. Detection team'den controller map olmadan chain'i yeniden oluşturmasını isteyin.
7. `HT-TARGET` üzerinde EAP-TLS/managed-device posture özelliğini etkinleştirin, pivot'un approved target certificate'ını kaldırın ve işlemi tekrarlayın. Access, admission aşamasında başarısız olmalıdır.
8. İşlemi first-seen randomized MAC ile tekrarlayın. Certificate/device decision'ın hâlâ çalıştığını ve hiçbir rule'un yalnızca MAC'i identity olarak değerlendirmediğini doğrulayın.

### Success criteria

- Target başlangıçta workstation yerine local Wi-Fi client görür.
- Joined telemetry, eş zamanlı neighbor-control ve target-radio paths içeren tek bir pivot tanımlar.
- Certificate/device-backed admission ikinci çalıştırmayı engeller.
- İzole lab dışındaki hiçbir network'e packet ulaşmaz.

## Lab 5: dead-drop resolver sequence

**Amaç:** Legitimate-looking bir object'i okuyan, bir pointer'ı decode eden ve hemen ardından ikinci bir service'a bağlanan bir process'i tespit etmek.

### Build
```bash
docker network create ht-ddr-net
docker run -d --name ht-ddr-c2 --network ht-ddr-net nginx:alpine

docker run -d --name ht-ddr-web --network ht-ddr-net python:3-alpine \
sh -c 'mkdir -p /srv && printf aHR0cDovL2h0LWRkci1jMjo4MC8= > /srv/profile.txt && python -m http.server 8000 -d /srv'

docker run --rm --name ht-ddr-client --network ht-ddr-net python:3-alpine \
python -c 'import base64,urllib.request; p=urllib.request.urlopen("http://ht-ddr-web:8000/profile.txt").read(); u=base64.b64decode(p).decode(); print(urllib.request.urlopen(u).status)'

docker logs ht-ddr-web
docker logs ht-ddr-c2
```
Kodlanmış içerik `http://ht-ddr-c2:80/` şeklindedir. Çalışan bir detection, aynı kısa ömürlü process/container'ın `/profile.txt` dosyasını okumasını, içeriği decode etmesini ve saniyeler içinde `ht-ddr-c2` ile iletişime geçmesini birleştirir. Object response'un hash'ini alın ve koruyun.

### Temizleme
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: sentetik peel-chain ve bridge graph

**Amaç:** gerçek varlıklar, hesaplar veya servisler olmadan value tracing pratiği yapmak.

### Veri kümesini oluşturun ve trace edin
```bash
ht_graph_dir="$(mktemp -d)"
cat >"$ht_graph_dir/edges.csv" <<'EOF'
time,chain,source,destination,amount,label
10:00,A,theft,a1,100,source
10:10,A,a1,shop1,3,payment
10:10,A,a1,a2,96.9,change
10:20,A,a2,shop2,4,payment
10:20,A,a2,a3,92.8,change
10:30,A,a3,bridge_in,90,bridge_deposit
10:36,X,bridge_in,bridge_out,89.5,bridge_link_inference
10:36,B,bridge_out,b1,89.5,bridge_withdrawal
10:50,B,b1,exchange,89,service_deposit
EOF

python3 - "$ht_graph_dir/edges.csv" <<'PY'
import csv, sys
edges = list(csv.DictReader(open(sys.argv[1], newline="")))
frontier, seen = {"theft"}, set()
while frontier:
src = frontier.pop()
for e in edges:
if e["source"] == src and (src, e["destination"]) not in seen:
seen.add((src, e["destination"]))
print(f'{e["time"]} {e["chain"]}: {src} -> {e["destination"]} {e["amount"]} [{e["label"]}]')
frontier.add(e["destination"])
PY
```
Analistler peel/change pattern'ını belirlemeli, bridge link'ini ayrı olarak desteklenmesi gereken bir çıkarım şeklinde ele almalı, fee/value farkını hesaplamalı ve exchange'i off-chain evidence request olarak işaretlemelidir. Bir value/time değerini değiştirin ve confidence'ın nasıl değiştiğini belgeleyin.

### Teardown
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: pasif trafik-sinyalleme sensörü

**Objective:** Bir shell, persistence veya remote access oluşturmadan pasif, magic-value-activated bir implant'ın network signature'ını taklit etmek. Listener yalnızca loopback'e bağlanır ve zararsız bir olayı kaydeder.
```bash
ht_signal_dir="$(mktemp -d)"
cat >"$ht_signal_dir/listener.py" <<'PY'
import hmac, socket

token = b"HT-LAB-ACTIVATE"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 45679))
for _ in range(2):
data, peer = sock.recvfrom(1024)
if hmac.compare_digest(data, token):
print(f"authorized lab activation from {peer[0]}", flush=True)
PY

python3 "$ht_signal_dir/listener.py" >"$ht_signal_dir/events.log" &
ht_signal_pid=$!
sleep 1

python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ordinary-traffic", ("127.0.0.1", 45679))
s.sendto(b"HT-LAB-ACTIVATE", ("127.0.0.1", 45679))
PY

wait "$ht_signal_pid"
cat "$ht_signal_dir/events.log"
rm -rf -- "$ht_signal_dir"
```
Beklenen sonuç: ordinary traffic hiçbir application event üretmez; yalnızca designated token üretir. Çalışma sırasında loopback traffic'i yakalayın ve bir network sensor'ünün her iki datagram'ı da hâlâ görebildiğini doğrulayın. Ardından beklenmeyen, uzun süre çalışan bir packet listener'ı veya packet-capture filter'ını tespit eden host controls'ü değerlendirin. Gerçek RedPenguin passive implants, bir router üzerindeki traffic'i incelemiş ve tehlikeli işlevler sunmuştur; bu lab kasıtlı olarak bunların hiçbirini yapmaz.

## Exercise report template

Her lab için şunları kaydedin:

- authorization ve isolated scope;
- hypothesis ve ATT&CK technique;
- topology ve observer tablosu;
- kesin başlangıç/bitiş zamanı ve configuration hash'leri;
- her sensor için beklenen events;
- gerçekte gözlemlenen events ve retention gaps;
- analytic logic, threshold ve false-positive sample;
- target team'in path'i yeniden oluşturup oluşturmadığı;
- mitigation retest sonucu; ve
- teardown/recovery kanıtı.

Detection mitigation sonrasında yeniden çalıştırılmadıkça ve her lab resource kaldırılmadıkça exercise tamamlanmış sayılmaz.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
