# Local Network and Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Linux host üzerinde bir shell elde ettikten sonra, en kullanışlı network hedefleri genellikle dışarıya açık değildir. Yalnızca loopback üzerinden erişilebilen servisler, veth ağları, Unix socket'leri, geçici listener'lar, packet capture'lar ve yerel firewall kuralları credential'ları veya yalnızca yerel erişime açık attack surface'leri açığa çıkarabilir.

Bu sayfa, genel remote network pentesting yerine pratik local post-exploitation tekniklerine odaklanır.

## Loopback ve Local Service Enumeration

Listening servislerini, bind adreslerini ve izinler elverdiğinde bunlara sahip olan process'i belirleyerek başlayın:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Önemli kalıplar:

- `127.0.0.1:<port>` veya `[::1]:<port>`: varsayılan olarak yalnızca host üzerinden erişilebilir.
- `0.0.0.0:<port>`: filtrelenmediği sürece tüm IPv4 arayüzleri üzerinden erişilebilir.
- `veth*`, `docker*`, `br-*`, `cni*` üzerindeki `172.x`, `10.x` veya `192.168.x`: büyük olasılıkla container veya yerel lab network'leri.
- `/run`, `/var/run`, `/tmp` veya application directory'leri altındaki Unix socket'leri: yerel IPC yüzeyleri.

Hafif probe'larla yerel portları eşleyin:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Mevcut olduğunda `nmap`'i yerel olarak kullanın:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Gizli veth ve Container Subnet'leri

Container veya lab ortamları çoğu zaman servisleri yalnızca bir bridge ya da veth subnet'inde açığa çıkarır. Bir servisin erişilemez olduğunu varsaymadan önce interface'leri ve route'ları enumerate edin:
```bash
ip -br addr
ip route
ip neigh
```
Olası yerel alt ağları bulun:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Keşfedilen subnet'i dikkatlice tarayın:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Bu teknik, bir web paneli, debug endpoint'i veya yardımcı servis harici taramalardan gizlenmiş ancak ele geçirilmiş host ya da container network'inden erişilebilir olduğunda kullanışlıdır.

## socat veya SSH ile Local Pivot

Bir servis loopback'e bağlıysa servisin kendisini değiştirmek yerine, izin verilen bir kanal üzerinden erişime açın.

Local-only bir HTTP servisini SSH ile forward edin:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Zaten shell erişiminiz varken `socat` ile yerel bir portu köprüleyin:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Yerel test için bir Unix socket'i TCP'ye yönlendirin:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Bu, tek başına herhangi bir şeyi exploit etmez. Yalnızca local-only bir surface'i tooling'iniz üzerinden erişilebilir hâle getirir; böylece onunla normal bir service gibi etkileşim kurabilirsiniz.

## Banner Grabbing ve Basit Protocol'ler

Her service HTTP değildir. Birçok local service, bir banner veya tek satırlık protocol aracılığıyla yeterli miktarda bilgi leak eder.

Temel probe'lar:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Tarayıcı olmadan HTTP kontrolü:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLS için:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Amaç; protokolü, authentication scheme'i, sürümü ve service'in local client'lara güvenip güvenmediğini belirlemektir.

## Loopback Traffic'i Yakalama

Local traffic; header'ları, bearer token'ları, Basic Auth kimlik bilgilerini veya application-specific secret'ları açığa çıkarabilir. Yalnızca yetkilendirilmiş ortamlarda capture gerçekleştirin.

Loopback HTTP traffic'ini capture edin:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Belirli bir yerel servisi yakalayın:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Yakalanmış veya loglanmış bir header'dan Basic Auth'u decode edin:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Metin yakalamalarında aranabilecek yararlı string'ler:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Bir lab ortamında client process environment üzerinde kontrolünüz varsa, `SSLKEYLOGFILE` TLS oturumlarının Wireshark veya uyumlu tooling ile decrypt edilebilir hâle gelmesini sağlayabilir. Bu, TLS'e doğrudan saldırmadan local HTTPS trafiğini anlamak için kullanışlıdır.

Key logging etkinleştirilmiş bir client çalıştırın:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Trafiği aynı anda yakalayın:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Ardından `/tmp/tls.pcap` ve `/tmp/sslkeys.log` dosyalarını Wireshark'a yükleyin. Bu yalnızca client library NSS-style key logging desteklediğinde ve bağlantı kurulmadan önce environment'ı ayarlayabildiğinizde çalışır.

## Unix Socket Interaction ve Command Injection

Unix sockets, yerel IPC endpoints'leridir. HTTP APIs, custom protocols veya güvenli olmayan command handlers sunabilirler.

Sockets'leri bulun:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket üzerinden HTTP ile etkileşim kurun:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Raw socket ile etkileşim kur:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Kullanıcı tarafından kontrol edilen socket girdisi bir shell'e veya ayrıcalıklı bir yardımcı programa aktarılırsa command injection'a dönüşebilir. Odaklanmış bir örnek için [Socket Command Injection](socket-command-injection.md) bölümüne bakın.

## nftables İncelemesi ve Yetkili Kural Değişiklikleri

Yerel firewall kuralları, bir servisin neden yerel olarak görünürken uzaktan engellendiğini veya yüksek bir portun neden bir arayüzden erişilemez göründüğünü açıklayabilir.

Kuralları inceleyin:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Hedef portu etkileyen drop'ları arayın:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Yetkili bir lab ortamında, belirli bir engelleme kuralını handle ile kaldırın:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Tam tabloları flush etmek yerine tam handle'ı silmeyi tercih edin. Teknik, davranışa neden olan kesin filtreyi belirlemek ve yalnızca o kuralı değiştirmektir.

## Hızlı İş Akışı
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Yalnızca yerel olan, daha ayrıcalıklı bir kullanıcı olarak çalışan, admin/debug işlevlerini açığa çıkaran veya loopback/container-network istemcilerine güvenen servisleri önceliklendirin.

{{#include ../../banners/hacktricks-training.md}}
