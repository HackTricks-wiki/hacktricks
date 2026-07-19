# Yerel Ağ ve Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Bir Linux host üzerinde shell elde ettikten sonra, en kullanışlı network hedefleri genellikle dışarıya açık değildir. Yalnızca loopback üzerinde çalışan servisler, veth network'leri, Unix socket'leri, geçici listener'lar, packet capture'ları ve yerel firewall kuralları credential'ları veya yalnızca yerel erişime açık attack surface'leri açığa çıkarabilir.

Bu sayfa genel remote network pentesting yerine pratik yerel post-exploitation tekniklerine odaklanır.

## Loopback ve Yerel Service Enumeration

İzinler olanak verdiğinde, listening servislerini, bind adreslerini ve bunların sahibi olan process'i belirleyerek başlayın:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Önemli kalıplar:

- `127.0.0.1:<port>` veya `[::1]:<port>`: varsayılan olarak yalnızca host üzerinden erişilebilir.
- `0.0.0.0:<port>`: filtrelenmediği sürece tüm IPv4 arayüzlerinden erişilebilir.
- `veth*`, `docker*`, `br-*`, `cni*` üzerindeki `172.x`, `10.x` veya `192.168.x`: büyük olasılıkla container veya yerel lab ağlarıdır.
- `/run`, `/var/run`, `/tmp` veya uygulama dizinlerindeki Unix socket'leri: yerel IPC yüzeyleridir.

Yerel portları hafif sondalarla eşleyin:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Kullanılabilir olduğunda yerel olarak `nmap` kullanın:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Gizli veth ve Container Alt Ağları

Container'laştırılmış veya lab ortamları, servisleri genellikle yalnızca bir bridge ya da veth alt ağı üzerinden sunar. Bir servise erişilemez olduğunu varsaymadan önce arayüzleri ve rotaları enumerate edin:
```bash
ip -br addr
ip route
ip neigh
```
Olası yerel alt ağları bulun:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Keşfedilmiş bir subnet'i dikkatlice tarayın:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Bu technique, bir web paneli, debug endpoint'i veya yardımcı service harici taramalardan gizlenmiş ancak ele geçirilmiş host ya da container network'ünden erişilebilir olduğunda kullanışlıdır.

## socat veya SSH ile Local Pivot

Bir service loopback'e bağlıysa service'in kendisini değiştirmek yerine, izin verilen bir channel üzerinden açığa çıkarın.

Local-only HTTP service'i SSH ile forward edin:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Zaten shell erişiminiz varsa `socat` ile yerel bir portu köprüleyin:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Yerel test için bir Unix socket'i TCP'ye yönlendirin:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Bu, tek başına hiçbir şeyi exploit etmez. Yalnızca yerel kullanım ile sınırlı bir yüzeyi tooling'iniz üzerinden erişilebilir hâle getirir; böylece onunla normal bir servis gibi etkileşim kurabilirsiniz.

## Banner Grabbing ve Basit Protokoller

Her servis HTTP değildir. Birçok yerel servis, bir banner veya tek satırlık protokol aracılığıyla yeterli bilgiyi leak eder.

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
Amaç; protokolü, kimlik doğrulama şemasını, sürümü ve servisin yerel istemcilere güvenip güvenmediğini belirlemektir.

## Loopback Trafiğini Yakalama

Yerel trafik; başlıkları, bearer token'larını, Basic Auth kimlik bilgilerini veya uygulamaya özgü sırları açığa çıkarabilir. Yalnızca yetkili ortamlarda yakalama yapın.

Loopback HTTP trafiğini yakalayın:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Belirli bir yerel servisi yakalayın:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Yakalanan veya loglanmış bir header'dan Basic Auth'u decode edin:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Metin yakalamalarında aranabilecek yararlı string'ler:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Bir lab ortamında client process environment'ını kontrol edebiliyorsanız, `SSLKEYLOGFILE` TLS session'larını Wireshark veya uyumlu tooling ile decrypt edilebilir hale getirebilir. Bu, TLS'e saldırmadan local HTTPS trafiğini anlamak için kullanışlıdır.

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
Ardından `/tmp/tls.pcap` ve `/tmp/sslkeys.log` dosyalarını Wireshark'a yükleyin. Bu yalnızca client library NSS-style key logging'i desteklediğinde ve bağlantı kurulmadan önce environment'ı ayarlayabildiğinizde çalışır.

## Unix Socket Etkileşimi ve Command Injection

Unix socket'leri yerel IPC endpoint'leridir. HTTP API'leri, özel protokoller veya güvenli olmayan command handler'lar sunabilirler.

Socket'leri bulun:
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
Kullanıcı tarafından kontrol edilen socket girdisi bir shell'e veya ayrıcalıklı yardımcı programa aktarılırsa command injection'a dönüşebilir. Odaklanmış bir örnek için bkz. [Socket Command Injection](socket-command-injection.md).

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
Yetkilendirilmiş bir lab ortamında, belirli bir engelleme kuralını handle'ı ile kaldırın:
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
