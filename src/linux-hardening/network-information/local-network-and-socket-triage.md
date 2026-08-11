# Yerel Ağ ve Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Bir Linux host üzerinde shell elde ettikten sonra, en kullanışlı network hedefleri genellikle dışarıya açık değildir. Yalnızca loopback üzerinden erişilebilen servisler, veth network'leri, Unix socket'leri, geçici listener'lar, packet capture'lar ve yerel firewall kuralları kimlik bilgilerini veya yalnızca yerel erişime açık attack surface'lerini ortaya çıkarabilir.

Bu sayfa, genel remote network pentesting yerine pratik yerel post-exploitation tekniklerine odaklanır.

## Loopback ve Yerel Servis Enumeration'ı

Dinleyen servisleri, bind adreslerini ve izinler elverdiğinde bunların sahibi olan process'i belirleyerek başlayın.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Önemli kalıplar:

- `127.0.0.1:<port>` veya `[::1]:<port>`: varsayılan olarak yalnızca host üzerinden erişilebilir.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: filtrelenmediği sürece tüm IPv4 arayüzlerinden erişilebilir.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` veya `192.168.0.0/16` değerlerinin `veth*`, `docker*`, `br-*`, `cni*` üzerinde bulunması: büyük olasılıkla container veya yerel lab ağlarını gösterir.<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`, `/var/run`, `/tmp` veya uygulama dizinleri altındaki Unix socket'leri: yerel IPC yüzeyleridir.<sup>[[5]](#references)</sup>

Hafif problarla yerel portları haritalayın.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Mümkün olduğunda yerel olarak `nmap` kullanın.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Gizli veth ve Container Subnet'leri

Containerized veya lab ortamları, servisleri genellikle yalnızca bir bridge ya da veth subnet'i üzerinde erişime açar. Bir servisin erişilemez olduğunu varsaymadan önce interface'leri ve route'ları enumerate edin.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Olası yerel alt ağları bulun.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Keşfedilen bir subnet'i dikkatlice probe edin.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Bu teknik, bir web paneli, debug endpoint'i veya yardımcı servis dış taramalardan gizlendiğinde ancak ele geçirilmiş host ya da container network'inden erişilebilir olduğunda kullanışlıdır.

## socat veya SSH ile Local Pivot

Bir servis loopback'e bağlıysa, servisin kendisini değiştirmek yerine izin verilen bir kanal üzerinden erişime açın.

Local-only HTTP servisini SSH ile forward edin.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Zaten shell erişiminiz varsa yerel bir portu `socat` ile köprüleyin.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Yerel test için bir Unix socket'i TCP'ye yönlendirin.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Bu, tek başına herhangi bir şeyi exploit etmez. Yalnızca yerel erişime özel bir surface'i tooling'iniz üzerinden erişilebilir hâle getirir; böylece onunla normal bir servis gibi etkileşime girebilirsiniz.

## Banner Grabbing ve Basit Protokoller

Her servis HTTP değildir. Birçok yerel servis, bir banner veya tek satırlık protokol üzerinden yeterli miktarda bilgi leak eder.

Temel probe'lar.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Tarayıcı olmadan HTTP kontrolü.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
TLS için.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Amaç; protokolü, authentication scheme'i, sürümü ve servisin local client'lara güvenip güvenmediğini belirlemektir.

## Loopback Traffic Yakalama

Local traffic; header'ları, bearer token'ları, Basic Auth kimlik bilgilerini veya uygulamaya özgü secret'ları açığa çıkarabilir.<sup>[[17]](#references)[[25]](#references)</sup> Yalnızca yetkili ortamlarda capture yapın.

Loopback HTTP traffic'ini capture edin.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Belirli bir yerel servisi yakalayın.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Yakalanmış veya loglanmış bir header'dan Basic Auth'u decode edin.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Metin yakalamalarında aranabilecek yararlı dizeler:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Bir lab ortamında client process environment'ını kontrol edebiliyorsanız, `SSLKEYLOGFILE` TLS session'larını Wireshark veya uyumlu araçlarda decrypt edilebilir hale getirebilir.<sup>[[19]](#references)[[20]](#references)</sup> Bu, TLS'in kendisine saldırmadan local HTTPS trafiğini anlamak için kullanışlıdır.

Key logging etkinleştirilmiş bir client çalıştırın.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Trafiği aynı anda yakalayın.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Ardından `/tmp/tls.pcap` ve `/tmp/sslkeys.log` dosyalarını Wireshark'a yükleyin. Bu yalnızca client library NSS tarzı key logging'i desteklediğinde ve bağlantı kurulmadan önce ortamı ayarlayabildiğinizde çalışır.<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket Etkileşimi ve Command Injection

Unix socket'leri yerel IPC endpoint'leridir.<sup>[[5]](#references)</sup> HTTP API'leri, özel protokoller veya güvenli olmayan command handler'lar sunabilirler.<sup>[[12]](#references)[[14]](#references)</sup>

Socket'leri bulun.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Unix socket üzerinden HTTP ile etkileşim kurun.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Raw socket ile etkileşim kurun.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Kullanıcı tarafından kontrol edilen socket girdisi bir shell'e veya ayrıcalıklı yardımcı programa aktarılırsa command injection'a dönüşebilir.<sup>[[26]](#references)</sup> Odaklanılmış bir örnek için bkz. [Socket Command Injection](socket-command-injection.md).

## nftables İncelemesi ve Yetkili Kural Değişiklikleri

Yerel firewall kuralları, bir servisin neden yerel olarak görünür ancak uzaktan engellenmiş olduğunu veya yüksek bir portun neden bir arayüzden erişilemez göründüğünü açıklayabilir.<sup>[[22]](#references)</sup>

Kuralları inceleyin.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Hedef bir portu etkileyen drop'ları arayın.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Yetkilendirilmiş bir lab ortamında, belirli bir engelleme kuralını handle ile kaldırın.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Tam tabloları flushing etmek yerine kesin handle'ı silmeyi tercih edin. Teknik, davranışa neden olan kesin filter'ı belirlemek ve yalnızca o rule'u değiştirmektir.<sup>[[22]](#references)</sup>

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
Daha yüksek ayrıcalıklara sahip bir kullanıcı olarak çalışan, yalnızca yerel olan, admin/debug işlevlerini açığa çıkaran veya loopback/container-network istemcilerine güvenen hizmetlere öncelik verin.

## References

- [1] [ss(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Version 6 Adresleme Mimarisi](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Yönlendirmeler (Bash Referans Kılavuzu)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Tarama Teknikleri (Nmap Referans Kılavuzu)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Ana Bilgisayar Keşfi (Nmap Referans Kılavuzu)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Belirtimi ve Tarama Sırası (Nmap Referans Kılavuzu)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux kılavuz sayfası](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD kılavuz sayfası](https://man.openbsd.org/nc.1)
- [14] [curl komut satırı aracı kılavuzu](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL Belgeleri](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 'Basic' HTTP Kimlik Doğrulama Şeması](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL Belgeleri](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark Kullanıcı Kılavuzu](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables kılavuzu](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Özel İnternetler için Adres Tahsisi (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 Yetkilendirme Çerçevesi: Bearer Token Kullanımı (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Bir İşletim Sistemi Komutunda Kullanılan Özel Öğelerin Hatalı Etkisizleştirilmesi](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
