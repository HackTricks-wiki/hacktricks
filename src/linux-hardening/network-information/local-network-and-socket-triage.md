# Yerel Ağ ve Socket Triage

{{#include ../../banners/hacktricks-training.md}}

Bir Linux host üzerinde shell aldıktan sonra, en kullanışlı ağ hedefleri çoğu zaman dışarıya açık değildir. Yalnızca loopback üzerinden erişilebilen servisler, veth ağları, Unix socket'leri, geçici dinleyiciler, packet capture'lar ve yerel firewall kuralları kimlik bilgilerini veya yalnızca yerelden erişilebilen saldırı yüzeylerini açığa çıkarabilir.

Bu sayfa, genel uzaktan ağ pentesting'i yerine pratik yerel post-exploitation tekniklerine odaklanır.

## Loopback ve Yerel Servislerin Numaralandırılması

Dinleyen servisleri, bind adreslerini ve izinler elverdiğinde bunların sahibi olan süreçleri belirleyerek başlayın.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Önemli kalıplar:

- `127.0.0.1:<port>` veya `[::1]:<port>`: varsayılan olarak yalnızca host üzerinden erişilebilir.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: filtrelenmediği sürece tüm IPv4 arayüzlerinden erişilebilir.<sup>[[3]](#references)</sup>
- `veth*`, `docker*`, `br-*`, `cni*` arayüzlerindeki `10.0.0.0/8`, `172.16.0.0/12` veya `192.168.0.0/16`: muhtemelen container veya yerel lab ağlarıdır.<sup>[[23]](#references)[[24]](#references)</sup>
- `/run`, `/var/run`, `/tmp` veya uygulama dizinlerindeki Unix socket'leri: yerel IPC yüzeyleridir.<sup>[[5]](#references)</sup>

Tarihteki [snapd socket ayrıştırma sorunu, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) için çalışan daemon'u, yerel API socket'ini ve kurulu paketi veya snap revizyonunu ilgili dağıtım için yayımlanan düzeltmeyle karşılaştırarak inceleyin. Hata, `snap-confine` içinde değil, snapd'in bir eşin socket adresini doğrulamasındaydı; set-user-ID `snap-confine` dosyası veya tek başına upstream sürüm dizesi, sistemin bu sorundan etkilendiğini kanıtlamaz. Ubuntu, sürüme özgü paket sürümleriyle düzeltmeler yayımladı ve snapd, dağıtım paketinden bağımsız olarak snap üzerinden güncellenmiş olabilir. Ayrıcalıklı API sınırını değerlendirmeden önce gerçekten çalışan derlemeyi ve yerel socket'e erişilebilirliği doğrulayın. Pasif numaralandırma, özel hazırlanmış bir socket isteği göndermemeli veya snap kurmamalıdır.

[`socat` ve `EXEC` kullanılarak](https://man7.org/linux/man-pages/man1/socat.1.html) başlatılan bir loopback listener, yerel istemci girdisini ayrı bir programa iletebilir. Root sahibi özel bir hizmeti ayrıcalık yükseltme adayı olarak değerlendirmeden önce listener'ın komutunu, çalıştırılabilir dosya yolunu, alt sürecin etkin kimliğini, yerel erişilebilirliğini ve kimlik doğrulamasını ilişkilendirin. Bellek güvenliği açığı veya güvenli olmayan girdiden komuta giden yol, ilgili ikili dosya ve derlemeye özgü kanıt gerektirir; tek başına port numarası, `socat` süreci veya root sahipliği bunu kanıtlamaz. Pasif numaralandırma, hizmete girdi göndermek yerine süreç, socket ve dosya meta verileriyle sınırlı kalmalıdır.

Yerel bir Salt master, loopback üzerinde veya container tarafından yayımlanan bir host portunda 4505 ve 4506 TCP portlarını dinleyebilir. [Salt'ın 3000.2 sürüm notlarında](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) kimlik doğrulamasız bir yöntem erişimi açığı olan CVE-2020-11651 açıklanmıştır; bu açık upstream 2019.2.4 ve 3000.2 sürümlerinde giderilmiştir. Listener'ı ayrıcalık yükseltme adayı olarak değerlendirmeden önce gerçek `salt-master` süreciyle, erişilebilir arayüzle, kurulu paket ve tedarikçi yamalarıyla ve etkin container veya host kimliğiyle ilişkilendirin; tek başına bir port veya upstream sürümü kanıt değildir. Master bir container içinde çalışıyorsa host-root etkisi ayrı bir sınırdır: kullanılabilir bir host runtime API socket'inin bu container'a bağlandığını ve container içinden erişilebilir olduğunu doğrulayın. Maruziyeti belirlemek için pasif numaralandırma Salt istek sunucusuna sorgu göndermemeli veya container oluşturmamalıdır. Bkz. [Salt'ın port belgeleri](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) ve [runtime API triyajı](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Yerel portları hafif problarla eşleyin.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Mevcutsa `nmap`'i yerel olarak kullan.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Gizli veth ve Container Alt Ağları

Container tabanlı veya laboratuvar ortamları, hizmetleri genellikle yalnızca bir bridge ya da veth alt ağında sunar. Bir hizmetin erişilemez olduğunu varsaymadan önce arayüzleri ve yönlendirme tablolarını listeleyin.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Olası yerel alt ağları bulun.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Keşfedilen alt ağı dikkatlice araştırın.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Teknik, web paneli, debug endpoint'i veya yardımcı hizmeti dış taramalardan gizli olduğu hâlde ele geçirilmiş ana makineden ya da container ağından erişilebilir olduğunda kullanışlıdır.

Loopback notebook hizmeti, başlangıçta işlem çıktısına yazdırılan bir token ile kimlik doğrulaması yapabilir. Bu çıktı başka bir yerel hesap tarafından okunabilen bir log dosyasına yönlendirilirse token kullanıcı sınırını aşabilir ve notebook sunucusunun hesabında kod yürütülmesine olanak tanıyabilir. Bir log yolunu yetki yükseltme ipucu olarak değerlendirmeden önce dinleyen işlemin sahibini, log hedefini ve izinlerini, geçerli token yapılandırmasını ve notebook erişim denetimlerini ilişkilendirin. Pasif keşif sırasında log metadata'sını listeleyin; ana makineyi yalnızca sınıflandırmak için token'ları yazdırmayın veya hizmete bağlanmayın.

## socat veya SSH ile Yerel Pivot

Bir hizmet loopback'e bağlıysa, hizmetin kendisini değiştirmek yerine izin verilen bir kanal üzerinden erişime açın.

SSH ile yalnızca yerelde çalışan bir HTTP hizmetini yönlendirin.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Shell erişiminiz olduğunda `socat` ile yerel bir portu köprüleyin.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Yerel testler için bir Unix soketini TCP'ye yönlendirin.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Bu, tek başına hiçbir şeyi exploit etmez. Yalnızca yerel bir yüzeyi araçlarınızdan erişilebilir hâle getirir; böylece onunla normal bir servis gibi etkileşim kurabilirsiniz.

## Banner Grabbing ve Basit Protokoller

Her servis HTTP kullanmaz. Birçok yerel servis, bir banner veya tek satırlık protokol aracılığıyla yeterli bilgiyi leak eder.

Temel yoklamalar.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

HTTP'yi tarayıcı olmadan kontrol et.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

TLS için.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Amaç; protokolü, kimlik doğrulama şemasını, sürümü ve hizmetin yerel istemcilere güvenip güvenmediğini belirlemektir.

Bir aiohttp listener için static-route yapılandırmasının yanı sıra sürümünü de inceleyin. CVE-2024-23334, `follow_symlinks=True` etkinleştirilmiş bir static route kullanıldığında 3.9.2 öncesi aiohttp sürümlerini etkiler: bu route'a yapılan istekler, static root dışındaki dosyaları okuyabilir. Hizmet root olarak çalışıyorsa ve route'a erişilebiliyorsa root tarafından okunabilen dosyalar açığa çıkabilir. Bir sürüm banner'ı veya loopback bind, tek başına güvenlik açığı bulunan yapılandırmanın ya da dosyalara erişimin varlığını kanıtlamaz.<sup>[[27]](#references)</sup>

## Loopback Trafiğini Yakalama

Yerel trafik; header'ları, bearer token'ları, Basic Auth kimlik bilgilerini veya uygulamaya özgü sırları açığa çıkarabilir.<sup>[[17]](#references)[[25]](#references)</sup> Yalnızca yetkili ortamlarda yakalama yapın.

Loopback HTTP trafiğini yakalayın.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Belirli bir yerel hizmeti yakalayın.<sup>[[16]](#references)</sup>

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

Bir lab ortamında client process environment'ını kontrol edebiliyorsanız, `SSLKEYLOGFILE` TLS oturumlarının Wireshark'ta veya uyumlu araçlarda çözümlenmesini sağlayabilir.<sup>[[19]](#references)[[20]](#references)</sup> Bu, TLS'nin kendisine saldırmadan yerel HTTPS trafiğini anlamak için kullanışlıdır.

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

Ardından `/tmp/tls.pcap` ve `/tmp/sslkeys.log` dosyalarını Wireshark'a yükleyin. Bu yalnızca istemci kütüphanesi NSS tarzı anahtar günlük kaydını desteklediğinde ve bağlantı kurulmadan önce ortamı ayarlayabildiğinizde işe yarar.<sup>[[20]](#references)[[21]](#references)</sup>

## Unix Socket Etkileşimi ve Command Injection

Unix soketleri yerel IPC uç noktalarıdır.<sup>[[5]](#references)</sup> HTTP API'leri, özel protokoller veya güvenli olmayan komut işleyicileri sunabilirler.<sup>[[12]](#references)[[14]](#references)</sup>

Grup yazma iznine sahip, root tarafından sahip olunan bir soket tek başına bir güvenlik açığı değil, bir yetkilendirme sınırıdır. Risk değerlendirmesi yapmadan önce grubunu ve izinlerini mevcut hesapla karşılaştırın, dinleyen süreci belirleyin ve bu sürecin istemcilerden gelen hangi verileri kabul ettiğini inceleyin. Özellikle, gönderilen PHP kodunu çalıştıran ayrıcalıklı bir hizmet, çağıranın seçtiği bir `php.ini` yoluna da güveniyorsa veya çağıranın `disable_functions` ya da `open_basedir` değerlerini değiştirmesine izin veriyorsa ikinci bir sınırı aşabilir; etkin yapılandırmayı ve hizmetin doğrulama yolunu inceleyin. [PHP yapılandırma kılavuzu](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) bu yönergeleri açıklar. Tek başına soket meta verileri kod yürütüldüğünü kanıtlamaz.

Soketleri bulun.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Unix socket üzerinden HTTP ile etkileşim kurun.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Ham bir socket ile etkileşim kurun.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Kullanıcı denetimindeki soket girdisi bir shell'e veya ayrıcalıklı bir yardımcı programa aktarılırsa komut enjeksiyonuna yol açabilir.<sup>[[26]](#references)</sup> Odaklanmış bir örnek için bkz. [Socket Command Injection](socket-command-injection.md).

## nftables İncelemesi ve Yetkili Kural Değişiklikleri

Yerel güvenlik duvarı kuralları, bir hizmetin yerel olarak görünürken uzaktan neden engellendiğini veya yüksek numaralı bir portun bir arayüzden neden erişilemez göründüğünü açıklayabilir.<sup>[[22]](#references)</sup>

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

Yetkili bir laboratuvarda, belirli bir engelleme kuralını handle ile kaldırın.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Tam tabloları flush etmek yerine tam handle'ı silmeyi tercih edin. Teknik, davranışa neden olan belirli filtreyi tespit edip yalnızca o kuralı değiştirmektir.<sup>[[22]](#references)</sup>

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

Yalnızca yerel erişime açık olan, daha ayrıcalıklı bir kullanıcı olarak çalışan, yönetim/hata ayıklama işlevleri sunan veya loopback/container-network istemcilerine güvenen hizmetlere öncelik verin.

## References

- [1] [ss(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Sürüm 6 Adresleme Mimarisi](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Yönlendirmeler (Bash Başvuru Kılavuzu)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout kullanımı (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Tarama Teknikleri (Nmap Başvuru Kılavuzu)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Ana Bilgisayar Keşfi (Nmap Başvuru Kılavuzu)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Belirtimi ve Tarama Sırası (Nmap Başvuru Kılavuzu)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux kılavuz sayfası](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD kılavuz sayfası](https://man.openbsd.org/nc.1)
- [14] [curl komut satırı aracı kılavuzu](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL Belgeleri](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: 'Basic' HTTP Kimlik Doğrulama Şeması](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 kullanımı (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL Belgeleri](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark Kullanım Kılavuzu](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables kılavuzu](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Özel İnternetler için Adres Tahsisi (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [OAuth 2.0 Yetkilendirme Çerçevesi: Bearer Token Kullanımı (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Bir İşletim Sistemi Komutunda Kullanılan Özel Öğelerin Uygunsuz Etkisizleştirilmesi](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp bakımcı güvenlik bildirimi: follow_symlinks ile statik rota geçişi](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
