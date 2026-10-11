# Traffic Capture, Firewall ve Egress Triage

{{#include ../../banners/hacktricks-training.md}}

[local listeners and Unix sockets](local-network-and-socket-triage.md) konumlarını belirledikten sonra, trafiğin hangi arayüzlerden geçtiğini ve erişilebilirliği hangi firewall veya proxy kurallarının etkilediğini inceleyin. Yalnızca loopback üzerinden erişilebilen bir hizmet, başka bir host'tan erişilemese bile hassas HTTP başlıkları taşıyor olabilir.

## Capture izinlerini kontrol edin ve bir arayüz seçin

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap`, mevcut kullanıcının sudo erişimi olmasa bile paket yakalama yeteneklerine sahip olabilir. Çalıştırılabilir dosyanın gerçek yeteneklerini ve grup izinlerini kontrol edin. Mümkün olan en sınırlı arayüzü, süreyi ve filtreyi kullanarak yakalama yapın; yakalama kimlik bilgileri veya kişisel veriler içerebilir.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` düz metin TCP akışlarını yeniden oluşturur; `tshark` bir capture'dan filtreleme yapabilir ve alanları çıkarabilir. TLS trafiğinin şifresini çözmek için uç nokta anahtarları veya bağlantı kurulmadan önce `SSLKEYLOGFILE` için yapılandırılmış desteklenen bir istemci gerekir. [Yerel ağ triyajı sayfasında](local-network-and-socket-triage.md#tls-key-logging) bu iş akışı gösterilir. Şifrelenmiş bir capture'ı okunabilir düz metin olarak değerlendirmeyin.

Saklanan olay artefaktları bu değerlendirmeyi değiştirebilir. [Linux core dump, işlem belleğinin bir görüntüsüdür](https://man7.org/linux/man-pages/man5/core.5.html) ve bir oturum anahtarını koruyor olabilir; okunabilir bir dump ile paket capture'ı aynı işlem ve oturumdan geldiyse bir analist bu trafiğin şifresini çözebilir. Önce artefakt yollarını ve izinlerini envanterleyin, ardından işlem kimliğini, capture zamanını, protokolü ve anahtar biçimini ayrı ayrı doğrulayın. Şifresi çözülmüş trafik veya kurtarılmış bir arşiv, bilgi ifşasına dair bir ipucudur; başka bir hesabın erişimine kanıt değildir: kısmi SSH anahtar materyali yine de yeniden oluşturulmalı, karşılık gelen açık anahtarla eşleştirilmeli ve ilgili hesabın SSH politikasınca kabul edilmelidir. Core dump içeriğini veya capture payload'larını geniş kapsamlı envanter çıktısına dökmekten kaçının.

## Firewall katmanlarını belirleyin

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` ve `iptables`, UFW veya firewalld gibi dağıtım sarmalayıcıları üzerinden sunulabilir. Etkin kuralları ve sarmalayıcının kalıcı yapılandırmasını okuyun; bir gösterimde görünen kural başka bir araç tarafından oluşturulmuş olabilir. Engellenen bir hizmeti belirli bir kurala bağlamadan önce arayüzü, yönü, kaynağı, hedefi, protokolü, portu ve bağlantı durumunu inceleyin. Odaklanmış bir örnek için bkz. [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes).

## Dışa giden trafiği ve proxy davranışını test edin

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS hatasını TCP, TLS veya proxy hatasından ayrı değerlendirin. Değerlendirmeyle ilgili hedefi ve protokolü özel olarak test edin; ICMP erişilebilir olması, TCP veya UDP trafiğine izin verildiği anlamına gelmez. Bir proxy yapılandırılmışsa, amaçlanan proxy üzerinden yapılan isteği aynı hedefe yönelik ve geçerli `no_proxy` kurallarına tabi istekle karşılaştırın. Yerel bir port yönlendirmesi de loopback hizmetini başka bir yerde erişilebilir hâle getirebilir; bu nedenle firewall görünümü ile gözlemlenen maruziyet uyuşmuyorsa etkin dinleyicileri ve SSH tünellerini inceleyin.
{{#include ../../banners/hacktricks-training.md}}
