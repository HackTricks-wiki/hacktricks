# Trafik Yakalama, Güvenlik Duvarı ve Çıkış Trafiği İncelemesi

{{#include ../../banners/hacktricks-training.md}}

[Yerel dinleyicileri ve Unix soketlerini](local-network-and-socket-triage.md) bulduktan sonra, trafiğin hangi arayüzlerden geçtiğini ve erişilebilirliği hangi güvenlik duvarı veya proxy kurallarının etkilediğini inceleyin. Yalnızca loopback üzerinden erişilebilen bir hizmet, başka bir ana bilgisayardan erişilemese bile hassas HTTP başlıkları taşıyor olabilir.

## Yakalama izinlerini kontrol edin ve bir arayüz seçin

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap`, mevcut kullanıcının sudo erişimi olmasa bile paket yakalama yeteneklerine sahip olabilir. Yürütülebilir dosyanın gerçek yeteneklerini ve grup izinlerini denetleyin. Kullanılabilir en küçük arayüzü, süreyi ve filtreyi seçerek yakalama yapın; yakalama kimlik bilgileri veya kişisel veriler içerebilir.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` düz metin TCP akışlarını yeniden oluşturur; `tshark` bir yakalamadaki alanları filtreleyip çıkarabilir. TLS trafiğinin şifresini çözmek için uç nokta anahtarları veya bağlantıdan önce `SSLKEYLOGFILE` için yapılandırılmış desteklenen bir istemci gerekir. [Yerel ağ triyajı sayfasında](local-network-and-socket-triage.md#tls-key-logging) bu iş akışı gösterilir. Şifrelenmiş bir yakalamayı okunabilir düz metin olarak değerlendirmeyin.

Saklanan olay artefaktları bu değerlendirmeyi değiştirebilir. [Linux core dump'ı süreç belleğinin bir görüntüsüdür](https://man7.org/linux/man-pages/man5/core.5.html) ve bir oturum anahtarını içerebilir; okunabilir bir döküm ile paket yakalaması aynı süreçten ve oturumdan geldiyse analist bu trafiğin şifresini çözebilir. Önce artefakt yollarını ve izinlerini envantere alın, ardından süreç kimliğini, yakalama zamanını, protokolü ve anahtar biçimini ayrı ayrı doğrulayın. Şifresi çözülmüş trafik veya kurtarılmış bir arşiv, ifşaya işaret eder; başka bir hesabın eriştiğinin kanıtı değildir: kısmi SSH anahtarı materyali hâlâ yeniden oluşturulmalı, ilgili ortak anahtarla eşleştirilmeli ve söz konusu hesabın SSH politikası tarafından kabul edilmelidir. Geniş kapsamlı envanter çıktılarında core dump içeriğini veya yakalama yüklerini dökmekten kaçının.

## Güvenlik duvarı katmanlarını belirleme

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` ve `iptables`, UFW veya firewalld gibi dağıtım sarmalayıcıları üzerinden sunulabilir. Etkin kuralları ve sarmalayıcının kalıcı yapılandırmasını okuyun; bir gösterimde görünen kural başka bir araç tarafından oluşturulmuş olabilir. Engellenen bir hizmeti belirli bir kurala bağlamadan önce arayüzü, yönü, kaynağı, hedefi, protokolü, portu ve bağlantı durumunu inceleyin. Odaklanmış bir örnek için [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) bölümüne bakın.

## Giden trafiği ve proxy davranışını test edin

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS hatasını TCP, TLS veya proxy hatasından ayırın. Değerlendirmeyle ilgili belirli hedefi ve protokolü test edin; ICMP erişilebilirliği, TCP veya UDP trafiğine izin verildiği anlamına gelmez. Bir proxy yapılandırılmışsa, proxy üzerinden gönderilmesi amaçlanan isteği aynı hedefe `no_proxy` kuralları uygulanarak gönderilen istekle karşılaştırın. Yerel bir port yönlendirmesi, loopback hizmetini başka bir yerde de erişilebilir kılabilir; bu nedenle güvenlik duvarı görünümü ile gözlemlenen dışa açıklık uyuşmuyorsa etkin dinleyicileri ve SSH tünellerini inceleyin.
{{#include ../../banners/hacktricks-training.md}}
