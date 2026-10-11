# Trafik Yakalama, Güvenlik Duvarı ve Egress Triyajı

{{#include ../../banners/hacktricks-training.md}}

[Yerel dinleyicileri ve Unix socket'lerini](local-network-and-socket-triage.md) bulduktan sonra, trafiğin hangi arayüzlerden geçtiğini ve erişilebilirliği hangi güvenlik duvarı veya proxy kurallarının etkilediğini inceleyin. Yalnızca loopback üzerinden erişilebilen bir hizmet, başka bir host'tan erişilemiyor olsa bile hassas HTTP header'ları taşıyor olabilir.

## Yakalama izinlerini kontrol edin ve bir arayüz seçin

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap`, mevcut kullanıcının sudo erişimi olmasa bile paket yakalama yeteneklerine sahip olabilir. Çalıştırılabilir dosyanın gerçek yeteneklerini ve grup izinlerini kontrol edin. En küçük işe yarar arayüzü, süreyi ve filtreyi kullanarak yakalama yapın; yakalama kimlik bilgileri veya kişisel veriler içerebilir.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow`, düz metin TCP akışlarını yeniden oluşturur; `tshark` ise bir yakalamadaki alanları filtreleyip çıkarabilir. TLS trafiğinin şifresini çözmek için bağlantıdan önce uç nokta anahtarları veya `SSLKEYLOGFILE` için yapılandırılmış, desteklenen bir istemci gerekir. [Yerel ağ triyajı sayfasında](local-network-and-socket-triage.md#tls-key-logging) bu iş akışı gösterilir. Şifrelenmiş bir yakalamanın okunabilir düz metin olduğunu varsaymayın.

Saklanan olay artefaktları bu değerlendirmeyi değiştirebilir. [Linux core dump, işlem belleğinin bir görüntüsüdür](https://man7.org/linux/man-pages/man5/core.5.html) ve bir oturum anahtarını saklıyor olabilir; okunabilir bir dump ile paket yakalaması aynı işlem ve oturumdan geldiyse analist bu trafiğin şifresini çözebilir. Önce artefakt yollarını ve izinlerini envantere alın, ardından işlem kimliğini, yakalama zamanını, protokolü ve anahtar biçimini ayrı ayrı doğrulayın. Şifresi çözülmüş trafik veya kurtarılmış bir arşiv, olası bir veri ifşasına işaret eder; başka bir hesabın erişimine kanıt değildir: kısmi SSH anahtar materyali hâlâ birleştirilmeli, karşılık gelen açık anahtarla eşleştirilmeli ve hesabın SSH ilkesi tarafından kabul edilmelidir. Geniş kapsamlı envanter çıktılarında core dump içeriğini veya yakalama yüklerini dökmekten kaçının.

## Güvenlik duvarı katmanlarını belirleyin

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` ve `iptables`, UFW veya firewalld gibi dağıtım wrapper'ları üzerinden sunulabilir. Etkin kuralları ve wrapper'ın kalıcı yapılandırmasını okuyun; bir gösterimde görünen kural başka bir araç tarafından oluşturulmuş olabilir. Engellenen bir hizmeti belirli bir kurala bağlamadan önce arayüzü, yönü, kaynağı, hedefi, protokolü, portu ve bağlantı durumunu inceleyin. Odaklı bir örnek için [nftables kural incelemesi](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) bölümüne bakın.

## Egress ve proxy davranışını test edin

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS hatasını TCP, TLS veya proxy hatasından ayırın. Değerlendirmeyle ilgili belirli hedefi ve protokolü test edin; ICMP erişilebilirliği, TCP veya UDP trafiğine izin verildiği anlamına gelmez. Bir proxy yapılandırılmışsa, proxy üzerinden gönderilmesi amaçlanan isteği aynı hedefe `no_proxy` kurallarının geçerli olduğu durumda gönderilen istekle karşılaştırın. Yerel bir port yönlendirmesi, loopback hizmetini başka bir yerde de kullanılabilir hâle getirebilir. Bu nedenle, firewall görünümü ile gözlemlenen maruziyet uyuşmadığında etkin dinleyicileri ve SSH tünellerini inceleyin.
{{#include ../../banners/hacktricks-training.md}}
