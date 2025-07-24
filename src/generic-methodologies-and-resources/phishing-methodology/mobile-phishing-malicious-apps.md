# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona omawia techniki stosowane przez aktorów zagrożeń do dystrybucji **złośliwych APK Androida** i **profilów konfiguracji mobilnej iOS** poprzez phishing (SEO, inżynieria społeczna, fałszywe sklepy, aplikacje randkowe itp.).
> Materiał jest dostosowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki podobnych domen (randkowe, chmurowe, usługi samochodowe…).
– Użyj lokalnych słów kluczowych i emotikonów w elemencie `<title>`, aby uzyskać wysoką pozycję w Google.
– Umieść *zarówno* instrukcje instalacji Androida (`.apk`), jak i iOS na tej samej stronie docelowej.
2. **First Stage Download**
* Android: bezpośredni link do *niepodpisanego* lub „sklepu zewnętrznego” APK.
* iOS: `itms-services://` lub zwykły link HTTPS do złośliwego **mobileconfig** (patrz poniżej).
3. **Post-install Social Engineering**
* Przy pierwszym uruchomieniu aplikacja prosi o **kod zaproszenia / weryfikacji** (iluzja ekskluzywnego dostępu).
* Kod jest **wysyłany metodą POST przez HTTP** do Command-and-Control (C2).
* C2 odpowiada `{"success":true}` ➜ złośliwe oprogramowanie kontynuuje.
* Analiza dynamiczna w piaskownicy / AV, która nigdy nie przesyła ważnego kodu, nie widzi **złośliwego zachowania** (unikanie).
4. **Runtime Permission Abuse** (Android)
* Niebezpieczne uprawnienia są żądane **dopiero po pozytywnej odpowiedzi C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Starsze wersje również prosiły o uprawnienia SMS -->
```
* Ostatnie warianty **usuwają `<uses-permission>` dla SMS z `AndroidManifest.xml`**, ale pozostawiają ścieżkę kodu Java/Kotlin, która odczytuje SMS-y przez refleksję ⇒ obniża wynik statyczny, a jednocześnie działa na urządzeniach, które przyznają uprawnienia poprzez nadużycie `AppOps` lub stare cele.
5. **Facade UI & Background Collection**
* Aplikacja pokazuje nieszkodliwe widoki (przeglądarka SMS, wybieracz galerii) zaimplementowane lokalnie.
* W międzyczasie eksfiltruje:
- IMEI / IMSI, numer telefonu
- Pełny zrzut `ContactsContract` (tablica JSON)
- JPEG/PNG z `/sdcard/DCIM` skompresowane z [Luban](https://github.com/Curzibn/Luban), aby zmniejszyć rozmiar
- Opcjonalna zawartość SMS (`content://sms`)
Ładunki są **spakowane w paczki** i wysyłane przez `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Pojedynczy **profil konfiguracji mobilnej** może żądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itp., aby zarejestrować urządzenie w nadzorze podobnym do „MDM”.
* Instrukcje inżynierii społecznej:
1. Otwórz Ustawienia ➜ *Profil pobrany*.
2. Stuknij *Zainstaluj* trzy razy (zrzuty ekranu na stronie phishingowej).
3. Zaufaj niepodpisanemu profilowi ➜ atakujący zyskuje uprawnienia *Kontakty* i *Zdjęcia* bez przeglądu App Store.
7. **Network Layer**
* Zwykły HTTP, często na porcie 80 z nagłówkiem HOST jak `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS → łatwe do wykrycia).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Podczas oceny złośliwego oprogramowania, zautomatyzuj fazę kodu zaproszenia za pomocą Frida/Objection, aby dotrzeć do złośliwej gałęzi.
* **Manifest vs. Runtime Diff** – Porównaj `aapt dump permissions` z runtime `PackageManager#getRequestedPermissions()`; brak niebezpiecznych uprawnień to czerwony flag.
* **Network Canary** – Skonfiguruj `iptables -p tcp --dport 80 -j NFQUEUE`, aby wykryć niesolidne wybuchy POST po wprowadzeniu kodu.
* **mobileconfig Inspection** – Użyj `security cms -D -i profile.mobileconfig` na macOS, aby wylistować `PayloadContent` i zauważyć nadmierne uprawnienia.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** w celu wychwycenia nagłych wybuchów domen bogatych w słowa kluczowe.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` z klientów Dalvik poza Google Play.
* **Invite-code Telemetry** – POST 6–8 cyfrowych kodów numerycznych krótko po instalacji APK może wskazywać na staging.
* **MobileConfig Signing** – Zablokuj niepodpisane profile konfiguracji za pomocą polityki MDM.

## Useful Frida Snippet: Auto-Bypass Invitation Code
```python
# frida -U -f com.badapp.android -l bypass.js --no-pause
# Hook HttpURLConnection write to always return success
Java.perform(function() {
var URL = Java.use('java.net.URL');
URL.openConnection.implementation = function() {
var conn = this.openConnection();
var HttpURLConnection = Java.use('java.net.HttpURLConnection');
if (Java.cast(conn, HttpURLConnection)) {
conn.getResponseCode.implementation = function(){ return 200; };
conn.getInputStream.implementation = function(){
return Java.use('java.io.ByteArrayInputStream').$new("{\"success\":true}".getBytes());
};
}
return conn;
};
});
```
## Wskaźniki (Ogólne)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
## Odniesienia

- [Ciemna strona romansu: kampania extorsyjna SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – biblioteka kompresji obrazów dla Androida](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
