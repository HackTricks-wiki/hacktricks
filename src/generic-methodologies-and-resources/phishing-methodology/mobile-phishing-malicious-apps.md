# 모바일 피싱 및 악성 앱 배포 (안드로이드 및 iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 위협 행위자들이 피싱(SEO, 소셜 엔지니어링, 가짜 스토어, 데이팅 앱 등)을 통해 **악성 안드로이드 APK** 및 **iOS 모바일 구성 프로필**을 배포하는 데 사용하는 기술을 다룹니다.
> 이 자료는 Zimperium zLabs(2025)에 의해 폭로된 SarangTrap 캠페인과 기타 공개 연구에서 수정되었습니다.

## 공격 흐름

1. **SEO/피싱 인프라**
* 유사 도메인 수십 개 등록(데이팅, 클라우드 공유, 차량 서비스 등).
– Google에서 순위를 매기기 위해 `<title>` 요소에 지역 언어 키워드와 이모지를 사용합니다.
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
* 최근 변종은 **`AndroidManifest.xml`에서 SMS에 대한 `<uses-permission>`을 제거**하지만, SMS를 리플렉션을 통해 읽는 Java/Kotlin 코드 경로는 남겨둡니다 ⇒ 권한을 `AppOps` 남용 또는 이전 대상을 통해 부여받는 장치에서 여전히 기능하면서 정적 점수를 낮춥니다.
5. **페사드 UI 및 백그라운드 수집**
* 앱은 로컬에서 구현된 무해한 뷰(SMS 뷰어, 갤러리 선택기)를 표시합니다.
* 동시에 다음을 유출합니다:
- IMEI / IMSI, 전화번호
- 전체 `ContactsContract` 덤프(JSON 배열)
- 크기를 줄이기 위해 [Luban](https://github.com/Curzibn/Luban)으로 압축된 `/sdcard/DCIM`의 JPEG/PNG
- 선택적 SMS 내용(`content://sms`)
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
* **매니페스트 vs. 런타임 차이** – `aapt dump permissions`와 런타임 `PackageManager#getRequestedPermissions()`를 비교합니다; 위험한 권한이 누락된 것은 경고 신호입니다.
* **네트워크 카나리** – 코드 입력 후 비정상적인 POST 폭주를 감지하기 위해 `iptables -p tcp --dport 80 -j NFQUEUE`를 구성합니다.
* **mobileconfig 검사** – macOS에서 `security cms -D -i profile.mobileconfig`를 사용하여 `PayloadContent`를 나열하고 과도한 권한을 찾아냅니다.

## 블루팀 탐지 아이디어

* **인증서 투명성 / DNS 분석**을 통해 키워드가 풍부한 도메인의 갑작스러운 폭주를 포착합니다.
* **User-Agent 및 경로 정규 표현식**: `(?i)POST\s+/(check|upload)\.php` Google Play 외부의 Dalvik 클라이언트에서.
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
## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
