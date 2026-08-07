# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

macOS에 익숙하지 않다면 다음 macOS 기본 사항부터 학습해야 합니다.

- 주요 macOS **files & permissions:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- 일반적인 macOS **users**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- k**ernel**의 **architecture**


{{#ref}}
mac-os-architecture/
{{#endref}}

- 일반적인 macOS **n**etwork services & protocols**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz`를 다운로드하려면 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)와 같은 URL을 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)로 변경합니다.

### MacOS MDM

기업의 **macOS** 시스템은 높은 확률로 **MDM으로 관리**됩니다. 따라서 attacker의 관점에서는 **이것이 어떻게 작동하는지** 알아두는 것이 중요합니다:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspecting, Debugging and Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

**root로 실행되는 process가** 사용자가 제어할 수 있는 파일을 **작성하면**, 해당 사용자는 이를 악용하여 **privileges를 escalate**할 수 있습니다.\
다음과 같은 상황에서 발생할 수 있습니다:

- 사용된 파일이 이미 사용자에 의해 생성된 경우(사용자가 소유)
- group 때문에 사용자가 사용된 파일에 write할 수 있는 경우
- 사용된 파일이 사용자가 소유한 directory 내부에 있는 경우(사용자가 파일을 생성할 수 있음)
- 사용된 파일이 root가 소유한 directory 내부에 있지만 group 때문에 사용자가 해당 directory에 write access를 가진 경우(사용자가 파일을 생성할 수 있음)

**파일을 생성**할 수 있고 해당 파일이 **root에 의해 사용**될 예정이라면, 사용자는 그 content를 **악용**하거나, 파일을 다른 위치를 가리키도록 **symlinks/hardlinks**를 생성할 수도 있습니다.

이러한 유형의 vulnerabilities를 찾을 때는 **취약한 `.pkg` installers**도 잊지 말고 **check**해야 합니다:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

파일 확장자로 등록된 이상한 apps를 악용할 수 있으며, 서로 다른 applications가 특정 protocols를 열도록 등록될 수 있습니다.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

macOS에서는 **applications와 binaries가 folders 또는 settings에 접근할 permissions를 가질 수 있으며**, 이로 인해 다른 것보다 더 높은 privileges를 가질 수 있습니다.

따라서 macOS machine을 성공적으로 compromise하려는 attacker는 **TCC privileges를 escalate**해야 하며(필요에 따라 **SIP를 bypass**해야 할 수도 있음), 자신에게 필요한 작업을 수행해야 합니다.

이러한 privileges는 일반적으로 application이 서명될 때 함께 제공되는 **entitlements** 형태로 부여되거나, application이 일부 access를 요청한 후 **사용자가 승인하면** **TCC databases**에서 확인할 수 있습니다. process가 이러한 privileges를 획득하는 또 다른 방법은 해당 **privileges**를 가진 process의 **child**가 되는 것입니다. 이러한 privileges는 일반적으로 **inherited**됩니다.<sup>[[5]](#references)</sup>

다음 links에서 [**TCC에서 privileges를 escalate**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses)하는 여러 방법, [**TCC를 bypass**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html)하는 방법, 그리고 과거에 [**SIP가 bypass된 방법**](macos-security-protections/macos-sip.md#sip-bypasses)을 확인할 수 있습니다.

## macOS Traditional Privilege Escalation

물론 red teams의 관점에서는 root로 escalate하는 것에도 관심이 있어야 합니다. 다음 post에서 몇 가지 힌트를 확인하세요:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
