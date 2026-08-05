# macOS 보안 및 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## macOS 기초

macOS에 익숙하지 않다면 다음 macOS 기초부터 학습해야 합니다:

- 특수 macOS **파일 및 권한:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- 일반적인 macOS **사용자**


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

- 일반적인 macOS **네트워크 서비스 및 프로토콜**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz`를 다운로드하려면 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)와 같은 URL을 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)로 변경합니다.

### macOS MDM

기업 환경의 **macOS** 시스템은 높은 확률로 **MDM으로 관리됩니다**. 따라서 공격자 관점에서는 **이것이 어떻게 작동하는지** 알아두는 것이 유용합니다:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### macOS - Inspecting, Debugging 및 Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## macOS 보안 보호 기능


{{#ref}}
macos-security-protections/
{{#endref}}

## 공격 표면

### 파일 권한

**root로 실행 중인 process가 사용자가 제어할 수 있는 파일을 작성하면**, 해당 사용자는 이를 악용하여 **권한을 상승**시킬 수 있습니다.\
이는 다음과 같은 상황에서 발생할 수 있습니다:

- 사용된 파일이 사용자가 이미 생성한 파일인 경우 (사용자 소유)
- group으로 인해 사용자가 해당 파일에 쓸 수 있는 경우
- 사용된 파일이 사용자 소유의 directory 내부에 있는 경우 (사용자가 파일을 생성할 수 있음)
- 사용된 파일이 root 소유의 directory 내부에 있지만 group으로 인해 사용자가 해당 directory에 쓸 수 있는 경우 (사용자가 파일을 생성할 수 있음)

**root가 사용하게 될 파일을 생성**할 수 있으면, 사용자는 **파일의 콘텐츠를 악용**하거나 해당 파일을 다른 위치를 가리키는 **symlinks/hardlinks**로 생성할 수도 있습니다.

이러한 유형의 취약점을 확인할 때는 **취약한 `.pkg` installers**를 확인하는 것을 잊지 마세요:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### 파일 확장자 및 URL scheme app handlers

파일 확장자로 등록된 비정상적인 apps가 악용될 수 있으며, 특정 프로토콜을 열도록 서로 다른 applications를 등록할 수 있습니다.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP 권한 상승

macOS에서 **applications 및 binaries는 폴더나 설정에 접근할 수 있는 permissions**을 가질 수 있으며, 이로 인해 다른 것보다 더 높은 권한을 갖게 됩니다.

따라서 macOS 시스템을 성공적으로 compromise하려는 공격자는 **TCC privileges를 상승**시키거나 (필요에 따라) **SIP를 bypass**해야 합니다.

이러한 privileges는 일반적으로 application이 서명될 때 포함된 **entitlements** 형태로 부여됩니다. 또는 application이 특정 접근 권한을 요청한 후 **사용자가 이를 승인하면**, 해당 권한은 **TCC databases**에서 확인할 수 있습니다. process가 이러한 privileges를 얻는 또 다른 방법은 해당 **privileges**를 가진 process의 **child process**가 되는 것입니다. 이러한 권한은 일반적으로 **상속**됩니다.

다음 링크에서 [**TCC에서 privileges를 상승**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses)하는 다양한 방법, [**TCC를 bypass**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html)하는 방법, 그리고 과거에 [**SIP가 어떻게 bypass되었는지**](macos-security-protections/macos-sip.md#sip-bypasses)를 확인할 수 있습니다.

## macOS Traditional Privilege Escalation

물론 red teams 관점에서는 root로 privilege를 상승시키는 것에도 관심이 있어야 합니다. 다음 post에서 몇 가지 힌트를 확인하세요:


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
