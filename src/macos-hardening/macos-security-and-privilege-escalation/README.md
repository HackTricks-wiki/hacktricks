# macOS 보안 및 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## 기본 MacOS

macOS에 익숙하지 않다면, macOS의 기본을 배우기 시작해야 합니다:

- 특별한 macOS **파일 및 권한:**

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

- k**ernel**의 **구조**

{{#ref}}
mac-os-architecture/
{{#endref}}

- 일반적인 macOS n**etwork 서비스 및 프로토콜**

{{#ref}}
macos-protocols.md
{{#endref}}

- **오픈소스** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz`를 다운로드하려면 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)와 같은 URL을 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)로 변경하세요.

### MacOS MDM

기업에서는 **macOS** 시스템이 **MDM으로 관리될 가능성이 높습니다**. 따라서 공격자의 관점에서 **그 작동 방식을 아는 것이 흥미롭습니다**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - 검사, 디버깅 및 퍼징

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS 보안 보호

{{#ref}}
macos-security-protections/
{{#endref}}

## 공격 표면

### 파일 권한

**루트로 실행되는 프로세스가** 사용자가 제어할 수 있는 파일에 쓰면, 사용자는 이를 악용하여 **권한을 상승시킬 수 있습니다**.\
이는 다음과 같은 상황에서 발생할 수 있습니다:

- 사용자가 이미 생성한 파일(사용자가 소유)
- 그룹 때문에 사용자가 쓸 수 있는 파일
- 사용자가 파일을 생성할 수 있는 사용자가 소유한 디렉토리 내의 파일
- 루트가 소유한 디렉토리 내의 파일이지만 사용자가 그룹 때문에 쓰기 권한이 있는 경우(사용자가 파일을 생성할 수 있음)

**루트에 의해 사용될 파일을 생성할 수 있는** 것은 사용자가 **그 내용의 이점을 취하거나** 심지어 **심볼릭 링크/하드 링크**를 만들어 다른 위치를 가리키게 할 수 있게 합니다.

이러한 종류의 취약점에 대해서는 **취약한 `.pkg` 설치 프로그램을 확인하는 것을 잊지 마세요**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### 파일 확장자 및 URL 스킴 앱 핸들러

파일 확장자로 등록된 이상한 앱은 악용될 수 있으며, 특정 프로토콜을 열기 위해 다양한 애플리케이션이 등록될 수 있습니다.

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP 권한 상승

macOS에서 **애플리케이션과 바이너리는** 폴더나 설정에 접근할 수 있는 권한을 가질 수 있으며, 이는 다른 것들보다 더 특권을 부여합니다.

따라서 macOS 머신을 성공적으로 침해하고자 하는 공격자는 **TCC 권한을 상승시켜야 합니다**(또는 필요에 따라 **SIP를 우회해야 합니다**).

이러한 권한은 일반적으로 애플리케이션이 서명된 **권한**의 형태로 제공되거나, 애플리케이션이 일부 접근을 요청하고 **사용자가 이를 승인한 후** **TCC 데이터베이스**에서 찾을 수 있습니다. 프로세스가 이러한 권한을 얻는 또 다른 방법은 **그 권한을 가진 프로세스의 자식**이 되는 것입니다. 이 권한은 일반적으로 **상속됩니다**.

다양한 방법으로 [**TCC에서 권한을 상승시키는 방법**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**TCC를 우회하는 방법**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) 및 과거에 [**SIP가 우회된 방법**](macos-security-protections/macos-sip.md#sip-bypasses)을 찾으려면 이 링크를 따르세요.

## macOS 전통적인 권한 상승

물론 레드 팀의 관점에서 루트로 상승하는 것에도 관심이 있어야 합니다. 다음 게시물을 확인하여 몇 가지 힌트를 얻으세요:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS 준수

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## 참고 문헌

- [**OS X 사고 대응: 스크립팅 및 분석**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
