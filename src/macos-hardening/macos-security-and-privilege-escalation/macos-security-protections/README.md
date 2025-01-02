# macOS 보안 보호

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper는 일반적으로 **Quarantine + Gatekeeper + XProtect**의 조합을 의미하며, 이는 사용자가 **잠재적으로 악성 소프트웨어를 실행하는 것을 방지**하려고 시도하는 3개의 macOS 보안 모듈입니다.

자세한 정보는 다음에서 확인할 수 있습니다:

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## 프로세스 제한

### MACF

### SIP - 시스템 무결성 보호

{{#ref}}
macos-sip.md
{{#endref}}

### 샌드박스

MacOS 샌드박스는 **샌드박스 프로필**에 지정된 **허용된 작업**으로 샌드박스 내에서 실행되는 애플리케이션을 **제한**합니다. 이는 **애플리케이션이 예상된 리소스만 접근하도록 보장**하는 데 도움이 됩니다.

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **투명성, 동의 및 제어**

**TCC (투명성, 동의 및 제어)**는 보안 프레임워크입니다. 이는 애플리케이션의 **권한을 관리**하도록 설계되었으며, 특히 민감한 기능에 대한 접근을 규제합니다. 여기에는 **위치 서비스, 연락처, 사진, 마이크, 카메라, 접근성 및 전체 디스크 접근**과 같은 요소가 포함됩니다. TCC는 앱이 명시적인 사용자 동의를 얻은 후에만 이러한 기능에 접근할 수 있도록 보장하여 개인 데이터에 대한 프라이버시와 제어를 강화합니다.

{{#ref}}
macos-tcc/
{{#endref}}

### 실행/환경 제약 및 신뢰 캐시

macOS의 실행 제약은 **프로세스 시작을 규제**하는 보안 기능으로, **누가** 프로세스를 시작할 수 있는지, **어떻게**, **어디서** 시작할 수 있는지를 정의합니다. macOS Ventura에서 도입된 이 기능은 시스템 바이너리를 제약 카테고리로 분류하여 **신뢰 캐시** 내에 저장합니다. 모든 실행 가능한 바이너리는 **자기**, **부모**, **책임** 제약을 포함한 **시작**에 대한 **규칙**이 설정되어 있습니다. macOS Sonoma에서 **환경** 제약으로 제3자 앱에 확장되어, 이러한 기능은 프로세스 시작 조건을 규제하여 잠재적인 시스템 악용을 완화하는 데 도움이 됩니다.

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - 맬웨어 제거 도구

맬웨어 제거 도구(MRT)는 macOS의 보안 인프라의 또 다른 부분입니다. 이름에서 알 수 있듯이, MRT의 주요 기능은 **감염된 시스템에서 알려진 맬웨어를 제거하는 것**입니다.

Mac에서 맬웨어가 감지되면(XProtect 또는 다른 방법으로), MRT를 사용하여 자동으로 **맬웨어를 제거**할 수 있습니다. MRT는 백그라운드에서 조용히 작동하며, 일반적으로 시스템이 업데이트되거나 새로운 맬웨어 정의가 다운로드될 때 실행됩니다(맬웨어를 감지하기 위한 규칙이 바이너리 내에 있는 것으로 보입니다).

XProtect와 MRT는 모두 macOS의 보안 조치의 일부이지만, 서로 다른 기능을 수행합니다:

- **XProtect**는 예방 도구입니다. 이는 **파일이 다운로드될 때**(특정 애플리케이션을 통해) 파일을 검사하고, 알려진 유형의 맬웨어가 감지되면 **파일이 열리는 것을 방지**하여 맬웨어가 시스템에 감염되는 것을 방지합니다.
- **MRT**는 반응 도구입니다. 이는 시스템에서 맬웨어가 감지된 후 작동하며, 문제의 소프트웨어를 제거하여 시스템을 정리하는 것을 목표로 합니다.

MRT 애플리케이션은 **`/Library/Apple/System/Library/CoreServices/MRT.app`**에 위치합니다.

## 백그라운드 작업 관리

**macOS**는 이제 도구가 코드 실행을 지속하기 위해 잘 알려진 **기법을 사용할 때마다** 알림을 보냅니다(예: 로그인 항목, 데몬 등), 따라서 사용자는 **어떤 소프트웨어가 지속되고 있는지** 더 잘 알 수 있습니다.

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

이는 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`에 위치한 **데몬**과 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`에 위치한 **에이전트**와 함께 실행됩니다.

**`backgroundtaskmanagementd`**가 지속적인 폴더에 설치된 무언가를 아는 방법은 **FSEvents를 가져오고** 이를 위한 **핸들러**를 생성하는 것입니다.

또한, 애플이 유지 관리하는 **잘 알려진 애플리케이션**이 포함된 plist 파일이 있으며, 이는 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`에 위치합니다.
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Apple cli 도구를 사용하여 **구성된 모든** 백그라운드 항목을 나열할 수 있습니다:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
또한, 이 정보를 [**DumpBTM**](https://github.com/objective-see/DumpBTM)으로 나열하는 것도 가능합니다.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
이 정보는 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**에 저장되며, Terminal은 FDA가 필요합니다.

### BTM 조작하기

새로운 지속성이 발견되면 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 유형의 이벤트가 발생합니다. 따라서, 이 **이벤트**가 전송되는 것을 **방지**하거나 **에이전트가 사용자에게 경고하는 것을 방지**하는 방법은 공격자가 BTM을 _**우회**_하는 데 도움이 됩니다.

- **데이터베이스 재설정**: 다음 명령을 실행하면 데이터베이스가 재설정됩니다(기초부터 다시 구축해야 함). 그러나 어떤 이유로 인해, 이를 실행한 후에는 **시스템이 재부팅될 때까지 새로운 지속성이 경고되지 않습니다**.
- **root** 권한이 필요합니다.
```bash
# Reset the database
sfltool resettbtm
```
- **에이전트 중지**: 새로운 탐지가 발견될 때 **사용자에게 알리지 않도록** 에이전트에 중지 신호를 보낼 수 있습니다.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **버그**: **지속성을 생성한 프로세스가 그 직후에 빠르게 존재하면**, 데몬은 그것에 대한 **정보를 얻으려고 시도하고**, **실패하며**, **새로운 것이 지속되고 있다는 이벤트를 보낼 수 없습니다**.

참조 및 **BTM에 대한 추가 정보**:

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
