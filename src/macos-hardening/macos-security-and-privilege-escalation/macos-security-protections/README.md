# macOS 보안 보호 기능

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper는 일반적으로 **Quarantine + Gatekeeper + XProtect**의 조합을 가리키며, 이는 **사용자가 다운로드한 잠재적으로 악성인 소프트웨어를 실행하지 못하도록 방지**하는 3개의 macOS 보안 모듈입니다.

자세한 정보:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## 프로세스 제한

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox는 Sandbox 내부에서 실행되는 **애플리케이션을 해당 앱이 실행되는 Sandbox profile에 지정된 허용된 작업으로 제한**합니다. 이를 통해 **애플리케이션이 예상된 리소스에만 액세스하도록** 할 수 있습니다.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)**는 보안 프레임워크입니다. 이 프레임워크는 애플리케이션의 **권한을 관리**하도록 설계되었으며, 특히 민감한 기능에 대한 액세스를 규제합니다. 여기에는 **위치 서비스, 연락처, 사진, 마이크, 카메라, 접근성 및 전체 디스크 액세스**와 같은 요소가 포함됩니다. TCC는 앱이 명시적인 사용자 동의를 얻은 후에만 이러한 기능에 액세스할 수 있도록 하여 개인정보 보호와 개인 데이터에 대한 제어를 강화합니다.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS의 Launch constraints는 **누가**, **어떻게**, **어디에서** 프로세스를 시작할 수 있는지 정의하여 **프로세스 시작을 규제**하는 보안 기능입니다. macOS Ventura에서 도입된 이 기능은 시스템 바이너리를 **trust cache** 내의 제약 조건 카테고리로 분류합니다. 모든 실행 가능한 바이너리에는 **self**, **parent**, **responsible** constraints를 포함하여 **launch**에 대한 **규칙**이 설정되어 있습니다. macOS Sonoma에서는 서드파티 앱에 대해 **Environment Constraints**로 확장되었으며, 이러한 기능은 프로세스 실행 조건을 통제하여 잠재적인 시스템 exploitations를 완화하는 데 도움이 됩니다.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool(MRT)은 macOS 보안 인프라의 또 다른 구성 요소입니다. 이름에서 알 수 있듯이 MRT의 주요 기능은 **감염된 시스템에서 알려진 malware를 제거**하는 것입니다.

Mac에서 malware가 감지되면(XProtect 또는 다른 수단을 통해) MRT를 사용하여 **malware를 자동으로 제거**할 수 있습니다. MRT는 백그라운드에서 조용히 작동하며 일반적으로 시스템이 업데이트되거나 새로운 malware 정의가 다운로드될 때 실행됩니다(MRT가 malware를 감지하는 데 사용하는 규칙은 binary 내부에 있는 것으로 보입니다).

XProtect와 MRT는 모두 macOS의 보안 조치에 속하지만 서로 다른 기능을 수행합니다.

- **XProtect**는 예방 도구입니다. **파일이 다운로드될 때**(특정 애플리케이션을 통해) 파일을 **검사**하고, 알려진 유형의 malware를 감지하면 **파일이 열리지 않도록 방지**하여 malware가 애초에 시스템을 감염시키지 못하게 합니다.
- 반면 **MRT**는 **대응 도구**입니다. 시스템에서 malware가 감지된 후 작동하며, 문제가 되는 소프트웨어를 제거하여 시스템을 정리하는 것을 목표로 합니다.

MRT application은 **`/Library/Apple/System/Library/CoreServices/MRT.app`**에 있습니다.

## Background Tasks Management

**macOS**는 이제 도구가 코드 실행을 지속시키는 잘 알려진 **technique**(예: Login Items, Daemons...)을 사용할 때마다 **알림을 표시**하므로, 사용자는 **어떤 software가 지속성을 유지하고 있는지** 더 잘 알 수 있습니다.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

이는 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`에 위치한 **daemon**과 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`에 있는 **agent**를 통해 실행됩니다.<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`**가 persistent folder에 무언가 설치되었음을 아는 방식은 **FSEvents를 가져오고** 해당 이벤트에 대한 **handlers**를 생성하는 것입니다.<sup>[[1]](#references)</sup>

또한 Apple이 관리하는, 자주 persistence를 유지하는 **잘 알려진 applications**가 포함된 plist 파일이 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`에 있습니다.<sup>[[3]](#references)</sup>
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
### 열거

Apple CLI tool을 실행하여 구성된 **모든** background items를 **열거**할 수 있습니다:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
또한 [**DumpBTM**](https://github.com/objective-see/DumpBTM)을 사용하여 이 정보를 나열할 수도 있습니다.<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
이 정보는 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**에 저장되며 Terminal에는 FDA가 필요합니다.<sup>[[2]](#references)</sup>

### BTM 조작

새로운 persistence가 발견되면 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 유형의 event가 발생합니다. 따라서 이 **event**가 전송되지 않도록 하거나 **agent가 사용자에게 alert하지 못하도록** 하는 모든 방법은 공격자가 BTM을 _**우회**_하는 데 도움이 됩니다.<sup>[[1]](#references)</sup>

- **데이터베이스 초기화**: 다음 명령을 실행하면 데이터베이스가 초기화됩니다(처음부터 다시 빌드되어야 함). 그러나 어떤 이유에서인지 이 명령을 실행한 후에는 시스템이 reboot될 때까지 **새로운 persistence가 alert되지 않습니다**.<sup>[[1]](#references)</sup>
- **root**가 필요합니다.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent 중지**: Agent에 중지 신호를 보내 새로운 탐지 결과가 발견되어도 **사용자에게 알림을 보내지 않도록 할 수 있습니다**.<sup>[[1]](#references)</sup>
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
- **Bug**: **persistence를 생성한 process가 생성 직후 빠르게 종료되면**, daemon은 해당 process에 대한 **정보를 가져오려고 시도하지만**, **실패하고**, 새로운 항목이 persistence되고 있음을 나타내는 **event를 전송할 수 없게 됩니다**.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
