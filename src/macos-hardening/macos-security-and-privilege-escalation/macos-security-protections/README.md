# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper는 일반적으로 **Quarantine + Gatekeeper + XProtect**의 조합을 의미하며, 이는 **다운로드한 잠재적으로 악성인 software를 사용자가 실행하지 못하도록 방지**하는 3가지 macOS security module입니다.

자세한 정보:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Process 제한

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox는 Sandbox에서 실행되는 **application이 해당 app에 적용된 Sandbox profile에 지정된 허용된 action만 수행하도록 제한**합니다. 이를 통해 **application이 예상된 resource에만 access하도록 보장**할 수 있습니다.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)**는 security framework입니다. 이 framework는 application의 **permission을 관리**하고, 특히 민감한 feature에 대한 access를 규제하도록 설계되었습니다. 여기에는 **location service, contact, photo, microphone, camera, accessibility 및 full disk access** 등이 포함됩니다. TCC는 app이 명시적인 사용자 동의를 받은 후에만 이러한 feature에 access하도록 하여, 개인 data에 대한 privacy와 control을 강화합니다.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS의 launch constraint는 **process 시작을 규제**하는 security feature로, process를 **누가**, **어떻게**, **어디에서 launch할 수 있는지**를 정의합니다. macOS Ventura에서 도입된 이 기능은 system binary를 **trust cache** 내의 constraint category로 분류합니다. 모든 executable binary에는 **launch**를 위한 **self**, **parent** 및 **responsible** constraint를 포함한 **rule**이 설정되어 있습니다. macOS Sonoma에서는 third-party app에 **Environment Constraint**로 확장되었으며, 이러한 feature는 process launch 조건을 제어하여 잠재적인 system exploitation을 완화하는 데 도움을 줍니다.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool(MRT)은 macOS security infrastructure의 또 다른 구성 요소입니다. 이름에서 알 수 있듯이 MRT의 주요 기능은 **감염된 system에서 알려진 malware를 제거**하는 것입니다.

Mac에서 malware가 감지되면(XProtect 또는 다른 방법을 통해) MRT를 사용하여 **malware를 자동으로 제거**할 수 있습니다. MRT는 background에서 조용히 동작하며, 일반적으로 system이 update되거나 새로운 malware definition이 다운로드될 때 실행됩니다(MRT가 malware를 감지하는 데 사용하는 rule이 binary 내부에 있는 것으로 보입니다).

XProtect와 MRT는 모두 macOS security measure의 일부이지만, 서로 다른 기능을 수행합니다.

- **XProtect**는 예방 도구입니다. 특정 application을 통해 **file이 다운로드될 때 이를 검사**하고, 알려진 유형의 malware를 감지하면 **file이 열리지 않도록 방지**하여 malware가 system을 감염시키는 것을 사전에 차단합니다.
- 반면 **MRT**는 **reactive tool**입니다. system에서 malware가 감지된 후 동작하며, 문제가 되는 software를 제거하여 system을 정리하는 것을 목표로 합니다.

MRT application은 **`/Library/Apple/System/Library/CoreServices/MRT.app`**에 있습니다.

## Background Tasks Management

**macOS**는 이제 tool이 code execution을 persist하기 위해 잘 알려진 **technique을 사용할 때마다 alert**를 표시합니다(Login Items, Daemons 등). 이를 통해 사용자는 **어떤 software가 persistence를 유지하고 있는지** 더 잘 알 수 있습니다.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

이는 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`에 위치한 **daemon**과 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`에 위치한 **agent**를 통해 실행됩니다.<sup>[1]</sup>

**`backgroundtaskmanagementd`**가 무언가가 persistence folder에 설치되었음을 알아내는 방식은 **FSEvents를 가져오고** 해당 이벤트에 대한 **handler를 생성하는 것**입니다.<sup>[1]</sup>

또한 Apple이 관리하는 **자주 persistence되는 잘 알려진 application**이 포함된 plist file이 있으며, 다음 위치에 있습니다: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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

Apple CLI tool을 사용하여 구성된 **모든** background items를 열거할 수 있습니다:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
또한 [**DumpBTM**](https://github.com/objective-see/DumpBTM)을 사용하여 이 정보를 나열할 수도 있습니다.<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
이 정보는 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**에 저장되며, Terminal에는 FDA가 필요합니다.<sup>[2]</sup>

### BTM 조작

새로운 persistence가 발견되면 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 유형의 event가 발생합니다. 따라서 이 **event**가 전송되지 않도록 하거나 **agent가 사용자에게 alerting하지 않도록** 하는 방법은 무엇이든 공격자가 BTM을 _**bypass**_하는 데 도움이 됩니다.<sup>[1]</sup>

- **데이터베이스 초기화**: 다음 명령을 실행하면 데이터베이스가 초기화됩니다(처음부터 다시 구축되어야 함). 그러나 어떤 이유에서인지 이 작업을 실행한 후에는 시스템을 reboot할 때까지 **새로운 persistence가 alerting되지 않습니다**.<sup>[1]</sup>
- **root**가 필요합니다.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent 중지**: Agent에 중지 신호를 보내 새 탐지 항목이 발견되었을 때 **사용자에게 알림을 표시하지 않도록 할 수 있습니다**.<sup>[1]</sup>
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
- **버그**: **persistence를 생성한 process가 생성 직후 빠르게 종료되면**, daemon은 해당 process에 대한 **정보를 가져오려고 시도하지만**, **실패하여** 새로운 항목이 persistence되고 있음을 나타내는 **event를 전송할 수 없게 됩니다**.<sup>[1]</sup>

## References

- [1] [OBTS v6.0: "macOS의 Background Task Management에 대한 오해 해소 및 우회" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [새로운 (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Mac에서 login items 및 background tasks 관리 - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
