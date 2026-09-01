# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**는 Mac 운영 체제를 위해 개발된 보안 기능으로, 사용자가 시스템에서 **신뢰할 수 있는 software만 실행하도록** 설계되었습니다. 이 기능은 사용자가 **App Store 외부의 source**에서 다운로드하여 열려고 하는 software, 예를 들어 app, plug-in 또는 installer package를 **검증**합니다.

Gatekeeper의 핵심 메커니즘은 **검증** 프로세스입니다. 다운로드한 software가 **인정된 developer에 의해 서명되었는지** 확인하여 software의 진위성을 보장합니다. 또한 해당 software가 **Apple에 의해 notarised되었는지** 확인하여, 알려진 악성 콘텐츠가 없고 notarisation 이후 변조되지 않았는지 검증합니다.

추가로 Gatekeeper는 다운로드한 software를 처음 열 때 **사용자에게 실행 승인을 요청**하여 사용자 제어와 보안을 강화합니다. 이 보호 기능은 사용자가 무해한 data file로 착각한 잠재적으로 유해한 executable code를 실수로 실행하는 것을 방지하는 데 도움이 됩니다.

### Application Signatures

Application signatures는 code signatures라고도 하며, Apple 보안 인프라의 핵심 구성 요소입니다. 이는 **software author**(developer)의 신원을 **확인**하고, 마지막으로 서명된 이후 code가 변조되지 않았는지 확인하는 데 사용됩니다.

작동 방식은 다음과 같습니다.

1. **Application 서명:** developer가 application을 배포할 준비가 되면 **private key를 사용하여 application에 서명**합니다. 이 private key는 developer가 Apple Developer Program에 등록할 때 **Apple이 developer에게 발급하는 certificate**와 연결되어 있습니다. 서명 과정에서는 app의 모든 부분에 대한 cryptographic hash를 생성하고, developer의 private key로 이 hash를 암호화합니다.
2. **Application 배포:** 서명된 application은 대응하는 public key가 포함된 developer의 certificate와 함께 사용자에게 배포됩니다.
3. **Application 검증:** 사용자가 application을 다운로드하고 실행하려고 하면 Mac 운영 체제는 developer의 certificate에 있는 public key를 사용하여 hash를 복호화합니다. 그런 다음 application의 현재 상태를 기준으로 hash를 다시 계산하고, 이를 복호화한 hash와 비교합니다. 두 hash가 일치하면 **developer가 서명한 이후 application이 수정되지 않았음**을 의미하므로 시스템은 application 실행을 허용합니다.

Application signatures는 Apple의 Gatekeeper 기술에서 필수적인 부분입니다. 사용자가 **인터넷에서 다운로드한 application을 열려고** 하면 Gatekeeper가 application signature를 검증합니다. Apple이 알려진 developer에게 발급한 certificate로 서명되어 있고 code가 변조되지 않았다면 Gatekeeper는 application 실행을 허용합니다. 그렇지 않으면 application을 차단하고 사용자에게 알립니다.

macOS Catalina부터 **Gatekeeper는 application이 Apple에 의해 notarized되었는지도 확인**하여 보안 계층을 추가합니다. notarization 과정에서는 application에 알려진 보안 문제와 악성 code가 있는지 검사하며, 이러한 검사를 통과하면 Apple은 Gatekeeper가 검증할 수 있는 ticket을 application에 추가합니다.

#### 서명 확인

일부 **malware sample**을 확인할 때는 항상 **binary의 signature를 확인**해야 합니다. 해당 binary에 서명한 **developer가 이미** **malware와 연관되어 있을** 수 있기 때문입니다.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### 공증(Notarization)

Apple의 notarization process는 잠재적으로 유해한 software로부터 사용자를 보호하기 위한 추가적인 안전장치 역할을 합니다. 이 과정에는 **developer가 자신의 application을 검사받기 위해 제출하는 것**이 포함되며, 검사는 App Review와 혼동해서는 안 되는 **Apple's Notary Service**에서 수행됩니다. 이 service는 제출된 software에 **malicious content**가 포함되어 있는지와 code-signing 관련 잠재적 문제를 조사하는 **automated system**입니다.

software가 우려할 만한 문제 없이 이 검사를 **통과**하면 Notary Service는 notarization ticket을 생성합니다. 이후 developer는 이 ticket을 자신의 software에 **첨부해야 하며**, 이 과정을 'stapling'이라고 합니다. 또한 notarization ticket은 온라인에도 게시되므로 Apple의 security technology인 Gatekeeper가 이에 접근할 수 있습니다.

사용자가 software를 처음 설치하거나 실행할 때, executable에 stapled되어 있거나 온라인에서 발견되는 notarization ticket의 존재는 **software가 Apple의 notarization을 완료했음을 Gatekeeper에 알립니다**. 그 결과 Gatekeeper는 최초 실행 dialog에 설명 메시지를 표시하여 해당 software가 Apple에 의해 malicious content 검사를 받았음을 알립니다. 이를 통해 사용자는 자신의 system에 설치하거나 실행하는 software의 security에 대해 더 큰 신뢰를 가질 수 있습니다.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia version부터는 **`spctl`**을 사용하여 더 이상 Gatekeeper configuration을 수정할 수 없습니다.

**`spctl`**은 Gatekeeper와 상호작용하고 Gatekeeper를 열거하기 위한 CLI tool입니다(`syspolicyd` daemon과 XPC messages를 통해). 예를 들어 다음 명령으로 **GateKeeper의 status**를 확인할 수 있습니다:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper 서명 검사는 모든 파일이 아니라 **Quarantine attribute가 있는 파일**에 대해서만 수행됩니다.

GateKeeper는 **preferences 및 signature**에 따라 binary를 실행할 수 있는지 확인합니다:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**는 Gatekeeper 적용을 담당하는 주요 daemon입니다. `/var/db/SystemPolicy`에 위치한 database를 유지 관리하며, [database를 지원하는 code는 여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)에서, [SQL template은 여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)에서 확인할 수 있습니다. 이 database는 SIP의 제한을 받지 않으며 root가 쓸 수 있습니다. 또한 database `/var/db/.SystemPolicy-default`는 다른 database가 손상된 경우 원본 backup으로 사용됩니다.

또한 **`/var/db/gke.bundle`** 및 **`/var/db/gkopaque.bundle`** bundle에는 database에 삽입되는 rules가 포함된 파일이 있습니다. 다음 명령으로 root 권한에서 이 database를 확인할 수 있습니다:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`**는 `assess`, `update`, `record`, `cancel`과 같은 다양한 작업을 제공하는 XPC 서버도 노출하며, 이러한 작업은 **`Security.framework`의 `SecAssessment*`** API를 사용해서도 접근할 수 있습니다. 또한 **`spctl`**은 실제로 XPC를 통해 **`syspolicyd`**와 통신합니다.

첫 번째 규칙은 "**App Store**"로 끝나고 두 번째 규칙은 "**Developer ID**"로 끝난다는 점, 그리고 이전 이미지에서는 **App Store 및 식별된 developer의 앱을 실행하도록 활성화되어 있었다**는 점에 유의하세요.\
해당 설정을 App Store로 **수정**하면 "**Notarized Developer ID" 규칙이 사라집니다**.

**GKE** 유형의 규칙도 수천 개가 있습니다:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
다음은 다음 위치에서 가져온 hash입니다:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

또는 다음 명령으로 이전 정보를 나열할 수 있습니다:
```bash
sudo spctl --list
```
**`--master-disable`** 및 **`--global-disable`** `spctl` 옵션은 이러한 signature checks를 완전히 **disable**합니다:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
완전히 활성화되면 새로운 옵션이 나타납니다:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

다음 명령으로 **GateKeeper가 App을 허용할지 확인**할 수 있습니다:
```bash
spctl --assess -v /Applications/App.app
```
macOS 14 이상에서는 **`syspolicy_check`**가 애플리케이션 번들에 대한 유용한 고수준 사전 배포 검사입니다. 단순한 `spctl` 결과보다 더 실행 가능한 trusted-execution 진단을 제공하지만, Apple은 quarantine 전파도 함께 테스트할 수 있으므로 실제 다운로드/압축 해제/최초 실행 경로를 테스트할 것을 여전히 권장합니다.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
GateKeeper에 다음을 사용하여 특정 앱의 실행을 허용하는 새 규칙을 추가할 수 있습니다:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
**kernel extensions**와 관련하여, `/var/db/SystemPolicyConfiguration` 폴더에는 로드가 허용된 kext 목록이 포함된 파일이 있습니다. 또한 `spctl`에는 `com.apple.private.iokit.nvram-csr` entitlement가 있습니다. 이는 사전 승인된 새로운 kernel extensions를 추가할 수 있으며, 해당 확장 프로그램은 `kext-allowed-teams` 키를 사용해 NVRAM에도 저장해야 하기 때문입니다.

#### macOS 15 (Sequoia) 이상에서 Gatekeeper 관리

- 오랫동안 사용되던 Finder의 **Ctrl+Open / 마우스 오른쪽 버튼 클릭 → Open** bypass가 제거되었습니다. 사용자는 최초 차단 대화상자가 표시된 후 **System Settings → Privacy & Security → Open Anyway**에서 차단된 앱을 명시적으로 허용해야 합니다.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable`은 더 이상 unattended policy changes로 허용되지 않습니다. rule database 또는 global assessment state를 수정하는 작업은 deprecated되었으므로, assessment에는 `spctl`을 사용하고 enforcement는 UI 또는 MDM을 통해 구성해야 합니다.

macOS 15 Sequoia부터 end users는 더 이상 `spctl`에서 Gatekeeper policy를 전환할 수 없습니다. 관리는 System Settings를 통해 수행하거나, `com.apple.systempolicy.control` payload가 포함된 MDM configuration profile을 배포하여 수행합니다. App Store 및 identified developers는 허용하지만 "Anywhere"는 허용하지 않는 profile snippet 예시는 다음과 같습니다.

<details>
<summary>App Store 및 identified developers를 허용하는 MDM profile</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Quarantine Files

애플리케이션이나 파일을 **다운로드**하면 웹 브라우저나 이메일 클라이언트와 같은 특정 macOS **applications**가 일반적으로 "**quarantine flag**"라고 알려진 **extended file attribute**를 다운로드한 파일에 추가합니다. 이 attribute는 **file을 표시**하여 해당 파일이 신뢰할 수 없는 소스(인터넷)에서 왔으며 잠재적인 위험을 포함할 수 있음을 나타내는 보안 조치로 작동합니다. 그러나 모든 application이 이 attribute를 추가하는 것은 아닙니다. 예를 들어 일반적인 BitTorrent client software는 보통 이 과정을 우회합니다.

**quarantine flag가 존재하면 사용자가 파일을 실행하려고 할 때 macOS의 Gatekeeper 보안 기능이 작동합니다**.

**quarantine flag가 없는 경우**(일부 BitTorrent client를 통해 다운로드한 파일 등), Gatekeeper의 **checks가 수행되지 않을 수 있습니다**. 따라서 사용자는 보안 수준이 낮거나 출처를 알 수 없는 곳에서 다운로드한 파일을 열 때 주의해야 합니다.

> [!NOTE] > 코드 서명의 **validity를 확인**하는 작업은 코드와 번들된 모든 리소스의 암호화 **hashes**를 생성하는 과정이 포함되므로 **resource-intensive**합니다. 또한 certificate validity를 확인하려면 Apple 서버에 **online check**를 수행하여 해당 certificate가 발급 후 revoke되었는지 확인해야 합니다. 이러한 이유로 전체 code signature 및 notarization check를 **앱이 실행될 때마다 수행하는 것은 비현실적입니다**.
>
> 따라서 이러한 checks는 **quarantined attribute가 있는 앱을 실행할 때만 수행됩니다.**

> [!WARNING]
> 이 attribute는 파일을 생성하거나 **다운로드하는 application이 설정해야 합니다**.
>
> 그러나 sandboxed된 파일은 자신이 생성하는 모든 파일에 이 attribute가 설정됩니다. 또한 non sandboxed 앱은 직접 설정하거나 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key를 **Info.plist**에 지정할 수 있으며, 이렇게 하면 system이 생성된 파일에 `com.apple.quarantine` extended attribute를 설정합니다.

또한 **`qtn_proc_apply_to_self`**를 호출하는 process가 생성하는 모든 파일은 quarantined됩니다. 또는 **`qtn_file_apply_to_path`** API를 사용하면 지정된 file path에 quarantine attribute가 추가됩니다.

다음을 사용하여 **상태를 확인하고 활성화/비활성화할 수 있습니다** (root 필요):
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
또한 다음과 같이 **파일에 quarantine 확장 속성이 있는지 확인할 수 있습니다**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes**의 **value**를 확인하고 다음 명령으로 quarantine attr을 기록한 앱을 알아냅니다:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
실제로 프로세스는 "자신이 생성하는 파일에 quarantine flags를 설정할 수 있습니다" (생성된 파일에 USER_APPROVED flag를 적용해 보았지만 적용되지 않았습니다):

<details>

<summary>quarantine flags를 적용하는 Source Code</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

그리고 다음 명령으로 해당 **attribute를 제거**합니다:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
그리고 다음 명령으로 격리된 모든 파일을 찾습니다:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine 정보는 LaunchServices가 관리하는 중앙 데이터베이스인 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**에도 저장되며, 이를 통해 GUI가 파일의 출처에 대한 데이터를 가져올 수 있습니다. 또한 출처를 숨기려는 애플리케이션이 이 정보를 덮어쓸 수도 있습니다. 이는 LaunchServices APIs를 통해서도 가능합니다.

#### **libquarantine.dylib**

이 library는 extended attribute 필드를 조작할 수 있는 여러 함수를 export합니다.

`qtn_file_*` APIs는 file quarantine 정책을 처리하고, `qtn_proc_*` APIs는 processes에 적용됩니다(process가 생성한 files). Export되지 않은 `__qtn_syscall_quarantine*` 함수는 정책을 적용하며, 첫 번째 인수로 "Quarantine"을 전달하는 `mac_syscall`을 호출하고 요청을 `Quarantine.kext`로 보냅니다.

#### **Quarantine.kext**

이 kernel extension은 **시스템의 kernel cache를 통해서만** 사용할 수 있습니다. 하지만 [**https://developer.apple.com/**](https://developer.apple.com/)에서 **Kernel Debug Kit을 다운로드**할 수 있으며, 여기에는 symbolicated된 extension 버전이 포함되어 있습니다.

이 Kext는 MACF를 통해 여러 call을 hook하여 모든 file lifecycle event를 trap합니다. 여기에는 Creation, opening, renaming, hard-linking이 포함되며, `com.apple.quarantine` extended attribute가 설정되지 않도록 `setxattr`도 가로챕니다.

또한 몇 가지 MIB를 사용합니다.

- `security.mac.qtn.sandbox_enforce`: Sandbox와 함께 quarantine 강제
- `security.mac.qtn.user_approved_exec`: Quarantine된 procs는 승인된 files만 실행 가능

#### Provenance xattr (Ventura and later)

macOS 13 Ventura에서는 quarantine된 app이 실행을 허용받는 최초 시점에 기록되는 별도의 provenance mechanism이 도입되었습니다.<sup>[[2]](#references)</sup> 두 가지 artefact가 생성됩니다.

- `.app` bundle directory의 `com.apple.provenance` xattr (primary key와 flags를 포함하는 고정 크기의 binary 값)
- `/var/db/SystemPolicyConfiguration/ExecPolicy/`의 ExecPolicy database 내 `provenance_tracking` table에 저장되는 app의 cdhash 및 metadata 행

실용적인 사용법:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect는 macOS에 내장된 **안티멀웨어** 기능입니다. XProtect는 **애플리케이션이 처음 실행되거나 수정될 때마다 해당 애플리케이션을 알려진 malware 및 안전하지 않은 파일 형식 데이터베이스와 대조하여 검사합니다**. Safari, Mail 또는 Messages와 같은 특정 앱을 통해 파일을 다운로드하면 XProtect가 자동으로 파일을 스캔합니다. 데이터베이스에 등록된 알려진 malware와 일치하면 XProtect는 **파일 실행을 차단하고** 해당 위협을 알립니다.

XProtect 데이터베이스는 Apple에 의해 새로운 malware 정의로 **정기적으로 업데이트**되며, 이러한 업데이트는 Mac에 자동으로 다운로드 및 설치됩니다. 이를 통해 XProtect는 최신 알려진 위협 정보를 항상 유지합니다.

하지만 **XProtect는 모든 기능을 갖춘 안티바이러스 솔루션이 아닙니다**. 특정 목록에 포함된 알려진 위협만 확인하며, 대부분의 안티바이러스 소프트웨어처럼 on-access scanning을 수행하지 않습니다.

다음을 실행하여 최신 XProtect 업데이트 정보를 확인할 수 있습니다:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect는 SIP로 보호되는 **`/Library/Apple/System/Library/CoreServices/XProtect.bundle`**에 있으며, bundle 내부에서 XProtect가 사용하는 정보를 확인할 수 있습니다.

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 해당 cdhash를 가진 code가 legacy entitlements를 사용할 수 있도록 허용합니다.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID와 TeamID를 통해 load가 허용되지 않는 plugins 및 extensions를 나열하거나 최소 version을 지정합니다.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware를 탐지하기 위한 Yara rules입니다.
- **`XProtect.bundle/Contents/Resources/gk.db`**: 차단된 applications 및 TeamIDs의 hashes가 포함된 SQLite3 database입니다.

**`/Library/Apple/System/Library/CoreServices/XProtect.app`**에도 XProtect와 관련된 다른 App이 있지만, Gatekeeper process에는 관여하지 않습니다.

> XProtect Remediator: 최신 macOS에서 Apple은 malware family를 탐지하고 remediatation하기 위해 launchd를 통해 주기적으로 실행되는 on-demand scanners(XProtect Remediator)를 제공합니다. unified logs에서 이러한 scans를 확인할 수 있습니다:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Not Gatekeeper

> [!CAUTION]
> Gatekeeper는 application을 실행할 때마다 **실행되지 않습니다**. 대신 _**AppleMobileFileIntegrity**_는 Gatekeeper에 의해 이미 실행되고 검증된 app을 실행할 때 **executable code signatures만 verify**합니다.

따라서 이전에는 Gatekeeper를 통해 app을 실행하여 cache한 다음 **application의 executable이 아닌 files**(예: Electron asar 또는 NIB files)를 **modify**할 수 있었으며, 다른 protections가 적용되어 있지 않다면 application은 **malicious** additions와 함께 **실행**되었습니다.

하지만 이제는 macOS가 **application bundles 내부의 files 수정을 방지**하므로 더 이상 불가능합니다. 따라서 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack을 시도하면, Gatekeeper를 통해 app을 실행하여 cache한 후에는 bundle을 modify할 수 없으므로 더 이상 이를 abuse할 수 없다는 것을 확인하게 됩니다. 또한 예를 들어 exploit에 설명된 것처럼 Contents directory의 이름을 NotCon으로 변경한 다음 app의 main binary를 실행하여 Gatekeeper를 통해 cache하려고 하면 error가 발생하고 실행되지 않습니다.

## Gatekeeper Bypasses

Gatekeeper를 bypass하는 모든 방법(Gatekeeper가 차단해야 하는 무언가를 user가 download하고 execute하도록 만드는 것)은 macOS의 vulnerability로 간주됩니다. 다음은 과거 Gatekeeper를 bypass할 수 있었던 techniques에 할당된 일부 CVEs입니다.

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**를 extraction에 사용할 경우 **886 characters를 초과하는 paths**를 가진 files에는 com.apple.quarantine extended attribute가 적용되지 않는 것이 관찰되었습니다. 이로 인해 해당 files가 **Gatekeeper의** security checks를 **우회**할 수 있었습니다.<sup>[[5]](#references)</sup>

자세한 내용은 [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)를 확인하세요.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**로 application을 생성하면, application이 실행하는 데 필요한 정보는 executable이 아니라 `application.app/Contents/document.wflow` 내부에 있습니다. executable은 **Automator Application Stub**이라는 generic Automator binary일 뿐입니다.

따라서 `application.app/Contents/MacOS/Automator\ Application\ Stub`이 **system 내부의 다른 Automator Application Stub을 가리키도록 symbolic link를 생성**할 수 있으며, 실제 executable에는 quarantine xattr이 없기 때문에 **Gatekeeper를 trigger하지 않고** `document.wflow` 내부의 내용(사용자의 script)을 실행합니다.<sup>[[6]](#references)</sup>

예상되는 위치의 예: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

자세한 내용은 [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)를 확인하세요.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

이 bypass에서는 `application.app`이 아니라 `application.app/Contents`부터 compression을 시작하도록 zip file을 생성했습니다. 따라서 **quarantine attr**이 **`application.app/Contents`의 모든 files**에는 적용되지만 **`application.app`에는 적용되지 않았습니다**. Gatekeeper가 확인하는 대상은 `application.app`이므로, `application.app`이 trigger될 때 **quarantine attribute가 없었기 때문에** Gatekeeper가 bypass되었습니다.<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
자세한 내용은 [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)를 확인하세요.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

구성 요소는 다르지만 이 vulnerability의 exploitation은 이전 것과 매우 유사합니다. 이 경우 **`application.app/Contents`**에서 Apple Archive를 생성하므로, **`application.app`은 Archive Utility로 압축 해제될 때 quarantine attr을 얻지 않습니다**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
자세한 내용은 [**원본 보고서**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)를 확인하세요.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**를 사용하면 누구도 파일의 attribute에 값을 쓰지 못하도록 방지할 수 있습니다:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
또한 **AppleDouble** 파일 형식은 ACE를 포함하여 파일을 복사합니다.<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 **`com.apple.acl.text`**라는 xattr 내부에 저장된 ACL 텍스트 표현이 압축 해제된 파일에 ACL로 설정되는 것을 확인할 수 있습니다. 따라서 다른 xattr가 해당 파일에 기록되지 않도록 하는 ACL이 포함된 **AppleDouble** 파일 형식으로 애플리케이션을 zip 파일로 압축하면... quarantine xattr가 애플리케이션에 설정되지 않았습니다:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
자세한 내용은 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.<sup>[[9]](#references)</sup>

이는 AppleArchives를 사용하여 악용할 수도 있다는 점에 유의하세요:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

일부 macOS 내부 문제로 인해 **Google Chrome이 다운로드한 파일에 quarantine attribute를 설정하지 않는 문제**가 발견되었습니다.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble은 파일의 attribute를 `._`로 시작하는 별도의 파일에 저장합니다. 이를 통해 **macOS 시스템 간에 파일 attribute를 복사**할 수 있습니다. 그러나 AppleDouble 파일의 압축을 해제한 후 `._`로 시작하는 파일에 **quarantine attribute가 부여되지 않는 문제**가 있었습니다.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
quarantine attribute가 설정되지 않는 파일을 생성할 수 있었기 때문에, **Gatekeeper를 우회하는 것이 가능했다.** 방법은 AppleDouble name convention (`._`으로 시작)을 사용해 **DMG file application**을 생성하고, quarantine attribute가 없는 이 hidden 파일에 대한 **visible file을 sym link로** 생성하는 것이었다.\
**dmg file이 실행되면**, quarantine attribute가 없으므로 **Gatekeeper를 우회한다.**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Apple은 향상된 검사를 통해 macOS Sonoma 14.0에서 LaunchServices의 로직 오류를 수정했습니다. 공개 권고문에는 앱이 Gatekeeper를 우회할 수 있었다고만 명시되어 있으므로, CVE 항목만으로 특정 carrier 형식이나 exploitation chain을 추론하지 마세요.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

2024년 3월에 릴리스된 macOS 14.4의 Gatekeeper 우회 취약점은 악성 ZIP에 대한 `libarchive` 처리에서 비롯되었으며, 앱이 assessment를 회피할 수 있도록 했습니다. Apple이 이 문제를 해결한 14.4 이상으로 업데이트하세요.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

다운로드한 앱에 포함된 **Automator Quick Action workflow**가 Gatekeeper assessment 없이 실행될 수 있었습니다. workflow가 data로 처리된 후 일반적인 notarization prompt 경로 외부에서 Automator helper에 의해 실행되었기 때문입니다. 따라서 shell script를 실행하는 Quick Action이 포함된 조작된 `.app`(예: `Contents/PlugIns/*.workflow/Contents/document.wflow` 내부)은 실행 즉시 동작할 수 있었습니다. Apple은 추가 consent dialog를 도입하고 Ventura **13.7**, Sonoma **14.7**, Sequoia **15**에서 assessment 경로를 수정했습니다.<sup>[[3]](#references)</sup>

### 추출 및 복사 경계에서의 Quarantine 전파 실패

2024년 연구에서는 테스트한 iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z), 7z Utility (DMG/ZIP/7Z) 버전에서 전파 누락이 발견되었습니다. 또한 VMware Tools의 host-to-guest 복사 중 attribute가 손실되는 현상도 관찰되었습니다. 이후 여러 vendor가 수정 사항을 발표했으므로, 이 이름들을 영구적인 취약 software 목록이 아니라 **version-specific retesting**을 위한 단서로 취급하세요. 동일한 trust-boundary 문제는 native Unix workflow에도 적용됩니다. `curl`/`scp`는 quarantine을 추가하지 않으며, command-line `tar`/`unzip`은 carrier archive에서 quarantine을 자동으로 상속하지 않습니다.<sup>[[15]](#references)</sup>

offensive testing에서는 **모든** browser, mail client, archive, disk-image, cloud-sync, shared-folder, VM-copy 전환 이후 carrier와 최종 app을 비교하세요. 명시적인 `spctl` rejection은 누락된 xattr을 복구하지 않습니다. quarantine이 없으면 일반적인 최초 실행 시 Gatekeeper 경로에서 해당 assessment를 요청하지 않을 수 있습니다.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- 앱을 포함하는 디렉터리를 생성합니다.
- 앱에 uchg를 추가합니다.
- 앱을 tar.gz 파일로 압축합니다.
- tar.gz 파일을 피해자에게 전송합니다.
- 피해자가 tar.gz 파일을 열고 앱을 실행합니다.
- Gatekeeper는 앱을 검사하지 않습니다.<sup>[[12]](#references)</sup>

### Quarantine xattr 방지

".app" 번들에 quarantine xattr가 추가되지 않은 경우, 이를 실행해도 **Gatekeeper가 트리거되지 않습니다**.

확장 속성을 방지하거나 삭제할 수 있는 filesystem-, flag-, ACL-, AppleDouble-based primitives는 [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks)를 참조하세요.



## References

- [1] [Apple Platform Security: macOS Sonoma 14.4의 보안 콘텐츠 정보(CVE-2024-27853 포함)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS가 이제 앱의 출처를 추적하는 방법](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7의 보안 콘텐츠 정보(CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia에서 Control‑click “Open” Gatekeeper 우회 제거](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810의 발견](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper 우회](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper 우회를 허용하는 Safari 취약점 식별](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper 우회를 허용하는 macOS Archive Utility 취약점 식별(CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper의 아킬레스건: macOS 취약점 발굴](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Gatekeeper 우회 발견(CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor의 도움을 받아 Gatekeeper 우회 exploit을 찾고 보고하기](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security and Privacy Mechanisms 우회 — Gatekeeper에서 System Integrity Protection까지(Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14의 보안 콘텐츠 정보(CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: 공증된 제품 테스트](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper 우회 — macOS 보안 메커니즘의 취약점 발견](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
