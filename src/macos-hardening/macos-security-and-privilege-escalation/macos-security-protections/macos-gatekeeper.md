# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**는 Mac 운영 체제를 위해 개발된 보안 기능으로, 사용자가 시스템에서 **신뢰할 수 있는 software만 실행하도록** 설계되었습니다. 이 기능은 사용자가 **App Store 외부의 source**에서 다운로드한 후 열려고 시도하는 software(예: app, plug-in 또는 installer package)를 **검증**합니다.

Gatekeeper의 핵심 메커니즘은 **verification** 과정에 있습니다. 다운로드한 software가 **인식된 developer에 의해 서명되었는지** 확인하여 software의 진위성을 검증합니다. 또한 해당 software가 **Apple에 의해 notarised되었는지** 확인하여 알려진 악성 content가 없고 notarisation 이후 변조되지 않았는지 검증합니다.

또한 Gatekeeper는 다운로드한 software를 처음 열 때 **사용자에게 실행을 승인하도록 요청**하여 사용자 제어와 보안을 강화합니다. 이 보호 기능은 사용자가 무해한 data file로 착각할 수 있는 잠재적으로 유해한 executable code를 실수로 실행하는 것을 방지하는 데 도움이 됩니다.

### Application Signatures

Application signatures는 code signatures라고도 하며, Apple 보안 인프라의 핵심 구성 요소입니다. 이는 **software author**(developer)의 신원을 **검증**하고 code가 마지막으로 서명된 이후 변조되지 않았는지 확인하는 데 사용됩니다.

작동 방식은 다음과 같습니다.

1. **Signing the Application:** developer가 application을 배포할 준비가 되면 **private key를 사용하여 application에 서명**합니다. 이 private key는 developer가 Apple Developer Program에 등록할 때 **Apple이 developer에게 발급하는 certificate**와 연결됩니다. signing 과정에서는 app의 모든 부분에 대한 cryptographic hash를 생성하고, developer의 private key로 이 hash를 암호화합니다.
2. **Distributing the Application:** 서명된 application은 해당 public key가 포함된 developer의 certificate와 함께 사용자에게 배포됩니다.
3. **Verifying the Application:** 사용자가 application을 다운로드하고 실행하려고 하면 Mac 운영 체제는 developer의 certificate에 포함된 public key를 사용하여 hash를 복호화합니다. 그런 다음 application의 현재 상태를 기반으로 hash를 다시 계산하고, 이를 복호화된 hash와 비교합니다. 두 값이 일치하면 **developer가 서명한 이후 application이 수정되지 않았음**을 의미하며, 시스템은 application의 실행을 허용합니다.

Application signatures는 Apple의 Gatekeeper 기술에서 필수적인 부분입니다. 사용자가 **인터넷에서 다운로드한 application을 열려고** 하면 Gatekeeper가 application signature를 검증합니다. Apple이 알려진 developer에게 발급한 certificate로 서명되었고 code가 변조되지 않았다면 Gatekeeper는 application의 실행을 허용합니다. 그렇지 않으면 application을 차단하고 사용자에게 알립니다.

macOS Catalina부터는 **Gatekeeper가 application이 Apple에 의해 notarized되었는지도 확인**하여 보안 계층을 추가합니다. notarization 과정에서는 알려진 보안 문제와 malicious code가 있는지 application을 검사하며, 이 검사를 통과하면 Apple은 Gatekeeper가 검증할 수 있는 ticket을 application에 추가합니다.

#### Check Signatures

일부 **malware sample**을 확인할 때는 항상 binary의 **signature를 확인해야 합니다.** 해당 binary에 서명한 **developer가 이미** **malware와 관련되어 있을** 수 있기 때문입니다.
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
### Notarization

Apple의 notarization process는 잠재적으로 유해한 software로부터 사용자를 보호하기 위한 추가적인 보호 장치를 제공합니다. 이 process는 **developer가 자신의 application을 검사받기 위해 제출**하는 과정이며, **Apple's Notary Service**에서 수행됩니다. 이는 App Review와 혼동해서는 안 됩니다. 이 service는 제출된 software에 **malicious content**가 포함되어 있는지와 code-signing 관련 잠재적 문제가 있는지를 검사하는 **automated system**입니다.

software가 문제를 일으키지 않고 이 검사를 **통과**하면 Notary Service는 notarization ticket을 생성합니다. 이후 developer는 이 ticket을 자신의 software에 **첨부**해야 하며, 이 과정을 'stapling'이라고 합니다. 또한 notarization ticket은 온라인에도 게시되므로, Apple의 security technology인 Gatekeeper가 이에 접근할 수 있습니다.

사용자가 software를 처음 설치하거나 실행할 때, notarization ticket이 executable에 stapled되어 있거나 온라인에서 발견되면 **Gatekeeper에 해당 software가 Apple의 notarization을 거쳤음을 알립니다**. 그 결과 Gatekeeper는 최초 실행 대화상자에 설명 메시지를 표시하여, 해당 software가 Apple에 의해 malicious content 검사를 받았음을 알립니다. 이를 통해 사용자는 자신의 system에 설치하거나 실행하는 software의 security에 대해 더 큰 신뢰를 가질 수 있습니다.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia version부터는 **`spctl`**을 사용하여 더 이상 Gatekeeper configuration을 수정할 수 없습니다.

**`spctl`**은 Gatekeeper를 열거하고 상호작용하기 위한 CLI tool입니다(XPC messages를 통해 `syspolicyd` daemon과 상호작용). 예를 들어 다음 명령으로 **GateKeeper의 status**를 확인할 수 있습니다:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper signature 검사는 모든 파일이 아니라 **Quarantine attribute가 있는 파일**에 대해서만 수행됩니다.

GateKeeper는 **preferences와 signature**에 따라 binary를 실행할 수 있는지 확인합니다:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**는 Gatekeeper를 적용하는 주 daemon입니다. `/var/db/SystemPolicy`에 위치한 database를 유지 관리하며, [database를 지원하는 code는 여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)에서, [SQL template은 여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)에서 확인할 수 있습니다. 이 database는 SIP의 제한을 받지 않으며 root가 쓸 수 있습니다. 또한 다른 database가 손상된 경우 원본 backup으로 사용되는 database는 `/var/db/.SystemPolicy-default`입니다.

또한 **`/var/db/gke.bundle`** 및 **`/var/db/gkopaque.bundle`** bundle에는 database에 삽입되는 rule이 포함된 파일이 있습니다. 다음 명령으로 root 권한에서 이 database를 확인할 수 있습니다:
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
**`syspolicyd`**는 `assess`, `update`, `record`, `cancel`과 같은 다양한 작업을 수행하는 XPC 서버도 노출하며, 이러한 작업은 **`Security.framework`의 `SecAssessment*`** API를 사용해서도 접근할 수 있습니다. 또한 **`spctl`**은 실제로 XPC를 통해 **`syspolicyd`**와 통신합니다.

첫 번째 규칙은 "**App Store**"로 끝나고 두 번째 규칙은 "**Developer ID**"로 끝난다는 점, 그리고 이전 이미지에서는 **App Store 및 식별된 개발자의 앱을 실행하도록 활성화되어 있었다**는 점에 유의하세요.\
해당 설정을 App Store로 **수정**하면 "**공증된 Developer ID" 규칙이 사라집니다**.

**GKE** 유형의 규칙도 수천 개 존재합니다:
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
**`spctl`**의 **`--master-disable`** 및 **`--global-disable`** 옵션은 이러한 서명 검사를 완전히 **비활성화**합니다:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
완전히 활성화되면 새로운 옵션이 표시됩니다:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

다음 명령어로 **App이 GateKeeper에 의해 허용되는지 확인**할 수 있습니다:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper에 새로운 규칙을 추가하여 특정 앱의 실행을 허용할 수 있습니다:
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
Regarding **kernel extensions**, 폴더 `/var/db/SystemPolicyConfiguration`에는 로드가 허용된 kext 목록이 포함된 파일이 있습니다. 또한 `spctl`에는 `com.apple.private.iokit.nvram-csr` entitlement가 있습니다. 이는 사전 승인된 새로운 kernel extensions를 추가할 수 있으며, 해당 extensions는 `kext-allowed-teams` key의 NVRAM에도 저장해야 하기 때문입니다.

#### macOS 15 (Sequoia) 및 이후 버전에서 Gatekeeper 관리

- 오랫동안 사용되던 Finder의 **Ctrl+Open / Right-click → Open** bypass가 제거되었습니다. 사용자는 첫 번째 차단 dialog가 표시된 후 **System Settings → Privacy & Security → Open Anyway**에서 차단된 app을 명시적으로 허용해야 합니다.<sup>[4]</sup>
- `spctl --master-disable/--global-disable`은 더 이상 허용되지 않습니다. `spctl`은 assessment 및 label management에서 사실상 read-only로 동작하며, policy enforcement는 UI 또는 MDM을 통해 구성합니다.

macOS 15 Sequoia부터 end user는 더 이상 `spctl`에서 Gatekeeper policy를 전환할 수 없습니다. Management는 System Settings를 통해 수행하거나 `com.apple.systempolicy.control` payload가 포함된 MDM configuration profile을 배포하여 수행합니다. App Store 및 identified developers를 허용하되 "Anywhere"는 허용하지 않는 profile snippet 예시는 다음과 같습니다.

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

애플리케이션이나 파일을 **다운로드**하면 웹 브라우저나 이메일 클라이언트 같은 특정 macOS **애플리케이션**이 일반적으로 "**quarantine flag**"라고 알려진 **확장 파일 속성**을 다운로드한 파일에 **추가**합니다. 이 속성은 **파일을 표시**하여 해당 파일이 신뢰할 수 없는 출처(인터넷)에서 가져온 것이며 잠재적인 위험을 포함할 수 있음을 나타내는 보안 수단으로 작동합니다. 그러나 모든 애플리케이션이 이 속성을 추가하는 것은 아닙니다. 예를 들어 일반적인 BitTorrent 클라이언트 소프트웨어는 보통 이 과정을 우회합니다.

**quarantine flag가 존재하면 사용자가 파일을 실행하려고 할 때 macOS의 Gatekeeper 보안 기능이 작동합니다**.

**quarantine flag가 없는 경우**(일부 BitTorrent 클라이언트를 통해 다운로드한 파일 등), Gatekeeper의 **검사가 수행되지 않을 수 있습니다**. 따라서 사용자는 보안성이 낮거나 출처를 알 수 없는 곳에서 다운로드한 파일을 열 때 주의해야 합니다.

> [!NOTE] > **code signature의 유효성**을 **확인**하는 과정은 code와 번들된 모든 리소스의 암호화 **hash**를 생성하는 작업을 포함하므로 **많은 리소스를 사용합니다**. 또한 certificate의 유효성을 확인하려면 Apple 서버에 **온라인 검사**를 수행하여 발급 이후 해당 certificate가 revoke되었는지 확인해야 합니다. 이러한 이유로 전체 code signature 및 notarization 검사를 **앱이 실행될 때마다 수행하는 것은 비현실적입니다**.
>
> 따라서 이러한 검사는 **quarantined attribute가 있는 앱을 실행할 때만 수행됩니다.**

> [!WARNING]
> 이 속성은 파일을 생성하거나 다운로드하는 **애플리케이션이 설정해야 합니다**.
>
> 그러나 sandbox된 파일은 생성하는 모든 파일에 이 속성이 설정됩니다. 또한 non sandboxed 앱은 이 속성을 직접 설정하거나 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) 키를 **Info.plist**에 지정할 수 있으며, 이렇게 하면 시스템이 생성된 파일에 `com.apple.quarantine` 확장 속성을 설정합니다.

또한 **`qtn_proc_apply_to_self`**를 호출하는 process가 생성한 모든 파일은 quarantine됩니다. 또는 **`qtn_file_apply_to_path`** API가 지정된 file path에 quarantine attribute를 추가합니다.

다음 명령으로 **상태를 확인하고 활성화/비활성화**할 수 있습니다(root 필요).
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
다음을 사용하여 파일에 **quarantine extended attribute**가 있는지도 확인할 수 있습니다:
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
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
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
그리고 다음 명령으로 해당 attribute를 **제거**합니다:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
그리고 다음 명령어로 quarantine된 모든 파일을 찾습니다:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine 정보는 LaunchServices가 관리하는 중앙 database에도 저장되며, 위치는 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**입니다. 이를 통해 GUI는 파일의 출처에 대한 데이터를 가져올 수 있습니다. 또한 출처를 숨기려는 애플리케이션에 의해 이 정보가 덮어쓰여질 수 있습니다. 이는 LaunchServices API를 통해서도 수행할 수 있습니다.

#### **libquarantine.dylib**

이 library는 extended attribute 필드를 조작할 수 있는 여러 함수를 export합니다.

`qtn_file_*` API는 file quarantine policy를 처리하고, `qtn_proc_*` API는 process에 적용됩니다(process가 생성한 파일). export되지 않은 `__qtn_syscall_quarantine*` 함수는 policy를 적용하는 함수로, 첫 번째 인수로 "Quarantine"을 전달하여 `mac_syscall`을 호출하고 요청을 `Quarantine.kext`로 보냅니다.

#### **Quarantine.kext**

이 kernel extension은 **시스템의 kernel cache를 통해서만** 사용할 수 있습니다. 그러나 **[**https://developer.apple.com/**](https://developer.apple.com/)에서 Kernel Debug Kit를** 다운로드할 수 있으며, 여기에는 symbolicated 버전의 extension이 포함되어 있습니다.

이 Kext는 MACF를 통해 여러 call을 hook하여 모든 file lifecycle event를 trap합니다. 여기에는 생성, 열기, 이름 변경, hard-link 생성 등이 포함되며, `setxattr`을 통한 `com.apple.quarantine` extended attribute 설정도 방지합니다.

또한 몇 가지 MIB를 사용합니다.

- `security.mac.qtn.sandbox_enforce`: Sandbox와 함께 quarantine 강제 적용
- `security.mac.qtn.user_approved_exec`: Querantined proc는 승인된 file만 실행 가능

#### Provenance xattr (Ventura and later)

macOS 13 Ventura에서는 quarantined app의 실행이 처음으로 허용될 때 채워지는 별도의 provenance mechanism이 도입되었습니다.<sup>[2]</sup> 두 가지 artefact가 생성됩니다.

- `.app` bundle directory의 `com.apple.provenance` xattr(primary key와 flags를 포함하는 고정 크기의 binary value)
- `/var/db/SystemPolicyConfiguration/ExecPolicy/`의 ExecPolicy database 내부 `provenance_tracking` table에 저장되는 app의 cdhash 및 metadata 행

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

XProtect는 macOS에 내장된 **anti-malware** 기능입니다. XProtect는 **애플리케이션이 처음 실행되거나 수정될 때마다 알려진 malware 및 안전하지 않은 파일 유형의 데이터베이스와 대조하여 검사합니다**. Safari, Mail 또는 Messages와 같은 특정 앱을 통해 파일을 다운로드하면 XProtect가 파일을 자동으로 scan합니다. 데이터베이스에 등록된 알려진 malware와 일치하면 XProtect는 **파일 실행을 차단하고** 해당 위협을 알려줍니다.

XProtect 데이터베이스는 Apple에 의해 **새로운 malware 정의로 정기적으로 업데이트**되며, 이러한 업데이트는 Mac에 자동으로 다운로드되고 설치됩니다. 이를 통해 XProtect는 알려진 최신 위협을 항상 반영할 수 있습니다.

그러나 **XProtect는 모든 기능을 갖춘 antivirus solution이 아니라는 점**에 유의해야 합니다. XProtect는 알려진 위협의 특정 목록만 검사하며, 대부분의 antivirus software처럼 on-access scanning을 수행하지 않습니다.

다음을 실행하여 최신 XProtect 업데이트 정보를 확인할 수 있습니다:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect는 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**의 SIP protected location에 있으며, bundle 내부에서 XProtect가 사용하는 정보를 확인할 수 있습니다:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 해당 cdhash를 가진 code가 legacy entitlements를 사용할 수 있도록 허용합니다.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID와 TeamID를 기준으로 로드가 허용되지 않는 plugin과 extension 또는 필요한 minimum version을 지정한 목록입니다.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware를 탐지하기 위한 Yara rules입니다.
- **`XProtect.bundle/Contents/Resources/gk.db`**: 차단된 application과 TeamID의 hash가 저장된 SQLite3 database입니다.

**/Library/Apple/System/Library/CoreServices/XProtect.app**에도 XProtect와 관련된 다른 App이 있지만, Gatekeeper process에는 관여하지 않습니다.

> XProtect Remediator: 최신 macOS에서 Apple은 malware family를 탐지하고 remediate하기 위해 launchd를 통해 주기적으로 실행되는 on-demand scanner(XProtect Remediator)를 제공합니다. unified log에서 이러한 scan을 확인할 수 있습니다:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper 아님

> [!CAUTION]
> Gatekeeper는 application을 실행할 때마다 **실행되지 않습니다**. 대신 _**AppleMobileFileIntegrity**_는 Gatekeeper에 의해 이미 실행되고 검증된 app을 실행할 때 executable code signature만 **verify**합니다.

따라서 이전에는 Gatekeeper로 app을 cache하기 위해 app을 실행한 다음, application의 **executable이 아닌 file**(예: Electron asar 또는 NIB file)을 **modify**할 수 있었으며, 다른 protection이 적용되지 않았다면 application은 **malicious**한 추가 내용과 함께 **실행**되었습니다.

하지만 이제는 macOS가 application bundle 내부의 **file 수정을 방지**하므로 이 방법은 불가능합니다. 따라서 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack을 시도하면, Gatekeeper로 cache하기 위해 app을 실행한 후 bundle을 modify할 수 없으므로 더 이상 이를 abuse할 수 없다는 것을 알 수 있습니다. 또한 exploit에 표시된 것처럼 예를 들어 Contents directory의 이름을 NotCon으로 변경한 다음 app의 main binary를 실행하여 Gatekeeper로 cache하려고 하면 error가 발생하고 실행되지 않습니다.

## Gatekeeper Bypasses

Gatekeeper를 우회하는 모든 방법(사용자가 무언가를 download하고 Gatekeeper가 이를 disallow해야 하는 상황에서 실행하도록 만드는 방법)은 macOS의 vulnerability로 간주됩니다. 과거에 Gatekeeper를 bypass할 수 있었던 technique에 할당된 CVE는 다음과 같습니다:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**를 extraction에 사용하면 **886자를 초과하는 path**를 가진 file에는 com.apple.quarantine extended attribute가 적용되지 않는 것이 확인되었습니다. 이로 인해 해당 file은 의도치 않게 **Gatekeeper의** security check를 **우회**할 수 있습니다.<sup>[5]</sup>

자세한 내용은 [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)를 확인하세요.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**로 application을 생성하면 실행에 필요한 정보가 executable이 아니라 `application.app/Contents/document.wflow` 내부에 저장됩니다. executable은 **Automator Application Stub**이라는 generic Automator binary일 뿐입니다.

따라서 `application.app/Contents/MacOS/Automator\ Application\ Stub`을 **system 내부의 다른 Automator Application Stub을 가리키는 symbolic link로 만들면**, 실제 executable에 quarantine xattr가 없기 때문에 **Gatekeeper를 trigger하지 않고** `document.wflow` 내부의 내용(사용자의 script)을 실행할 수 있습니다.<sup>[6]</sup>

예상되는 os location의 예: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

자세한 내용은 [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)를 확인하세요.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

이 bypass에서는 `application.app`이 아니라 `application.app/Contents`부터 compression을 시작하도록 zip file을 생성했습니다. 따라서 **quarantine attr**은 **`application.app/Contents`의 모든 file**에 적용되지만 **`application.app`에는 적용되지 않았습니다**. Gatekeeper가 확인하는 대상은 `application.app`이므로, `application.app`이 trigger될 때 **quarantine attribute가 없었기 때문에** Gatekeeper가 bypass되었습니다.<sup>[7]</sup>
```bash
zip -r test.app/Contents test.zip
```
자세한 내용은 [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)를 확인하세요.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

구성 요소는 다르지만 이 취약점의 exploitation은 이전 취약점과 매우 유사합니다. 이 경우 **`application.app/Contents`**에서 Apple Archive를 생성하므로 **`application.app`**은 **Archive Utility**로 압축 해제될 때 quarantine attr을 받지 않습니다.<sup>[8]</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
자세한 내용은 [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)를 확인하세요.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**를 사용하면 누구도 파일의 attribute를 작성하지 못하도록 방지할 수 있습니다:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
또한, **AppleDouble** 파일 형식은 ACE를 포함하여 파일을 복사합니다.<sup>[9]</sup>

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 xattr **`com.apple.acl.text`** 내부에 저장된 ACL 텍스트 표현이 압축 해제된 파일의 ACL로 설정된다는 것을 확인할 수 있습니다. 따라서 다른 xattr이 해당 파일에 기록되지 않도록 하는 ACL과 함께 애플리케이션을 **AppleDouble** 파일 형식의 zip 파일로 압축하면... quarantine xattr이 애플리케이션에 설정되지 않았습니다:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
자세한 내용은 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.

이 문제는 AppleArchives를 사용해서도 exploit할 수 있다는 점에 유의하세요:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

일부 macOS 내부 문제로 인해 **Google Chrome이 다운로드한 파일에 quarantine attribute를 설정하지 않는 문제**가 발견되었습니다.<sup>[10]</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 파일 형식은 파일의 attribute를 `._`로 시작하는 별도의 파일에 저장하며, 이를 통해 **macOS 시스템 간에 파일 attribute를** 복사할 수 있습니다. 그러나 AppleDouble 파일의 압축을 해제한 후 `._`로 시작하는 파일에 **quarantine attribute가 부여되지 않는 문제**가 확인되었습니다.<sup>[11]</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
quarantine attribute가 설정되지 않는 파일을 생성할 수 있었기 때문에 **Gatekeeper를 우회할 수 있었습니다.** 그 방법은 AppleDouble 명명 규칙(`._`로 시작)을 사용해 **DMG 파일 application을 생성**한 다음, quarantine attribute가 없는 이 숨김 파일을 가리키는 **visible file을 sym link로 생성하는 것**이었습니다.\
**dmg 파일이 실행될 때**, quarantine attribute가 없으므로 **Gatekeeper를 우회합니다.**
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

macOS Sonoma 14.0에서 수정된 Gatekeeper bypass로, 조작된 앱이 프롬프트 없이 실행될 수 있었습니다. 세부 내용은 패치 이후 공개되었으며, 수정 전에는 해당 문제가 실제 환경에서 활발히 악용되었습니다. Sonoma 14.0 이상이 설치되어 있는지 확인하십시오.

### [CVE-2024-27853]

2024년 3월에 출시된 macOS 14.4의 Gatekeeper bypass는 악성 ZIP 처리 과정에서 발생한 `libarchive` 문제로 인해 앱이 assessment를 우회할 수 있도록 했습니다. Apple이 해당 문제를 해결한 14.4 이상으로 업데이트하십시오.<sup>[1]</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

다운로드한 앱에 포함된 **Automator Quick Action workflow**가 Gatekeeper assessment 없이 실행될 수 있었습니다. workflow가 데이터로 처리되었고, 일반적인 notarization 프롬프트 경로 외부에서 Automator helper에 의해 실행되었기 때문입니다. 따라서 shell script를 실행하는 Quick Action이 포함된 조작된 `.app`(예: `Contents/PlugIns/*.workflow/Contents/document.wflow` 내부)은 실행 시 즉시 코드를 실행할 수 있었습니다. Apple은 Ventura **13.7**, Sonoma **14.7**, Sequoia **15**에서 추가 동의 대화상자를 도입하고 assessment 경로를 수정했습니다.<sup>[3]</sup>

### 서드파티 unarchiver의 quarantine 전파 오류 (2023–2024)

인기 있는 여러 extraction tool(예: The Unarchiver)의 취약점으로 인해 archive에서 추출된 파일에 `com.apple.quarantine` xattr이 누락될 수 있었으며, 이로 인해 Gatekeeper bypass 기회가 발생했습니다. 테스트할 때는 항상 macOS Archive Utility 또는 패치된 도구를 사용하고, 추출 후 xattr을 검증하십시오.

### uchg (이 [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)에서 발췌)

- 앱이 포함된 디렉터리를 생성합니다.
- 앱에 uchg를 추가합니다.
- 앱을 tar.gz 파일로 압축합니다.
- tar.gz 파일을 피해자에게 전송합니다.
- 피해자가 tar.gz 파일을 열고 앱을 실행합니다.
- Gatekeeper는 앱을 검사하지 않습니다.<sup>[12]</sup>

### Quarantine xattr 방지

".app" bundle에 quarantine xattr이 추가되지 않으면 해당 앱을 실행할 때 **Gatekeeper가 트리거되지 않습니다**.


## 참고 문헌

- [1] [Apple Platform Security: macOS Sonoma 14.4의 보안 콘텐츠 정보(CVE-2024-27853 포함)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS가 이제 앱의 출처를 추적하는 방법](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7의 보안 콘텐츠 정보(CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia에서 Control-click “Open” Gatekeeper bypass 제거](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: CVE-2021-1810의 발견](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper 우회](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper bypass를 허용하는 Safari 취약점 식별](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper bypass를 허용하는 macOS Archive Utility 취약점 식별 (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper의 Achilles heel: macOS 취약점 발굴](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Gatekeeper Bypass 발견 (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor의 도움을 받아 Gatekeeper bypass exploit 발견 및 보고](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS Security 및 Privacy Mechanism 우회 — Gatekeeper에서 System Integrity Protection까지 (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa)

{{#include ../../../banners/hacktricks-training.md}}
