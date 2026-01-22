# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**는 Mac 운영체제를 위해 개발된 보안 기능으로, 사용자가 시스템에서 **신뢰할 수 있는 소프트웨어만 실행하도록** 보장하도록 설계되었습니다. 이 기능은 사용자가 **App Store** 외부에서 다운로드하여 열려고 하는 앱, 플러그인 또는 설치 패키지와 같은 소프트웨어를 **검증**함으로써 작동합니다.

Gatekeeper의 핵심 메커니즘은 **검증(verification)** 프로세스에 있습니다. 다운로드된 소프트웨어가 **인증된 개발자에 의해 서명되었는지** 확인하여 소프트웨어의 정당성을 보장합니다. 또한 소프트웨어가 **Apple에 의해 notarised되었는지**를 확인해 알려진 악성 콘텐츠가 없고 notarisation 이후에 변조되지 않았는지도 검증합니다.

추가로, Gatekeeper는 사용자가 다운로드한 소프트웨어를 처음 열 때 **열기를 승인하도록 사용자에게 알림을 표시**하여 사용자 통제와 보안을 강화합니다. 이 보호 장치는 사용자가 무해한 데이터 파일로 착각해 잠재적으로 해로운 실행 코드를 실수로 실행하는 것을 방지하는 데 도움을 줍니다.

### Application Signatures

애플리케이션 서명(또는 code signatures)은 Apple의 보안 인프라에서 중요한 구성요소입니다. 이는 소프트웨어 저자(개발자)의 신원을 **확인**하고 서명 이후 코드가 변조되지 않았는지 보장하는 데 사용됩니다.

작동 방식은 다음과 같습니다:

1. **Signing the Application:** 개발자가 애플리케이션을 배포할 준비가 되면 **개인 키(private key)**로 애플리케이션에 서명합니다. 이 개인 키는 개발자가 Apple Developer Program에 등록할 때 Apple이 발급한 **certificate**와 연관되어 있습니다. 서명 과정은 앱의 모든 부분에 대해 암호학적 해시를 생성하고 이 해시를 개발자의 개인 키로 암호화하는 방식으로 이루어집니다.
2. **Distributing the Application:** 서명된 애플리케이션은 대응하는 공개 키를 포함한 개발자의 certificate와 함께 사용자에게 배포됩니다.
3. **Verifying the Application:** 사용자가 애플리케이션을 다운로드하여 실행하려고 하면, 운영체제는 개발자의 certificate에 포함된 공개 키를 사용해 암호화된 해시를 복호화합니다. 그런 다음 애플리케이션의 현재 상태로부터 해시를 다시 계산하여 복호화된 해시와 비교합니다. 일치하면 **애플리케이션이 서명 이후 수정되지 않았음**을 의미하며 시스템은 애플리케이션의 실행을 허용합니다.

애플리케이션 서명은 Apple의 Gatekeeper 기술에서 필수적인 부분입니다. 사용자가 **인터넷에서 다운로드한 애플리케이션을 열려고 할 때**, Gatekeeper는 애플리케이션 서명을 검증합니다. 해당 서명이 Apple이 알려진 개발자에게 발급한 certificate로 서명되었고 코드가 변조되지 않았다면 Gatekeeper는 애플리케이션의 실행을 허용합니다. 그렇지 않으면 애플리케이션을 차단하고 사용자에게 경고합니다.

macOS Catalina부터는 **Gatekeeper가 애플리케이션이 Apple에 의해 notarized되었는지도 확인**하여 보안 계층을 추가합니다. notarization 프로세스는 알려진 보안 문제와 악성 코드 여부를 검사하고, 이 검사가 통과되면 Apple은 Gatekeeper가 검증할 수 있는 티켓을 애플리케이션에 추가합니다.

#### Check Signatures

일부 **malware sample**을 검사할 때는 항상 바이너리의 **서명**을 **확인**해야 합니다. 서명한 **개발자**가 이미 **malware**와 연관되어 있을 수 있기 때문입니다.
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
### 노타리제이션

Apple의 노타리제이션 프로세스는 잠재적으로 유해한 소프트웨어로부터 사용자를 보호하기 위한 추가적인 안전 장치 역할을 합니다. 이 과정은 **개발자가 자신의 애플리케이션을 검사 위해 제출하는 것**을 포함하며, 이는 App Review와 혼동해서는 안 됩니다. 이 서비스는 제출된 소프트웨어를 **악성 콘텐츠**의 존재 여부와 코드 서명과 관련된 잠재적인 문제를 검사하는 **자동화된 시스템**입니다.

소프트웨어가 이러한 검사에서 문제 없이 **통과**하면 Notary Service는 노타리제이션 티켓을 생성합니다. 이후 개발자는 이 티켓을 소프트웨어에 **첨부(stapling)** 해야 합니다. 또한 노타리제이션 티켓은 Gatekeeper가 접근할 수 있도록 온라인에도 게시됩니다.

사용자가 소프트웨어를 처음 설치하거나 실행할 때, 실행 파일에 스테이플된 형태이든 온라인에서 발견된 형태이든 노타리제이션 티켓의 존재는 **Gatekeeper에게 해당 소프트웨어가 Apple에 의해 노타리됨(노타리제이션된)** 을 알려줍니다. 결과적으로 Gatekeeper는 초기 실행 대화상자에 소프트웨어가 Apple에 의해 악성 콘텐츠 검사를 받았다는 설명 메시지를 표시합니다. 이 과정은 사용자가 시스템에 설치하거나 실행하는 소프트웨어의 보안에 대한 신뢰를 높여줍니다.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia 버전부터 **`spctl`**는 더 이상 Gatekeeper 구성을 수정할 수 없다는 점에 유의하세요.

**`spctl`**는 Gatekeeper와 상호작용하고 열거하기 위한 CLI 도구입니다(`syspolicyd` 데몬과 XPC 메시지를 통해). 예를 들어, 다음 명령으로 GateKeeper의 **상태**를 확인할 수 있습니다:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper 서명 검사는 모든 파일이 아니라 **Quarantine attribute**가 설정된 파일에만 수행된다는 점에 유의하세요.

GateKeeper는 **환경 설정 및 서명**에 따라 바이너리를 실행할 수 있는지 여부를 검사합니다:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**는 Gatekeeper를 강제하는 주요 데몬입니다. 이 데몬은 `/var/db/SystemPolicy`에 위치한 데이터베이스를 관리하며, 해당 데이터베이스를 지원하는 코드는 [여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)에서, SQL 템플릿은 [여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)에서 확인할 수 있습니다. 데이터베이스는 SIP의 제약을 받지 않으며 root로 쓰기 가능하고, 다른 데이터베이스가 손상될 경우 원본 백업으로 `/var/db/.SystemPolicy-default`가 사용됩니다.

또한 번들 **`/var/db/gke.bundle`** 및 **`/var/db/gkopaque.bundle`**에는 데이터베이스에 삽입되는 규칙 파일들이 포함되어 있습니다. 루트로 이 데이터베이스를 확인하려면 다음을 사용하세요:
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
**`syspolicyd`** 또한 `assess`, `update`, `record` 및 `cancel` 같은 다양한 연산을 제공하는 XPC 서버를 노출합니다. 이 연산들은 **`Security.framework`'s `SecAssessment*`** APIs로도 접근 가능하며, **`spctl`**은 실제로 XPC를 통해 **`syspolicyd`**와 통신합니다.

첫 번째 규칙이 "**App Store**"로 끝나고 두 번째가 "**Developer ID**"로 끝난다는 점에 주목하세요. 이전 이미지에서는 **App Store와 식별된 개발자로부터의 앱 실행이 허용되어 있었습니다**.\

그 설정을 **modify**하여 **App Store**로 바꾸면, **"Notarized Developer ID" 규칙이 사라집니다**.

또한 **type GKE** 규칙이 수천 개 있습니다 :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
다음은 다음 경로에서 가져온 해시들입니다:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

또는 다음을 사용하여 이전 정보를 나열할 수 있습니다:
```bash
sudo spctl --list
```
**`spctl`**의 옵션 **`--master-disable`** 및 **`--global-disable`**는 이러한 서명 검사를 완전히 **비활성화**합니다:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
완전히 활성화되면 새 옵션이 나타납니다:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

다음 명령으로 **App이 GateKeeper에 의해 허용되는지 확인할 수 있습니다**:
```bash
spctl --assess -v /Applications/App.app
```
다음 방법으로 GateKeeper에 새 규칙을 추가하여 특정 앱의 실행을 허용할 수 있습니다:
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
Regarding **kernel extensions**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

#### Managing Gatekeeper on macOS 15 (Sequoia) and later

- 오랫동안 존재하던 Finder **Ctrl+Open / Right‑click → Open** 우회는 제거되었습니다; 사용자는 첫 차단 대화 상자 이후 차단된 앱을 **System Settings → Privacy & Security → Open Anyway**에서 명시적으로 허용해야 합니다.
- `spctl --master-disable/--global-disable`는 더 이상 허용되지 않습니다; `spctl`은 사실상 평가 및 라벨 관리를 위한 읽기 전용이며 정책 적용은 UI 또는 MDM을 통해 구성됩니다.

Starting in macOS 15 Sequoia, end users can no longer toggle Gatekeeper policy from `spctl`. Management is performed via System Settings or by deploying an MDM configuration profile with the `com.apple.systempolicy.control` payload. Example profile snippet to allow App Store and identified developers (but not "Anywhere"):

<details>
<summary>App Store 및 identified developers를 허용하는 MDM 프로필</summary>
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

### 격리 파일

애플리케이션이나 파일을 **다운로드**하면, 웹 브라우저나 이메일 클라이언트 같은 특정 macOS **applications**가 다운로드한 파일에 확장 파일 속성(일반적으로 "quarantine flag"라고 알려진)을 **붙입니다**. 이 속성은 해당 파일이 인터넷 같은 신뢰할 수 없는 출처에서 왔음을 **표시**하여 잠재적 위험을 알리는 보안 수단입니다. 다만 모든 애플리케이션이 이 속성을 붙이는 것은 아니며, 예를 들어 일반적인 BitTorrent 클라이언트 소프트웨어는 보통 이 과정을 우회합니다.

**파일에 quarantine flag가 있으면 사용자가 파일을 실행하려 할 때 macOS의 Gatekeeper 보안 기능이 이를 감지합니다.**

만약 **quarantine flag가 없는 경우**(일부 BitTorrent 클라이언트로 다운로드한 파일처럼) Gatekeeper의 **검사가 수행되지 않을 수 있습니다**. 따라서 보안 수준이 낮거나 알 수 없는 출처에서 다운로드한 파일을 열 때는 주의해야 합니다.

> [!NOTE] > **검증**은 코드 서명의 **유효성**을 확인하는 작업은 코드와 번들된 모든 리소스의 암호학적 **해시**를 생성하는 등 **리소스 집약적**인 과정입니다. 또한 인증서 유효성을 확인하려면 발급 후 폐기 여부를 확인하기 위해 Apple의 서버에 대한 **온라인 확인**이 필요합니다. 이러한 이유로 전체 코드 서명 및 notarization 검사를 **앱 실행 시마다 매번 수행하는 것은 비현실적입니다**.
>
> 따라서 이 검사는 **quarantined 속성이 있는 앱을 실행할 때만 수행됩니다.**

> [!WARNING]
> 이 속성은 파일을 **생성/다운로드하는 애플리케이션이 설정해야 합니다.**
>
> 다만 샌드박스된 프로세스가 생성하는 모든 파일에는 이 속성이 설정됩니다. 샌드박스되지 않은 앱은 스스로 설정할 수 있으며, 또는 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) 키를 **Info.plist**에 지정하면 시스템이 생성된 파일에 `com.apple.quarantine` 확장 속성을 설정합니다.

또한 **`qtn_proc_apply_to_self`**를 호출하는 프로세스가 생성한 모든 파일은 격리됩니다. 또는 API **`qtn_file_apply_to_path`**가 지정된 파일 경로에 quarantine 속성을 추가합니다.

다음 명령으로 **상태를 확인하고 활성화/비활성화**할 수 있습니다 (root 필요):
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
다음 명령으로 파일에 quarantine 확장 속성이 있는지 **확인할 수도 있습니다:**
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**확장된** **속성**의 **값**을 확인하고 quarantine attr을 기록한 app을 확인하세요:
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
실제로 프로세스는 "생성하는 파일에 quarantine 플래그를 설정할 수 있다" (이미 생성한 파일에 USER_APPROVED 플래그를 적용해봤지만 적용되지 않았습니다):

<details>

<summary>quarantine 플래그 적용 소스 코드</summary>
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

그리고 그 속성을 **제거**하려면:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
그리고 다음 명령으로 격리된 모든 파일을 찾으세요:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine 정보는 또한 GUI가 파일 출처 정보를 얻을 수 있게 해주는 LaunchServices가 관리하는 중앙 데이터베이스인 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**에 저장됩니다. 또한 애플리케이션이 자신의 출처를 숨기기 위해 이 정보를 덮어쓸 수 있으며, 이는 LaunchServices APIS에서 수행될 수 있습니다.

#### **libquarantine.dylib**

이 라이브러리는 확장 속성 필드를 조작할 수 있는 여러 함수를 내보냅니다.

`qtn_file_*` APIs는 파일 quarantine 정책을 처리하며, `qtn_proc_*` APIs는 프로세스(프로세스에 의해 생성된 파일)에 적용됩니다. 내보내지 않은 `__qtn_syscall_quarantine*` 함수들이 정책을 적용하며, 이들은 첫 번째 인자로 "Quarantine"을 사용하여 `mac_syscall`을 호출해 `Quarantine.kext`로 요청을 보냅니다.

#### **Quarantine.kext**

해당 커널 확장은 **시스템의 kernel cache**를 통해서만 사용할 수 있습니다; 그러나 [**https://developer.apple.com/**](https://developer.apple.com/)에서 **Kernel Debug Kit**을 다운로드하면 확장에 대한 심볼이 포함된 버전을 얻을 수 있습니다.

이 Kext는 MACF를 통해 여러 호출을 훅킹하여 파일 생명주기 이벤트(생성, 열기, 이름 변경, 하드 링크 생성 등)를 모두 가로챕니다. 심지어 `com.apple.quarantine` 확장 속성의 설정을 막기 위해 `setxattr`도 가로챕니다.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: 샌드박스와 함께 quarantine을 강제함
- `security.mac.qtn.user_approved_exec`: 격리된 프로세스는 승인된 파일만 실행할 수 있음

#### Provenance xattr (Ventura 및 이후)

macOS 13 Ventura는 격리된 앱이 처음 실행 허용될 때 채워지는 별도의 provenance 메커니즘을 도입했습니다. 두 가지 아티팩트가 생성됩니다:

- `.app` 번들 디렉터리에 생기는 `com.apple.provenance` xattr (기본 키와 플래그를 포함한 고정 크기 이진 값).
- 앱의 cdhash와 메타데이터를 저장하는 `/var/db/SystemPolicyConfiguration/ExecPolicy/`의 ExecPolicy 데이터베이스 내 `provenance_tracking` 테이블의 행.

실용적인 사용:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect는 macOS에 내장된 **anti-malware** 기능입니다. XProtect는 **애플리케이션이 처음 실행되거나 변경될 때 해당 애플리케이션을 알려진 맬웨어 및 안전하지 않은 파일 형식의 데이터베이스와 대조하여 검사합니다**. Safari, Mail, Messages 같은 특정 앱을 통해 파일을 다운로드하면 XProtect가 자동으로 파일을 스캔합니다. 데이터베이스의 알려진 맬웨어와 일치하면 XProtect는 **해당 파일의 실행을 차단**하고 위협을 경고합니다.

XProtect 데이터베이스는 Apple이 새로운 맬웨어 정의로 **정기적으로 업데이트**하며, 이러한 업데이트는 자동으로 다운로드되어 Mac에 설치됩니다. 이를 통해 XProtect는 항상 최신 알려진 위협에 대응할 수 있습니다.

그러나 **XProtect는 완전한 안티바이러스 솔루션이 아닙니다**. XProtect는 특정 알려진 위협 목록만 검사하며 대부분의 안티바이러스 소프트웨어처럼 실시간(on-access) 스캔을 수행하지 않습니다.

다음 명령으로 최신 XProtect 업데이트에 대한 정보를 확인할 수 있습니다:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect는 SIP로 보호된 위치인 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**에 있습니다. 번들 내부에는 XProtect가 사용하는 정보들이 들어 있습니다:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 해당 cdhash를 가진 코드가 legacy entitlements를 사용할 수 있도록 허용합니다.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID와 TeamID로 로드가 금지된 플러그인 및 확장 목록 또는 최소 버전을 지정합니다.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: 악성코드 탐지를 위한 Yara 규칙입니다.
- **`XProtect.bundle/Contents/Resources/gk.db`**: 차단된 애플리케이션의 해시와 TeamID를 담은 SQLite3 데이터베이스입니다.

참고로 XProtect와 관련된 다른 App이 **`/Library/Apple/System/Library/CoreServices/XProtect.app`**에 존재하지만, 해당 앱은 Gatekeeper 프로세스와는 관련이 없습니다.

> XProtect Remediator: 최신 macOS에서 Apple은 launchd를 통해 주기적으로 실행되는 온디맨드 스캐너(XProtect Remediator)를 제공하여 악성코드 군을 탐지하고 복구합니다. 이러한 스캔은 unified logs에서 확인할 수 있습니다:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Not Gatekeeper

> [!CAUTION]
> Gatekeeper는 애플리케이션을 실행할 때마다 **실행되는 것은 아님**을 주의하세요. 이미 Gatekeeper에 의해 실행되고 검증된 앱을 실행할 때는 오직 _**AppleMobileFileIntegrity**_ (AMFI)가 **실행 가능한 코드 서명을 검증**합니다.

따라서, 과거에는 Gatekeeper로 캐시하기 위해 앱을 먼저 실행한 뒤 애플리케이션의 **실행 파일이 아닌 파일들**(예: Electron asar나 NIB 파일)을 수정할 수 있었고, 다른 보호 장치가 없으면 애플리케이션이 그 **악의적인** 추가와 함께 **실행**되곤 했습니다.

하지만 현재는 macOS가 애플리케이션 번들 내부의 파일 수정을 **차단**하기 때문에 이 방식은 더 이상 통하지 않습니다. 따라서 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 공격을 시도해 보면, Gatekeeper로 캐시하기 위해 앱을 실행한 후 번들을 수정할 수 없기 때문에 더 이상 악용할 수 없음을 알게 될 것입니다. 예를 들어 exploit에서 지시한 대로 Contents 디렉터리 이름을 NotCon으로 바꾸고, 그 후 앱의 메인 바이너리를 실행해 Gatekeeper로 캐시하려 하면 오류가 발생하여 실행되지 않습니다.

## Gatekeeper Bypasses

사용자가 Gatekeeper가 차단해야 할 것을 다운로드하고 실행하도록 유도하는 모든 방법은 macOS의 취약점으로 간주됩니다. 과거 Gatekeeper를 우회할 수 있게 했던 기법들에 할당된 몇몇 CVE는 다음과 같습니다:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Archive Utility를 사용해 압축을 풀 경우, **경로 길이가 886자를 초과하는** 파일에는 com.apple.quarantine 확장 속성이 부여되지 않는 것으로 관찰되었습니다. 이로 인해 해당 파일들은 의도치 않게 Gatekeeper의 보안 검사를 **회피**할 수 있습니다.

Check the [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) for more information.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Automator로 생성된 애플리케이션의 경우 실행에 필요한 정보가 실행 파일이 아닌 `application.app/Contents/document.wflow`에 들어 있고, 실행 파일은 **Automator Application Stub**이라는 일반적인 Automator 바이너리입니다.

따라서 `application.app/Contents/MacOS/Automator\ Application\ Stub`을 시스템 내의 다른 Automator Application Stub을 가리키는 심볼릭 링크로 연결하면 `document.wflow`(여러분의 스크립트)에 들어있는 내용을 **Gatekeeper를 트리거하지 않고** 실행할 수 있습니다. 이는 실제 실행 파일에 quarantine xattr가 없기 때문입니다.

예상되는 시스템 위치 예: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Check the [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) for more information.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

이 우회에서는 애플리케이션을 `application.app`가 아닌 `application.app/Contents`에서부터 압축하기 시작해 zip 파일을 만든 사례가 있었습니다. 이 경우 **`application.app/Contents`의 모든 파일에는 quarantine 속성이 적용되었지만**, Gatekeeper가 검사하던 `application.app`에는 적용되지 않았기 때문에 Gatekeeper가 우회되었습니다. 다시 말해 `application.app`을 트리거했을 때 **quarantine 속성이 없었기 때문**입니다.
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

구성 요소가 다르더라도 이 취약점의 악용은 이전 취약점과 매우 유사합니다. 이 경우 **`application.app/Contents`**에서 Apple Archive를 생성하므로 **`application.app`는 quarantine attr을 받지 않습니다** **Archive Utility**로 압축 해제될 때.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**는 파일의 속성을 누구도 쓸 수 없도록 하는 데 사용할 수 있다:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
또한, **AppleDouble** 파일 포맷은 ACEs를 포함한 파일을 복사합니다.

이 [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 **`com.apple.acl.text`**라는 xattr 안에 저장된 ACL의 텍스트 표현이 압축 해제된 파일의 ACL로 설정된다는 것을 확인할 수 있습니다. 

따라서, 다른 xattr가 해당 파일에 기록되는 것을 막는 ACL을 가진 상태로 응용 프로그램을 **AppleDouble** 파일 포맷으로 압축(zip)했다면... quarantine xattr가 애플리케이션에 설정되지 않았습니다:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
자세한 내용은 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.

이것은 AppleArchives로도 악용될 수 있다는 점에 유의하세요:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

일부 macOS 내부 문제로 인해 **Google Chrome이 다운로드된 파일에 quarantine attribute를 설정하지 않고 있었습니다**.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 파일 형식은 파일의 속성을 `._`로 시작하는 별도의 파일에 저장하며, 이는 파일 속성을 **macOS 머신들 간에** 복사하는 데 도움이 됩니다. 그러나 AppleDouble 파일을 압축 해제한 후 `._`로 시작하는 파일에 **quarantine attribute가 부여되지 않는 것으로** 관찰되었습니다.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
quarantine attribute가 설정되지 않는 파일을 만들 수 있었기 때문에, **Gatekeeper를 우회할 수 있었다.** 트릭은 AppleDouble 이름 규칙(앞에 `._`를 붙임)을 사용해 **DMG file application을 생성**하고 quarantine attribute가 없는 이 숨겨진 파일을 가리키는 **visible file을 sym link로 만드는 것**이었다.\
**dmg file을 실행할 때**, quarantine attribute가 없기 때문에 **Gatekeeper를 우회한다**.
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

macOS Sonoma 14.0에서 수정된 Gatekeeper 우회로 인해 제작된 앱이 프롬프트 없이 실행될 수 있었습니다. 세부 사항은 패치 후 공개되었고, 수정 이전 실제로 악용된 사례가 있었습니다. Sonoma 14.0 이상이 설치되어 있는지 확인하세요.

### [CVE-2024-27853]

macOS 14.4(2024년 3월 출시)의 Gatekeeper 우회는 `libarchive`가 악성 ZIP을 처리하는 방식에서 기인하여 앱이 평가를 회피할 수 있게 했습니다. Apple이 문제를 해결한 14.4 이상으로 업데이트하세요.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

다운로드된 앱에 포함된 **Automator Quick Action workflow**가 Gatekeeper 평가 없이 트리거될 수 있었습니다. 워크플로우가 데이터로 취급되어 Automator 헬퍼가 정상적인 notarization 프롬프트 경로 밖에서 실행되었기 때문입니다. 셸 스크립트를 실행하는 Quick Action을 번들한 조작된 `.app`(예: `Contents/PlugIns/*.workflow/Contents/document.wflow`)은 실행 즉시 코드가 실행될 수 있었습니다. Apple은 추가 동의 대화상자를 도입하고 Ventura **13.7**, Sonoma **14.7**, Sequoia **15**에서 평가 경로를 수정했습니다.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

The Unarchiver 등 인기 있는 압축 해제 도구들의 여러 취약점으로 인해 아카이브에서 추출된 파일에 `com.apple.quarantine` xattr가 누락되어 Gatekeeper 우회 가능성이 발생했습니다. 테스트 시에는 항상 macOS Archive Utility 또는 패치된 도구를 사용하고, 추출 후 xattr을 검증하세요.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- 앱을 포함한 디렉터리를 생성합니다.
- 앱에 uchg를 추가합니다.
- 앱을 tar.gz로 압축합니다.
- tar.gz 파일을 피해자에게 보냅니다.
- 피해자가 tar.gz 파일을 열고 앱을 실행합니다.
- Gatekeeper는 앱을 검사하지 않습니다.

### Prevent Quarantine xattr

".app" 번들에 quarantine xattr가 추가되지 않으면 실행 시 **Gatekeeper가 트리거되지 않습니다**.

## References

- Apple Platform Security: macOS Sonoma 14.4의 보안 내용 정보 (CVE-2024-27853 포함) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: macOS가 이제 앱의 출처를 추적하는 방법 – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: macOS Sonoma 14.7 / Ventura 13.7의 보안 내용 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
