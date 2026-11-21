# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper**는 Mac 운영 체제용으로 개발된 보안 기능으로, 사용자가 시스템에서 **신뢰할 수 있는 소프트웨어만 실행하도록** 합니다. 앱, 플러그인 또는 설치 패키지와 같이 사용자가 **App Store 외부의 출처**에서 다운로드하여 열려고 하는 소프트웨어를 **검증**합니다.

Gatekeeper의 핵심 메커니즘은 **검증** 프로세스입니다. 다운로드한 소프트웨어가 **인증된 개발자가 서명했는지** 확인하여 소프트웨어의 진위 여부를 검증합니다. 또한 소프트웨어가 Apple의 **공증을 받았는지** 확인하여 알려진 악성 콘텐츠가 없고 공증 이후 변조되지 않았음을 확인합니다.

또한 Gatekeeper는 다운로드한 소프트웨어를 처음 열 때 **사용자에게 실행 승인을 요청**하여 사용자의 제어권과 보안을 강화합니다. 이 보호 기능은 사용자가 무해한 데이터 파일로 착각한 잠재적으로 유해한 실행 코드를 실수로 실행하지 않도록 도와줍니다.

### 애플리케이션 서명

코드 서명이라고도 하는 애플리케이션 서명은 Apple 보안 인프라의 핵심 요소입니다. 이는 **소프트웨어 작성자**(개발자)의 신원을 **확인**하고, 마지막 서명 이후 코드가 변조되지 않았는지 확인하는 데 사용됩니다.

작동 방식은 다음과 같습니다.

1. **애플리케이션 서명:** 개발자가 애플리케이션을 배포할 준비가 되면 **개인 키를 사용해 애플리케이션에 서명**합니다. 이 개인 키는 개발자가 Apple Developer Program에 등록할 때 **Apple이 개발자에게 발급하는 인증서**와 연결되어 있습니다. 서명 과정에서는 앱의 모든 부분에 대한 암호화 해시를 생성하고 이 해시를 개발자의 개인 키로 암호화합니다.
2. **애플리케이션 배포:** 서명된 애플리케이션은 해당 공개 키가 포함된 개발자 인증서와 함께 사용자에게 배포됩니다.
3. **애플리케이션 검증:** 사용자가 애플리케이션을 다운로드하여 실행하려고 하면 Mac 운영 체제는 개발자 인증서의 공개 키를 사용해 해시를 복호화합니다. 그런 다음 현재 애플리케이션 상태를 바탕으로 해시를 다시 계산하고 복호화된 해시와 비교합니다. 두 해시가 일치하면 개발자가 서명한 이후 **애플리케이션이 수정되지 않았음**을 의미하며, 시스템은 애플리케이션의 실행을 허용합니다.

애플리케이션 서명은 Apple의 Gatekeeper 기술에서 필수적인 부분입니다. 사용자가 인터넷에서 다운로드한 애플리케이션을 **열려고 하면** Gatekeeper가 애플리케이션 서명을 확인합니다. Apple이 알려진 개발자에게 발급한 인증서로 서명되어 있고 코드가 변조되지 않았다면 Gatekeeper는 애플리케이션의 실행을 허용합니다. 그렇지 않으면 애플리케이션을 차단하고 사용자에게 알립니다.

macOS Catalina부터 **Gatekeeper는 애플리케이션이 Apple의 공증을 받았는지도 확인**하여 보안 계층을 추가합니다. 공증 과정에서는 알려진 보안 문제와 악성 코드를 검사합니다. 검사를 통과하면 Apple은 Gatekeeper가 확인할 수 있는 티켓을 애플리케이션에 추가합니다.

#### 서명 확인

**malware 샘플**을 검사할 때는 해당 바이너리의 **서명을 확인**해야 합니다. 서명한 **개발자**가 이미 **malware와 관련되어 있을 수 있기 때문입니다.**

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

### 공증

Apple의 공증 절차는 잠재적으로 유해한 소프트웨어로부터 사용자를 보호하는 추가 안전장치입니다. 이 절차에서는 개발자가 **Apple의 Notary Service에 애플리케이션 검사를 의뢰**합니다. 이는 App Review와 혼동해서는 안 됩니다. Notary Service는 제출된 소프트웨어에 **악성 콘텐츠**가 있는지, 코드 서명과 관련된 문제가 있는지 면밀히 살펴보는 **자동화 시스템**입니다.

소프트웨어가 이 검사에서 문제없이 **통과**하면 Notary Service는 공증 티켓을 생성합니다. 그런 다음 개발자는 이 티켓을 소프트웨어에 **첨부**해야 하는데, 이 과정을 '스태플링'이라고 합니다. 또한 공증 티켓은 온라인에도 게시되며, Apple의 보안 기술인 Gatekeeper가 이에 접근할 수 있습니다.

사용자가 소프트웨어를 처음 설치하거나 실행할 때, 실행 파일에 스태플링되어 있거나 온라인에서 찾을 수 있는 공증 티켓이 있으면 **Gatekeeper는 해당 소프트웨어가 Apple의 공증을 받았음을 확인**합니다. 그 결과 Gatekeeper는 최초 실행 대화상자에 설명 메시지를 표시하여, Apple이 해당 소프트웨어에 악성 콘텐츠가 있는지 검사했음을 알립니다. 이 절차는 사용자가 시스템에 설치하거나 실행하는 소프트웨어의 보안에 대한 신뢰를 높여 줍니다.

### spctl & syspolicyd

> [!CAUTION]
> Sequoia 버전부터는 **`spctl`**로 더 이상 Gatekeeper 구성을 수정할 수 없습니다.

**`spctl`**은 Gatekeeper를 열거하고 상호작용하는 CLI 도구입니다(`syspolicyd` 데몬과 XPC 메시지를 통해 통신). 예를 들어 다음과 같이 GateKeeper의 **상태**를 확인할 수 있습니다.

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> GateKeeper 서명 검사는 모든 파일이 아니라 **Quarantine 속성이 있는 파일에만** 수행된다는 점에 유의하세요.

GateKeeper는 **환경설정 및 서명**에 따라 바이너리를 실행할 수 있는지 확인합니다:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`**는 Gatekeeper 적용을 담당하는 주요 데몬입니다. 이 데몬은 `/var/db/SystemPolicy`에 있는 데이터베이스를 관리하며, [여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)에서 데이터베이스 지원 코드를, [여기](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)에서 SQL 템플릿을 확인할 수 있습니다. 이 데이터베이스는 SIP의 제한을 받지 않으며 root가 쓸 수 있습니다. 또한 다른 데이터베이스가 손상될 경우를 대비해 `/var/db/.SystemPolicy-default` 데이터베이스를 원본 백업으로 사용합니다.

또한 **`/var/db/gke.bundle`** 및 **`/var/db/gkopaque.bundle`** 번들에는 데이터베이스에 삽입되는 규칙이 담긴 파일이 있습니다. root로 다음 명령을 실행해 이 데이터베이스를 확인할 수 있습니다:

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

**`syspolicyd`**는 `assess`, `update`, `record`, `cancel` 같은 여러 작업을 제공하는 XPC 서버도 노출합니다. 이 작업들은 **`Security.framework`의 `SecAssessment*`** API를 사용해서도 호출할 수 있으며, **`spctl`**은 실제로 XPC를 통해 **`syspolicyd`**와 통신합니다.

첫 번째 규칙은 "**App Store**"로 끝나고 두 번째 규칙은 "**Developer ID**"로 끝나는 것을 확인하세요. 이전 이미지에서는 **App Store의 앱과 식별된 개발자의 앱을 실행하도록 활성화되어 있었습니다**.\
이 설정을 App Store로 **변경**하면 "**공증된 Developer ID" 규칙이 사라집니다**.

또한 **GKE 유형**의 규칙이 수천 개 있습니다. :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

다음에서 가져온 해시입니다:

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

다음 명령으로 **앱이 GateKeeper에서 허용되는지 확인할 수 있습니다**:

```bash
spctl --assess -v /Applications/App.app
```

macOS 14 이상에서는 **`syspolicy_check`**가 애플리케이션 번들의 배포 전 점검에 유용한 상위 수준 도구입니다. 단순한 `spctl` 결과보다 신뢰 실행 관련 진단 정보를 더 실행 가능한 형태로 제공하지만, quarantine 전파도 테스트할 수 있도록 실제 다운로드/압축 해제/최초 실행 경로를 테스트할 것을 Apple은 여전히 권장합니다.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

GateKeeper에 특정 앱의 실행을 허용하는 새 규칙을 추가할 수 있습니다:

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

커널 확장과 관련하여, `/var/db/SystemPolicyConfiguration` 폴더에는 로드가 허용된 kext 목록이 들어 있는 파일이 있습니다. 또한 `spctl`에는 `com.apple.private.iokit.nvram-csr` entitlement가 있습니다. 이는 새로 사전 승인된 커널 확장을 추가할 수 있으며, 해당 확장은 `kext-allowed-teams` 키의 NVRAM에도 저장해야 하기 때문입니다.

#### macOS 15 (Sequoia) 및 이후 버전에서 Gatekeeper 관리하기

- 오랫동안 사용되던 Finder의 **Ctrl+열기 / 오른쪽 클릭 → 열기** 우회 방법이 제거되었습니다. 사용자는 첫 번째 차단 대화상자가 표시된 후 **시스템 설정 → 개인정보 보호 및 보안 → 그래도 열기**에서 차단된 앱을 명시적으로 허용해야 합니다.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable`은 더 이상 자동으로 적용되는 정책 변경 명령으로 허용되지 않습니다. 규칙 데이터베이스나 전역 평가 상태를 변경하는 작업은 더 이상 사용되지 않으므로, 평가에는 `spctl`을 사용하고 시행 정책은 UI 또는 MDM을 통해 설정하세요.

macOS 15 Sequoia부터 최종 사용자는 더 이상 `spctl`에서 Gatekeeper 정책을 전환할 수 없습니다. 관리는 시스템 설정에서 수행하거나 `com.apple.systempolicy.control` payload가 포함된 MDM 구성 프로파일을 배포하여 수행합니다. App Store 및 확인된 개발자의 앱은 허용하되("어디서나"는 허용하지 않음) 설정하는 프로파일 예시는 다음과 같습니다.

<details>
<summary>App Store 및 확인된 개발자를 허용하는 MDM 프로파일</summary>

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

### Quarantine 파일

애플리케이션이나 파일을 **다운로드**하면 웹 브라우저나 이메일 클라이언트 같은 특정 macOS **애플리케이션**이 다운로드한 파일에 "**quarantine flag**"라고 흔히 불리는 확장 파일 속성을 **추가합니다**. 이 속성은 파일이 신뢰할 수 없는 출처(인터넷)에서 왔으며 잠재적 위험을 포함할 수 있음을 **표시하는** 보안 조치입니다. 그러나 모든 애플리케이션이 이 속성을 추가하는 것은 아닙니다. 예를 들어 일반적인 BitTorrent 클라이언트 소프트웨어는 대개 이 과정을 우회합니다.

**quarantine flag가 있으면 사용자가 파일을 실행하려 할 때 macOS의 Gatekeeper 보안 기능이 작동합니다**.

**quarantine flag가 없는 경우**(일부 BitTorrent 클라이언트를 통해 다운로드한 파일 등), Gatekeeper의 **검사가 수행되지 않을 수 있습니다**. 따라서 사용자는 보안이 취약하거나 알 수 없는 출처에서 다운로드한 파일을 열 때 주의해야 합니다.

> [!NOTE] > 코드 서명의 **유효성**을 **확인하는** 과정은 코드와 번들에 포함된 모든 리소스의 암호화 **해시**를 생성하므로 **많은 리소스를 사용합니다**. 또한 인증서의 유효성을 확인하려면 인증서 발급 이후 취소되었는지 알아보기 위해 Apple 서버에 **온라인으로 확인**해야 합니다. 이러한 이유로 앱을 실행할 때마다 전체 코드 서명 및 공증을 확인하는 것은 **현실적으로 어렵습니다**.
>
> 따라서 이러한 검사는 quarantine 속성이 있는 앱을 실행할 때만 수행됩니다.

> [!WARNING]
> 이 속성은 파일을 생성하거나 다운로드하는 **애플리케이션이 설정해야 합니다**.
>
> 그러나 sandboxed 파일은 생성하는 모든 파일에 이 속성이 설정됩니다. sandboxed가 아닌 앱은 직접 설정하거나 **Info.plist**에서 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) 키를 지정할 수 있습니다. 그러면 시스템이 생성된 파일에 `com.apple.quarantine` 확장 속성을 설정합니다.

또한 **`qtn_proc_apply_to_self`**를 호출하는 프로세스가 생성한 모든 파일은 quarantine 처리됩니다. 또는 **`qtn_file_apply_to_path`** API를 사용해 지정된 파일 경로에 quarantine 속성을 추가할 수 있습니다.

다음과 같이 상태를 **확인하고 활성화/비활성화**할 수 있습니다(root 권한 필요):

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

다음과 같이 **파일에 quarantine 확장 속성이 있는지도 확인할 수 있습니다**:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

**확장** **속성**의 **값**을 확인하고 다음을 사용해 quarantine attr을 기록한 앱을 알아보세요:

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

실제로 프로세스는 "자신이 생성한 파일에 quarantine 플래그를 설정할 수 있습니다" (생성한 파일에 USER_APPROVED 플래그를 설정해 보았지만 적용되지 않았습니다):

<details>

<summary>quarantine 플래그를 적용하는 소스 코드</summary>

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

그리고 다음 명령으로 해당 attribute를 **제거**합니다:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

그리고 다음 명령으로 격리된 모든 파일을 찾습니다:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantine 정보는 LaunchServices가 관리하는 중앙 데이터베이스 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**에도 저장되며, 이를 통해 GUI에서 파일의 출처 정보를 확인할 수 있습니다. 또한 출처를 숨기려는 애플리케이션이 이 정보를 덮어쓸 수도 있습니다. LaunchServices API를 통해서도 이를 수행할 수 있습니다.

#### **libquarantine.dylib**

이 라이브러리는 확장 속성 필드를 조작할 수 있는 여러 함수를 내보냅니다.

`qtn_file_*` API는 파일의 quarantine 정책을 처리하고, `qtn_proc_*` API는 프로세스에 적용됩니다(프로세스가 생성한 파일). 내보내지 않는 `__qtn_syscall_quarantine*` 함수는 정책을 적용하는 함수로, 첫 번째 인수로 `"Quarantine"`을 전달해 `mac_syscall`을 호출하고 요청을 `Quarantine.kext`로 보냅니다.

#### **Quarantine.kext**

이 커널 확장은 **시스템의 커널 캐시에서만** 사용할 수 있습니다. 하지만 [**https://developer.apple.com/**](https://developer.apple.com/)에서 **Kernel Debug Kit**를 다운로드할 수 있으며, 여기에는 심볼이 포함된 확장 버전이 들어 있습니다.

이 Kext는 MACF를 통해 여러 호출을 후킹해 파일의 전체 생명주기 이벤트를 가로챕니다. 여기에는 생성, 열기, 이름 변경, 하드 링크 생성이 포함되며, `com.apple.quarantine` 확장 속성을 설정하지 못하도록 `setxattr`도 가로챕니다.

또한 몇 가지 MIB를 사용합니다.

- `security.mac.qtn.sandbox_enforce`: Sandbox와 함께 quarantine을 적용합니다.
- `security.mac.qtn.user_approved_exec`: Quarantine된 프로세스는 승인된 파일만 실행할 수 있습니다.

#### Provenance xattr(Ventura 및 이후 버전)

macOS 13 Ventura에서는 quarantine된 앱의 실행이 처음으로 허용될 때 채워지는 별도의 provenance 메커니즘이 도입되었습니다.<sup>[[2]](#references)</sup> 다음 두 가지 아티팩트가 생성됩니다.

- `.app` 번들 디렉터리의 `com.apple.provenance` xattr(기본 키와 플래그가 포함된 고정 크기 바이너리 값).
- `/var/db/SystemPolicyConfiguration/ExecPolicy/`의 ExecPolicy 데이터베이스 내 `provenance_tracking` 테이블에 앱의 cdhash와 메타데이터가 저장된 행.

실제 사용법:

```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```

### XProtect

XProtect는 macOS에 내장된 **anti-malware** 기능입니다. XProtect는 애플리케이션이 처음 실행되거나 수정될 때마다 알려진 malware 및 안전하지 않은 파일 유형 데이터베이스와 대조해 **검사합니다**. Safari, Mail, Messages와 같은 특정 앱을 통해 파일을 다운로드하면 XProtect가 자동으로 파일을 검사합니다. 데이터베이스에 있는 알려진 malware와 일치하면 XProtect는 **파일이 실행되지 않도록 차단하고** 위협을 알립니다.

Apple은 새로운 malware 정의를 반영해 XProtect 데이터베이스를 **정기적으로 업데이트**하며, 이러한 업데이트는 Mac에 자동으로 다운로드되고 설치됩니다. 이를 통해 XProtect는 항상 최신 알려진 위협에 대응할 수 있습니다.

다만 **XProtect는 모든 기능을 갖춘 백신 솔루션이 아닙니다**. 특정한 알려진 위협 목록만 검사하며, 대부분의 백신 소프트웨어와 같은 on-access scanning은 수행하지 않습니다.

다음 명령을 실행하면 최신 XProtect 업데이트 정보를 확인할 수 있습니다:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect는 SIP로 보호되는 위치인 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**에 있으며, 번들 안에서 XProtect가 사용하는 정보를 찾을 수 있습니다.

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 해당 cdhash를 가진 코드가 legacy entitlements를 사용하도록 허용합니다.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID 및 TeamID를 기준으로 로드가 금지된 플러그인과 확장 프로그램을 나열하거나 최소 버전을 지정합니다.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware를 탐지하는 YARA 규칙입니다.
- **`XProtect.bundle/Contents/Resources/gk.db`**: 차단된 애플리케이션과 TeamID의 해시가 저장된 SQLite3 데이터베이스입니다.

XProtect와 관련된 다른 앱인 **`/Library/Apple/System/Library/CoreServices/XProtect.app`**도 있지만, Gatekeeper 프로세스에는 관여하지 않습니다.

> XProtect Remediator: 최신 macOS에서 Apple은 malware 계열을 탐지하고 제거하기 위해 launchd를 통해 주기적으로 실행되는 온디맨드 스캐너(XProtect Remediator)를 제공합니다. 다음과 같이 unified logs에서 이러한 검사를 확인할 수 있습니다:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper가 실행되지 않는 경우

> [!CAUTION]
> Gatekeeper는 애플리케이션을 실행할 때마다 **실행되는 것이 아닙니다**. _**AppleMobileFileIntegrity**_ (AMFI)는 Gatekeeper가 이미 실행하고 검증한 앱을 실행할 때만 **실행 파일의 코드 서명을 검증**합니다.

따라서 이전에는 앱을 실행해 Gatekeeper의 검증 결과를 캐시한 다음, 애플리케이션의 **실행 파일이 아닌 파일**(예: Electron asar 또는 NIB 파일)을 **수정**할 수 있었습니다. 다른 보호 기능이 적용되어 있지 않으면 앱은 **악성** 요소가 추가된 상태로 **실행**되었습니다.

하지만 이제 macOS가 애플리케이션 번들 내 파일의 **수정을 방지**하므로 이 방법은 사용할 수 없습니다. 따라서 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 공격을 시도해 보면, 앱을 실행해 Gatekeeper의 검증 결과를 캐시한 후에는 번들을 수정할 수 없으므로 더 이상 악용할 수 없다는 것을 알게 됩니다. 예를 들어 익스플로잇에 나온 것처럼 `Contents` 디렉터리의 이름을 `NotCon`으로 바꾸고, 앱의 메인 바이너리를 실행해 Gatekeeper의 검증 결과를 캐시하면 오류가 발생하고 앱은 실행되지 않습니다.

## Gatekeeper 우회

Gatekeeper를 우회하는 모든 방법(사용자가 Gatekeeper가 실행을 차단해야 하는 파일을 다운로드하고 실행하도록 만드는 방법)은 macOS 취약점으로 간주됩니다. 과거 Gatekeeper를 우회할 수 있게 했던 기법에 부여된 CVE는 다음과 같습니다.

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**를 사용해 압축을 풀면 **경로 길이가 886자를 초과하는** 파일에 com.apple.quarantine 확장 속성이 설정되지 않는 것으로 확인되었습니다. 이로 인해 해당 파일은 의도치 않게 Gatekeeper의 보안 검사를 **우회할 수 있습니다**.<sup>[[5]](#references)</sup>

자세한 내용은 [**원본 보고서**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)를 확인하세요.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**로 애플리케이션을 만들면 실행에 필요한 정보는 실행 파일이 아니라 `application.app/Contents/document.wflow`에 들어 있습니다. 실행 파일은 **Automator Application Stub**이라는 일반 Automator 바이너리일 뿐입니다.

따라서 `application.app/Contents/MacOS/Automator\ Application\ Stub`이 **시스템 내 다른 Automator Application Stub을 가리키도록 심볼릭 링크를 만들면**, 실제 실행 파일에는 격리 xattr이 없기 때문에 **Gatekeeper를 실행하지 않고도** `document.wflow`에 있는 내용(스크립트)을 실행할 수 있었습니다.<sup>[[6]](#references)</sup>

예상되는 위치의 예: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

자세한 내용은 [**원본 보고서**](https://ronmasas.com/posts/bypass-macos-gatekeeper)를 확인하세요.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

이 우회 기법에서는 `application.app` 대신 `application.app/Contents`에서 압축을 시작하도록 애플리케이션이 포함된 zip 파일을 만들었습니다. 따라서 **`application.app/Contents`의 모든 파일**에는 **격리 속성**이 적용되었지만, Gatekeeper가 검사하는 대상인 **`application.app`에는 적용되지 않았습니다**. 그 결과 `application.app`이 실행될 때 **격리 속성이 없어서** Gatekeeper를 우회할 수 있었습니다.<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

자세한 내용은 [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)를 확인하세요.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

구성 요소는 다르지만, 이 취약점의 exploitation은 이전 취약점과 매우 유사합니다. 이 경우 **`application.app/Contents`**에서 Apple Archive를 생성하므로, **Archive Utility**로 압축을 풀 때 **`application.app`**에 quarantine 속성이 설정되지 않습니다.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

자세한 내용은 [**원본 보고서**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)를 확인하세요.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**을 사용하면 누구도 파일의 속성을 쓰지 못하도록 할 수 있습니다:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

`com.apple.acl.text`/AppleDouble 메커니즘 및 사이드카 완전 재현은 [AppleDouble ACL quarantine bypass reproduction](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md)을 참조하세요. Gatekeeper 애플리케이션 ZIP 변형은 다음 순서를 사용합니다:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

자세한 내용은 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.<sup>[[9]](#references)</sup>

이 취약점은 AppleArchives를 사용해서도 악용할 수 있습니다:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

일부 macOS 내부 문제로 인해 **Google Chrome이 다운로드한 파일에 quarantine attribute를 설정하지 않는다는 사실이 발견되었습니다**.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble은 파일의 속성을 이름이 `._`로 시작하는 별도의 파일에 저장합니다. 이는 **macOS 기기 간에** 파일 속성을 복사하는 데 도움이 됩니다. 그러나 AppleDouble 파일의 압축을 해제한 후, `._`로 시작하는 파일에는 **quarantine attribute가 지정되지 않았습니다**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

quarantine attribute가 설정되지 않는 파일을 만들 수 있었기 때문에 **Gatekeeper를 우회할 수 있었습니다.** AppleDouble 이름 규칙(`._`로 시작)을 사용해 **DMG 파일 애플리케이션을 만들고**, quarantine attribute가 없는 이 숨겨진 파일을 가리키는 **표시되는 파일을 심볼릭 링크로 만드는** 방법이었습니다.\
**DMG 파일을 실행하면** quarantine attribute가 없으므로 **Gatekeeper를 우회합니다.**

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

Apple은 검사를 개선해 macOS Sonoma 14.0에서 LaunchServices 로직 오류를 수정했습니다. 공개 권고문에는 앱이 Gatekeeper를 bypass할 수 있다고만 명시되어 있으므로, CVE 항목만으로 특정 전달 형식이나 익스플로잇 체인을 추론하지 마세요.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

악성 ZIP을 처리하는 `libarchive`에서 비롯된 macOS 14.4(2024년 3월 출시)의 Gatekeeper bypass로 앱이 검사를 회피할 수 있었습니다. Apple이 이 문제를 해결한 14.4 이상으로 업데이트하세요.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

다운로드한 앱에 포함된 **Automator Quick Action workflow**가 Gatekeeper 검사 없이 실행될 수 있었습니다. workflow가 데이터로 취급되고, 일반적인 notarization 확인 절차 외부에서 Automator helper가 실행했기 때문입니다. 따라서 shell script를 실행하는 Quick Action이 포함된 조작된 `.app`(예: `Contents/PlugIns/*.workflow/Contents/document.wflow` 내부)은 앱 실행 즉시 동작할 수 있었습니다. Apple은 추가 동의 대화상자를 추가하고 Ventura **13.7**, Sonoma **14.7**, Sequoia **15**에서 검사 경로를 수정했습니다.<sup>[[3]](#references)</sup>

### 추출 및 복사 경계에서의 quarantine 전파 실패

2024년 연구에서는 테스트한 iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z), 7z Utility (DMG/ZIP/7Z)에서 전파 공백을 확인했습니다. VMware Tools를 사용해 호스트에서 게스트로 복사할 때도 해당 속성이 사라지는 현상이 관찰됐습니다. 이후 여러 공급업체가 수정 사항을 발표했으므로, 이 이름들은 영구적인 취약 소프트웨어 목록이 아니라 **버전별 재테스트**를 위한 단서로 취급하세요. 동일한 신뢰 경계 문제는 기본 Unix workflow에도 적용됩니다. `curl`/`scp`는 quarantine을 추가하지 않으며, 명령줄 `tar`/`unzip`도 전달 아카이브에서 해당 속성을 자동으로 상속하지 않습니다.<sup>[[15]](#references)</sup>

공격 관점의 테스트에서는 브라우저, 메일 클라이언트, 아카이브, 디스크 이미지, cloud-sync, 공유 폴더, VM 복사 전환을 **매번 거친 후** 전달 파일과 최종 앱을 비교하세요. 명시적인 `spctl` 거부로 누락된 xattr이 복구되지는 않습니다. quarantine이 없으면 일반적인 최초 실행 시 Gatekeeper가 검사를 요청하지 않을 수도 있습니다.<sup>[[15]](#references)</sup>

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

- 앱이 포함된 디렉터리를 만듭니다.
- 앱에 uchg를 추가합니다.
- 앱을 tar.gz 파일로 압축합니다.
- tar.gz 파일을 피해자에게 보냅니다.
- 피해자가 tar.gz 파일을 열고 앱을 실행합니다.
- Gatekeeper는 앱을 검사하지 않습니다.<sup>[[12]](#references)</sup>

### Quarantine xattr 방지

".app" 번들에 quarantine xattr가 추가되지 않으면, 실행 시 **Gatekeeper가 트리거되지 않습니다**.

확장 속성을 방지하거나 제거할 수 있는 파일 시스템, 플래그, ACL 및 AppleDouble 기반 프리미티브는 [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks)를 참조하세요.





## References

- [1] [Apple Platform Security: macOS Sonoma 14.4 보안 콘텐츠에 관하여 (CVE-2024-27853 포함)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOS가 이제 앱의 출처를 추적하는 방법](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7 보안 콘텐츠에 관하여 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia에서 Control-클릭 “열기” Gatekeeper 우회 방법 제거](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810의 발견](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, macOS Gatekeeper 우회](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs, Gatekeeper 우회를 허용하는 Safari 취약점 확인](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs, Gatekeeper 우회를 허용하는 macOS Archive Utility 취약점 확인 (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper의 아킬레스건: macOS 취약점 발견](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Gatekeeper 우회 발견 (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitor의 도움을 받아 Gatekeeper 우회 익스플로잇을 찾아 보고하기](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: macOS 보안 및 개인정보 보호 메커니즘 우회 — Gatekeeper에서 System Integrity Protection까지 (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14 보안 콘텐츠에 관하여 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: 공증된 제품 테스트하기](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper 우회 — macOS 보안 메커니즘의 약점 파헤치기](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
