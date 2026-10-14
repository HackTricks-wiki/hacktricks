# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## 주요 Keychain

- **사용자 Keychain** (`~/Library/Keychains/login.keychain-db`)은 애플리케이션 암호, 인터넷 암호, 사용자가 생성한 인증서, 네트워크 암호, 사용자가 생성한 공개/개인 키와 같은 **사용자별 자격 증명**을 저장하는 데 사용됩니다.
- **시스템 Keychain** (`/Library/Keychains/System.keychain`)은 WiFi 암호, 시스템 루트 인증서, 시스템 개인 키, 시스템 애플리케이션 암호와 같은 **시스템 전체 자격 증명**을 저장합니다.<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*`에서 인증서와 같은 다른 구성 요소를 찾을 수 있습니다.
- **iOS**에는 `/private/var/Keychains/`에 있는 **Keychain**이 하나만 존재합니다. 이 폴더에는 `TrustStore`, 인증 기관(`caissuercache`), OSCP 항목(`ocspache`)의 데이터베이스도 들어 있습니다.
  - 앱은 애플리케이션 식별자를 기준으로 Keychain 내 자신의 비공개 영역에만 접근하도록 제한됩니다.

### 암호를 사용한 Keychain 접근

이 파일들은 기본적인 보호 기능이 없어 **다운로드**할 수 있지만, 암호화되어 있으므로 복호화하려면 **사용자의 평문 암호가 필요합니다**. [**Chainbreaker**](https://github.com/n0fate/chainbreaker)와 같은 도구를 복호화에 사용할 수 있습니다.<sup>[[1]](#references)</sup>

## Keychain 항목 보호

### ACL

Keychain의 각 항목은 **Access Control List(ACL)**의 적용을 받으며, ACL은 Keychain 항목에서 수행할 수 있는 작업을 다음과 같이 지정합니다.<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: 보유자가 비밀의 평문을 가져올 수 있도록 허용합니다.
- **`kSecACLAuthorizationExportWrapped`**: 보유자가 제공된 다른 암호로 암호화된 비밀의 평문을 가져올 수 있도록 허용합니다.
- **`kSecACLAuthorizationAny`**: 보유자가 모든 작업을 수행할 수 있도록 허용합니다.

ACL에는 메시지를 표시하지 않고 작업을 수행할 수 있는 **신뢰된 애플리케이션 목록**도 포함됩니다. 목록은 다음과 같을 수 있습니다.<sup>[[1]](#references)</sup>

- **N`il`** (권한 부여가 필요 없음, **모두 신뢰됨**)
- **빈** 목록 (**아무도** 신뢰되지 않음)
- 특정 **애플리케이션**의 **목록**

항목에는 **teamid, apple,** 및 **cdhash**를 식별하는 데 사용되는 **`kSecACLAuthorizationPartitionID`** 키가 포함될 수도 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

- **teamid**가 지정되면, 애플리케이션은 **메시지 표시 없이 항목 값에 접근**하려면 **동일한 teamid**를 가져야 합니다.
- **apple**이 지정되면, 앱은 **Apple에서 서명**해야 합니다.
- **cdhash**가 지정되면, **앱**은 해당 **cdhash**를 가져야 합니다.

### Keychain 항목 생성

**`Keychain Access.app`**을 사용해 **새 항목**을 만들면 다음 규칙이 적용됩니다.<sup>[[1]](#references)</sup>

- 모든 앱이 암호화할 수 있습니다.
- **어떤 앱도** (사용자에게 메시지를 표시하지 않고) 내보내기/복호화할 수 없습니다.
- 모든 앱이 무결성 검사를 확인할 수 있습니다.
- 어떤 앱도 ACL을 변경할 수 없습니다.
- **partitionID**는 **`apple`**로 설정됩니다.

**애플리케이션이 Keychain에 항목을 생성하는 경우**, 규칙은 약간 다릅니다.<sup>[[1]](#references)</sup>

- 모든 앱이 암호화할 수 있습니다.
- **항목을 생성한 애플리케이션**(또는 명시적으로 추가된 다른 앱)만 (사용자에게 메시지를 표시하지 않고) 내보내기/복호화할 수 있습니다.
- 모든 앱이 무결성 검사를 확인할 수 있습니다.
- 어떤 앱도 ACL을 변경할 수 없습니다.
- **partitionID**는 **`teamid:[teamID here]`**로 설정됩니다.

## Keychain 접근

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S`는 항목의 partition list를 설정하고, `-k`는 해당 변경에 필요한 현재 Keychain 암호를 지정합니다. 암호를 받는 플래그는 deprecated 상태입니다.<sup>[[4]](#references)</sup> 업데이트에 성공했다고 해서 이후 읽기 작업이 프롬프트 없이 진행된다는 뜻은 아닙니다. 비활성화된 프로토타입에서도 `Security.framework`를 통해 항목을 조회할 때 확인 프롬프트가 표시된 사례가 관찰되었습니다. 일치하는 partition ID는 위에서 설명한 ACL 및 trusted-application 검사 중 하나일 뿐이므로 실제 읽기 경로를 확인하세요.<sup>[[3]](#references)</sup>

### API

> [!TIP]
> 프롬프트를 **표시하지 않고** secret을 **열거하고 덤프**하려면 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 도구를 사용할 수 있습니다.
>
> 다른 API endpoint는 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) 소스 코드에서 찾을 수 있습니다.

**Security Framework**를 사용하거나 Apple의 오픈 소스 CLI 도구인 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.**를 사용해 각 Keychain 항목을 나열하고 **정보**를 확인할 수 있습니다. API 예시:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`**은 각 항목의 정보를 반환하며, 사용할 때 설정할 수 있는 속성은 다음과 같습니다.
  - **`kSecReturnData`**: true이면 데이터를 복호화하려고 시도합니다(잠재적인 팝업을 피하려면 false로 설정).
  - **`kSecReturnRef`**: Keychain 항목에 대한 참조도 가져옵니다(나중에 팝업 없이 복호화할 수 있는지 확인할 경우 true로 설정).
  - **`kSecReturnAttributes`**: 항목의 metadata를 가져옵니다.
  - **`kSecMatchLimit`**: 반환할 결과의 수
  - **`kSecClass`**: Keychain 항목의 종류

각 항목의 **ACL**을 가져옵니다.<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`**를 사용하면 **Keychain 항목의 ACL**을 가져올 수 있습니다. 이 API는 ACL 목록(예: `kSecACLAuthorizationExportClear` 및 앞서 언급한 기타 ACL)을 반환하며, 각 항목에는 다음이 포함됩니다.<sup>[[1]](#references)[[2]](#references)</sup>
  - 설명
  - **Trusted Application List**. 다음과 같은 항목이 포함될 수 있습니다.
    - 앱: /Applications/Slack.app
    - 바이너리: /usr/libexec/airportd
    - 그룹: group://AirPort

데이터를 내보냅니다.<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`**는 plaintext를 가져옵니다.
- API **`SecItemExport`**는 키와 인증서를 내보냅니다. 콘텐츠를 암호화된 상태로 내보내려면 암호를 설정해야 할 수 있습니다.

프롬프트 없이 secret을 **내보내려면** 다음 **요건**을 충족해야 합니다.<sup>[[1]](#references)</sup>

- trusted 앱이 **1개 이상** 나열된 경우:
  - 적절한 **authorizations**가 필요합니다(**`Nil`**이거나, secret 정보에 액세스하도록 허용된 앱 목록에 포함되어야 함).
  - 코드 서명이 **PartitionID**와 일치해야 합니다.
  - 코드 서명이 trusted 앱 중 하나의 코드 서명과 일치해야 합니다(또는 올바른 KeychainAccessGroup의 구성원이어야 함).
- **모든 애플리케이션이 trusted**인 경우:
  - 적절한 **authorizations**가 필요합니다.
  - 코드 서명이 **PartitionID**와 일치해야 합니다.
    - **PartitionID**가 없다면 이 조건은 필요하지 않습니다.

> [!CAUTION]
> 따라서 나열된 애플리케이션이 **1개**라면 해당 애플리케이션에 **코드를 주입**해야 합니다.
>
> **partitionID**에 **apple**이 지정되어 있다면 **`osascript`**로 액세스할 수 있습니다. 즉, partitionID에 apple이 포함된 모든 애플리케이션을 trust하는 항목에 액세스할 수 있습니다. **`Python`**도 사용할 수 있습니다.

### 추가 속성 두 가지

- **Invisible**: Keychain 앱의 **UI**에서 항목을 **숨기는** boolean 플래그입니다.<sup>[[1]](#references)</sup>
- **General**: **metadata**를 저장하는 데 사용됩니다(즉, **암호화되지 않습니다**).<sup>[[1]](#references)</sup>
  - Microsoft는 민감한 endpoint에 액세스하기 위한 refresh token을 모두 plaintext로 저장했습니다.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "macOS Keychain 잠금 따기" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - MacSync macOS stealer의 새 버전, 암호화폐 애호가와 개발자를 표적으로 삼다](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page 미러](https://keith.github.io/xcode-man-pages/security.1.html)
