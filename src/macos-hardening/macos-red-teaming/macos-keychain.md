# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **사용자 키체인** (`~/Library/Keychains/login.keychain-db`): 애플리케이션 비밀번호, 인터넷 비밀번호, 사용자 생성 인증서, 네트워크 비밀번호 및 사용자 생성 공개/개인 키와 같은 **사용자 특정 자격 증명**을 저장하는 데 사용됩니다.
- **시스템 키체인** (`/Library/Keychains/System.keychain`): WiFi 비밀번호, 시스템 루트 인증서, 시스템 개인 키 및 시스템 애플리케이션 비밀번호와 같은 **시스템 전체 자격 증명**을 저장합니다.
- `/System/Library/Keychains/*`에서 인증서와 같은 다른 구성 요소를 찾을 수 있습니다.
- **iOS**에는 `/private/var/Keychains/`에 위치한 **키체인**이 하나만 있습니다. 이 폴더에는 `TrustStore`, 인증서 기관(`caissuercache`) 및 OSCP 항목(`ocspache`)에 대한 데이터베이스도 포함되어 있습니다.
- 앱은 애플리케이션 식별자에 따라 키체인에서 자신의 개인 영역으로만 제한됩니다.

### 비밀번호 키체인 접근

이 파일들은 본래 보호가 없고 **다운로드**할 수 있지만, 암호화되어 있으며 **사용자의 평문 비밀번호로 복호화**해야 합니다. [**Chainbreaker**](https://github.com/n0fate/chainbreaker)와 같은 도구를 사용하여 복호화할 수 있습니다.

## 키체인 항목 보호

### ACLs

키체인의 각 항목은 **액세스 제어 목록(ACLs)**에 의해 관리되며, 이는 키체인 항목에 대해 다양한 작업을 수행할 수 있는 사람을 규정합니다. 여기에는 다음이 포함됩니다:

- **ACLAuhtorizationExportClear**: 보유자가 비밀의 평문을 가져올 수 있도록 허용합니다.
- **ACLAuhtorizationExportWrapped**: 보유자가 다른 제공된 비밀번호로 암호화된 평문을 가져올 수 있도록 허용합니다.
- **ACLAuhtorizationAny**: 보유자가 모든 작업을 수행할 수 있도록 허용합니다.

ACL은 이러한 작업을 수행할 수 있는 **신뢰할 수 있는 애플리케이션 목록**과 함께 제공됩니다. 이는 다음과 같을 수 있습니다:

- **N`il`** (인증 필요 없음, **모두 신뢰됨**)
- **빈** 목록 (**아무도** 신뢰되지 않음)
- 특정 **애플리케이션**의 **목록**.

또한 항목에는 **`ACLAuthorizationPartitionID`**라는 키가 포함될 수 있으며, 이는 **teamid, apple,** 및 **cdhash**를 식별하는 데 사용됩니다.

- **teamid**가 지정된 경우, **프롬프트 없이** 항목 값을 **액세스**하려면 사용된 애플리케이션이 **같은 teamid**를 가져야 합니다.
- **apple**이 지정된 경우, 앱은 **Apple**에 의해 **서명**되어야 합니다.
- **cdhash**가 표시된 경우, **앱**은 특정 **cdhash**를 가져야 합니다.

### 키체인 항목 생성

**`Keychain Access.app`**를 사용하여 **새로운** **항목**이 생성될 때 다음 규칙이 적용됩니다:

- 모든 앱이 암호화할 수 있습니다.
- **어떤 앱도** 내보내기/복호화할 수 없습니다(사용자에게 프롬프트 없이).
- 모든 앱이 무결성 검사를 볼 수 있습니다.
- 어떤 앱도 ACL을 변경할 수 없습니다.
- **partitionID**는 **`apple`**로 설정됩니다.

**애플리케이션이 키체인에 항목을 생성할 때** 규칙은 약간 다릅니다:

- 모든 앱이 암호화할 수 있습니다.
- **생성하는 애플리케이션**(또는 명시적으로 추가된 다른 앱)만 내보내기/복호화할 수 있습니다(사용자에게 프롬프트 없이).
- 모든 앱이 무결성 검사를 볼 수 있습니다.
- 어떤 앱도 ACL을 변경할 수 없습니다.
- **partitionID**는 **`teamid:[teamID here]`**로 설정됩니다.

## 키체인 접근

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **키체인 열거 및 비밀 덤프**는 **프롬프트를 생성하지 않는** 비밀에 대해 도구 [**LockSmith**](https://github.com/its-a-feature/LockSmith)를 사용하여 수행할 수 있습니다.
>
> 다른 API 엔드포인트는 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) 소스 코드에서 찾을 수 있습니다.

**Security Framework**를 사용하여 각 키체인 항목에 대한 **정보**를 나열하고 가져오거나, Apple의 오픈 소스 CLI 도구 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.**를 확인할 수도 있습니다. 몇 가지 API 예시:

- API **`SecItemCopyMatching`**은 각 항목에 대한 정보를 제공하며, 사용할 때 설정할 수 있는 몇 가지 속성이 있습니다:
- **`kSecReturnData`**: true인 경우 데이터를 복호화하려고 시도합니다(팝업을 피하려면 false로 설정).
- **`kSecReturnRef`**: 키체인 항목에 대한 참조도 가져옵니다(나중에 팝업 없이 복호화할 수 있는 경우 true로 설정).
- **`kSecReturnAttributes`**: 항목에 대한 메타데이터를 가져옵니다.
- **`kSecMatchLimit`**: 반환할 결과 수.
- **`kSecClass`**: 키체인 항목의 종류.

각 항목의 **ACL**을 가져옵니다:

- API **`SecAccessCopyACLList`**를 사용하여 **키체인 항목의 ACL**을 가져올 수 있으며, 각 목록에는 다음과 같은 ACL 목록이 반환됩니다(예: `ACLAuhtorizationExportClear` 및 이전에 언급된 다른 항목들):
- 설명
- **신뢰할 수 있는 애플리케이션 목록**. 이는 다음과 같을 수 있습니다:
- 애플리케이션: /Applications/Slack.app
- 바이너리: /usr/libexec/airportd
- 그룹: group://AirPort

데이터를 내보냅니다:

- API **`SecKeychainItemCopyContent`**는 평문을 가져옵니다.
- API **`SecItemExport`**는 키와 인증서를 내보내지만, 암호화된 콘텐츠를 내보내려면 암호를 설정해야 할 수 있습니다.

그리고 **프롬프트 없이 비밀을 내보내기 위한 요구 사항**은 다음과 같습니다:

- **1개 이상의 신뢰할 수 있는** 애플리케이션이 나열된 경우:
- 적절한 **권한**이 필요합니다 (**`Nil`**, 또는 비밀 정보에 접근하기 위한 권한의 허용 목록에 **포함**되어야 함).
- 코드 서명이 **PartitionID**와 일치해야 합니다.
- 코드 서명이 하나의 **신뢰할 수 있는 애플리케이션**과 일치해야 합니다(또는 올바른 KeychainAccessGroup의 구성원이어야 함).
- **모든 애플리케이션이 신뢰할 수 있는** 경우:
- 적절한 **권한**이 필요합니다.
- 코드 서명이 **PartitionID**와 일치해야 합니다.
- **PartitionID**가 없는 경우, 이는 필요하지 않습니다.

> [!CAUTION]
> 따라서 **1개의 애플리케이션이 나열된 경우**, 해당 애플리케이션에 **코드를 주입해야** 합니다.
>
> **apple**이 **partitionID**에 표시된 경우, **`osascript`**를 사용하여 접근할 수 있으며, partitionID에 apple이 포함된 모든 애플리케이션을 신뢰할 수 있습니다. **`Python`**도 이를 위해 사용할 수 있습니다.

### 두 가지 추가 속성

- **Invisible**: UI 키체인 앱에서 항목을 **숨기기** 위한 부울 플래그입니다.
- **General**: **메타데이터**를 저장하기 위한 것입니다(따라서 **암호화되지 않음**).
- Microsoft는 민감한 엔드포인트에 접근하기 위해 모든 새로 고침 토큰을 평문으로 저장하고 있었습니다.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
