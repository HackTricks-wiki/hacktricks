# macOS 키체인

{{#include ../../banners/hacktricks-training.md}}

## 주요 키체인

- **사용자 키체인** (`~/Library/Keychains/login.keychain-db`)은 애플리케이션 암호, 인터넷 암호, 사용자가 생성한 인증서, 네트워크 암호, 사용자가 생성한 공개 키/개인 키 등 **사용자별 자격 증명**을 저장하는 데 사용됩니다.
- **시스템 키체인** (`/Library/Keychains/System.keychain`)은 WiFi 암호, 시스템 루트 인증서, 시스템 개인 키, 시스템 애플리케이션 암호 등 **시스템 전체에서 사용하는 자격 증명**을 저장합니다.<sup>[[1]](#references)</sup>
  - `/System/Library/Keychains/*`에서 인증서와 같은 다른 구성 요소를 찾을 수도 있습니다.
- 사용자별 **데이터 보호 키체인**은 Keychain Access에서 **Local Items** 또는 **iCloud**로 표시됩니다. `login.keychain-db`와는 별개이며 로컬 전용 항목과 동기화 가능한 항목을 모두 포함합니다. `security`는 주로 파일 기반 키체인용 도구이므로 `dump-keychain` 결과가 짧다고 해서 이곳에 자격 증명이 없다고 단정할 수는 없습니다.<sup>[[5]](#references)</sup>
- **iOS**에는 `/private/var/Keychains/`에 있는 **키체인** 하나만 있습니다. 이 폴더에는 `TrustStore`, 인증 기관(`caissuercache`), OSCP 항목(`ocspache`)의 데이터베이스도 포함되어 있습니다.
  - 앱은 애플리케이션 식별자를 기준으로 키체인의 비공개 영역에만 접근할 수 있습니다.

### 암호 키체인 접근

복사한 **파일 기반** 키체인은 평문이 아닙니다. 보호된 항목을 오프라인에서 복호화하려면 키체인 암호 또는 이에 상응하는 키 자료가 필요합니다. [**Chainbreaker**](https://github.com/n0fate/chainbreaker)는 이 형식을 대상으로 합니다.<sup>[[1]](#references)</sup> 이는 잠금 해제된 사용자 세션에서 실시간으로 읽는 것과 다릅니다. 이 경우 항목 접근 제어에 따라 로그인 암호를 다시 입력하지 않아도 읽을 수 있거나, 입력 요청이 표시될 수 있습니다. 데이터 보호 키체인은 보호 및 접근 그룹 모델이 다릅니다.<sup>[[5]](#references)</sup>

## 키체인 항목 보호

### 파일 기반 키체인 ACL

아래의 `SecAccess` ACL 및 partition-list 규칙은 **파일 기반** 키체인에 해당합니다. 데이터 보호 키체인 항목은 코드 서명 접근 그룹과 선택적 `SecAccessControl` 조건을 사용하므로, 파일 기반 ACL 덤프를 근거로 해당 항목의 접근 가능성을 추론하지 마세요.<sup>[[5]](#references)</sup>

파일 기반 키체인의 각 항목은 **접근 제어 목록(ACL)**에 따라 관리됩니다. ACL은 키체인 항목에 대해 수행할 수 있는 작업을 지정하며, 여기에는 다음이 포함됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: 보유자가 비밀의 평문을 가져올 수 있습니다.
- **`kSecACLAuthorizationExportWrapped`**: 보유자가 제공된 다른 암호로 암호화된 비밀의 평문을 가져올 수 있습니다.
- **`kSecACLAuthorizationAny`**: 보유자가 모든 작업을 수행할 수 있습니다.

ACL에는 메시지 표시 없이 이러한 작업을 수행할 수 있는 **신뢰하는 애플리케이션 목록**도 함께 설정됩니다. 목록은 다음 중 하나일 수 있습니다.<sup>[[1]](#references)</sup>

- **N`il`** (권한 확인 불필요, **모두 신뢰됨**)
- **빈** 목록 (**아무도** 신뢰되지 않음)
- 특정 **애플리케이션**의 **목록**

또한 항목에 **`kSecACLAuthorizationPartitionID`** 키가 포함될 수 있습니다. 이 키는 **teamid, apple,** 및 **cdhash**를 식별하는 데 사용됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

- **teamid**가 지정된 경우, 애플리케이션은 메시지 표시 없이 항목 값에 **접근하려면** **동일한 teamid**를 가져야 합니다.
- **apple**이 지정된 경우, 앱은 **Apple**에서 **서명**되어야 합니다.
- **cdhash**가 지정된 경우, **앱**은 지정된 **cdhash**를 가져야 합니다.

### 파일 기반 키체인 항목 만들기

**`Keychain Access.app`**을 사용해 **새** **항목**을 만들면 다음 규칙이 적용됩니다.<sup>[[1]](#references)</sup>

- 모든 앱이 암호화할 수 있습니다.
- **어떤 앱도** 사용자에게 메시지를 표시하지 않고 내보내기/복호화할 수 없습니다.
- 모든 앱이 무결성 검사를 확인할 수 있습니다.
- 어떤 앱도 ACL을 변경할 수 없습니다.
- **partitionID**는 **`apple`**로 설정됩니다.

**애플리케이션이 키체인에 항목을 만들면** 규칙이 조금 달라집니다.<sup>[[1]](#references)</sup>

- 모든 앱이 암호화할 수 있습니다.
- 생성한 **애플리케이션**(또는 명시적으로 추가된 다른 앱)만 사용자에게 메시지를 표시하지 않고 내보내기/복호화할 수 있습니다.
- 모든 앱이 무결성 검사를 확인할 수 있습니다.
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S`는 항목의 partition list를 설정하고, `-k`는 해당 변경에 필요한 현재 Keychain 비밀번호를 제공합니다. 비밀번호를 받는 플래그는 deprecated되었습니다.<sup>[[4]](#references)</sup> 업데이트가 성공했다고 해서 이후 읽기 시 경고가 표시되지 않는다는 뜻은 아닙니다. 관찰된 한 비활성 prototype은 `Security.framework`를 통해 항목을 조회할 때도 확인 prompt를 띄웠습니다. 일치하는 partition ID는 위에서 설명한 ACL 및 trusted-application 검사 중 한 요소일 뿐이므로 실제 읽기 경로를 확인하세요.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> prompt를 **띄우지 않고** secret을 **열거하고 덤프**하려면 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 도구를 사용할 수 있습니다.
>
> 다른 API endpoint는 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) 소스 코드에서 확인할 수 있습니다.

**Security Framework**를 사용해 각 Keychain 항목을 나열하고 **정보**를 가져오거나, Apple의 open source CLI 도구인 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.**를 확인할 수도 있습니다. API 사용 예:<sup>[[1]](#references)</sup>

- **`SecItemCopyMatching`** API는 각 항목의 정보를 제공하며, 사용할 때 다음과 같은 attribute를 설정할 수 있습니다.
  - **`kSecReturnData`**: true이면 데이터를 복호화하려고 합니다(잠재적인 pop-up을 피하려면 false로 설정).
  - **`kSecReturnRef`**: key, certificate 또는 identity의 object reference를 가져옵니다. password 항목에는 이 object 표현이 없습니다. 나중에 대상을 지정해 조회할 password를 식별하려면 `kSecReturnPersistentRef`를 사용하세요.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: 항목의 metadata를 가져옵니다.
  - **`kSecMatchLimit`**: 반환할 결과 수
  - **`kSecClass`**: Keychain 항목의 종류

각 항목의 **ACL** 가져오기:<sup>[[1]](#references)</sup>

- **`SecAccessCopyACLList`** API를 사용하면 **Keychain 항목의 ACL**을 가져올 수 있습니다. 이 API는 ACL 목록(예: `kSecACLAuthorizationExportClear` 및 앞서 언급한 다른 항목)을 반환하며, 각 항목에는 다음이 포함됩니다.<sup>[[1]](#references)[[2]](#references)</sup>
  - Description
  - **Trusted Application List**. 다음과 같은 항목이 포함될 수 있습니다.
    - 앱: /Applications/Slack.app
    - 바이너리: /usr/libexec/airportd
    - 그룹: group://AirPort

데이터 내보내기:<sup>[[1]](#references)</sup>

- **`SecKeychainItemCopyContent`** API는 plaintext를 가져옵니다.
- **`SecItemExport`** API는 key와 certificate를 내보냅니다. 콘텐츠를 암호화해 내보내려면 password를 설정해야 할 수도 있습니다.

다음은 prompt 없이 secret을 **내보내기** 위한 **요건**입니다.<sup>[[1]](#references)</sup>

- **trusted 앱이 1개 이상** 나열된 경우:
  - 적절한 **authorizations**가 필요합니다(**`Nil`**이거나, secret 정보에 접근하도록 authorization에서 허용된 앱 목록에 **포함**되어야 합니다).
  - code signature가 **PartitionID**와 일치해야 합니다.
  - code signature가 **trusted 앱** 중 하나와 일치해야 합니다(또는 올바른 KeychainAccessGroup의 구성원이어야 합니다).
- **모든 애플리케이션이 trusted**인 경우:
  - 적절한 **authorizations**가 필요합니다.
  - code signature가 **PartitionID**와 일치해야 합니다.
    - **PartitionID가 없으면** 이 요건은 필요하지 않습니다.

> [!CAUTION]
> 따라서 **애플리케이션이 1개 나열되어 있다면**, 해당 애플리케이션에 **코드를 inject해야 합니다**.
>
> **partitionID**에 **apple**이 지정되어 있으면, partitionID에 apple이 포함된 모든 애플리케이션을 trust하는 항목에 **`osascript`**로 접근할 수 있습니다. **`Python`**도 사용할 수 있습니다.

### 추가 attribute 두 가지

- **Invisible**: Keychain 앱의 **UI**에서 항목을 **숨기는** boolean flag입니다.<sup>[[1]](#references)</sup>
- **General**: **metadata**를 저장하는 용도입니다(따라서 **암호화되지 않습니다**).<sup>[[1]](#references)</sup>
  - Microsoft는 민감한 endpoint에 접근하는 데 필요한 refresh token을 모두 plaintext로 저장하고 있었습니다.<sup>[[1]](#references)</sup>

### Data protection keychain: 열거한 다음 단일 항목 조회

`kSecUseDataProtectionKeychain: true`를 지정해 **대상 사용자의 로그인 context에서 실행되는 서명된 앱**으로 `SecItemCopyMatching`을 실행하세요. `security dump-keychain`이나 기본 SecItem query가 이 store를 검색한다고 가정하지 마세요. 호출자는 자신에게 허용된 access group만 볼 수 있습니다.<sup>[[5]](#references)</sup>

테스트 코드가 다른 process 안에서 실행되는 경우, 해당 코드의 data protection keychain 접근 권한은 host executable의 entitlements를 따릅니다. `codesign -d --entitlements - /path/to/Target.app`으로 실제 서명된 entitlements를 확인하고, 관련 검사는 [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md)를 참조하세요.<sup>[[7]](#references)</sup>

먼저 하나의 항목 class에 대해 **attributes만** 요청하세요. `kSecAttrSynchronizableAny`는 로컬 항목과 iCloud 동기화 항목을 모두 포함하며, 이를 생략하면 동기화 항목은 제외됩니다.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip`은 광범위한 열거 중 인증 UI가 표시되지 않도록 하는 대신, 보호된 항목은 건너뜁니다.<sup>[[9]](#references)</sup> 필요한 경우 `kSecClassInternetPassword`로 반복하세요.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

허용된 secret read를 위해 선택한 항목에 맞는 새롭고 범위가 좁은 query(예: class, service, account)를 만들고, `kSecReturnData: true`와 `kSecMatchLimit: kSecMatchLimitOne`을 설정한 뒤, 항목별 인증이나 오류가 발생할 수 있음을 예상하세요. Password 항목에는 `kSecReturnData`와 `kSecMatchLimitAll`을 함께 사용하지 마세요.<sup>[[10]](#references)</sup> `errSecItemNotFound` 결과는 자격 증명이 없어서가 아니라 잘못된 store, sync filter 또는 누락된 access-group entitlement 때문일 수도 있습니다.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "macOS Keychain 잠금 따기" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - MacSync macOS stealer의 새 버전, 암호화폐 애호가와 개발자를 표적으로 삼다](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page 미러](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Mac keychain API와 구현에 관하여](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: 기본 사항](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: 주의 사항 및 모범 사례](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Face ID 또는 Touch ID로 Keychain 항목에 접근하기](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
