# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- **User Keychain** (`~/Library/Keychains/login.keychain-db`)은 애플리케이션 비밀번호, 인터넷 비밀번호, 사용자가 생성한 인증서, 네트워크 비밀번호, 사용자가 생성한 public/private key와 같은 **사용자별 자격 증명**을 저장하는 데 사용됩니다.
- **System Keychain** (`/Library/Keychains/System.keychain`)은 WiFi 비밀번호, 시스템 root 인증서, 시스템 private key, 시스템 애플리케이션 비밀번호와 같은 **시스템 전체 자격 증명**을 저장합니다.<sup>[[1]](#references)</sup>
- `/System/Library/Keychains/*`에서 인증서와 같은 다른 구성 요소를 찾을 수도 있습니다.
- **iOS**에는 `/private/var/Keychains/`에 위치한 하나의 **Keychain**만 있습니다. 이 폴더에는 `TrustStore`, 인증 기관(`caissuercache`) 및 OSCP 항목(`ocspache`)을 위한 데이터베이스도 포함되어 있습니다.
- 앱은 애플리케이션 식별자를 기준으로 Keychain 내 자신의 private 영역으로만 제한됩니다.

### Password Keychain Access

이 파일들은 자체적인 보호 기능이 없어 **다운로드**할 수 있지만, 암호화되어 있으며 **사용자의 평문 비밀번호가 있어야 복호화할 수 있습니다**. [**Chainbreaker**](https://github.com/n0fate/chainbreaker)와 같은 도구를 복호화에 사용할 수 있습니다.<sup>[[1]](#references)</sup>

## Keychain Entries Protections

### ACLs

Keychain의 각 항목은 해당 항목에서 다양한 작업을 수행할 수 있는 주체를 결정하는 **Access Control Lists (ACLs)**의 적용을 받습니다.<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: 보유자가 secret의 평문을 가져올 수 있도록 허용합니다.
- **ACLAuhtorizationExportWrapped**: 보유자가 제공된 다른 비밀번호로 암호화된 secret의 평문을 가져올 수 있도록 허용합니다.
- **ACLAuhtorizationAny**: 보유자가 모든 작업을 수행할 수 있도록 허용합니다.

ACL에는 prompt 없이 이러한 작업을 수행할 수 있는 **trusted applications 목록**도 함께 포함됩니다. 다음과 같은 형태일 수 있습니다.<sup>[[1]](#references)</sup>

- **N`il`** (authorization이 필요하지 않으며, **모두가 trusted**)
- **빈** 목록 (**아무도 trusted가 아님**)
- 특정 **애플리케이션**의 **목록**

또한 해당 항목에는 **`ACLAuthorizationPartitionID`** key가 포함될 수 있으며, 이는 **teamid, apple** 및 **cdhash**를 식별하는 데 사용됩니다.<sup>[[1]](#references)</sup>

- **teamid**가 지정된 경우, prompt 없이 **entry** 값에 **access**하려면 사용되는 애플리케이션이 **동일한 teamid**를 가져야 합니다.
- **apple**이 지정된 경우, 앱은 **Apple**에 의해 **signed**되어야 합니다.
- **cdhash**가 지정된 경우, **app**은 지정된 **cdhash**를 가져야 합니다.

### Creating a Keychain Entry

**`Keychain Access.app`**을 사용하여 **새** **entry**를 생성하면 다음 규칙이 적용됩니다.<sup>[[1]](#references)</sup>

- 모든 앱이 encrypt할 수 있습니다.
- **어떤 앱도** 사용자의 prompt 없이 export/decrypt할 수 없습니다.
- 모든 앱이 integrity check를 확인할 수 있습니다.
- 어떤 앱도 ACL을 변경할 수 없습니다.
- **partitionID**는 **`apple`**로 설정됩니다.

**애플리케이션이 Keychain에 entry를 생성**하면 규칙이 약간 다릅니다.<sup>[[1]](#references)</sup>

- 모든 앱이 encrypt할 수 있습니다.
- **생성한 애플리케이션**(또는 명시적으로 추가된 다른 앱)만 사용자의 prompt 없이 export/decrypt할 수 있습니다.
- 모든 앱이 integrity check를 확인할 수 있습니다.
- 어떤 앱도 ACL을 변경할 수 없습니다.
- **partitionID**는 **`teamid:[teamID here]`**로 설정됩니다.

## Accessing the Keychain

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
> **prompt를 생성하지 않는** secret의 **keychain enumeration 및 dumping**은 [**LockSmith**](https://github.com/its-a-feature/LockSmith) tool로 수행할 수 있습니다.
>
> 다른 API endpoint는 [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code에서 확인할 수 있습니다.

**Security Framework**를 사용하여 각 keychain entry에 대한 **info**를 나열하고 가져오거나, Apple의 open source cli tool인 [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.**를 확인할 수도 있습니다. 일부 API 예시:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`**은 각 entry에 대한 info를 제공하며, 사용할 때 설정할 수 있는 일부 attributes가 있습니다:
- **`kSecReturnData`**: true인 경우 data를 decrypt하려고 시도합니다 (잠재적인 pop-up을 방지하려면 false로 설정)
- **`kSecReturnRef`**: keychain item에 대한 reference도 가져옵니다 (나중에 pop-up 없이 decrypt할 수 있음을 확인한 경우 true로 설정)
- **`kSecReturnAttributes`**: entry에 대한 metadata를 가져옵니다
- **`kSecMatchLimit`**: 반환할 결과의 수
- **`kSecClass`**: keychain entry의 종류

각 entry의 **ACL** 가져오기:<sup>[[1]](#references)</sup>

- API **`SecAccessCopyACLList`**를 사용하면 **keychain item의 ACL**을 가져올 수 있으며, ACL 목록(`ACLAuhtorizationExportClear` 및 앞서 언급한 기타 항목과 같은)을 반환합니다. 각 목록에는 다음이 포함됩니다:
- Description
- **Trusted Application List**. 다음과 같을 수 있습니다:
- An app: /Applications/Slack.app
- A binary: /usr/libexec/airportd
- A group: group://AirPort

Data export:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`**는 plaintext를 가져옵니다
- API **`SecItemExport`**는 keys와 certificates를 export하지만, content를 encrypted 상태로 export하려면 password를 설정해야 할 수 있습니다

그리고 다음은 **prompt 없이 secret을 export**할 수 있기 위한 **requirements**입니다:<sup>[[1]](#references)</sup>

- **1개 이상의 trusted** app이 나열된 경우:
- 적절한 **authorizations**가 필요합니다 (**`Nil`**이거나, secret info에 접근하기 위한 authorization의 허용된 app 목록에 **포함**되어 있어야 함)
- code signature가 **PartitionID**와 일치해야 합니다
- code signature가 **trusted app** 중 하나의 것과 일치해야 합니다 (또는 올바른 KeychainAccessGroup의 member여야 함)
- **모든 application이 trusted**인 경우:
- 적절한 **authorizations**가 필요합니다
- code signature가 **PartitionID**와 일치해야 합니다
- **PartitionID가 없다면**, 이는 필요하지 않습니다

> [!CAUTION]
> 따라서 **1개의 application이 나열되어 있다면**, 해당 **application에 code를 inject**해야 합니다.
>
> **partitionID**에 **apple**이 표시되어 있다면, **`osascript`**로 접근할 수 있습니다. 따라서 partitionID에 apple이 포함된 상태로 모든 application을 trust하는 모든 항목에 접근할 수 있습니다. **`Python`**도 사용할 수 있습니다.

### 두 가지 추가 attributes

- **Invisible**: entry를 **UI** Keychain app에서 **숨기기 위한** boolean flag입니다<sup>[[1]](#references)</sup>
- **General**: **metadata**를 저장하기 위한 것으로 (따라서 **ENCRYPTED되지 않음**)<sup>[[1]](#references)</sup>
- Microsoft는 sensitive endpoint에 접근하기 위한 모든 refresh token을 plaintext로 저장하고 있었습니다.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
