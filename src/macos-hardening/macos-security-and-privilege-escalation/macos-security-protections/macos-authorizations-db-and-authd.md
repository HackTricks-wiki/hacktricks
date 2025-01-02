# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorization DB**

`/var/db/auth.db`에 위치한 데이터베이스는 민감한 작업을 수행하기 위한 권한을 저장하는 데 사용됩니다. 이러한 작업은 **사용자 공간**에서 완전히 수행되며, 일반적으로 **XPC 서비스**에서 사용되어 **호출 클라이언트가 특정 작업을 수행할 수 있는 권한이 있는지** 이 데이터베이스를 확인합니다.

이 데이터베이스는 처음에 `/System/Library/Security/authorization.plist`의 내용으로 생성됩니다. 이후 일부 서비스가 이 데이터베이스에 다른 권한을 추가하거나 수정할 수 있습니다.

규칙은 데이터베이스 내의 `rules` 테이블에 저장되며 다음과 같은 열을 포함합니다:

- **id**: 각 규칙에 대한 고유 식별자로, 자동으로 증가하며 기본 키 역할을 합니다.
- **name**: 권한 시스템 내에서 규칙을 식별하고 참조하는 데 사용되는 고유한 규칙 이름입니다.
- **type**: 규칙의 유형을 지정하며, 권한 논리를 정의하기 위해 1 또는 2의 값으로 제한됩니다.
- **class**: 규칙을 특정 클래스에 분류하며, 양의 정수여야 합니다.
- "allow"는 허용을, "deny"는 거부를, "user"는 그룹 속성이 접근을 허용하는 그룹을 나타내는 경우, "rule"은 충족해야 할 규칙을 배열로 나타내며, "evaluate-mechanisms"는 `mechanisms` 배열을 따르며, 이는 내장형이거나 `/System/Library/CoreServices/SecurityAgentPlugins/` 또는 /Library/Security//SecurityAgentPlugins 내의 번들 이름입니다.
- **group**: 그룹 기반 권한 부여를 위한 규칙과 관련된 사용자 그룹을 나타냅니다.
- **kofn**: "k-of-n" 매개변수를 나타내며, 총 수 중에서 얼마나 많은 하위 규칙이 충족되어야 하는지를 결정합니다.
- **timeout**: 규칙에 의해 부여된 권한이 만료되기 전의 지속 시간을 초 단위로 정의합니다.
- **flags**: 규칙의 동작 및 특성을 수정하는 다양한 플래그를 포함합니다.
- **tries**: 보안을 강화하기 위해 허용된 권한 시도 횟수를 제한합니다.
- **version**: 버전 관리를 위한 규칙의 버전을 추적합니다.
- **created**: 감사 목적으로 규칙이 생성된 타임스탬프를 기록합니다.
- **modified**: 규칙에 대한 마지막 수정의 타임스탬프를 저장합니다.
- **hash**: 규칙의 무결성을 보장하고 변조를 감지하기 위한 해시 값을 보유합니다.
- **identifier**: 규칙에 대한 외부 참조를 위한 고유 문자열 식별자(예: UUID)를 제공합니다.
- **requirement**: 규칙의 특정 권한 요구 사항 및 메커니즘을 정의하는 직렬화된 데이터를 포함합니다.
- **comment**: 문서화 및 명확성을 위해 규칙에 대한 사람이 읽을 수 있는 설명 또는 주석을 제공합니다.

### Example
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
또한 [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)에서 `authenticate-admin-nonshared`의 의미를 확인할 수 있습니다:
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

클라이언트가 민감한 작업을 수행하도록 승인 요청을 받을 데몬입니다. `XPCServices/` 폴더 내에 정의된 XPC 서비스로 작동하며, 로그는 `/var/log/authd.log`에 기록됩니다.

또한 보안 도구를 사용하여 많은 `Security.framework` API를 테스트할 수 있습니다. 예를 들어 `AuthorizationExecuteWithPrivileges`를 실행하면: `security execute-with-privileges /bin/ls`

이는 `/usr/libexec/security_authtrampoline /bin/ls`를 루트로 포크하고 실행하며, ls를 루트로 실행하기 위한 권한을 요청하는 프롬프트가 표시됩니다:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
