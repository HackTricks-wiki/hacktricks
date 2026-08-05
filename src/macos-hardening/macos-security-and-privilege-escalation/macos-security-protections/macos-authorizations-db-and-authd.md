# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorizations DB**

`/var/db/auth.db`에 위치한 데이터베이스는 민감한 작업을 수행할 수 있는 권한을 저장하는 데 사용되는 데이터베이스입니다. 이러한 작업은 전적으로 **user space**에서 수행되며, 일반적으로 이 데이터베이스를 확인하여 **호출한 client가** 특정 작업을 수행할 권한이 있는지 확인해야 하는 **XPC services**에서 사용됩니다.

처음에 이 데이터베이스는 `/System/Library/Security/authorization.plist`의 내용으로 생성됩니다. 그런 다음 일부 서비스가 다른 권한을 추가하기 위해 이 데이터베이스를 추가하거나 수정할 수 있습니다.

규칙은 데이터베이스 내부의 `rules` 테이블에 저장되며 다음 열을 포함합니다.

- **id**: 각 규칙의 고유 식별자로, 자동으로 증가하며 primary key 역할을 합니다.
- **name**: authorization system 내에서 규칙을 식별하고 참조하는 데 사용되는 고유한 규칙 이름입니다.
- **type**: 규칙의 유형을 지정하며, authorization logic을 정의하기 위해 1 또는 2 값으로 제한됩니다.
- **class**: 규칙을 특정 class로 분류하며, 양의 정수여야 합니다.
- "allow"는 허용, "deny"는 거부, "user"는 group property가 access를 허용하는 group을 나타내는 경우, "rule"은 충족해야 하는 rule을 배열로 나타내는 경우, "evaluate-mechanisms"는 `mechanisms` 배열을 따르며, 이 배열의 값은 `/System/Library/CoreServices/SecurityAgentPlugins/` 또는 `/Library/Security//SecurityAgentPlugins` 내부의 builtin 또는 bundle 이름입니다.
- **group**: group 기반 authorization에 사용되는 사용자 group을 나타냅니다.
- **kofn**: 전체 subrule 중 충족해야 하는 subrule의 수를 결정하는 "k-of-n" parameter를 나타냅니다.
- **timeout**: rule에 의해 부여된 authorization이 만료되기 전까지의 시간을 초 단위로 정의합니다.
- **flags**: rule의 동작과 특성을 변경하는 다양한 flag를 포함합니다.
- **tries**: 보안을 강화하기 위해 허용되는 authorization 시도 횟수를 제한합니다.
- **version**: version control 및 업데이트를 위해 rule의 version을 추적합니다.
- **created**: auditing 목적으로 rule이 생성된 timestamp를 기록합니다.
- **modified**: rule이 마지막으로 수정된 timestamp를 저장합니다.
- **hash**: rule의 무결성을 보장하고 tampering을 감지하기 위한 hash 값을 저장합니다.
- **identifier**: rule을 외부에서 참조하기 위한 UUID와 같은 고유한 문자열 identifier를 제공합니다.
- **requirement**: rule의 구체적인 authorization requirements 및 mechanisms를 정의하는 serialized data를 포함합니다.
- **comment**: 문서화와 명확성을 위해 사람이 읽을 수 있는 rule 설명 또는 comment를 제공합니다.

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
또한 [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)에서 `authenticate-admin-nonshared`의 의미를 확인할 수 있습니다:<sup>[[1]](#references)</sup>
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

민감한 작업을 수행하도록 client를 authorize하기 위한 요청을 수신하는 daemon입니다. `XPCServices/` 폴더 내부에 정의된 XPC service로 작동하며 로그를 `/var/log/authd.log`에 기록합니다.

또한 security tool을 사용하면 여러 `Security.framework` API를 테스트할 수 있습니다. 예를 들어 `AuthorizationExecuteWithPrivileges` 실행은 다음과 같습니다: `security execute-with-privileges /bin/ls`

이 명령은 `/usr/libexec/security_authtrampoline /bin/ls`를 root로 fork 및 exec하고, 권한을 요청하는 prompt를 표시하여 ls를 root로 실행합니다:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - macOS Authorization Right 개요](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
