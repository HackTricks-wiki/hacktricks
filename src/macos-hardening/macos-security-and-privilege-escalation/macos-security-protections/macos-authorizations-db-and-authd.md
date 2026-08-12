# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## 권한 부여 데이터베이스

Security framework의 Authorization Services를 사용하면 권한이 있는 helper 및 기타 구성 요소가 이름이 지정된 authorization rights를 평가할 수 있습니다. 최신 macOS 버전에서는 이러한 규칙 중 상당수가 `/var/db/auth.db`에 저장되고 `authd`에 의해 평가됩니다. 이 파일과 해당 SQLite 스키마는 구현 세부 사항이며 릴리스마다 변경될 수 있습니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

시스템 기본값은 역사적으로 `/System/Library/Security/authorization.plist`에서 초기화되었으며, installer 또는 권한이 있는 service가 이름이 지정된 rights를 추가할 수 있습니다. 데이터베이스를 직접 편집하기보다는 지원되는 `security authorizationdb read|write|remove` interface를 사용하는 것이 좋습니다.<sup>[[3]](#references)</sup>

문서화된 build에서 확인된 `rules` table에는 다음 columns가 포함되어 있습니다. 이를 안정적인 public schema가 아닌 forensic map으로 취급하십시오.

- **id**: 각 rule의 고유 identifier이며, 자동으로 증가하고 primary key 역할을 합니다.
- **name**: authorization system 내에서 rule을 식별하고 참조하는 데 사용되는 고유한 name입니다.
- **type**: rule의 type을 지정하며, authorization logic을 정의하기 위해 1 또는 2 값으로 제한됩니다.
- **class**: rule을 특정 class로 분류하며, 양의 정수여야 합니다.
- 일반적인 rule classes에는 `allow`, `deny`, `user`, `rule`, `evaluate-mechanisms`가 있습니다. Mechanisms는 built-in이거나 `/System/Library/CoreServices/SecurityAgentPlugins/` 또는 `/Library/Security/SecurityAgentPlugins/` 아래의 Security Agent plug-in일 수 있습니다.<sup>[[2]](#references)</sup>
- **group**: group-based authorization에 사용되는 rule과 연결된 user group을 나타냅니다.
- **kofn**: 전체 subrule 수 중 충족되어야 하는 subrule 수를 결정하는 "k-of-n" parameter를 나타냅니다.
- **timeout**: rule에 의해 부여된 authorization이 만료되기 전까지의 시간을 초 단위로 정의합니다.
- **flags**: rule의 동작과 특성을 변경하는 다양한 flags를 포함합니다.
- **tries**: 보안을 강화하기 위해 허용되는 authorization 시도 횟수를 제한합니다.
- **version**: version control 및 업데이트를 위해 rule의 version을 추적합니다.
- **created**: auditing 목적으로 rule이 생성된 timestamp를 기록합니다.
- **modified**: rule이 마지막으로 수정된 timestamp를 저장합니다.
- **hash**: rule의 무결성을 보장하고 tampering을 감지하기 위한 hash 값을 보유합니다.
- **identifier**: rule에 대한 외부 참조에 사용되는 UUID와 같은 고유한 string identifier를 제공합니다.
- **requirement**: rule의 구체적인 authorization requirements 및 mechanisms를 정의하는 serialized data를 포함합니다.
- **comment**: documentation 및 명확성을 위해 rule에 대한 사람이 읽을 수 있는 설명 또는 comment를 제공합니다.

### 예시
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
다음 디코딩된 규칙은 문서화된 macOS 버전에서 `authenticate-admin-nonshared`를 보여준다:<sup>[[1]](#references)</sup>
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

`authd`는 Authorization Services 요청을 평가하는 XPC service입니다. 현재 macOS 빌드에서는 `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`에서 해당 bundle을 확인할 수 있습니다. 이 경로는 구현 세부 사항이므로 릴리스에 따라 다를 수 있습니다. 이전 릴리스에서는 `/var/log/authd.log`에 로그를 기록했지만, 현재 릴리스에서는 주로 unified logging system을 사용하며, `authd` process predicate를 사용해 `log show`/`log stream`으로 조회할 수 있습니다.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

`security` tool은 여러 Authorization Services 작업을 제공합니다. 과거에는 `security execute-with-privileges /bin/ls`를 사용해 `AuthorizationExecuteWithPrivileges`를 호출했습니다. Apple은 macOS 10.7에서 해당 API를 deprecated 처리했으며, 최신 privileged helper는 launchd-managed helper와 XPC authorization을 사용해야 합니다.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

이를 아직 지원하는 릴리스에서는 `/usr/libexec/security_authtrampoline`을 사용하며, command를 root로 실행하기 전에 authorization prompt를 표시합니다:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - macOS Authorization Right 개요](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (archive)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS manual page](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: launchd job 생성](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security project - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
