# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Authorization Database

Security framework の Authorization Services を使用すると、privileged helper やその他のコンポーネントで、名前付き authorization rights を評価できます。現在の macOS バージョンでは、これらのルールの多くが `/var/db/auth.db` に保存され、`authd` によって評価されます。このファイルと SQLite スキーマは実装の詳細であり、release 間で変更される可能性があります。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

System defaults は、従来 `/System/Library/Security/authorization.plist` から初期設定されており、installers や privileged services が名前付き rights を追加する場合があります。database を直接編集するよりも、サポートされている `security authorizationdb read|write|remove` interface を使用してください。<sup>[[3]](#references)</sup>

記載された build で確認された `rules` table には、以下の columns が含まれます。これは forensic map として扱い、安定した public schema と見なさないでください。

- **id**: 各 rule の一意な identifier。自動的に increment され、primary key として機能します。
- **name**: authorization system 内で rule を識別および参照するために使用される、一意な rule の名前。
- **type**: rule の type を指定します。authorization logic を定義するため、値 1 または 2 に制限されています。
- **class**: rule を特定の class に分類します。正の integer である必要があります。
- 一般的な rule classes には `allow`、`deny`、`user`、`rule`、`evaluate-mechanisms` があります。Mechanisms には built-ins、または `/System/Library/CoreServices/SecurityAgentPlugins/` や `/Library/Security/SecurityAgentPlugins/` にある Security Agent plug-ins を使用できます。<sup>[[2]](#references)</sup>
- **group**: group-based authorization において、rule に関連付けられた user group を示します。
- **kofn**: "k-of-n" parameter を表し、合計数のうち、満たす必要がある subrules の数を決定します。
- **timeout**: rule によって付与された authorization が expire するまでの秒数を定義します。
- **flags**: rule の動作と特性を変更するさまざまな flags を含みます。
- **tries**: security を強化するため、許可される authorization attempts の回数を制限します。
- **version**: version control と updates のために rule の version を追跡します。
- **created**: auditing の目的で、rule が作成された timestamp を記録します。
- **modified**: rule に対して最後に行われた modification の timestamp を保存します。
- **hash**: rule の integrity を確保し、tampering を検出するための hash value を保持します。
- **identifier**: rule への external references 用に、UUID などの一意な string identifier を提供します。
- **requirement**: rule 固有の authorization requirements と mechanisms を定義する serialized data を含みます。
- **comment**: documentation と明確化のために、rule に関する human-readable description または comment を提供します。

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
以下のデコードされたルールは、文書化されたmacOSバージョンにおける`authenticate-admin-nonshared`を示しています。<sup>[[1]](#references)</sup>
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

`authd` は Authorization Services のリクエストを評価する XPC service です。現在の macOS build では、その bundle を `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc` で調査できます。この path は実装上の詳細であり、release によって異なる場合があります。古い release では `/var/log/authd.log` に書き込まれていましたが、現在の release では主に unified logging system が使用され、`authd` process predicate を使用して `log show`/`log stream` でクエリできます。<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

`security` tool は、Authorization Services の複数の操作を公開しています。歴史的な例では、`security execute-with-privileges /bin/ls` を使用して `AuthorizationExecuteWithPrivileges` を呼び出します。Apple は macOS 10.7 でこの API を deprecated にしました。modern privileged helper では、launchd-managed helper と XPC authorization を使用する必要があります。<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

引き続きサポートされている release では、これは `/usr/libexec/security_authtrampoline` を使用し、command を root として実行する前に authorization prompt を表示します：

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [macOS Authorization Right の authenticate-admin-nonshared - 概要](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide（archive）](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS manual page](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide：launchd jobs の作成](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security project - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
