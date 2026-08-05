# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorizations DB**

`/var/db/auth.db` にあるデータベースは、機密性の高い操作を実行するための権限を保存するために使用されます。これらの操作は完全に **user space** で実行され、通常は **XPC services** によって使用されます。XPC services は、このデータベースを確認して **calling client が特定のアクションを実行する権限を持っているか** をチェックする必要があります。

このデータベースは、最初に `/System/Library/Security/authorization.plist` の内容から作成されます。その後、一部の services が他の権限を追加するために、このデータベースを追加または変更する場合があります。

ルールはデータベース内の `rules` table に保存され、次の columns が含まれます。

- **id**: 各 rule の一意な識別子。自動的にインクリメントされ、primary key として機能します。
- **name**: authorization system 内で rule を識別および参照するために使用される、一意な rule 名。
- **type**: rule の type を指定します。authorization logic を定義する値 1 または 2 に限定されます。
- **class**: rule を特定の class に分類します。正の整数である必要があります。
- "allow" は許可、"deny" は拒否、`group` property が membership によって access を許可する group を示す場合は "user"、"rule" は満たす必要がある rule を array で示し、"evaluate-mechanisms" の後に続く `mechanisms` array には、builtins または `/System/Library/CoreServices/SecurityAgentPlugins/` や `/Library/Security//SecurityAgentPlugins` 内の bundle 名が含まれます。
- **group**: group-based authorization に関連付けられた user group を示します。
- **kofn**: 「k-of-n」parameter を表し、合計 number のうち、満たす必要がある subrules の数を決定します。
- **timeout**: rule によって付与された authorization が期限切れになるまでの秒数を定義します。
- **flags**: rule の動作と特性を変更するさまざまな flags が含まれます。
- **tries**: 許可される authorization attempts の回数を制限し、security を向上させます。
- **version**: version control および updates のために rule の version を追跡します。
- **created**: auditing のために rule が作成された timestamp を記録します。
- **modified**: rule に対して最後に変更が行われた timestamp を保存します。
- **hash**: rule の integrity を保証し、tampering を検出するための hash value を保持します。
- **identifier**: rule への外部参照用に、UUID などの一意な string identifier を提供します。
- **requirement**: rule 固有の authorization requirements および mechanisms を定義する serialized data が含まれます。
- **comment**: documentation および明確化のために、rule に関する人間が読める説明または comment を提供します。

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
さらに、[https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) では、`authenticate-admin-nonshared` の意味を確認できます:<sup>[[1]](#references)</sup>
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

これは、クライアントが機密性の高いアクションを実行するための authorization requests を受信する deamon です。`XPCServices/` フォルダー内で定義された XPC service として動作し、ログは `/var/log/authd.log` に書き込みます。

さらに、security tool を使用すると、多くの `Security.framework` APIs をテストできます。例えば、`AuthorizationExecuteWithPrivileges` の実行です: `security execute-with-privileges /bin/ls`

これにより、`/usr/libexec/security_authtrampoline /bin/ls` が root として fork および exec され、ls を root として実行するための permissions を求める prompt が表示されます:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
