# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorizations DB**

`/var/db/auth.db` にあるデータベースは、機密性の高い操作を実行するための権限を保存するために使用されます。これらの操作は完全に **user space** で実行され、通常は、呼び出し元のクライアントがデータベースを確認して特定のアクションを実行する権限を **持っているか** をチェックする必要がある **XPC services** によって使用されます。

このデータベースは、最初に `/System/Library/Security/authorization.plist` の内容から作成されます。その後、一部のサービスがこのデータベースに他の権限を追加するため、データを追加または変更する場合があります。

ルールはデータベース内の `rules` テーブルに保存され、次のカラムが含まれます。

- **id**: 各ルールの一意な識別子。自動的にインクリメントされ、primary key として機能します。
- **name**: authorization system 内でルールを識別および参照するために使用される、ルールの一意な名前。
- **type**: ルールのタイプを指定します。authorization logic を定義するため、値は 1 または 2 に限定されます。
- **class**: ルールを特定のクラスに分類します。正の整数である必要があります。
- "allow" は許可、"deny" は拒否、`group` property が所属することでアクセスを許可する group を示す場合は "user"、満たす必要のあるルールを配列で示す場合は "rule"、続いて `mechanisms` 配列を持つ "evaluate-mechanisms"。この配列には、`builtins` または `/System/Library/CoreServices/SecurityAgentPlugins/` もしくは `/Library/Security//SecurityAgentPlugins` 内の bundle 名が含まれます。
- **group**: group-based authorization に関連付けられた user group を示します。
- **kofn**: "k-of-n" parameter を表し、合計数のうち満たす必要がある subrules の数を決定します。
- **timeout**: ルールによって付与された authorization が期限切れになるまでの秒数を定義します。
- **flags**: ルールの動作と特性を変更するさまざまな flags が含まれます。
- **tries**: security を強化するため、許可される authorization attempts の回数を制限します。
- **version**: version control および更新のため、ルールの version を追跡します。
- **created**: auditing のため、ルールが作成された時刻の timestamp を記録します。
- **modified**: ルールに対して最後に変更が行われた時刻の timestamp を保存します。
- **hash**: ルールの integrity を保証し、tampering を検出するための hash value を保持します。
- **identifier**: ルールへの外部参照に使用される、UUID などの一意な string identifier を提供します。
- **requirement**: ルール固有の authorization requirements および mechanisms を定義する serialized data が含まれます。
- **comment**: documentation および明確化のため、ルールに関する human-readable な説明または comment を提供します。

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
さらに、[https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) では、`authenticate-admin-nonshared`の意味を確認できます:<sup>[[1]](#references)</sup>
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

これは、クライアントが機密性の高いアクションを実行するための認証リクエストを受け取る daemon です。`XPCServices/` フォルダ内で定義された XPC service として動作し、ログは `/var/log/authd.log` に書き込まれます。

さらに、security tool を使用すると、多くの `Security.framework` API をテストできます。例えば、`AuthorizationExecuteWithPrivileges` は次のように実行できます。

`security execute-with-privileges /bin/ls`

これにより、root として `/usr/libexec/security_authtrampoline /bin/ls` が fork および exec され、root として ls を実行するための権限を求める prompt が表示されます。

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)


{{#include ../../../banners/hacktricks-training.md}}
