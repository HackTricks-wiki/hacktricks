# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Athorizarions DB**

`/var/db/auth.db` にあるデータベースは、機密操作を実行するための権限を保存するために使用されるデータベースです。これらの操作は完全に **ユーザースペース** で実行され、通常は **XPCサービス** によって使用され、特定のアクションを実行するために **呼び出しクライアントが認可されているかどうか** をこのデータベースをチェックして確認します。

最初にこのデータベースは `/System/Library/Security/authorization.plist` の内容から作成されます。その後、一部のサービスがこのデータベースに他の権限を追加または変更することがあります。

ルールはデータベース内の `rules` テーブルに保存され、以下の列を含みます：

- **id**: 各ルールの一意の識別子で、自動的にインクリメントされ、主キーとして機能します。
- **name**: 認可システム内で識別および参照するために使用されるルールの一意の名前。
- **type**: ルールのタイプを指定し、認可ロジックを定義するために値 1 または 2 に制限されます。
- **class**: ルールを特定のクラスに分類し、正の整数であることを保証します。
- "allow" は許可、"deny" は拒否、"user" はグループプロパティがアクセスを許可するメンバーシップを示すグループを示し、"rule" は満たすべきルールを配列で示し、"evaluate-mechanisms" は `mechanisms` 配列に続き、組み込みまたは `/System/Library/CoreServices/SecurityAgentPlugins/` または /Library/Security//SecurityAgentPlugins 内のバンドルの名前を示します。
- **group**: グループベースの認可のためにルールに関連付けられたユーザーグループを示します。
- **kofn**: "k-of-n" パラメータを表し、満たすべきサブルールの数を決定します。
- **timeout**: ルールによって付与された認可が期限切れになるまでの秒数を定義します。
- **flags**: ルールの動作と特性を変更するさまざまなフラグを含みます。
- **tries**: セキュリティを強化するために許可される認可試行の回数を制限します。
- **version**: ルールのバージョンを追跡し、バージョン管理と更新を行います。
- **created**: 監査目的のためにルールが作成されたタイムスタンプを記録します。
- **modified**: ルールに対して行われた最後の変更のタイムスタンプを保存します。
- **hash**: ルールのハッシュ値を保持し、その整合性を確保し、改ざんを検出します。
- **identifier**: ルールへの外部参照のための一意の文字列識別子（UUIDなど）を提供します。
- **requirement**: ルールの特定の認可要件とメカニズムを定義するシリアライズされたデータを含みます。
- **comment**: ドキュメントと明確さのためにルールに関する人間が読める説明またはコメントを提供します。

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
さらに、[https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) では、`authenticate-admin-nonshared` の意味を見ることができます：
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

これは、クライアントが機密アクションを実行するための承認要求を受け取るデーモンです。これは、`XPCServices/`フォルダー内に定義されたXPCサービスとして機能し、ログを`/var/log/authd.log`に書き込みます。

さらに、セキュリティツールを使用すると、多くの`Security.framework` APIをテストすることができます。例えば、`AuthorizationExecuteWithPrivileges`を実行するには、次のようにします: `security execute-with-privileges /bin/ls`

これにより、`/usr/libexec/security_authtrampoline /bin/ls`がrootとしてフォークされ、lsをrootとして実行するための権限を求めるプロンプトが表示されます:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
