# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

すべてのプロセスには、セキュリティコンテキストを定義する**プライマリアクセストークン**があります。スレッドは通常このトークンを使用しますが、一時的に**偽装トークン**を持つこともできます。トークンには、ユーザー SID、グループ SID、特権、整合性情報、およびログオンセッションのログオン SID が含まれます。プロセスは通常、親プロセスのプライマリトークンへの参照を継承します。トークンの内容の独立したコピーを受け取るわけではありません。<sup>[[4]](#references)</sup>

`whoami /all`を実行すると、この情報を確認できます。

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

または、Sysinternals の _Process Explorer_ を使用します（プロセスを選択し、[Security] タブにアクセスします）:

![Access Tokens - Access Tokens: または、Sysinternals の Process Explorer を使用します（プロセスを選択し、[Security] タブにアクセスします）](<../../images/image (772).png>)

### ローカル管理者

管理者に **UAC Admin Approval Mode** が適用されている場合、対話型ログオンでは完全な管理者 token とフィルターされた token が作成されます。Explorer と通常の子プロセスは、デフォルトでフィルターされた token を使用します。**Run as administrator** などの昇格要求により、UAC は完全な token を使ってプログラムを起動します。組み込みの Administrator アカウントを使用する場合や、Admin Approval Mode が無効な場合は、動作が異なります。<sup>[[5]](#references)</sup>

バイパス手法とポリシーの詳細については、専用の [**UAC ページ**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) を参照してください。

実際には、**昇格されていない管理者の shell は通常、フィルターされた token で実行される**ということです。そのため、プロセスが昇格されるまでは、`whoami /groups` に **`BUILTIN\Administrators` が `Deny only` として表示される**ことがよくあります。内部では、Windows は**リンクされた昇格済み token**（`TokenLinkedToken`）を保持し、`TokenElevationType` などのフィールドで状態を追跡します。

### 認証情報を使ったユーザー偽装

**他のユーザーの有効な認証情報**があれば、その認証情報を使って**新しいログオンセッションを作成**できます:

```
runas /user:domain\username cmd.exe
```

**access token**には、**LSASS**内のログオン セッションへの参照も含まれています。これは、プロセスがネットワーク上のオブジェクトにアクセスする必要がある場合に役立ちます。\
次の方法で、**ネットワーク サービスへのアクセスに異なる資格情報を使用するプロセス**を起動できます。

```
runas /user:domain\username /netonly cmd.exe
```

ネットワーク内のオブジェクトにアクセスするための有効な資格情報があるものの、その資格情報が現在のホスト内では有効でない場合に便利です。資格情報はネットワーク内でのみ使用されるため、現在のホストでは現在のユーザー権限が使用されます。

#### `runas /netonly` の詳細

`runas /netonly`（および `make_token` などの C2 ヘルパー）は **`LOGON32_LOGON_NEW_CREDENTIALS`** token を作成します。これはラテラルムーブメントを理解するうえで非常に重要です。<sup>[[3]](#references)</sup>

- **ローカルでは**、新しいプロセスは現在の token と同じローカル ID、グループ、整合性レベル、およびほとんどのアクセス判断を引き継ぎます。
- **リモートでは**、SMB / WinRM / LDAP / HTTP / Kerberos / NTLM の送信認証に **指定した資格情報** を使用できます。
- そのため、ネットワークアクセスでは **別のアカウント** が使われていても、`whoami` には **元のローカルユーザー** が表示される場合があります。

資格情報がドメインまたは別のホストでは有効だが、そのユーザーが現在のマシンに **ローカルログオンできない、またはすべきでない** 場合に有効な方法です。

### token の種類

利用できる token は2種類あります。<sup>[[4]](#references)[[6]](#references)</sup>

- **プライマリ token**: プロセスのセキュリティコンテキストを表します。通常、子プロセスは親のプライマリ token を継承します。一方、明示的に token を指定するプロセス作成 API には、それぞれ独自の token アクセス要件と呼び出し元の特権要件があります。
- **偽装 token**: サーバーのスレッドがクライアントのセキュリティコンテキストを一時的に使用してアクセスチェックを行えるようにします。次の4つのレベルがあります。
  - **Anonymous**: 未識別ユーザーと同等のアクセスをサーバーに許可します。
  - **Identification**: オブジェクトアクセスにクライアントの ID を利用せず、その ID の確認をサーバーに許可します。
  - **Impersonation**: サーバーがクライアントの ID で動作できるようにします。
  - **Delegation**: 認証メカニズムとアカウント設定が委任をサポートしている場合、サーバーがリモートシステム上でクライアントを偽装できるようにします。

#### 使用前に取得した token をトリアージする

ユーザー名だけで token を選択しないでください。同じアカウントでも、ログオンセッション、サービス SID、特権、整合性レベル、制限、ネットワーク資格情報が異なる複数の token を持つ場合があります。<sup>[[9]](#references)</sup> `GetTokenInformation` を使って、少なくとも **`TokenType`**、**`TokenImpersonationLevel`**、**`TokenElevationType`**、**`TokenLinkedToken`**、**`TokenIntegrityLevel`**、**`TokenSessionId`**、**`TokenIsRestricted`** / **`TokenHasRestrictions`**、および **`TokenStatistics.AuthenticationId`** を照会してください。<sup>[[7]](#references)</sup>

制限付き token には、拒否専用 SID、削除された特権、制限 SID が含まれる場合があります。制限 SID がある場合、Windows は有効な SID を使ったアクセスチェックと制限 SID を使ったアクセスチェックをそれぞれ実行し、**両方のチェックでアクセスが許可される必要があります**。したがって、出力に魅力的なユーザー SID や有効なグループが表示されていても、それだけでは token が対象オブジェクトにアクセスできるとは限りません。<sup>[[8]](#references)</sup>

文書化されている token とプロセス作成の要件に基づき、次の手順で判断してください。<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **プライマリ token** を `CreateProcessWithTokenW` または `CreateProcessAsUserW` に渡すには、`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` を指定したハンドルが必要です。
2. **偽装 token** は `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` で変換します。Identification レベルの token から ID 情報を取得することはできますが、そのクライアントとしてアクセスチェックを実行することはできません。
3. `CreateProcessWithTokenW` には `SeImpersonatePrivilege` が必要で、子プロセスは呼び出し元のセッションで起動します。一方、`CreateProcessAsUserW` は token のセッションを使用しますが、通常 `SeIncreaseQuotaPrivilege` が必要で、`SeAssignPrimaryTokenPrivilege` も必要になる場合があります。資格情報はあるもののこれらの特権がない場合、文書化されている代替手段は `CreateProcessWithLogonW` です。

#### プロセスの所有者だけでなく token ハンドルを探す

各プロセスのプライマリ token を開くだけでは、サービスやブローカーのプロセス内に通常のハンドルとして保持されている **偽装 token** を見逃すことがあります。再利用可能なハンドルテーブルの手順は、システムハンドルを列挙し、token オブジェクトでフィルターし、各所有者を `PROCESS_DUP_HANDLE` で開き、候補のハンドルを現在のプロセスに複製してから、上記のフィールドを照会する方法です。複製したハンドルに `TOKEN_QUERY` と `TOKEN_DUPLICATE` が含まれていることを確認してください。token ハンドルが見つかっても、それを使用可能なプライマリ token に複製できるとは限りません。保護されたプロセスやプロセス DACL によって、所有者プロセスのハンドルを開けない場合もあります。<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` は、プロセスのプライマリ token と保持されている token ハンドルの両方の列挙を自動化します。`list_token` はユーザー名ごとに優先候補を1つ保持し、`list_all_token` はすべての候補を出力します。PID を指定すると、列挙対象を1つの所有者プロセスに限定できます。<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

手動での調査やアクセス確認には、**TokenUniverse**を使ってプロセスやスレッドのトークンを開き、既存のトークンハンドルを検索し、制限やログオンセッションを調査し、トークンを複製し、複数のプロセス作成方法をテストできます。<sup>[[13]](#references)</sup> 基盤となるプロセス間ハンドルのプリミティブについては、こちらを参照してください。

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### トークンの偽装

十分な権限があれば、metasploitの_**incognito**_モジュールを使って、他の**トークン**を簡単に**一覧表示**し、**偽装**できます。これにより、**他のユーザーになりすまして操作**できるため便利です。この手法で**権限昇格**することもできます。

操作中に忘れやすい実用上の注意点をいくつか挙げます。<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**を使うには、呼び出し元に**`SeImpersonatePrivilege`**が必要です。また、新しいプロセスは**呼び出し元のセッション**で実行されます。
- **`CreateProcessWithTokenW`**が`1314`で失敗した場合、呼び出し元が必要な権限を満たしていれば、**`CreateProcessAsUserW`**を代替手段として使えます。子プロセスを**トークンが参照するセッション**で実行する場合にも、こちらが適切な選択肢です。<sup>[[9]](#references)[[10]](#references)</sup>
- トークンが**`LogonUser(LOGON32_LOGON_NETWORK)`**から取得された場合、通常は**偽装トークン**です。そのため、プロセスの起動を試みる前に**`DuplicateTokenEx(..., TokenPrimary, ...)`**が必要です。
- 偽装トークンはどれも同じように使えるわけではありません。**`SecurityIdentification`**ではユーザーを調査できますが、**そのユーザーとして操作することはできません**。強制実行プリミティブやpipe/RPCクライアントから識別レベルのトークンしか取得できない場合は、**`TokenImpersonationLevel`**を確認し、**`SecurityImpersonation`**以上のレベルを得られるプリミティブに切り替えてください。

#### LSASSに触れずにトークンを窃取する

すでに**サービス**または**SYSTEM**のコンテキストを持っていて、**特権ユーザーがログオン中**であれば、そのユーザーのトークンを窃取または複製する方が、**LSASS**をダンプするより目立ちにくいことがよくあります。実際の侵入では、多くの場合、これだけで次のことが可能です。<sup>[[2]](#references)</sup>

- そのユーザーとしてローカルで操作する
- そのユーザーとしてリモートリソースにアクセスする
- 再利用可能な認証情報を先に抽出せずにAD操作を行う

特権コンテキストから**セッション/ユーザートークンを乗っ取る**例については、[**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)を確認してください。**`WTSQueryUserToken`**などのAPIは**高度に信頼されたサービス**向けであり、通常は**`LocalSystem` + `SeTcbPrivilege`**が必要です。そのため、主にサービスレベルのコンテキストをすでに掌握している場合に役立ちます。まず**SYSTEM**を取得するための、権限に応じた方法については、以下のページを確認してください。

### トークンの特権

**権限昇格に悪用できるトークンの特権**について学びましょう。


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**トークンの特権とその定義の一覧（外部ページ）**](https://github.com/gtworek/Priv2Admin)も確認してください。

## References

- [1] [アクセス トークンの理解と悪用 — パート II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASSに触れずにWindowsのトークンを悪用してActive Directoryを侵害する](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strikeの「make_token」コマンドを解き明かす](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [アクセス トークン - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [ユーザー アカウント制御の仕組み - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [偽装レベル - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS列挙型 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [制限付きトークン - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
