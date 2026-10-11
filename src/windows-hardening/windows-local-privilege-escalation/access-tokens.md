# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

すべてのプロセスには、セキュリティコンテキストを定義する**プライマリアクセストークン**があります。スレッドは通常このトークンを使用しますが、一時的に**インパーソネーショントークン**を持つこともできます。トークンには、ユーザー SID、グループ SID、権限、整合性情報、ログオンセッションのログオン SID が含まれます。プロセスは通常、親のプライマリトークンへの参照を継承します。その内容の独立したコピーを受け取るわけではありません。<sup>[[4]](#references)</sup>

`whoami /all` を実行すると、この情報を確認できます。

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

または Sysinternals の _Process Explorer_ を使用します（プロセスを選択し、「Security」タブにアクセスします）：

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### ローカル管理者

管理者に **UAC Admin Approval Mode** が適用されている場合、対話型ログオンでは完全な管理者トークンとフィルター処理されたトークンが作成されます。Explorer および通常の子プロセスは、デフォルトでフィルター処理されたトークンを使用します。**Run as administrator** などの昇格要求により、UAC は完全なトークンを使ってプログラムを起動します。組み込みの Administrator アカウントを使用する場合や、Admin Approval Mode が無効の場合は、動作が異なります。<sup>[[5]](#references)</sup>

バイパス手法とポリシーの詳細については、専用の[**UAC ページ**](../authentication-credentials-uac-and-efs/uac-user-account-control.md)を参照してください。

実際には、**昇格されていない管理者シェルは通常、フィルター処理されたトークンで実行されます**。そのため、プロセスが昇格されるまでは、`whoami /groups` で **`BUILTIN\Administrators` が `Deny only` と表示される**ことがよくあります。内部的には、Windows は**リンクされた昇格済みトークン**（`TokenLinkedToken`）を保持し、`TokenElevationType` などのフィールドで状態を追跡します。

### 資格情報を使ったユーザー偽装

**他のユーザーの有効な資格情報があれば**、その資格情報を使って**新しいログオンセッションを作成**できます：

```
runas /user:domain\username cmd.exe
```

**access token** には、**LSASS** 内のログオンセッションへの **参照** も含まれています。これは、プロセスがネットワーク上のオブジェクトにアクセスする必要がある場合に役立ちます。\
次のコマンドを使うと、**ネットワークサービスへのアクセスに異なる認証情報を使用する**プロセスを起動できます。

```
runas /user:domain\username /netonly cmd.exe
```

これは、ネットワーク上のオブジェクトにアクセスするための有効な資格情報を持っていても、その資格情報が現在のホスト内では有効でない場合に役立ちます。資格情報はネットワーク上でのみ使用されるためです（現在のホストでは、現在のユーザー権限が使用されます）。

#### `runas /netonly` の詳細

`runas /netonly`（および `make_token` などの C2 ヘルパー）は、**`LOGON32_LOGON_NEW_CREDENTIALS`** トークンを作成します。これは横展開時に理解しておくと非常に役立ちます。<sup>[[3]](#references)</sup>

- **ローカルでは**、新しいプロセスは現在のトークンと**同じローカル ID**、グループ、整合性レベル、およびほとんどのアクセス判定を引き継ぎます。
- **リモートでは**、SMB / WinRM / LDAP / HTTP / Kerberos / NTLM の送信認証に**指定した資格情報**を使用できます。
- そのため、ネットワークアクセスが**別のアカウント**で行われていても、`whoami` には**元のローカルユーザー**が表示される場合があります。

資格情報がドメインまたは別のホストで有効でも、ユーザーが現在のマシンに**ローカルログオンできない、またはログオンすべきでない**場合に最適な方法です。

### トークンの種類

トークンには次の2種類があります。<sup>[[4]](#references)[[6]](#references)</sup>

- **プライマリトークン**: プロセスのセキュリティコンテキストを表します。子プロセスは通常、親プロセスのプライマリトークンを継承します。一方、明示的なトークンを指定するプロセス作成 API には、それぞれ独自のトークンアクセス要件と呼び出し元の特権要件があります。
- **偽装トークン**: サーバースレッドがクライアントのセキュリティコンテキストを一時的に使用してアクセスチェックを行えるようにします。レベルは次の4つです。
  - **Anonymous**: 識別されていないユーザーと同等のアクセスをサーバーに許可します。
  - **Identification**: オブジェクトへのアクセスにクライアントの ID を使用せずに、サーバーがその ID を確認できるようにします。
  - **Impersonation**: サーバーがクライアントの ID で操作できるようにします。
  - **Delegation**: 認証方式とアカウント設定で委任がサポートされている場合、サーバーがリモートシステム上でクライアントを偽装できるようにします。

#### 使用前に取得したトークンをトリアージする

ユーザー名だけを基準にトークンを選択しないでください。同じアカウントでも、ログオンセッション、サービス SID、特権、整合性レベル、制限、ネットワーク資格情報が異なる複数のトークンを持つ場合があります。<sup>[[9]](#references)</sup> `GetTokenInformation` を使って、少なくとも **`TokenType`**、**`TokenImpersonationLevel`**、**`TokenElevationType`**、**`TokenLinkedToken`**、**`TokenIntegrityLevel`**、**`TokenSessionId`**、**`TokenIsRestricted`** / **`TokenHasRestrictions`**、および **`TokenStatistics.AuthenticationId`** を確認してください。<sup>[[7]](#references)</sup>

制限付きトークンには、拒否専用 SID、削除された特権、制限 SID が含まれる場合があります。制限 SID がある場合、Windows は有効な SID を使ったアクセスチェックと、制限 SID を使ったアクセスチェックをそれぞれ実行し、**両方のチェックでアクセスが許可されなければなりません**。したがって、出力に魅力的なユーザー SID や有効なグループが表示されても、それだけではトークンが対象オブジェクトにアクセスできることの証明にはなりません。<sup>[[8]](#references)</sup>

文書化されているトークンおよびプロセス作成の要件に従い、次の判断フローを使用してください。<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **プライマリトークン**を `CreateProcessWithTokenW` または `CreateProcessAsUserW` に渡すには、`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` を含むハンドルが必要です。
2. **偽装トークン**は `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` で変換します。Identification レベルのトークンから ID 情報を取得することはできますが、そのクライアントとしてアクセスチェックを行うことはできません。
3. `CreateProcessWithTokenW` には `SeImpersonatePrivilege` が必要で、子プロセスは呼び出し元のセッションで起動します。一方、`CreateProcessAsUserW` はトークンのセッションを使用しますが、通常は `SeIncreaseQuotaPrivilege` が必要で、`SeAssignPrimaryTokenPrivilege` も必要になる場合があります。資格情報が利用可能で、これらの特権がない場合、文書化されている代替手段は `CreateProcessWithLogonW` です。

#### プロセスの所有者だけでなくトークンハンドルを探す

各プロセスのプライマリトークンを開くだけでは、サービスやブローカープロセスが通常のハンドルとして保持している**偽装トークンを見落とす**ことがあります。再利用可能なハンドルテーブルの手順では、システムハンドルを列挙し、トークンオブジェクトをフィルタリングしてから、各所有プロセスを `PROCESS_DUP_HANDLE` で開き、候補のハンドルを現在のプロセスに複製して、前述のフィールドを確認します。複製されたハンドルに `TOKEN_QUERY` と `TOKEN_DUPLICATE` が含まれていることを確認してください。トークンハンドルが見つかっても、それを使用可能なプライマリトークンに複製できるとは限りません。保護されたプロセスやプロセス DACL によって、所有プロセスのハンドルを開けない場合もあります。<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` は、プロセスのプライマリトークンと保持されているトークンハンドルの両方を自動的に列挙します。`list_token` はユーザー名ごとに優先候補を1つ保持し、`list_all_token` はすべての候補を出力します。PID を指定すると、列挙対象を1つの所有プロセスに限定できます。<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

手動での検査やアクセス確認には、**TokenUniverse**を使ってプロセス／スレッドのトークンを開き、既存のトークンハンドルを検索し、制限やログオンセッションを調べ、トークンを複製し、複数のプロセス作成方法をテストできます。<sup>[[13]](#references)</sup> プロセス間ハンドルを取得する基礎的なプリミティブについては、以下を参照してください。

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### トークンの偽装

十分な権限があれば、metasploitの_**incognito**_モジュールを使って、他の**トークン**を簡単に**一覧表示**し、**偽装**できます。これにより、**他のユーザーになりすましてアクションを実行**できます。この手法で**権限昇格**することも可能です。

操作中に忘れがちな実用上の注意点をいくつか紹介します。<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**では、呼び出し元に**`SeImpersonatePrivilege`**が必要で、新しいプロセスは**呼び出し元のセッション**で実行されます。
- **`CreateProcessWithTokenW`**が`1314`で失敗した場合、呼び出し元が必要な権限を満たしていれば、**`CreateProcessAsUserW`**を代替手段として使えます。また、子プロセスを**トークンが参照するセッション**で実行する場合は、こちらが適切な選択肢です。<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`**から取得したトークンは通常、**偽装トークン**です。そのため、プロセスの起動に使う前に**`DuplicateTokenEx(..., TokenPrimary, ...)`**が必要です。
- 偽装トークンはすべて同じように使えるわけではありません。**`SecurityIdentification`**ではユーザーを検査できますが、**そのユーザーとして操作することはできません**。強制処理のプリミティブやパイプ／RPCクライアントから識別レベルのトークンしか得られない場合は、**`TokenImpersonationLevel`**を確認し、**`SecurityImpersonation`**以上のレベルを取得できるプリミティブに切り替えてください。

#### LSASSに触れずにトークンを窃取する

すでに**サービス**または**SYSTEM**のコンテキストがあり、**特権ユーザーがログオン中**であれば、そのユーザーのトークンを窃取または複製する方が、**LSASS**をダンプするより目立たないことがよくあります。実際の侵入では、多くの場合、これだけで次のことが可能です。<sup>[[2]](#references)</sup>

- そのユーザーとしてローカル操作を実行する
- そのユーザーとしてリモートリソースにアクセスする
- 再利用可能な認証情報を先に抽出せずにAD操作を行う

特権コンテキストからの**セッション／ユーザートークンのハイジャック**例については、[**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)を確認してください。**`WTSQueryUserToken`**などのAPIは**高い信頼性が求められるサービス**向けで、通常は**`LocalSystem` + `SeTcbPrivilege`**が必要です。そのため、主にサービスレベルのコンテキストをすでに制御している場合に役立ちます。まず**SYSTEM**を取得するための、権限に特化した方法については、以下のページを参照してください。

### トークン権限

**権限昇格に悪用できるトークン権限**について確認してください。


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**利用可能なすべてのトークン権限とその定義については、この外部ページを参照してください**](https://github.com/gtworek/Priv2Admin)。

## References

- [1] [アクセストークンの理解と悪用 — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASSに触れずにActive Directoryを侵害するためにWindowsのトークンを悪用する](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strikeの「make_token」コマンドを解明する](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [アクセストークン - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [ユーザーアカウント制御の仕組み - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [偽装レベル - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS列挙型 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [制限付きトークン - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
