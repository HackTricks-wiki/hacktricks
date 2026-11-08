# アクセス トークン

{{#include ../../banners/hacktricks-training.md}}

## アクセス トークン

すべてのプロセスには、セキュリティ コンテキストを定義する**プライマリ アクセス トークン**があります。スレッドは通常このトークンを使用しますが、一時的に**偽装トークン**を持つこともできます。トークンには、ユーザー SID、グループ SID、権限、整合性情報、およびログオン セッションのログオン SID が含まれます。通常、プロセスは親プロセスのプライマリ トークンへの参照を継承します。トークンの内容を独立したコピーとして受け取るわけではありません。<sup>[[4]](#references)</sup>

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

または Sysinternals の _Process Explorer_ を使用します（プロセスを選択し、「Security」タブにアクセス）:

![Access Tokens - Access Tokens: または Sysinternals の Process Explorer を使用します（プロセスを選択し、「Security」タブにアクセス）](<../../images/image (772).png>)

### ローカル管理者

**UAC Admin Approval Mode** が管理者に適用される場合、対話型ログオン時に完全な管理者トークンとフィルターされたトークンが作成されます。Explorer と通常の子プロセスは、デフォルトでフィルターされたトークンを使用します。**管理者として実行**などの昇格要求を行うと、UAC は完全なトークンでプログラムを起動します。正確な動作は、組み込みの Administrator アカウントを使用する場合や、Admin Approval Mode が無効な場合には異なります。<sup>[[5]](#references)</sup>

バイパス手法とポリシーの詳細は、専用の[**UAC ページ**](../authentication-credentials-uac-and-efs/uac-user-account-control.md)を参照してください。

実際には、**昇格されていない管理者シェルは通常、フィルターされたトークンで実行されます**。そのため、プロセスが昇格されるまで、`whoami /groups` では **`BUILTIN\Administrators` が `Deny only` と表示されることがよくあります**。内部的には、Windows は**リンクされた昇格トークン**（`TokenLinkedToken`）を保持し、`TokenElevationType` などのフィールドで状態を追跡します。

### 資格情報を使ったユーザー偽装

**他のユーザーの有効な資格情報**があれば、その資格情報を使って**新しいログオンセッションを作成**できます:

```
runas /user:domain\username cmd.exe
```

**access token**には、**LSASS**内のログオンセッションへの**reference**も含まれています。これは、プロセスがネットワーク上のオブジェクトにアクセスする必要がある場合に役立ちます。\
次の方法で、**ネットワークサービスへのアクセスに異なる認証情報を使用する**プロセスを起動できます。

```
runas /user:domain\username /netonly cmd.exe
```

ネットワーク内のオブジェクトにアクセスするための有効な認証情報があるものの、その認証情報はネットワーク内でのみ使用するもので、現在のホストでは有効でない場合に便利です（現在のホストでは、現在のユーザー権限が使用されます）。

#### `runas /netonly` の詳細

`runas /netonly`（および `make_token` などの C2 ヘルパー）は、**`LOGON32_LOGON_NEW_CREDENTIALS`** トークンを作成します。これは lateral movement の際に理解しておくと非常に役立ちます。<sup>[[3]](#references)</sup>

- **ローカルでは**、新しいプロセスは現在のトークンと**同じローカル ID**、グループ、整合性レベル、およびアクセス可否の判断の大半を引き継ぎます。
- **リモートでは**、SMB / WinRM / LDAP / HTTP / Kerberos / NTLM によるアウトバウンド認証で、**指定した認証情報**を使用できます。
- そのため、ネットワークアクセスには**別のアカウント**が使われていても、`whoami` には**元のローカルユーザー**が表示されることがあります。

認証情報がドメインまたは別のホストで有効である一方、現在のマシンにユーザーとして**ログオンできない、またはログオンすべきでない**場合に最適な方法です。

### トークンの種類

利用できるトークンは2種類あります。<sup>[[4]](#references)[[6]](#references)</sup>

- **プライマリトークン**: プロセスのセキュリティコンテキストを表します。通常、子プロセスは親のプライマリトークンを継承します。一方、明示的なトークンを使うプロセス作成 API では、それぞれ独自のトークンアクセス要件と呼び出し元の特権要件が課されます。
- **偽装トークン**: サーバースレッドがクライアントのセキュリティコンテキストを一時的に使用してアクセスチェックを行えるようにします。レベルは次の4種類です。
  - **Anonymous**: 未識別ユーザーと同等のアクセスをサーバーに許可します。
  - **Identification**: オブジェクトへのアクセスにクライアントの ID を使用せずに、サーバーがクライアントの ID を確認できるようにします。
  - **Impersonation**: サーバーがクライアントの ID で操作できるようにします。
  - **Delegation**: 認証メカニズムとアカウント設定が委任をサポートしている場合、サーバーがリモートシステム上でクライアントを偽装できるようにします。

#### 使用前に取得したトークンをトリアージする

ユーザー名だけでトークンを選ばないでください。同じアカウントでも、ログオンセッション、サービス SID、特権、整合性レベル、制限、ネットワーク認証情報が異なる複数のトークンを持つことがあります。<sup>[[9]](#references)</sup> `GetTokenInformation` を使って、少なくとも **`TokenType`**、**`TokenImpersonationLevel`**、**`TokenElevationType`**、**`TokenLinkedToken`**、**`TokenIntegrityLevel`**、**`TokenSessionId`**、**`TokenIsRestricted`** / **`TokenHasRestrictions`**、および **`TokenStatistics.AuthenticationId`** を照会してください。<sup>[[7]](#references)</sup>

制限付きトークンには、拒否専用 SID、削除された特権、制限 SID が含まれることがあります。制限 SID が存在する場合、Windows は有効な SID によるアクセスチェックと、制限 SID によるアクセスチェックをそれぞれ実行します。**両方のチェックでアクセスが許可される必要があります**。したがって、出力に魅力的なユーザー SID や有効なグループが表示されていても、それだけではそのトークンが対象オブジェクトにアクセスできるとは限りません。<sup>[[8]](#references)</sup>

文書化されているトークンおよびプロセス作成の要件に基づき、次の判断フローを使用してください。<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **プライマリトークン**を `CreateProcessWithTokenW` または `CreateProcessAsUserW` に渡すには、事前に `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` のアクセス権を持つハンドルが必要です。
2. **偽装トークン**は `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` で変換します。Identification レベルのトークンでは ID 情報を取得できますが、そのクライアントとしてアクセスチェックを実行することはできません。
3. `CreateProcessWithTokenW` には `SeImpersonatePrivilege` が必要で、子プロセスは呼び出し元のセッションで起動します。一方、`CreateProcessAsUserW` はトークンのセッションを使用しますが、通常 `SeIncreaseQuotaPrivilege` が必要で、場合によっては `SeAssignPrimaryTokenPrivilege` も必要です。認証情報はあるものの、これらの特権がない場合は、文書化されている代替手段として `CreateProcessWithLogonW` を使用できます。

#### プロセス所有者だけでなくトークンハンドルを調べる

各プロセスのプライマリトークンを開くだけでは、サービスやブローカープロセス内に通常のハンドルとして保持されている**偽装トークン**を見落とすことがあります。再利用可能なハンドルテーブルの手順は、システムハンドルを列挙し、トークンオブジェクトに絞り込み、`PROCESS_DUP_HANDLE` を使って各所有プロセスを開き、候補のハンドルを現在のプロセスに複製してから、上記のフィールドを照会する方法です。複製したハンドルに `TOKEN_QUERY` と `TOKEN_DUPLICATE` が含まれていることを確認してください。トークンハンドルが見つかっても、使用可能なプライマリトークンに複製できるとは限りません。保護されたプロセスやプロセス DACL によって、所有プロセスのハンドルを開けない場合もあります。<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` は、プロセスのプライマリトークンと保持されたトークンハンドルの両方を自動で列挙します。`list_token` はユーザー名ごとに優先候補を1つ保持し、`list_all_token` はすべての候補を出力します。PID を指定すると、1つの所有プロセスに列挙対象を限定できます。<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

手動での確認とアクセスチェックには、**TokenUniverse**を使ってプロセス/スレッドのトークンを開き、既存のトークンハンドルを検索し、制限やログオンセッションを調べ、トークンを複製し、複数のプロセス作成方法をテストできます。<sup>[[13]](#references)</sup> 基盤となるプロセス間ハンドルのプリミティブについては、以下を参照してください。

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### 有効なスレッド偽装トークンを探す

サービススレッドは、**プロセスのプライマリトークン**がサービスアカウントのものであっても、一時的にクライアントを偽装できます。そのため、プロセス所有者をスキャンするだけでは、クライアントのコンテキストを見逃す場合があります。<sup>[[4]](#references)</sup> TokenUniverseではアクセス可能なプロセス/スレッドのトークンを一覧表示できます。System Informerでは、プロセスの**Threads**タブを開き、**Impersonation**列を確認して候補となるスレッドを見つけます。<sup>[[13]](#references)[[14]](#references)</sup>

対象を絞ったAPIチェックでは、`TH32CS_SNAPTHREAD`のスナップショットを取得し、`THREADENTRY32.th32OwnerProcessID`をサービスのPIDでフィルタリングします。次に、アクセス可能な各スレッドに対して`OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)`と`OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)`を呼び出します。<sup>[[15]](#references)[[16]](#references)</sup> `TRUE`を指定すると、トークンを開く際のアクセスチェックで呼び出し元の**プロセス**コンテキストが使われます。スキャナー自体が識別レベルで偽装している場合、これは重要です。<sup>[[17]](#references)</sup> 上記の複製/プロセス作成の流れを試す前に、トークンのユーザー、種類、偽装レベル、ログオンIDを照会してください。<sup>[[7]](#references)</sup> 列挙してから開くまでの間にスレッドが偽装を停止することがあります。また、トークンが存在しない場合や、匿名トークン、保護されたスレッド、スレッドDACL、トークンDACLによって取得できない場合もあります。<sup>[[16]](#references)[[17]](#references)</sup> サービスが保持するトークンハンドルをスキャンする方法とは異なり、この方法では**現在割り当てられているスレッドトークン**を調べます。

既存のスレッドをスキャンするのではなく、特権クライアントに自分のパイプへ接続させてスレッドトークンを取得する攻撃経路については、[named-pipe client impersonation](named-pipe-client-impersonation.md)を参照してください。

#### トークンを偽装する

十分な権限があれば、metasploitの_**incognito**_モジュールを使って、他の**トークン**を簡単に**一覧表示**し、**偽装**できます。これにより、**別のユーザーとして操作**できます。この手法で**権限昇格**することも可能です。

操作中に忘れやすい実用上の注意点をいくつか示します。<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`**を呼び出すには、呼び出し元に**`SeImpersonatePrivilege`**が必要です。新しいプロセスは**呼び出し元のセッション**で実行されます。
- **`CreateProcessAsUserW`**は、`CreateProcessWithTokenW`が`1314`で失敗した場合の代替手段になりますが、呼び出し元が必要な権限を満たしている場合に限ります。また、子プロセスを**トークンが示すセッション**で実行する必要がある場合にも適切な選択肢です。<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`**は**偽装トークン**を返します。プロセスを作成する前に、**`DuplicateTokenEx(..., TokenPrimary, ...)`**で変換してください。変換後も、そのプロセスはこのネットワークログオンを使って、認証が必要なリモート共有やプリンターにアクセスできません。このログオン種別では資格情報がキャッシュされないためです。資格情報があり、後続のネットワークアクセスが必要な場合は、対話型ログオンまたはネットワーククリアテキストログオンを使用してください。ローカルのIDを維持しながら送信資格情報を指定する`LOGON32_LOGON_NEW_CREDENTIALS`（`runas /netonly`）と混同しないでください。<sup>[[18]](#references)</sup>
- すべての偽装トークンが同じように有用なわけではありません。**`SecurityIdentification`**ではユーザーを調べられますが、**そのユーザーとして操作することはできません**。coercion primitiveやパイプ/RPCクライアントから識別レベルのトークンしか得られない場合は、**`TokenImpersonationLevel`**を確認し、**`SecurityImpersonation`**以上を返すプリミティブに切り替えてください。

#### LSASSに触れずにトークンを窃取する

すでに**サービス**または**SYSTEM**のコンテキストがあり、**特権ユーザーがログオン中**であれば、そのユーザーのトークンを窃取または複製する方が、**LSASS**をダンプするより目立たないことがよくあります。実際の侵入では、次のことを行うにはこれで十分な場合が多くあります。<sup>[[2]](#references)</sup>

- そのユーザーとしてローカル操作を実行する
- そのユーザーとしてリモートリソースにアクセスする
- 再利用可能な資格情報を先に抽出せずにAD操作を実行する

特権コンテキストからの**セッション/ユーザートークンのハイジャック**の例については、[**WTS Impersonator**](../stealing-credentials/wts-impersonator.md)を参照してください。**`WTSQueryUserToken`**などのAPIは**高い信頼性が求められるサービス**向けで、通常は**`LocalSystem` + `SeTcbPrivilege`**が必要です。そのため、主にサービスレベルのコンテキストをすでに制御している場合に役立ちます。先に**SYSTEM**を取得するための、権限ごとの方法については以下のページを参照してください。

### トークンの権限

**権限昇格に悪用できるトークンの権限**を確認してください。


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**考えられるすべてのトークン権限とその定義をまとめた外部ページ**](https://github.com/gtworek/Priv2Admin)も確認してください。



## References

- [1] [アクセス トークンの理解と悪用 — パート II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASSに触れずにActive Directoryを侵害するWindowsトークンの悪用](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strikeの「make_token」コマンドを解明する](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [アクセス トークン - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [ユーザー アカウント制御のしくみ - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [偽装レベル - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS列挙型 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [制限付きトークン - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle関数 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [System Informerのスレッドトークン機能リクエスト](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [スレッド一覧の走査 - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
