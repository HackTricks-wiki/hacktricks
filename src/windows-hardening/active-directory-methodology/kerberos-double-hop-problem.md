# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Kerberosの「ダブルホップ」問題は、攻撃者が**2つのホップを跨いでKerberos認証を使用しようとする**ときに発生します。例えば、**PowerShell**/**WinRM**を使用する場合です。

**Kerberos**を通じて**認証**が行われると、**資格情報**は**メモリ**にキャッシュされません。したがって、mimikatzを実行しても、ユーザーがプロセスを実行していても、そのマシンにユーザーの**資格情報**は見つかりません。

これは、Kerberosで接続する際の手順が以下の通りだからです：

1. User1が資格情報を提供し、**ドメインコントローラー**がUser1にKerberosの**TGT**を返します。
2. User1が**TGT**を使用して**Server1**に接続するための**サービスチケット**を要求します。
3. User1が**Server1**に接続し、**サービスチケット**を提供します。
4. **Server1**はUser1の**資格情報**やUser1の**TGT**をキャッシュしていません。したがって、Server1からUser1が2番目のサーバーにログインしようとすると、**認証できません**。

### Unconstrained Delegation

PCで**制約のない委任**が有効になっている場合、これは発生しません。なぜなら、**サーバー**はアクセスする各ユーザーの**TGT**を取得するからです。さらに、制約のない委任が使用されると、そこから**ドメインコントローラーを侵害する**可能性があります。\
[**制約のない委任ページの詳細**](unconstrained-delegation.md)。

### CredSSP

この問題を回避するもう一つの方法は、[**特に安全でない**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**です。Microsoftによると：

> CredSSP認証は、ローカルコンピュータからリモートコンピュータにユーザーの資格情報を委任します。この実践は、リモート操作のセキュリティリスクを高めます。リモートコンピュータが侵害された場合、資格情報が渡されると、その資格情報を使用してネットワークセッションを制御できます。

セキュリティ上の懸念から、**CredSSP**は本番システム、敏感なネットワーク、および同様の環境では無効にすることを強く推奨します。**CredSSP**が有効かどうかを確認するには、`Get-WSManCredSSP`コマンドを実行できます。このコマンドは**CredSSPの状態を確認**することができ、**WinRM**が有効であればリモートで実行することも可能です。
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

ダブルホップの問題に対処するために、ネストされた `Invoke-Command` を使用する方法が提示されています。これは問題を直接解決するものではありませんが、特別な設定を必要とせずに回避策を提供します。このアプローチでは、最初の攻撃マシンから実行されたPowerShellコマンドまたは最初のサーバーとの以前に確立されたPS-Sessionを通じて、二次サーバー上でコマンド（`hostname`）を実行することができます。以下はその方法です：
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
代わりに、最初のサーバーとのPS-Sessionを確立し、`Invoke-Command`を`$cred`を使用して実行することが、タスクを中央集約するために推奨されます。

### PSSession構成の登録

ダブルホップ問題を回避するための解決策は、`Enter-PSSession`とともに`Register-PSSessionConfiguration`を使用することです。この方法は`evil-winrm`とは異なるアプローチを必要とし、ダブルホップの制限を受けないセッションを可能にします。
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

中間ターゲットのローカル管理者にとって、ポートフォワーディングは最終サーバーにリクエストを送信することを可能にします。`netsh`を使用して、フォワーディング用のルールを追加し、フォワードされたポートを許可するWindowsファイアウォールルールを追加できます。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` は、WinRM リクエストを転送するために使用でき、PowerShell の監視が懸念される場合には、検出されにくいオプションとして機能する可能性があります。以下のコマンドは、その使用法を示しています:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

最初のサーバーにOpenSSHをインストールすることで、ダブルホップの問題に対する回避策が有効になり、特にジャンプボックスシナリオに役立ちます。この方法では、Windows用のOpenSSHのCLIインストールと設定が必要です。パスワード認証用に構成されると、これにより中間サーバーがユーザーの代わりにTGTを取得できるようになります。

#### OpenSSH インストール手順

1. 最新のOpenSSHリリースzipをターゲットサーバーにダウンロードして移動します。
2. 解凍して`Install-sshd.ps1`スクリプトを実行します。
3. ポート22を開くためのファイアウォールルールを追加し、SSHサービスが実行中であることを確認します。

`Connection reset`エラーを解決するには、OpenSSHディレクトリに対して全員が読み取りおよび実行アクセスを持つように権限を更新する必要があるかもしれません。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## References

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
