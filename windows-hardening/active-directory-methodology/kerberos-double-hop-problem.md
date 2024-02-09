# Kerberos Double Hop Problem

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>から<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong>！</summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセス**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有する**ために、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## はじめに

Kerberosの「ダブルホップ」問題は、**Kerberos認証を2つのホップを介して**使用しようとするときに発生します。たとえば、**PowerShell**/**WinRM**を使用する場合です。

**Kerberos**を介した**認証**が行われると、**資格情報**は**メモリにキャッシュされません**。したがって、mimikatzを実行しても、ユーザーの資格情報をマシンで見つけることはできません。

これは、Kerberosで接続するときに次の手順が実行されるためです：

1. User1が資格情報を提供し、**ドメインコントローラー**がUser1にKerberos **TGT**を返します。
2. User1は**TGT**を使用して、Server1に接続するための**サービスチケット**を要求します。
3. User1は**Server1**に**接続**し、**サービスチケット**を提供します。
4. **Server1**にはUser1の資格情報やUser1の**TGT**がキャッシュされていないため、Server1から2番目のサーバーにログインしようとすると、**認証できません**。

### 制約のない委任

PCで**制約のない委任**が有効になっている場合、**サーバー**はそれにアクセスするすべてのユーザーの**TGT**を取得します。さらに、制約のない委任が使用されている場合、おそらく**ドメインコントローラーを侵害**できるでしょう。\
[**制約のない委任ページで詳細を確認**](unconstrained-delegation.md)。

### CredSSP

この問題を回避する別の方法は、[**著しく安全でない**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**です。Microsoftによると：

> CredSSP認証は、ユーザーの資格情報をローカルコンピューターからリモートコンピューターに委任します。この慣行は、リモート操作のセキュリティリスクを高めます。リモートコンピューターが侵害された場合、資格情報が渡されると、その資格情報を使用してネットワークセッションを制御することができます。

セキュリティ上の懸念から、**CredSSP**は本番システム、機密ネットワーク、類似の環境で無効にすることが強く推奨されます。**CredSSP**が有効かどうかを確認するには、`Get-WSManCredSSP`コマンドを実行できます。このコマンドにより、**CredSSPの状態を確認**し、**WinRM**が有効になっている場合はリモートで実行することもできます。
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 対処法

### Invoke Command

ダブルホップの問題に対処するために、ネストされた `Invoke-Command` を使用する方法が提示されています。これは問題を直接解決するのではなく、特別な構成を必要とせずに回避策を提供します。このアプローチにより、初期の攻撃マシンから実行されたPowerShellコマンドまたは最初のサーバーと事前に確立されたPS-Sessionを介して、セカンダリサーバーでコマンド (`hostname`) を実行できます。以下にその方法を示します：
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### PSSession構成の登録

ダブルホップ問題をバイパスする解決策として、`Register-PSSessionConfiguration`を`Enter-PSSession`と共に使用する方法が提案されています。この方法は、`evil-winrm`とは異なるアプローチが必要であり、ダブルホップの制限を受けないセッションを可能にします。
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### ポートフォワーディング

中間ターゲットのローカル管理者の場合、ポートフォワーディングを使用してリクエストを最終サーバーに送信できます。 `netsh`を使用して、ポートフォワーディングのためのルールを追加し、Windowsファイアウォールルールを転送されたポートを許可することができます。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`は、WinRMリクエストを転送するために使用できます。PowerShellの監視が懸念される場合、検出されにくいオプションとして機能するかもしれません。以下のコマンドは、その使用方法を示しています:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

最初のサーバーにOpenSSHをインストールすると、ジャンプボックスシナリオに特に有用なダブルホップの問題の回避策が可能になります。この方法では、Windows用のOpenSSHのCLIインストールとセットアップが必要です。パスワード認証用に構成されている場合、中間サーバーがユーザーの代わりにTGTを取得できるようになります。

#### OpenSSHのインストール手順

1. 最新のOpenSSHリリースzipをダウンロードして、対象サーバーに移動します。
2. zipファイルを解凍し、`Install-sshd.ps1`スクリプトを実行します。
3. ポート22を開くためのファイアウォールルールを追加し、SSHサービスが実行されていることを確認します。

`Connection reset`エラーを解決するには、アクセス権限を更新して、OpenSSHディレクトリで誰もが読み取りおよび実行アクセスを許可する必要がある場合があります。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 参考文献

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または**PEASSの最新バージョンにアクセス**したいですか？またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングトリックを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と**[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
