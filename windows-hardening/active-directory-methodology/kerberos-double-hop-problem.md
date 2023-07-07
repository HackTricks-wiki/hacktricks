# Kerberosダブルホップ問題

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのスワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## はじめに

Kerberosの「ダブルホップ」問題は、攻撃者が**Kerberos認証を使用して2つのホップ**を介して攻撃しようとした場合に発生します。たとえば、**PowerShell**/**WinRM**を使用する場合です。

**Kerberos**を介した**認証**が行われると、**資格情報はメモリにキャッシュされません**。したがって、mimikatzを実行しても、ユーザーの資格情報はマシンに存在しません。

これは、Kerberosで接続する場合の手順です。

1. ユーザー1が資格情報を提供し、**ドメインコントローラ**がユーザー1にKerberos **TGT**を返します。
2. ユーザー1は**TGT**を使用して、**Server1**に接続するための**サービスチケット**を要求します。
3. ユーザー1は**Server1**に**接続**し、**サービスチケット**を提供します。
4. **Server1**には、ユーザー1の資格情報やユーザー1の**TGT**がキャッシュされていません。そのため、Server1から2番目のサーバーにログインしようとすると、ユーザー1は**認証できません**。

### 制約のない委任

PCで**制約のない委任**が有効になっている場合、これは発生しません。なぜなら、**サーバー**はそれにアクセスする各ユーザーの**TGT**を**取得**するからです。さらに、制約のない委任が使用されている場合、それを介してドメインコントローラを**侵害**する可能性があります。\
[**制約のない委任ページで詳細を確認**](unconstrained-delegation.md)してください。

### CredSSP

この問題を回避するために、**システム管理者**に提案される別のオプションは、[**明らかに安全ではない**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**です。CredSSPを有効にすることは、さまざまなフォーラムで何年も言及されてきた解決策です。Microsoftからの引用：

_「CredSSP認証は、ユーザーの資格情報をローカルコンピュータからリモートコンピュータに委任します。この方法は、リモート操作のセキュリティリスクを増加させます。リモートコンピュータが侵害された場合、資格情報が渡されると、ネットワークセッションを制御するために資格情報が使用される可能性があります。」_

本番システム、機密ネットワークなどでCredSSPが有効になっている場合は、無効にすることをお勧めします。CredSSPのステータスを**確認する**簡単な方法は、`Get-WSManCredSSP`を実行することです。WinRMが有効になっている場合、リモートで実行することもできます。
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 回避策

### Invoke Command <a href="#invoke-command" id="invoke-command"></a>

この方法は、二重ホップの問題を「一緒に動作させる」方法であり、必ずしも解決するものではありません。構成に依存せず、攻撃ボックスから簡単に実行できます。基本的には**ネストされた`Invoke-Command`**です。

これにより、**2番目のサーバーで`hostname`を実行**します。
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
あなたはまた、最初のサーバーとの**PS-Session**を確立し、単にそこから`Invoke-Command`を`$cred`とともに実行することもできます。ただし、攻撃ボックスから実行することで、タスクを集中化することができます。
```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```
### PSSessionの構成を登録する

**`evil-winrm`**を使用する代わりに、**`Enter-PSSession`**コマンドレットを使用することで、**`Register-PSSessionConfiguration`**を使用して再接続し、ダブルホップ問題をバイパスすることができます。
```powershell
# Register a new PS Session configuration
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
# Restar WinRM
Restart-Service WinRM
# Get a PSSession
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
# Check that in this case the TGT was sent and is in memory of the PSSession
klist
# In this session you won't have the double hop problem anymore
```
### ポートフォワーディング <a href="#portproxy" id="portproxy"></a>

中間ターゲットである**bizintel: 10.35.8.17**にローカル管理者権限があるため、リクエストを最終/3番目のサーバーである**secdev: 10.35.8.23**に送信するためのポートフォワーディングルールを追加できます。

**netsh**を使用して、ワンライナーを作成してルールを追加できます。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```
以下は、Kerberosのダブルホップ問題に関する内容です。

最初のサーバーはポート5446でリッスンし、ポート5985（WinRMとも呼ばれる）にリクエストを転送します。

次に、Windowsファイアウォールに穴を開けます。これは、迅速なnetshのワンライナーで行うこともできます。
```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
セッションを確立し、**最初のサーバー**に転送します。

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

**`winrs.exe`**を使用すると、**WinRMのポートフォワーディング**リクエストも動作するようです。PowerShellが監視されていることを認識している場合、これはより良いオプションです。以下のコマンドは、`hostname`の結果として「**secdev**」を返します。
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
`Invoke-Command`と同様に、攻撃者はシステムコマンドを引数として簡単にスクリプト化することができます。一般的なバッチスクリプトの例である_winrm.bat_：

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

この方法では、最初のサーバーボックスに[OpenSSHをインストール](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH)する必要があります。Windows用のOpenSSHのインストールは、**完全にCLIで**行うことができ、それほど時間もかかりません - さらに、マルウェアとして検出されることもありません！

もちろん、特定の状況では実現が困難であったり、手間がかかったり、一般的なOpSecのリスクがある場合もあります。

この方法は、ジャンプボックスのセットアップ時に特に有用です - それ以外のネットワークにアクセスできない状況で。SSH接続が確立されると、ユーザー/攻撃者はセグメント化されたネットワークに対して必要なだけ`New-PSSession`を発行することができ、ダブルホップの問題に突入することなく処理することができます。

OpenSSHで**パスワード認証**を使用するように構成されている場合（キーまたはKerberosではなく）、**ログオンタイプは8**、つまり_ネットワーククリアテキストログオン_です。これはパスワードがクリアテキストで送信されることを意味するものではありません - 実際にはSSHによって暗号化されます。到着時には、[認証パッケージ](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN)を介してクリアテキストに復号化され、セッションのためのジューシーなTGTをさらに要求するためです！

これにより、中間サーバーはあなたの代わりにTGTを要求して取得し、中間サーバーにローカルに保存することができます。その後、セッションはこのTGTを使用して追加のサーバーに対して認証（PSリモート）することができます。

#### OpenSSHのインストールシナリオ

最新の[OpenSSHリリースzipをgithubからダウンロード](https://github.com/PowerShell/Win32-OpenSSH/releases)し、攻撃ボックスに移動させるか、直接ジャンプボックスにダウンロードします。

zipファイルを適当な場所に解凍します。次に、インストールスクリプト`Install-sshd.ps1`を実行します。

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

最後に、**ポート22を開く**ためのファイアウォールルールを追加します。SSHサービスがインストールされていることを確認し、それらを起動します。これらのサービスは、SSHが動作するために実行されている必要があります。

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

`Connection reset`エラーが表示される場合は、ルートのOpenSSHディレクトリで**Everyone: Read & Execute**を許可するために権限を更新してください。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 参考文献

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
