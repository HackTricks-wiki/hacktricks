# Kerberos Double Hop Problem

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有する**には、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## はじめに

Kerberosの「ダブルホップ」問題は、**Kerberos認証を2つのホップを介して**使用しようとするときに発生します。たとえば、**PowerShell**/**WinRM**を使用する場合です。

**Kerberos**を介した**認証**が行われると、**資格情報**は**メモリにキャッシュされません**。したがって、mimikatzを実行しても、ユーザーの資格情報をマシンで見つけることはできません。

これは、Kerberosで接続する際に次の手順が実行されるためです：

1. User1が資格情報を提供し、**ドメインコントローラ**がUser1にKerberos **TGT**を返します。
2. User1は**TGT**を使用して、**Server1**に接続するための**サービスチケット**を要求します。
3. User1が**Server1**に接続し、**サービスチケット**を提供します。
4. **Server1**にはUser1の資格情報やUser1の**TGT**がキャッシュされていません。そのため、Server1から2番目のサーバーにログインしようとすると、**認証できません**。

### 制約のない委任

PCで**制約のない委任**が有効になっている場合、**Server**はそれにアクセスするすべてのユーザーの**TGT**を取得します。さらに、制約のない委任が使用されている場合、おそらく**ドメインコントローラ**を**侵害**できる可能性があります。\
[**制約のない委任ページ**](unconstrained-delegation.md)で詳細を確認してください。

### CredSSP

この問題を回避するために**システム管理者**に提案される別のオプションは、[**著しく安全でない**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider**です。CredSSPを有効にすることは、多くのフォーラムで何年も前から言及されてきた解決策です。Microsoftから：

_「CredSSP認証は、ユーザーの資格情報をローカルコンピュータからリモートコンピュータに委任します。この慣行は、リモート操作のセキュリティリスクを増加させます。リモートコンピュータが侵害された場合、資格情報が渡されると、その資格情報を使用してネットワークセッションを制御できます。」_

本番システム、機密ネットワークなどで**CredSSPが有効**になっている場合、無効にすることが推奨されます。CredSSPのステータスを**簡単に確認**する方法は、`Get-WSManCredSSP`を実行することです。WinRMが有効になっている場合、リモートで実行できます。
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 回避策

### Invoke Command <a href="#invoke-command" id="invoke-command"></a>

この方法は、二重ホップの問題と「協力して」作業するものであり、必ずしも解決するものではありません。構成に依存せず、攻撃ボックスから簡単に実行できます。基本的には**ネストされた`Invoke-Command`**です。

これは、**2番目のサーバーで`hostname`を実行**します。
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
あなたは最初のサーバーと**PS-Session**を確立し、単純にそこから`Invoke-Command`を`$cred`と一緒に実行することもできます。ただし、攻撃ボックスから実行すると、タスクが集中します。
```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```
### PSSession構成の登録

代わりに**`evil-winrm`**を使用する代わりに**`Enter-PSSession`**コマンドレットを使用すると、**`Register-PSSessionConfiguration`**を使用して再接続し、ダブルホップ問題をバイパスできます。
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

中間ターゲット**bizintel: 10.35.8.17**でローカル管理者権限を持っているため、リクエストを最終/サードサーバー**secdev: 10.35.8.23**に送信するポートフォワーディングルールを追加できます。

**netsh**を使用して、ワンライナーを抽出してルールを追加できます。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```
So **the first server** is listening on port 5446 and will forward requests hitting 5446 off to **the second server** port 5985 (aka WinRM).

Then punch a hole in the Windows firewall, which can also be done with a swift netsh one-liner.
```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
今、最初のサーバーに転送されるセッションを確立します。

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

**Portforwarding WinRM** リクエストも、**`winrs.exe`** を使用すると機能するようです。PowerShell が監視されていることを認識している場合、これはより良い選択肢かもしれません。以下のコマンドは、`hostname` の結果として "secdev" を返します。
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### Kerberos Double Hop Problem

`Invoke-Command`と同様に、攻撃者はシステムコマンドを引数として簡単に発行できるため、スクリプト化することができます。一般的なバッチスクリプト例 _winrm.bat_:

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

この方法は、最初のサーバーボックスに[OpenSSHをインストール](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH)する必要があります。Windows用のOpenSSHをCLIを使用して完全にインストールすることができ、それほど時間がかからず、マルウェアとして検出されることはありません！

もちろん、特定の状況では実現不可能であったり、手間がかかったり、一般的なOpSecリスクがあるかもしれません。

この方法は、ジャンプボックスのセットアップで特に有用です - それ以外のネットワークにアクセスできない場合。SSH接続が確立されると、ユーザー/攻撃者はダブルホップの問題に突入することなく、セグメント化されたネットワークに対して必要なだけ多くの `New-PSSession` を開始できます。

OpenSSHで**パスワード認証**を使用するように構成されている場合（鍵やKerberosではなく）、**ログオンタイプは8**、つまり_ネットワーククリアテキストログオン_です。これは、パスワードが平文で送信されることを意味するものではありません - 実際にはSSHによって暗号化されます。到着時には、セッションのための[認証パッケージ](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN)を介してクリアテキストに復号化され、さらにジューシーなTGTを要求するために使用されます！

これにより、中間サーバーがあなたの代わりにTGTを要求して取得し、中間サーバーにローカルに保存することができます。その後、セッションはこのTGTを使用して他のサーバーに認証（PSリモート）できます。

#### OpenSSHインストールシナリオ

最新の[OpenSSHリリースzipをgithubからダウンロード](https://github.com/PowerShell/Win32-OpenSSH/releases)して攻撃ボックスに移動し（またはジャンプボックスに直接ダウンロード）、zipを好きな場所に解凍します。その後、インストールスクリプト `Install-sshd.ps1` を実行します。

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

最後に、**ポート22を開く**ためのファイアウォールルールを追加します。SSHサービスがインストールされていることを確認し、それらを起動します。これらのサービスの両方が実行されている必要があります。

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

`Connection reset`エラーが表示された場合は、**Everyone: Read & Execute**を許可するためにアクセス許可を更新してください。
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

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
