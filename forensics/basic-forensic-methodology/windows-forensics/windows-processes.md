<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


## smss.exe

**セッションマネージャ**。\
セッション0では**csrss.exe**と**wininit.exe**（**OSサービス**）が開始されますが、セッション1では**csrss.exe**と**winlogon.exe**（**ユーザーセッション**）が開始されます。ただし、プロセスツリーには**そのバイナリのプロセスが1つだけ**表示されるはずです。

また、セッション0と1以外のセッションは、RDPセッションが発生していることを意味する場合があります。


## csrss.exe

**クライアント/サーバーランサブシステムプロセス**。\
プロセスとスレッドを管理し、他のプロセスに**Windows API**を利用可能にし、**ドライブレターをマップ**し、**一時ファイルを作成**し、**シャットダウンプロセス**を処理します。

セッション0とセッション1のそれぞれに1つずつ存在します（プロセスツリーには2つのプロセスがあります）。新しいセッションごとにもう1つ作成されます。


## winlogon.exe

**Windowsログオンプロセス**。\
ユーザーの**ログオン**/**ログオフ**に責任があります。ユーザー名とパスワードを求めるために**logonui.exe**を起動し、それから**lsass.exe**を呼び出して検証します。

その後、**`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**にある**Userinit**キーで指定された**userinit.exe**を起動します。

さらに、前述のレジストリには**Shellキー**に**explorer.exe**があるはずであり、それは**マルウェアの持続性手法**として悪用される可能性があります。


## wininit.exe

**Windows初期化プロセス**。\
セッション0で**services.exe**、**lsass.exe**、**lsm.exe**を起動します。プロセスは1つだけであるはずです。


## userinit.exe

**Userinitログオンアプリケーション**。\
**ntduser.datをHKCUに**ロードし、**ユーザー**の**環境**を初期化し、**ログオンスクリプト**と**GPO**を実行します。

**explorer.exe**を起動します。


## lsm.exe

**ローカルセッションマネージャ**。\
smss.exeと協力してユーザーセッションを操作します：ログオン/ログオフ、シェルの開始、デスクトップのロック/ロック解除など。

W7以降、lsm.exeはサービス（lsm.dll）に変換されました。

W7では1つのプロセスのみが存在し、そのうちの1つがDLLを実行するサービスです。


## services.exe

**サービス制御マネージャ**。\
**自動起動**と**ドライバ**として構成された**サービス**を**ロード**します。

**svchost.exe**、**dllhost.exe**、**taskhost.exe**、**spoolsv.exe**などの親プロセスです。

サービスは`HKLM\SYSTEM\CurrentControlSet\Services`で定義され、このプロセスはサービス情報のメモリ内データベースを維持し、sc.exeによってクエリできます。

**一部のサービス**は**独自のプロセス**で実行され、他のサービスは**svchost.exeプロセスを共有**します。

プロセスは1つだけであるはずです。


## lsass.exe

**ローカルセキュリティ機関サブシステム**。\
ユーザーの**認証**を担当し、**セキュリティトークン**を作成します。認証パッケージは`HKLM\System\CurrentControlSet\Control\Lsa`にあります。

**セキュリティイベントログ**に書き込みます。プロセスは1つだけであるはずです。

このプロセスはパスワードをダンプするために攻撃されやすいことに注意してください。


## svchost.exe

**汎用サービスホストプロセス**。\
複数のDLLサービスを1つの共有プロセスでホストします。

通常、**svchost.exe**は`-k`フラグとともに起動されます。これにより、レジストリ**HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**にクエリが送信され、-kで指定された引数を持つキーがあり、同じプロセスで起動するサービスが含まれています。

例：`-k UnistackSvcGroup`は次のものを起動します：`PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

**フラグ`-s`**も引数とともに使用される場合、svchostにはこの引数で指定されたサービスのみを起動するように要求されます。

`svchost.exe`の複数のプロセスが存在します。**`-k`フラグを使用していない**ものがあれば、それは非常に疑わしいです。**services.exeが親でない**場合も非常に疑わしいです。
## taskhost.exe

このプロセスは、DLLから実行されるプロセスのホストとして機能します。また、DLLから実行されるサービスを読み込みます。

W8では、これはtaskhostex.exeと呼ばれ、W10ではtaskhostw.exeと呼ばれます。


## explorer.exe

これは、**ユーザーのデスクトップ**とファイルの拡張子を介してのファイルの起動を担当するプロセスです。

**ログインしているユーザーごとに1つだけ**のプロセスが生成されるべきです。

これは**userinit.exe**から実行され、このプロセスには**親プロセス**が表示されないように終了する必要があります。


# 悪意のあるプロセスの検出

* 期待されるパスから実行されていますか？（Windowsのバイナリは一時的な場所から実行されません）
* 奇妙なIPと通信していますか？
* デジタル署名をチェックします（Microsoftのアーティファクトは署名されているはずです）
* 正しくスペルされていますか？
* 期待されるSIDの下で実行されていますか？
* 親プロセスは期待されるものですか（ある場合）？
* 子プロセスは期待されるものですか（cmd.exe、wscript.exe、powershell.exeなどはありませんか？）


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**または**[telegramグループ](https://t.me/peass)**に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
