# PsExec/Winexec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## 動作原理

1. サービスバイナリをSMBのADMIN$共有にコピーする
2. バイナリを指すようにリモートマシン上にサービスを作成する
3. サービスをリモートで起動する
4. 終了時にサービスを停止し、バイナリを削除する

## **手動でのPsExec**

まず、msfvenomで生成しVeilで曖昧化（AVに検出されないように）したペイロード実行可能ファイルがあると仮定しましょう。この場合、私はmeterpreter reverse\_httpペイロードを作成し、それを'met8888.exe'と呼びました。

**バイナリをコピー**します。"jarrieta"のコマンドプロンプトから、バイナリをADMIN$に単純にコピーします。しかし、実際にはファイルシステム上のどこにでもコピーして隠すことができます。

![](../../.gitbook/assets/copy\_binary\_admin.png)

**サービスを作成**します。Windowsの`sc`コマンドは、Windowsサービスのクエリ、作成、削除などに使用され、リモートで使用することもできます。詳細は[こちら](https://technet.microsoft.com/en-us/library/bb490995.aspx)を参照してください。コマンドプロンプトから、アップロードしたバイナリを指すように名前が"meterpreter"のサービスをリモートで作成します。

![](../../.gitbook/assets/sc\_create.png)

**サービスを起動**します。最後のステップは、サービスを起動してバイナリを実行することです。_注意:_ サービスが開始されると、"タイムアウト"が発生し、エラーが生成されます。これは、私たちのmeterpreterバイナリが実際のサービスバイナリではなく、期待される応答コードを返さないためです。しかし、実行されるだけで十分です。

![](../../.gitbook/assets/sc\_start\_error.png)

Metasploitのリスナーを見ると、セッションが開かれていることがわかります。

**サービスをクリーンアップ**します。

![](../../.gitbook/assets/sc\_delete.png)

ここから抽出：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows SysinternalsバイナリPsExec.exeも使用できます：**

![](<../../.gitbook/assets/image (165).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
