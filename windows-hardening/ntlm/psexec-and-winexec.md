# PsExec/Winexec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を見たい**ですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたい**ですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。これは私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## それらの動作方法

1. SMB経由でサービスバイナリをADMIN$共有にコピーする
2. バイナリを指すリモートマシン上にサービスを作成する
3. リモートでサービスを開始する
4. 終了時にサービスを停止し、バイナリを削除する

## **手動でのPsExec**

まず、msfvenomで生成しVeilで難読化した（AVがフラグを立てないようにするため）ペイロード実行可能ファイルがあると仮定しましょう。この場合、私はmeterpreter reverse_httpペイロードを作成し、'met8888.exe'と名付けました。

**バイナリをコピーする**。"jarrieta"コマンドプロンプトから、単にバイナリをADMIN$にコピーします。実際には、ファイルシステム上のどこにでもコピーして隠すことができます。

![](../../.gitbook/assets/copy\_binary\_admin.png)

**サービスを作成する**。Windowsの`sc`コマンドは、Windowsサービスを問い合わせ、作成、削除などを行うために使用され、リモートで使用することができます。詳細は[こちら](https://technet.microsoft.com/en-us/library/bb490995.aspx)を読んでください。コマンドプロンプトから、アップロードしたバイナリを指す"meterpreter"という名前のサービスをリモートで作成します：

![](../../.gitbook/assets/sc\_create.png)

**サービスを開始する**。最後のステップは、サービスを開始してバイナリを実行することです。_注記:_ サービスが開始されると"タイムアウト"し、エラーが生成されます。それは、私たちのmeterpreterバイナリが実際のサービスバイナリではなく、期待される応答コードを返さないためです。それは問題ありません。私たちが必要なのは、一度実行して発火させることだけです：

![](../../.gitbook/assets/sc\_start\_error.png)

Metasploitリスナーを見ると、セッションが開始されたことがわかります。

**サービスをクリーンアップする。**

![](../../.gitbook/assets/sc\_delete.png)

ここから抜粋：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows SysinternalsバイナリのPsExec.exeも使用できます：**

![](<../../.gitbook/assets/image (165).png>)

また、[**SharpLateral**](https://github.com/mertdas/SharpLateral)を使用することもできます：

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、HackTricksをPDFで**ダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
