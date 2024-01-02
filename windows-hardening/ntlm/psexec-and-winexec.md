# PsExec/Winexec/ScExec

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) を使って AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFT**](https://opensea.io/collection/the-peass-family) コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングのコツを共有する。

</details>

## それらの動作原理

1. SMB 経由でサービスバイナリを ADMIN$ シェアにコピーする
2. バイナリを指すリモートマシン上にサービスを作成する
3. リモートでサービスを開始する
4. 終了時にサービスを停止し、バイナリを削除する

## **手動で PsExec を実行する**

まず、msfvenom で生成し Veil で難読化した（AV が検出しないようにするため）ペイロード実行可能ファイルがあると仮定します。この場合、私は meterpreter reverse_http ペイロードを作成し、'met8888.exe' と名付けました。

**バイナリをコピーする**。 "jarrieta" コマンドプロンプトから、バイナリを ADMIN$ に単純にコピーします。実際には、ファイルシステム上のどこにでもコピーして隠すことができます。

![](../../.gitbook/assets/copy\_binary\_admin.png)

**サービスを作成する**。 Windows の `sc` コマンドは、Windows サービスを問い合わせ、作成、削除などを行うために使用され、リモートで使用することができます。詳細は [こちら](https://technet.microsoft.com/en-us/library/bb490995.aspx) を読んでください。コマンドプロンプトから、アップロードしたバイナリを指す "meterpreter" という名前のサービスをリモートで作成します：

![](../../.gitbook/assets/sc\_create.png)

**サービスを開始する**。最後のステップは、サービスを開始してバイナリを実行することです。 _注記:_ サービスが開始されると "タイムアウト" し、エラーが生成されます。それは、私たちの meterpreter バイナリが実際のサービスバイナリではなく、期待される応答コードを返さないためです。それは問題ありません。一度実行して発火させるだけで十分です：

![](../../.gitbook/assets/sc\_start\_error.png)

Metasploit リスナーを見ると、セッションが開始されたことがわかります。

**サービスをクリーンアップする。**

![](../../.gitbook/assets/sc\_delete.png)

ここから抜粋： [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows Sysinternals バイナリ PsExec.exe も使用できます：**

![](<../../.gitbook/assets/image (165).png>)

また、[**SharpLateral**](https://github.com/mertdas/SharpLateral) を使用することもできます：

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
```markdown
{% endcode %}

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
```
