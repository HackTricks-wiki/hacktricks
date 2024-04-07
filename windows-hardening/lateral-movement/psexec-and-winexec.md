# PsExec/Winexec/ScExec

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

## 動作原理

以下の手順に従って、サービスバイナリがSMB経由で標的マシンでリモート実行される方法が説明されています：

1. **ADMIN$共有にサービスバイナリをコピー**します。
2. バイナリを指定して、リモートマシン上でサービスを**作成**します。
3. サービスを**リモートで起動**します。
4. 終了時に、サービスを**停止**し、バイナリを削除します。

### **PsExecの手動実行プロセス**

msfvenomで作成され、Veilを使用してウイルス対策ソフトの検出を回避するために難読化された、メータープリターの逆接続HTTPペイロードを表す実行可能ペイロード（'met8888.exe'という名前）があると仮定します。次の手順を実行します：

- **バイナリのコピー**：実行可能ファイルは、コマンドプロンプトからADMIN$共有にコピーされますが、ファイルシステムの任意の場所に配置して隠されたままにすることもできます。

- **サービスの作成**：Windowsの`sc`コマンドを使用して、Windowsサービスをリモートでクエリ、作成、削除できるため、アップロードされたバイナリを指すサービス「meterpreter」を作成します。

- **サービスの開始**：最後のステップは、サービスを開始することであり、バイナリが正規のサービスバイナリではなく、期待される応答コードを返さないため、「タイムアウト」エラーが発生する可能性が高いです。このエラーは、主な目標がバイナリの実行であるため、重要ではありません。

Metasploitリスナーを観察すると、セッションが正常に開始されたことがわかります。

[`sc`コマンドについて詳しく学ぶ](https://technet.microsoft.com/en-us/library/bb490995.aspx)。

詳細な手順はこちら：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows SysinternalsバイナリPsExec.exeを使用することもできます：**

![](<../../.gitbook/assets/image (165).png>)

[**SharpLateral**](https://github.com/mertdas/SharpLateral)も使用できます：

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローしてください**
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>