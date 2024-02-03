<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

# ファームウェアの整合性

**カスタムファームウェアやコンパイル済みバイナリをアップロードして、整合性や署名検証の欠陥を悪用することができます**。バックドアバインドシェルのコンパイルには、以下の手順を実行できます:

1. firmware-mod-kit (FMK)を使用してファームウェアを抽出する。
2. 対象のファームウェアアーキテクチャとエンディアンを特定する。
3. Buildrootやその他の適切な方法を使用してクロスコンパイラを構築する。
4. クロスコンパイラを使用してバックドアを構築する。
5. バックドアを抽出したファームウェアの/usr/binディレクトリにコピーする。
6. 適切なQEMUバイナリを抽出したファームウェアのrootfsにコピーする。
7. chrootとQEMUを使用してバックドアをエミュレートする。
8. netcatを介してバックドアにアクセスする。
9. QEMUバイナリを抽出したファームウェアのrootfsから削除する。
10. FMKを使用して修正されたファームウェアを再パッケージする。
11. ファームウェア分析ツールキット(FAT)を使用してエミュレートし、netcatを使用して対象のバックドアIPとポートに接続して、バックドア付きファームウェアをテストする。

動的分析、ブートローダーの操作、またはハードウェアセキュリティテストを通じて既にrootシェルが取得されている場合、悪意のあるプリコンパイル済みバイナリ、例えばインプラントやリバースシェルが実行される可能性があります。Metasploitフレームワークや'msfvenom'のような自動化されたペイロード/インプラントツールを、以下の手順で活用できます:

1. 対象のファームウェアアーキテクチャとエンディアンを特定する。
2. Msfvenomを使用して、ターゲットペイロード、攻撃者ホストIP、リスニングポート番号、ファイルタイプ、アーキテクチャ、プラットフォーム、および出力ファイルを指定する。
3. ペイロードを侵害されたデバイスに転送し、実行権限があることを確認する。
4. Metasploitを準備して、msfconsoleを起動し、ペイロードに応じて設定を構成して、着信リクエストを処理する。
5. 侵害されたデバイスでmeterpreterリバースシェルを実行する。
6. 開かれるmeterpreterセッションを監視する。
7. ポストエクスプロイト活動を実行する。

可能であれば、起動スクリプト内の脆弱性を悪用して、再起動をまたいでデバイスへの永続的なアクセスを得ることができます。これらの脆弱性は、起動スクリプトが、SDカードやルートファイルシステム外でデータを保存するために使用されるフラッシュボリュームなど、信頼できないマウントされた場所にあるコードを参照、[シンボリックリンク](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)、または依存している場合に発生します。

# 参考文献
* 詳細については、[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)をチェックしてください。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
