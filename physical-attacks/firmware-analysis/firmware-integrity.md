<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見る
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm**をフォローする**.
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する。

</details>

# ファームウェアの整合性

**カスタムファームウェアやコンパイルされたバイナリをアップロードして整合性や署名検証の欠陥を悪用**することができます。バックドアバインドシェルのコンパイルには次の手順が続けられます:

1. ファームウェアは firmware-mod-kit（FMK）を使用して抽出できます。
2. ターゲットのファームウェアアーキテクチャとエンディアンを特定する必要があります。
3. Buildrootや他の環境に適した方法を使用してクロスコンパイラを構築できます。
4. クロスコンパイラを使用してバックドアを構築できます。
5. バックドアを抽出されたファームウェアの /usr/bin ディレクトリにコピーできます。
6. 適切なQEMUバイナリを抽出されたファームウェアのrootfsにコピーできます。
7. chrootとQEMUを使用してバックドアをエミュレートできます。
8. バックドアにはnetcatを介してアクセスできます。
9. QEMUバイナリは抽出されたファームウェアのrootfsから削除する必要があります。
10. FMKを使用して修正されたファームウェアを再パッケージできます。
11. バックドア付きファームウェアは、ファームウェア解析ツールキット（FAT）を使用してエミュレートし、netcatを使用してターゲットのバックドアIPとポートに接続できます。

既にダイナミック解析、ブートローダー操作、またはハードウェアセキュリティテストを通じてルートシェルを取得している場合、インプラントやリバースシェルなどの事前にコンパイルされた悪意のあるバイナリを実行できます。Metasploitフレームワークや 'msfvenom'などの自動ペイロード/インプラントツールを使用する場合は、次の手順を使用できます:

1. ターゲットのファームウェアアーキテクチャとエンディアンを特定する必要があります。
2. Msfvenomを使用して、ターゲットペイロード、攻撃者のホストIP、リスニングポート番号、ファイルタイプ、アーキテクチャ、プラットフォーム、および出力ファイルを指定できます。
3. ペイロードを侵害されたデバイスに転送し、実行権限を持っていることを確認できます。
4. Metasploitを準備して、msfconsoleを起動し、設定をペイロードに応じて構成できます。
5. 侵害されたデバイスでメータプリタリバースシェルを実行できます。
6. メータプリタセッションが開かれると監視できます。
7. ポストエクスプロイテーション活動を実行できます。

可能であれば、起動スクリプト内の脆弱性を悪用して、再起動時にデバイスに持続的なアクセス権を取得することができます。これらの脆弱性は、起動スクリプトが、SDカードやルートファイルシステム以外のデータを保存するために使用されるフラッシュボリュームなどの信頼できないマウントされた場所にあるコードを参照、[シンボリックリンク](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)、または依存している場合に発生します。

## 参考文献
* 詳細については [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/) を参照してください。

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見る
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm**をフォローする**.
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する。

</details>
