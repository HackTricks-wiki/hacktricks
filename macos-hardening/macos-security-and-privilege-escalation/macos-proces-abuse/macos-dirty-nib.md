# macOS Dirty NIB

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 **@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローする。

- [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

**この技術の詳細については、元の投稿を確認してください: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)**。以下は要約です：

NIBファイルは、Appleの開発エコシステムの一部であり、アプリケーション内の**UI要素**とそれらの相互作用を定義するために意図されています。ウィンドウやボタンなどのシリアライズされたオブジェクトを含み、実行時に読み込まれます。Appleは現在、より包括的なUIフローの視覚化のためにStoryboardsを推奨していますが、NIBファイルは引き続き使用されています。

### NIBファイルのセキュリティ上の懸念
**NIBファイルはセキュリティリスク**であることに注意することが重要です。これらは**任意のコマンドを実行**する可能性があり、アプリ内のNIBファイルの変更はGatekeeperがアプリを実行するのを妨げないため、重大な脅威となります。

### Dirty NIB注入プロセス
#### NIBファイルの作成とセットアップ
1. **初期セットアップ**:
   - XCodeを使用して新しいNIBファイルを作成します。
   - インターフェースにオブジェクトを追加し、そのクラスを`NSAppleScript`に設定します。
   - User Defined Runtime Attributesを介して初期の`source`プロパティを構成します。

2. **コード実行ガジェット**:
   - このセットアップにより、必要に応じてAppleScriptを実行できます。
   - ボタンを統合して`Apple Script`オブジェクトをアクティブにし、特に`executeAndReturnError:`セレクタをトリガーします。

3. **テスト**:
   - テスト目的の簡単なAppleScript:
   ```bash
   set theDialogText to "PWND"
   display dialog theDialogText
   ```
   - XCodeデバッガで実行してボタンをクリックしてテストします。

#### アプリケーションのターゲティング（例: Pages）
1. **準備**:
   - ターゲットアプリ（例: Pages）を別のディレクトリ（例: `/tmp/`）にコピーします。
   - Gatekeeperの問題を回避し、アプリをキャッシュするためにアプリを起動します。

2. **NIBファイルの上書き**:
   - 既存のNIBファイル（例: About Panel NIB）を作成したDirtyNIBファイルで置き換えます。

3. **実行**:
   - アプリと対話して実行をトリガーします（例: `About`メニューアイテムを選択）。

#### 概念の証明: ユーザーデータへのアクセス
- ユーザーの同意なしに写真などのユーザーデータにアクセスして抽出するためにAppleScriptを変更します。

### コードサンプル: 悪意のある.xibファイル
- 任意のコードを実行することを示す[**悪意のある.xibファイルのサンプル**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)にアクセスしてレビューします。

### 起動制約の対処
- 起動制約は、予期しない場所（例: `/tmp`）からのアプリの実行を妨げます。
- 起動制約で保護されていないアプリを特定し、NIBファイルの注入の対象にすることが可能です。

### 追加のmacOS保護
macOS Sonoma以降、Appバンドル内の変更が制限されています。ただし、以前の方法は次のとおりです：
1. アプリを別の場所（例: `/tmp`）にコピーします。
2. 最初の保護をバイパスするためにアプリバンドル内のディレクトリの名前を変更します。
3. Gatekeeperに登録するためにアプリを実行した後、アプリバンドルを変更します（例: MainMenu.nibをDirty.nibに置き換えます）。
4. ディレクトリの名前を元に戻し、注入されたNIBファイルを実行するためにアプリを再実行します。

**注意**: 最近のmacOSのアップデートにより、Gatekeeperのキャッシュ後にアプリバンドル内のファイルの変更が防止され、この脆弱性が無効化されました。
