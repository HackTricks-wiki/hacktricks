# macOSインストーラーの悪用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Pkgの基本情報

macOSの**インストーラーパッケージ**（`.pkg`ファイルとも呼ばれる）は、macOSで**ソフトウェアを配布**するために使用されるファイル形式です。これらのファイルは、ソフトウェアのインストールと正常な動作に必要なすべてのものを含む**ボックスのようなもの**です。

パッケージファイル自体は、**ターゲットコンピュータにインストールされるファイルとディレクトリの階層**を保持するアーカイブです。また、ソフトウェアの古いバージョンをクリーンアップしたり、設定ファイルをセットアップしたりするための**インストール前後のタスクを実行するスクリプト**も含めることができます。

### 階層

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribution (xml)**: カスタマイズ（タイトル、ウェルカムテキストなど）とスクリプト/インストールチェック
* **PackageInfo (xml)**: 情報、インストール要件、インストール場所、実行するスクリプトへのパス
* **Bill of materials (bom)**: インストール、更新、または削除するファイルのリストとファイルのアクセス許可
* **Payload (CPIOアーカイブgzip圧縮)**: PackageInfoの`install-location`にインストールするファイル
* **Scripts (CPIOアーカイブgzip圧縮)**: インストール前後のスクリプトやその他のリソースを一時ディレクトリに抽出して実行するためのもの。

### 解凍
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## DMGの基本情報

DMGファイル、またはApple Disk Imagesは、AppleのmacOSで使用されるディスクイメージのファイル形式です。DMGファイルは、基本的には**マウント可能なディスクイメージ**（独自のファイルシステムを含む）であり、通常は圧縮され、時には暗号化された生のブロックデータを含んでいます。DMGファイルを開くと、macOSはそれを物理ディスクのようにマウントし、その内容にアクセスすることができます。

### 階層

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

DMGファイルの階層は、コンテンツに基づいて異なる場合があります。ただし、アプリケーションのDMGの場合、通常は次の構造に従います。

* トップレベル：これはディスクイメージのルートです。通常、アプリケーションとアプリケーションフォルダへのリンクが含まれています。
* アプリケーション（.app）：これが実際のアプリケーションです。macOSでは、アプリケーションは通常、アプリケーションを構成する多くの個々のファイルとフォルダを含むパッケージです。
* アプリケーションリンク：これはmacOSのApplicationsフォルダへのショートカットです。これの目的は、アプリケーションのインストールを簡単にすることです。.appファイルをこのショートカットにドラッグしてアプリをインストールできます。

## pkgの乱用による特権昇格

### パブリックディレクトリからの実行

もし、事前または事後のインストールスクリプトが**`/var/tmp/Installerutil`**から実行されている場合、攻撃者はそのスクリプトを制御できるため、実行されるたびに特権を昇格させることができます。また、別の類似の例としては次のようなものがあります：

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは、いくつかのインストーラやアップデータが**rootとして何かを実行**するために呼び出す[公開関数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この関数は、**実行するファイル**の**パス**をパラメータとして受け取りますが、攻撃者がこのファイルを**変更**できる場合、特権を昇格させるためにその実行を**乱用**することができます。
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
詳細については、このトークをチェックしてください：[https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### マウントによる実行

インストーラが`/tmp/fixedname/bla/bla`に書き込む場合、所有者のない`/tmp/fixedname`上に**マウントを作成**することができます。そのため、インストール中に任意のファイルを**変更してインストールプロセスを悪用**することができます。

これの例として、**CVE-2021-26089**があります。これは、定期的なスクリプトを上書きしてルートとして実行することに成功しました。詳細については、以下のトークを参照してください：[**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## マルウェアとしてのpkg

### 空のペイロード

単に**`.pkg`**ファイルを生成し、ペイロードなしで**事前および事後インストールスクリプト**を含めることができます。

### Distribution xml内のJS

パッケージの**distribution xml**ファイルに**`<script>`**タグを追加することができ、そのコードが実行され、**`system.run`**を使用してコマンドを実行できます：

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセス**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
