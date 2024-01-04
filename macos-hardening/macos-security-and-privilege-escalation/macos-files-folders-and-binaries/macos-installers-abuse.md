# macOSインストーラーの悪用

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## Pkg基本情報

macOSの**インストーラーパッケージ**（`.pkg`ファイルとしても知られています）は、macOSが**ソフトウェアを配布する**ために使用するファイル形式です。これらのファイルは、ソフトウェアが正しくインストールされ、実行されるために必要なすべてを含む**箱のようなもの**です。

パッケージファイル自体は、ターゲットコンピューターにインストールされる**ファイルとディレクトリの階層**を保持するアーカイブです。また、設定ファイルのセットアップやソフトウェアの古いバージョンのクリーンアップなど、インストールの前後に実行する**スクリプト**も含むことができます。

### 階層

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribution (xml)**: カスタマイズ（タイトル、ウェルカムテキストなど）およびスクリプト/インストールチェック
* **PackageInfo (xml)**: 情報、インストール要件、インストール場所、実行するスクリプトへのパス
* **Bill of materials (bom)**: ファイルの権限を持つインストール、更新、または削除するファイルのリスト
* **Payload (CPIOアーカイブgzip圧縮)**: PackageInfoの`install-location`にインストールするファイル
* **Scripts (CPIOアーカイブgzip圧縮)**: 実行のために一時ディレクトリに抽出されるインストール前後のスクリプトおよびその他のリソース。

### 展開
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
## DMG 基本情報

DMGファイル、またはApple Disk Imagesは、AppleのmacOSでディスクイメージに使用されるファイル形式です。DMGファイルは基本的に**マウント可能なディスクイメージ**（独自のファイルシステムを含む）であり、通常は圧縮され、時には暗号化された生のブロックデータを含んでいます。DMGファイルを開くと、macOSはそれを物理ディスクであるかのように**マウントし**、その内容にアクセスできるようになります。

### 階層

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

DMGファイルの階層は内容によって異なることがあります。しかし、アプリケーションのDMGの場合、通常はこの構造に従います：

* トップレベル：これはディスクイメージのルートです。しばしばアプリケーションと、アプリケーションフォルダへのリンクが含まれています。
* アプリケーション (.app)：これは実際のアプリケーションです。macOSでは、アプリケーションは通常、アプリケーションを構成する多くの個々のファイルとフォルダを含むパッケージです。
* アプリケーションリンク：これはmacOSのアプリケーションフォルダへのショートカットです。これの目的は、アプリケーションのインストールを簡単にすることです。.appファイルをこのショートカットにドラッグすることでアプリをインストールできます。

## pkg abuseによるPrivesc

### 公開ディレクトリからの実行

例えば、事前または事後のインストールスクリプトが**`/var/tmp/Installerutil`**から実行されている場合、攻撃者はそのスクリプトを制御して、実行されるたびに権限をエスカレーションすることができます。または、以下のような類似の例があります：

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは、いくつかのインストーラーやアップデーターが**rootとして何かを実行する**ために呼び出す[public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この関数は**実行する**ファイルの**パス**をパラメータとして受け入れますが、攻撃者がこのファイルを**変更**できれば、rootでの実行を**悪用**して**権限をエスカレーション**することができます。
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
詳細については、このトークをチェックしてください: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### マウントによる実行

インストーラーが `/tmp/fixedname/bla/bla` に書き込む場合、`/tmp/fixedname` 上に所有者なしで**マウントを作成**し、インストール中に任意のファイルを**変更して**インストールプロセスを悪用することが可能です。

これの一例は **CVE-2021-26089** で、定期的なスクリプトを**上書きして** root として実行を得ることに成功しました。詳細については、トークをご覧ください: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg をマルウェアとして使用

### 空のペイロード

ペイロードなしで、**事前および事後のインストールスクリプト**を含む **`.pkg`** ファイルを生成することが可能です。

### Distribution xml 内の JS

パッケージの **distribution xml** ファイルに **`<script>`** タグを追加することができ、そのコードは実行され、**`system.run`** を使用して**コマンドを実行**することができます:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式の PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、私たちの独占的な [**NFT**](https://opensea.io/collection/the-peass-family) コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを**共有する**。

</details>
