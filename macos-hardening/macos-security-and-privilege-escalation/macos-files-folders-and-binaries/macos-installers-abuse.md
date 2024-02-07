# macOS インストーラーの悪用

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つけてください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローしてください [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
- **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに PR を提出して、あなたのハッキングテクニックを共有してください。

</details>

## Pkg の基本情報

macOS の **インストーラーパッケージ**（または `.pkg` ファイルとしても知られる）は、macOS が **ソフトウェアを配布** するために使用するファイル形式です。これらのファイルは、**ソフトウェアがインストールおよび正常に実行されるために必要なすべてを含む箱のようなもの** です。

パッケージファイル自体は、**ターゲットコンピューターにインストールされるファイルとディレクトリの階層** を保持するアーカイブです。また、**設定ファイルのセットアップやソフトウェアの古いバージョンのクリーンアップなど、インストール前後にタスクを実行するスクリプト** も含めることができます。

### 階層

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: カスタマイズ（タイトル、ウェルカムテキストなど）およびスクリプト/インストールチェック
- **PackageInfo (xml)**: 情報、インストール要件、インストール場所、実行するスクリプトへのパス
- **Bill of materials (bom)**: ファイルのリスト、ファイルの権限とともにインストール、更新、削除する
- **Payload (CPIOアーカイブgzip圧縮)**: PackageInfo から `install-location` にインストールするファイル
- **Scripts (CPIOアーカイブgzip圧縮)**: インストール前後のスクリプトや実行用の一時ディレクトリに展開されるその他のリソース
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

DMGファイル、またはApple Disk Imagesは、AppleのmacOSで使用されるディスクイメージのファイル形式です。DMGファイルは基本的には**マウント可能なディスクイメージ**（独自のファイルシステムを含む）であり、通常は圧縮され、時には暗号化された生のブロックデータを含んでいます。DMGファイルを開くと、macOSはそれを物理ディスクのように**マウント**し、その内容にアクセスできるようにします。

### 階層

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

DMGファイルの階層は、内容によって異なることがあります。ただし、アプリケーションのDMGの場合、通常はこの構造に従います：

- トップレベル：これはディスクイメージのルートです。通常、アプリケーションとmacOSのApplicationsフォルダへのリンクが含まれています。
- アプリケーション（.app）：これが実際のアプリケーションです。macOSでは、アプリケーションは通常、アプリケーションを構成する多くの個々のファイルやフォルダを含むパッケージです。
- Applicationsリンク：これはmacOSのApplicationsフォルダへのショートカットです。これは、アプリケーションをインストールしやすくするためのものです。.appファイルをこのショートカットにドラッグしてアプリをインストールできます。

## pkgの悪用による特権昇格

### 公開ディレクトリからの実行

たとえば、事前または事後のインストールスクリプトが**`/var/tmp/Installerutil`**から実行されている場合、攻撃者はそのスクリプトを制御できるため、実行されるたびに特権を昇格させることができます。また、別の類似の例：

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

これは、いくつかのインストーラやアップデータが**rootとして何かを実行**するために呼び出す[公開関数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)です。この関数は、**実行するファイルのパス**をパラメータとして受け入れますが、攻撃者がこのファイルを**変更**できれば、特権を昇格させるためにその実行を**悪用**することができます。
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### マウントによる実行

インストーラが`/tmp/fixedname/bla/bla`に書き込む場合、`/tmp/fixedname`に所有者がいないマウントを作成することが可能です。これにより、インストール中に**任意のファイルを変更**してインストールプロセスを悪用することができます。

これの例として、**CVE-2021-26089**があり、**定期スクリプトを上書き**してルートとして実行することに成功しました。詳細については、以下のトークをご覧ください: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## マルウェアとしてのpkg

### 空のペイロード

単に**`.pkg`**ファイルを生成し、ペイロードなしで**事前および事後インストールスクリプト**を含めることが可能です。

### Distribution xml内のJS

パッケージの**distribution xml**ファイルに**`<script>`**タグを追加することが可能で、そのコードが実行され、**`system.run`**を使用して**コマンドを実行**することができます:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
