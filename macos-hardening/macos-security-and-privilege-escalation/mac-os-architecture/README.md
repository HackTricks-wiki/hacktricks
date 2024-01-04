# macOSカーネルとシステム拡張

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見する。私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## XNUカーネル

**macOSの核心はXNU**で、「X is Not Unix」を意味します。このカーネルは、**Machマイクロカーネル**（後で議論される）とBerkeley Software Distribution（**BSD**）の要素から構成されています。XNUはまた、**I/O Kitと呼ばれるシステムを介してカーネルドライバーのプラットフォームを提供します**。XNUカーネルはDarwinオープンソースプロジェクトの一部であり、**そのソースコードは自由にアクセス可能です**。

セキュリティ研究者やUnix開発者の視点から見ると、**macOS**は洗練されたGUIとカスタムアプリケーションのホストを備えた**FreeBSD**システムに非常に**似ている**と感じることがあります。BSD用に開発されたほとんどのアプリケーションは、Unixユーザーに馴染みのあるコマンドラインツールがmacOSにすべて存在するため、変更を加えることなくmacOSでコンパイルして実行できます。しかし、XNUカーネルがMachを組み込んでいるため、従来のUnixライクなシステムとmacOSの間にはいくつかの重要な違いがあり、これらの違いが潜在的な問題を引き起こしたり、ユニークな利点を提供したりすることがあります。

XNUのオープンソースバージョン: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Machは**UNIX互換**を目指して設計された**マイクロカーネル**です。その主要な設計原則の一つは、**カーネル**空間で実行される**コード**の量を**最小限**にし、ファイルシステム、ネットワーキング、I/Oなどの典型的なカーネル機能を**ユーザーレベルのタスクとして実行することを可能にすることでした**。

XNUでは、Machはプロセッサのスケジューリング、マルチタスキング、仮想メモリ管理など、カーネルが通常扱う多くの重要な低レベルの操作を**担当しています**。

### BSD

XNU**カーネル**は、**FreeBSD**プロジェクトから派生した大量のコードも**組み込んでいます**。このコードはMachと共に、同じアドレス空間内でカーネルの一部として**実行されます**。ただし、XNU内のFreeBSDコードは、Machとの互換性を確保するために必要な変更が加えられているため、元のFreeBSDコードとは大きく異なる場合があります。FreeBSDは多くのカーネル操作に貢献しており、以下を含みます：

* プロセス管理
* シグナル処理
* 基本的なセキュリティメカニズム、ユーザーとグループの管理を含む
* システムコールインフラストラクチャ
* TCP/IPスタックとソケット
* ファイアウォールとパケットフィルタリング

BSDとMachの相互作用を理解することは、それらの異なる概念フレームワークのために複雑になることがあります。例えば、BSDはプロセスを基本的な実行単位として使用するのに対し、Machはスレッドに基づいて操作します。この違いは、XNUでは**各BSDプロセスを正確に1つのMachスレッドを含むMachタスクに関連付けることで調整されます**。BSDのfork()システムコールが使用されると、カーネル内のBSDコードはMach関数を使用してタスクとスレッド構造を作成します。

さらに、**MachとBSDはそれぞれ異なるセキュリティモデルを維持しています**：**Machの**セキュリティモデルは**ポート権限**に基づいているのに対し、BSDのセキュリティモデルは**プロセス所有権**に基づいて操作します。これら2つのモデル間の不一致は、時折ローカル特権昇格の脆弱性を引き起こしてきました。典型的なシステムコールに加えて、**ユーザースペースのプログラムがカーネルと対話するためのMachトラップもあります**。これらの異なる要素が合わさって、macOSカーネルの多面的でハイブリッドなアーキテクチャを形成しています。

### I/O Kit - ドライバー

I/O KitはXNUカーネルのオープンソースでオブジェクト指向の**デバイスドライバーフレームワーク**であり、**動的にロードされるデバイスドライバー**の追加と管理を担当しています。これらのドライバーは、例えば異なるハードウェアで使用するためにカーネルに動的に追加されるモジュラーコードを可能にします。

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - プロセス間通信

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### カーネルキャッシュ

**カーネルキャッシュ**は、XNUカーネルの**事前にコンパイルされ、事前にリンクされたバージョン**であり、重要なデバイス**ドライバー**と**カーネル拡張**も含まれています。圧縮された形式で保存され、ブートアッププロセス中にメモリに解凍されます。カーネルキャッシュは、カーネルと重要なドライバーの準備ができたバージョンを利用可能にすることで、ブート時にこれらのコンポーネントを動的にロードしてリンクするためにかかる時間とリソースを削減し、**より高速なブート時間**を実現します。

iOSでは**`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**に位置していますが、macOSでは**`find / -name kernelcache 2>/dev/null`**で見つけることができます。

#### IMG4

IMG4ファイル形式は、AppleがiOSおよびmacOSデバイスでファームウェアコンポーネント（**カーネルキャッシュ**など）を安全に**保存および検証するために使用するコンテナ形式**です。IMG4形式にはヘッダーと、実際のペイロード（カーネルやブートローダーなど）、署名、およびマニフェストプロパティのセットをカプセル化するいくつかのタグが含まれています。この形式は暗号化検証をサポートしており、デバイスは実行する前にファームウェアコンポーネントの真正性と完全性を確認できます。

通常、以下のコンポーネントで構成されています：

* **ペイロード（IM4P）**：
* しばしば圧縮されています（LZFSE4、LZSS、…）
* オプションで暗号化されています
* **マニフェスト（IM4M）**：
* 署名が含まれています
* 追加のキー/値辞書
* **リストア情報（IM4R）**：
* APNonceとしても知られています
* 一部のアップデートのリプレイを防ぎます
* オプション：通常、これは見つかりません

カーネルキャッシュを解凍する：
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### カーネルキャッシュシンボル

時々Appleは**シンボル**を含む**カーネルキャッシュ**をリリースします。シンボル付きのファームウェアをダウンロードするには、[https://theapplewiki.com](https://theapplewiki.com/)のリンクをたどります。

### IPSW

これらは[**https://ipsw.me/**](https://ipsw.me/)からダウンロードできるAppleの**ファームウェア**です。他のファイルの中に**カーネルキャッシュ**が含まれています。\
ファイルを**抽出**するには、単に**解凍**します。

ファームウェアを抽出すると、**`kernelcache.release.iphone14`**のようなファイルが得られます。これは**IMG4**形式で、興味深い情報を抽出するには以下を使用します：

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
```markdown
シンボルをチェックするには、以下のコマンドを使用します: **`nm -a kernelcache.release.iphone14.e | wc -l`**

これで、**すべての拡張機能を抽出する**か、または**興味のある特定の拡張機能を抽出する**ことができます:
```
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS カーネル拡張

macOSはカーネル拡張（.kext）の読み込みに対して**非常に制限的**です。これはコードが高い権限で実行されるためです。実際、デフォルトではバイパスが見つからない限り、ほぼ不可能です。

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS システム拡張

カーネル拡張の使用を避けるために、macOSはシステム拡張を作成しました。これにより、開発者はカーネルと対話するためのユーザーレベルのAPIを提供します。

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
