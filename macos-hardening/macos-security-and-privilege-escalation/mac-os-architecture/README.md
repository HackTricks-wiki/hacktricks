# macOS カーネル & システム拡張

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を通じて、ゼロからヒーローまでAWSハッキングを学びましょう</summary>

HackTricks をサポートする他の方法:

- **HackTricks で企業を宣伝**したい場合や **HackTricks を PDF でダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
- [**公式 PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見る
- 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする
- **ハッキングテクニックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出する

</details>

## XNU カーネル

**macOS の中核は XNU** であり、これは "X is Not Unix" の略です。このカーネルは基本的に **Mach マイクロカーネル**（後述）と **Berkeley Software Distribution (BSD)** の要素から構成されています。XNU はまた、**I/O Kit と呼ばれるシステムを介してカーネルドライバを提供**します。XNU カーネルは Darwin オープンソースプロジェクトの一部であり、**そのソースコードは自由にアクセスできます**。

セキュリティ研究者や Unix 開発者の観点から見ると、**macOS** はエレガントな GUI と多くのカスタムアプリケーションを備えた **FreeBSD** システムにかなり **似て**います。BSD 向けに開発されたほとんどのアプリケーションは、Unix ユーザにとって馴染みのあるコマンドラインツールが macOS にすべて備わっているため、修正を加えることなく macOS でコンパイルおよび実行できます。ただし、XNU カーネルには Mach が組み込まれているため、従来の Unix ライクなシステムと macOS の間にはいくつかの重要な違いがあり、これらの違いは潜在的な問題を引き起こすか、独自の利点を提供する可能性があります。

XNU のオープンソースバージョン: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach は **UNIX 互換のマイクロカーネル** であり、その主要な設計原則の1つは、**カーネルスペースで実行されるコードの量を最小限に抑え、ファイルシステム、ネットワーキング、I/O などの典型的なカーネル機能をユーザレベルのタスクとして実行**することです。

XNU では、Mach が **プロセッサスケジューリング、マルチタスキング、および仮想メモリ管理**など、通常カーネルが処理する多くの重要な低レベル操作を担当しています。

### BSD

XNU カーネルはまた、**FreeBSD** プロジェクトから派生した大量のコードを **組み込んで**います。このコードは、Mach と同じアドレス空間内でカーネルの一部として実行されます。ただし、XNU 内の FreeBSD コードは、Mach との互換性を確保するために変更が加えられたため、元の FreeBSD コードとは大きく異なる場合があります。FreeBSD は以下の多くのカーネル操作に貢献しています:

- プロセス管理
- シグナル処理
- ユーザーおよびグループ管理を含む基本的なセキュリティメカニズム
- システムコールインフラストラクチャ
- TCP/IP スタックおよびソケット
- ファイアウォールおよびパケットフィルタリング

BSD と Mach の相互作用を理解することは複雑であり、それぞれ異なる概念フレームワークを持っています。たとえば、BSD はプロセスを基本的な実行単位として使用しますが、Mach はスレッドに基づいて動作します。この相違は、XNU において BSD プロセスを Mach タスクに **関連付ける**ことで調整されます。BSD の fork() システムコールが使用されると、カーネル内の BSD コードは、タスクとスレッド構造を作成するために Mach 関数を使用します。

さらに、**Mach と BSD はそれぞれ異なるセキュリティモデルを維持**しています: **Mach** のセキュリティモデルは **ポート権限**に基づいており、一方、BSD のセキュリティモデルは **プロセス所有権**に基づいて動作します。これら2つのモデルの相違は、場合によってはローカル特権昇格の脆弱性を引き起こすことがあります。典型的なシステムコールに加えて、**Mach トラップ**もあり、ユーザースペースプログラムがカーネルとやり取りすることができます。これらの異なる要素が組み合わさり、macOS カーネルの多面的でハイブリッドなアーキテクチャを形成しています。

### I/O Kit - ドライバ

I/O Kit は XNU カーネル内のオープンソースのオブジェクト指向 **デバイスドライバフレームワーク**であり、**動的にロードされるデバイスドライバ**を処理します。これにより、多様なハードウェアをサポートするために、カーネルにモジュラーコードを即座に追加できます。

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - プロセス間通信

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### カーネルキャッシュ

**カーネルキャッシュ**は、XNU カーネルの **事前にコンパイルおよびリンクされたバージョン** と、重要なデバイス **ドライバ** および **カーネル拡張** を含むものです。これは **圧縮形式** で保存され、起動時にメモリに展開されます。カーネルキャッシュにより、カーネルと重要なドライバがすぐに実行可能な状態で利用可能になるため、起動にかかる時間とリソースが削減され、**より高速な起動時間**が実現されます。

iOS では、**`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** にあり、macOS では **`find / -name kernelcache 2>/dev/null`** または **`mdfind kernelcache | grep kernelcache`** で見つけることができます。

**`kextstat`** を実行して、ロードされたカーネル拡張を確認することができます。

#### IMG4

IMG4 ファイル形式は、Apple が iOS および macOS デバイスで使用する **ファームウェアコンポーネント（カーネルキャッシュなど）を安全に保存および検証する**ために使用されるコンテナ形式です。IMG4 形式には、ヘッダーと複数のタグが含まれており、実際のペイロード（カーネルやブートローダなど）、署名、および一連のマニフェストプロパティをカプセル化しています。この形式は暗号的な検証をサポートしており、デバイスがファームウェアコンポーネントの真正性と整合性を実行する前に確認できます。

通常、以下のコンポーネントで構成されています:

- **ペイロード (IM4P)**:
  - しばしば圧縮されています（LZFSE4、LZSS など）
  - オプションで暗号化されています
- **マニフェスト (IM4M)**:
  - 署名を含む
  - 追加のキー/値の辞書
- **リストア情報 (IM4R)**:
  - APNonce としても知られています
  - 一部の更新の再生を防止します
  - オプション: 通常、これは見つかりません

カーネルキャッシュを展開する:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### カーネルキャッシュシンボル

時々、Appleは**シンボル**付きの**カーネルキャッシュ**をリリースします。[https://theapplewiki.com](https://theapplewiki.com/)のリンクをたどることで、いくつかのファームウェアにシンボルが付いているものをダウンロードできます。

### IPSW

これらはAppleの**ファームウェア**で、[**https://ipsw.me/**](https://ipsw.me/)からダウンロードできます。他のファイルの中には**カーネルキャッシュ**が含まれています。\
ファイルを**抽出**するには、単に**解凍**するだけです。

ファームウェアを抽出した後、次のようなファイルが得られます: **`kernelcache.release.iphone14`**。これは**IMG4**形式で、次のコマンドで興味深い情報を抽出できます:

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
次のコマンドを使用して、抽出されたkernelcacheのシンボルを確認できます: **`nm -a kernelcache.release.iphone14.e | wc -l`**

これで、**すべての拡張機能**または**興味を持っている1つ**を抽出できます:
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
## macOSカーネル拡張機能

macOSは、コードが実行される高い特権のために、**カーネル拡張機能**（.kext）の読み込みを非常に制限しています。実際、デフォルトでは（回避策が見つかるまで）ほぼ不可能です。

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOSシステム拡張機能

macOSはカーネル拡張機能の代わりにシステム拡張機能を作成しました。これにより、開発者はカーネル拡張機能を使用せずに、ユーザーレベルのAPIを介してカーネルとやり取りできます。

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
