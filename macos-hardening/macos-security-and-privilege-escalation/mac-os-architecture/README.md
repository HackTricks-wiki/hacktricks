# macOSカーネルとシステム拡張

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## XNUカーネル

**macOSのコアはXNU**であり、「X is Not Unix」を意味します。このカーネルは基本的には**Machマイクロカーネル**（後述）と**Berkeley Software Distribution（BSD）**の要素で構成されています。XNUはまた、**I/O Kitと呼ばれるシステムを介してカーネルドライバを提供**します。XNUカーネルはDarwinオープンソースプロジェクトの一部であり、**ソースコードは自由にアクセスできます**。

セキュリティ研究者やUnix開発者の観点から見ると、macOSはエレガントなGUIと多数のカスタムアプリケーションを備えたFreeBSDシステムに非常に似ていると感じるかもしれません。BSD向けに開発されたほとんどのアプリケーションは、修正を必要とせずにmacOSでコンパイルおよび実行されます。Unixユーザにとっては馴染みのあるコマンドラインツールがmacOSにはすべて備わっているためです。ただし、XNUカーネルにはMachが組み込まれているため、従来のUnixライクなシステムとmacOSの間にはいくつかの重要な違いがあり、これらの違いが潜在的な問題を引き起こす可能性があるか、または独自の利点を提供するかもしれません。

XNUのオープンソースバージョン：[https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Machは、**UNIX互換**の**マイクロカーネル**です。その主な設計原則の1つは、**カーネルスペースで実行されるコードの量を最小限に抑え、ファイルシステム、ネットワーキング、I/Oなどの典型的なカーネル機能をユーザレベルのタスクとして実行できるようにすること**です。

XNUでは、Machはプロセッサスケジューリング、マルチタスキング、仮想メモリ管理など、通常カーネルが処理する重要な低レベルの操作を担当しています。

### BSD

XNUカーネルは、**FreeBSDプロジェクト**から派生したコードも**組み込んでいます**。このコードはMachと同じアドレス空間でカーネルとして実行されます。ただし、XNU内のFreeBSDコードは、Machとの互換性を確保するために変更が加えられている場合があります。FreeBSDは以下のカーネル操作に貢献しています。

* プロセス管理
* シグナル処理
* ユーザとグループの管理を含む基本的なセキュリティメカニズム
* システムコールインフラストラクチャ
* TCP/IPスタックとソケット
* ファイアウォールとパケットフィルタリング

BSDとMachの相互作用を理解することは複雑です。たとえば、BSDはプロセスを基本的な実行単位として使用しますが、Machはスレッドに基づいて動作します。この相違は、XNUにおいてBSDの各プロセスをMachタスクに関連付けることで調整されます。BSDのfork()システムコールが使用されると、カーネル内のBSDコードはタスクとスレッド構造を作成するためにMach関数を使用します。

さらに、**MachとBSDはそれぞれ異なるセキュリティモデルを維持**しています。**Machの**セキュリティモデルは**ポート権限**に基づいており、BSDのセキュリティモデルは**プロセス所有権**に基づいて動作します。これら2つのモデルの相違は、ローカル特権昇格の脆弱性を引き起こすことがあります。典型的なシステムコール以外にも、**ユーザスペースプログラムがカーネルと対話するためのMachトラップ**もあります。これらの要素が組み合わさって、macOSカーネルの多面的なハイブリッドアーキテクチャが形成されます。

### I/O Kit - ドライバ

I/O Kitは、XNUカーネル内のオープンソースのオブジェクト指向の**デバイスドライバフレームワーク**であり、**動的にロードされるデバイスドライバ**の追加と管理を担当しています。これらのドライバにより、異なるハードウェアとの使用に動的にカーネルにモジュラーコードを追加できます。

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - プロセス間通信

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### カーネルキャッシュ

**カーネルキャッシュ**は、XNUカーネルの**事前コンパイルおよび事前リンクされたバージョン**と、必要なデバイス**ドライバ**と**カーネル拡張**を含んでいます。これは**圧縮された**形式で保存され、起動時にメモリに展開されます。カーネルキャッシュにより、カーネルと重要なドライバの実行準備が整った状態で利用できるため、起動時間が短縮され、動的にこれらのコンポーネントをロードおよびリンクするために必要な時間とリソースが削減されます。

iOSでは、**`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**にあります。macOSでは、**`find / -name kernelcache 2>/dev/null`**コマンドで見つけることができます。
#### IMG4

IMG4ファイル形式は、AppleがiOSおよびmacOSデバイスで使用するコンテナ形式で、ファームウェアコンポーネント（カーネルキャッシュなど）を**安全に保存および検証**するために使用されます。IMG4形式には、ヘッダーといくつかのタグが含まれており、実際のペイロード（カーネルまたはブートローダーなど）や署名、一連のマニフェストプロパティなど、さまざまなデータの断片をカプセル化しています。この形式は、暗号的な検証をサポートしており、デバイスがファームウェアコンポーネントを実行する前にその正当性と完全性を確認することができます。

通常、以下のコンポーネントで構成されています：

* **ペイロード（IM4P）**：
* しばしば圧縮されています（LZFSE4、LZSSなど）
* オプションで暗号化されています
* **マニフェスト（IM4M）**：
* 署名を含む
* 追加のキー/値の辞書
* **リストア情報（IM4R）**：
* APNonceとも呼ばれます
* 一部のアップデートの再生を防止します
* オプション：通常は見つかりません

カーネルキャッシュを展開する：
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### カーネルキャッシュシンボル

時々、Appleは**シンボル**を含んだ**カーネルキャッシュ**をリリースします。[https://theapplewiki.com](https://theapplewiki.com/)のリンクをたどることで、いくつかのファームウェアにシンボルが含まれているものをダウンロードすることができます。

### IPSW

これらはAppleの**ファームウェア**で、[**https://ipsw.me/**](https://ipsw.me/)からダウンロードできます。他のファイルと共に、**カーネルキャッシュ**が含まれています。\
ファイルを**抽出**するには、単にそれを**解凍**するだけです。

ファームウェアを抽出した後、次のようなファイルが得られます: **`kernelcache.release.iphone14`**。これは**IMG4**形式であり、次のコマンドで興味深い情報を抽出できます:

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
抽出されたkernelcacheのシンボルを確認するには、次のコマンドを使用します: **`nm -a kernelcache.release.iphone14.e | wc -l`**

これにより、**すべての拡張機能**または**興味のある拡張機能**を抽出できます:
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

macOSは、コードが実行される高い特権を持つため、カーネル拡張機能（.kext）の読み込みに非常に制限があります。実際には、デフォルトではほぼ不可能です（バイパスが見つかる場合を除く）。

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOSシステム拡張機能

macOSはカーネル拡張機能の代わりに、システム拡張機能を作成しました。これにより、開発者はカーネル拡張機能を使用せずにカーネルとのやり取りを行うためのユーザーレベルのAPIを利用することができます。

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
