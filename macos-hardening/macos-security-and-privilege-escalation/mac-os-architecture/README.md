# macOSカーネル

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのスワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## XNUカーネル

**macOSのコアはXNU**であり、「X is Not Unix」を意味します。このカーネルは基本的には**Machマイクロカーネル**（後述）と**Berkeley Software Distribution（BSD）**の要素で構成されています。XNUはまた、**I/O Kitと呼ばれるシステムを介してカーネルドライバを提供**します。XNUカーネルはDarwinオープンソースプロジェクトの一部であり、**そのソースコードは自由にアクセスできます**。

セキュリティ研究者やUnix開発者の観点から見ると、macOSはエレガントなGUIと多数のカスタムアプリケーションを備えたFreeBSDシステムに非常に似ていると感じるかもしれません。BSD向けに開発されたほとんどのアプリケーションは、修正を必要とせずにmacOSでコンパイルおよび実行されます。なぜなら、Unixユーザーにとって馴染みのあるコマンドラインツールはすべてmacOSに存在しているからです。ただし、XNUカーネルにはMachが組み込まれているため、従来のUnixライクなシステムとmacOSの間にはいくつかの重要な違いがあり、これらの違いが潜在的な問題を引き起こしたり、独自の利点を提供したりする可能性があります。

### Mach

Machは、**UNIX互換**であるように設計された**マイクロカーネル**です。その主な設計原則の1つは、**カーネルスペースで実行されるコードの量を最小限に抑え、ファイルシステム、ネットワーキング、I/Oなどの典型的なカーネル機能をユーザーレベルのタスクとして実行できるようにすること**です。

XNUでは、Machがプロセッサスケジューリング、マルチタスキング、仮想メモリ管理など、通常カーネルが処理する重要な低レベルの操作を担当しています。

### BSD

XNUカーネルは、**FreeBSDプロジェクト**から派生したコードも**組み込んでいます**。このコードはMachと同じアドレス空間でカーネルとして実行されます。ただし、XNU内のFreeBSDコードは、Machとの互換性を確保するために変更が加えられている場合があります。FreeBSDは、次のような多くのカーネル操作に貢献しています。

* プロセス管理
* シグナル処理
* ユーザーとグループの管理を含む基本的なセキュリティメカニズム
* システムコールインフラストラクチャ
* TCP/IPスタックとソケット
* ファイアウォールとパケットフィルタリング

BSDとMachの相互作用を理解することは複雑です。たとえば、BSDはプロセスを基本的な実行単位として使用しますが、Machはスレッドに基づいて動作します。この相違は、XNUにおいて、BSDの各プロセスが正確に1つのMachスレッドを含むMachタスクに関連付けられることで調整されます。BSDのfork()システムコールが使用されると、カーネル内のBSDコードはタスクとスレッド構造を作成するためにMach関数を使用します。

さらに、**MachとBSDはそれぞれ異なるセキュリティモデルを維持**しています。**Machの**セキュリティモデルは**ポート権限**に基づいており、一方、BSDのセキュリティモデルは**プロセスの所有権**に基づいています。これら2つのモデルの相違は、ローカル特権昇格の脆弱性を引き起こすことがあります。典型的なシステムコール以外にも、**ユーザースペースプログラムがカーネルと対話するためのMachトラップ**もあります。これらの異なる要素が組み合わさって、macOSカーネルの多面的なハイブリッドアーキテクチャを形成しています。

### I/O Kit - ドライバ

I/O Kitは、XNUカーネル内のオープンソースのオブジェクト指向の**デバイスドライバフレームワーク**であり、**動的にロードされるデバイスドライバの追加と管理**を担当しています。これらのドライバにより、異なるハードウェアとの使用に動的にカーネルにモジュラーコードを追加することができます。これらのドライバは次の場所にあります。

* `/System/Library/Extensions`
* OS Xオペレーティングシステムに組み込まれたKEXTファイル。
* `/Library/Extensions`
* サードパーティのソフトウェアによってインストールされたKEXTファイル
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
9までの番号のドライバは、**アドレス0にロードされます**。これは、それらが実際のドライバではなく、**カーネルの一部であり、アンロードすることはできない**ことを意味します。

特定の拡張機能を見つけるためには、次の方法を使用できます：
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
カーネル拡張機能をロードおよびアンロードするには、次の手順を実行します：

```bash
# カーネル拡張機能をロードする
sudo kextload /path/to/extension.kext

# カーネル拡張機能をアンロードする
sudo kextunload /path/to/extension.kext
```

これにより、指定したパスにあるカーネル拡張機能がロードまたはアンロードされます。
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
### IPC - プロセス間通信

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## macOS カーネル拡張

macOSは、コードが実行される高い特権のため、カーネル拡張（.kext）をロードすることが非常に制限されています。実際には、デフォルトではほぼ不可能です（バイパスが見つかる場合を除く）。

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS システム拡張

macOSは、カーネル拡張の代わりにシステム拡張を作成しました。これにより、開発者はカーネル拡張を使用する必要がなくなります。

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
