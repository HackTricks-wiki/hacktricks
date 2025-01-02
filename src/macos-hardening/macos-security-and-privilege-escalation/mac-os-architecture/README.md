# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOSのコアはXNUです**。これは「X is Not Unix」の略です。このカーネルは基本的に**Machマイクロカーネル**（後で説明します）と**Berkeley Software Distribution（BSD）**の要素で構成されています。XNUはまた、**I/O Kitというシステムを介してカーネルドライバのプラットフォームを提供します**。XNUカーネルはDarwinオープンソースプロジェクトの一部であり、**そのソースコードは自由にアクセス可能です**。

セキュリティ研究者やUnix開発者の視点から見ると、**macOS**は**FreeBSD**システムに非常に**似ている**と感じるかもしれません。洗練されたGUIと多数のカスタムアプリケーションがあります。BSD向けに開発されたほとんどのアプリケーションは、macOS上で修正なしにコンパイルおよび実行できます。Unixユーザーに馴染みのあるコマンドラインツールはすべてmacOSに存在します。しかし、XNUカーネルがMachを取り入れているため、従来のUnixライクなシステムとmacOSの間にはいくつかの重要な違いがあり、これらの違いが潜在的な問題を引き起こしたり、独自の利点を提供したりする可能性があります。

XNUのオープンソース版: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Machは**UNIX互換**に設計された**マイクロカーネル**です。その主要な設計原則の1つは、**カーネル**空間で実行される**コード**の量を**最小限に抑え**、ファイルシステム、ネットワーキング、I/Oなどの多くの典型的なカーネル機能を**ユーザーレベルのタスクとして実行できるようにすること**でした。

XNUでは、Machはカーネルが通常処理する多くの重要な低レベル操作、例えばプロセッサスケジューリング、マルチタスク、および仮想メモリ管理を**担当しています**。

### BSD

XNUの**カーネル**は、**FreeBSD**プロジェクトから派生したかなりの量のコードも**取り入れています**。このコードは**Machとともにカーネルの一部として同じアドレス空間で実行されます**。ただし、XNU内のFreeBSDコードは、Machとの互換性を確保するために修正が必要だったため、元のFreeBSDコードとは大きく異なる場合があります。FreeBSDは以下を含む多くのカーネル操作に寄与しています：

- プロセス管理
- シグナル処理
- ユーザーおよびグループ管理を含む基本的なセキュリティメカニズム
- システムコールインフラ
- TCP/IPスタックとソケット
- ファイアウォールとパケットフィルタリング

BSDとMachの相互作用を理解することは、異なる概念的枠組みのために複雑です。たとえば、BSDはプロセスを基本的な実行単位として使用しますが、Machはスレッドに基づいて動作します。この不一致は、**各BSDプロセスを1つのMachスレッドを含むMachタスクに関連付けることによってXNUで調整されます**。BSDのfork()システムコールが使用されると、カーネル内のBSDコードはMach関数を使用してタスクとスレッド構造を作成します。

さらに、**MachとBSDはそれぞれ異なるセキュリティモデルを維持しています**：**Machの**セキュリティモデルは**ポート権**に基づいていますが、BSDのセキュリティモデルは**プロセス所有権**に基づいています。これら2つのモデルの不一致は、時折ローカル特権昇格の脆弱性を引き起こすことがあります。典型的なシステムコールに加えて、**ユーザースペースプログラムがカーネルと相互作用することを可能にするMachトラップもあります**。これらの異なる要素が組み合わさって、macOSカーネルの多面的でハイブリッドなアーキテクチャを形成しています。

### I/O Kit - Drivers

I/O Kitは、XNUカーネル内のオープンソースのオブジェクト指向**デバイスドライバフレームワーク**であり、**動的にロードされるデバイスドライバ**を処理します。これにより、さまざまなハードウェアをサポートするために、カーネルにモジュラーコードを動的に追加できます。

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOSは**カーネル拡張**（.kext）をロードすることに非常に制限があります。これは、そのコードが高い特権で実行されるためです。実際、デフォルトではバイパスが見つからない限り、ほぼ不可能です。

次のページでは、macOSがその**kernelcache**内でロードする`.kext`を回復する方法も見ることができます：

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

カーネル拡張の代わりに、macOSはシステム拡張を作成しました。これにより、カーネルと相互作用するためのユーザーレベルのAPIが提供されます。この方法で、開発者はカーネル拡張を使用することを避けることができます。

{{#ref}}
macos-system-extensions.md
{{#endref}}

## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
