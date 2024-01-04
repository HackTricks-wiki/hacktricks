# macOSスレッドインジェクション via タスクポート

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

この投稿は[https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)からコピーされました（より多くの情報が含まれています）

### コード

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. スレッドハイジャック

最初に行うことは、タスクポートに対して**`task_threads()`**を呼び出してリモートタスク内のスレッドのリストを取得し、その中からハイジャックするスレッドを選ぶことです。従来のコードインジェクションフレームワークとは異なり、新しい緩和策によってブロックされるため、**新しいリモートスレッドを作成することはできません**。

次に、**`thread_suspend()`**を呼び出してスレッドの実行を停止します。

この時点で、リモートスレッドを制御できる唯一の方法は、それを**停止**させること、**開始**させること、その**レジスタ**の値を**取得**すること、およびレジスタの**値を設定**することです。したがって、リモートスレッドのレジスタ`x0`から`x7`に**引数**を設定し、**`pc`**を実行したい関数に設定し、スレッドを開始することで、**リモート関数呼び出しを開始**することができます。この時点で、リターンを検出し、スレッドがクラッシュしないようにする必要があります。

これにはいくつかの方法があります。一つの方法は、`thread_set_exception_ports()`を使用してリモートスレッドに対して**例外ハンドラを登録**し、関数を呼び出す前にリターンアドレスレジスタ`lr`を無効なアドレスに設定することです。そうすると、関数が実行された後に例外が生成され、例外ポートにメッセージが送信され、その時点でスレッドの状態を検査してリターン値を取得できます。しかし、簡単にするために、Ian Beerのtriple_fetchエクスプロイトで使用された戦略をコピーしました。それは、**`lr`を無限ループの命令のアドレスに設定**し、その後スレッドのレジスタを繰り返しポーリングして、**`pc`がその命令を指している**ことを検出するというものです。

### 2. 通信用のMachポート

次のステップは、**リモートスレッドと通信するためのMachポートを作成する**ことです。これらのMachポートは、後でタスク間で任意の送信権と受信権を転送するのに役立ちます。

双方向通信を確立するためには、**ローカルタスクとリモートタスクの両方でMach受信権を作成する**必要があります。その後、各ポートの送信権を**他のタスクに転送する**必要があります。これにより、各タスクは他方のタスクによって受信できるメッセージを送信する方法を持つことになります。

まず、ローカルタスクが受信権を持つポート、つまりローカルポートの設定に焦点を当てましょう。`mach_port_allocate()`を呼び出すことで、他のMachポートと同様にMachポートを作成できます。問題は、そのポートの送信権をリモートタスクにコピーする方法です。

基本的な実行プリミティブのみを使用して現在のタスクからリモートタスクに送信権をコピーする便利なトリックは、リモートスレッドの`THREAD_KERNEL_PORT`特別ポートにローカルポートへの**送信権を隠す**ことです。これは`thread_set_special_port()`を使用して行います。その後、リモートスレッドに`mach_thread_self()`を呼び出させて送信権を取得させます。

次に、リモートポートの設定に進みますが、これは先ほど行ったことのほぼ逆です。リモートスレッドに`mach_reply_port()`を呼び出させることで、**リモートスレッドにMachポートを割り当てさせる**ことができます。`mach_port_allocate()`は使用できません。なぜなら、後者は割り当てられたポート名をメモリに返すからですが、まだ読み取りプリミティブを持っていません。ポートを取得したら、リモートスレッドに`mach_port_insert_right()`を呼び出して送信権を作成します。その後、カーネルにポートを隠すために`thread_set_special_port()`を呼び出します。最後に、ローカルタスクに戻り、リモートスレッドに`thread_get_special_port()`を呼び出して、**リモートタスクで割り当てられたばかりのMachポートへの送信権を取得します**。

この時点で、双方向通信に使用するMachポートを作成しました。

### 3. 基本的なメモリ読み書き <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

次に、実行プリミティブを使用して基本的なメモリ読み書きプリミティブを作成します。これらのプリミティブはあまり使用されません（すぐにはるかに強力なプリミティブにアップグレードしますが）、リモートプロセスの制御を拡大するのに役立つ重要なステップです。

実行プリミティブを使用してメモリを読み書きするためには、次のような関数を探します：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
それらは次のアセンブリに対応する可能性があります：
```
_read_func:
ldr     x0, [x0]
ret
_write_func:
str     x1, [x0]
ret
```
一般的なライブラリを簡単に調べたところ、いくつかの良い候補が見つかりました。メモリを読むためには、[Objective-Cランタイムライブラリ](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)から`property_getName()`関数を使用できます：
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
```markdown
`prop`は`objc_property_t`の最初のフィールドであるため、これは上記の仮説の`read_func`に直接対応しています。私たちは、読みたいアドレスを最初の引数としてリモート関数呼び出しを行い、戻り値がそのアドレスのデータになるようにする必要があります。

メモリを書き込むための既製の関数を見つけるのは少し難しいですが、望ましくない副作用なしに素晴らしいオプションがまだあります。libxpcでは、`_xpc_int64_set_value()`関数は以下のディスアセンブリを持っています：
```
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
したがって、アドレス `address` で64ビット書き込みを行うには、リモートコールを実行できます：
```c
_xpc_int64_set_value(address - 0x18, value)
```
これらのプリミティブを手に入れたら、共有メモリを作成する準備が整います。

### 4. 共有メモリ

次のステップは、リモートタスクとローカルタスクの間に共有メモリを作成することです。これにより、プロセス間でデータをより簡単に転送できるようになります。共有メモリ領域があれば、任意のメモリの読み書きは`memcpy()`へのリモートコールとして簡単になります。さらに、共有メモリ領域があれば、8つ以上の引数を持つ関数を呼び出すためのスタックを簡単に設定できます。

簡単にするために、libxpcの共有メモリ機能を再利用できます。Libxpcは、XPCオブジェクトタイプ`OS_xpc_shmem`を提供し、XPCを介して共有メモリ領域を確立することができます。libxpcをリバースエンジニアリングすることで、`OS_xpc_shmem`がMachメモリエントリに基づいていることがわかります。これは、仮想メモリの領域を表すMachポートです。そして、リモートタスクにMachポートを送信する方法を既に示しているので、これを使用して簡単に独自の共有メモリを設定できます。

まず最初に、`mach_vm_allocate()`を使用して共有するメモリを割り当てる必要があります。`xpc_shmem_create()`を使用して領域の`OS_xpc_shmem`オブジェクトを作成できるように、`mach_vm_allocate()`を使用する必要があります。`xpc_shmem_create()`は、Machメモリエントリを作成し、不透明な`OS_xpc_shmem`オブジェクトのオフセット`0x18`にメモリエントリへのMach送信権を格納します。

メモリエントリポートを取得したら、同じメモリ領域を表すリモートプロセス内の`OS_xpc_shmem`オブジェクトを作成し、`xpc_shmem_map()`を呼び出して共有メモリマッピングを確立します。まず、`malloc()`へのリモートコールを実行して`OS_xpc_shmem`のメモリを割り当て、基本的な書き込みプリミティブを使用してローカル`OS_xpc_shmem`オブジェクトの内容をコピーします。残念ながら、結果として得られるオブジェクトは完全に正しいわけではありません。オフセット`0x18`のMachメモリエントリフィールドには、リモートタスクの名前ではなく、ローカルタスクの名前が含まれています。これを修正するために、`thread_set_special_port()`トリックを使用してリモートタスクにMachメモリエントリへの送信権を挿入し、フィールド`0x18`をリモートメモリエントリの名前で上書きします。この時点で、リモートの`OS_xpc_shmem`オブジェクトは有効になり、`xpc_shmem_remote()`へのリモートコールでメモリマッピングを確立できます。

### 5. 完全な制御 <a href="#step-5-full-control" id="step-5-full-control"></a>

既知のアドレスで共有メモリと任意の実行プリミティブを持つことで、基本的に完了です。任意のメモリ読み書きは、それぞれ共有領域への`memcpy()`の呼び出しによって実装されます。8つ以上の引数を持つ関数呼び出しは、呼び出し規約に従って最初の8つを超える追加の引数をスタック上に配置することで実行されます。タスク間で任意のMachポートを転送することは、以前に確立したポートを介してMachメッセージを送信することで行うことができます。プロセス間でファイルディスクリプタを転送することも、fileports（特別な感謝をIan Beerに、この技術をtriple_fetch!で示してくれたため）を使用して行うことができます。

簡単に言うと、被害プロセスを完全かつ簡単に制御できるようになりました。完全な実装と公開されたAPIは、[threadexec](https://github.com/bazad/threadexec)ライブラリで確認できます。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには、</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>
