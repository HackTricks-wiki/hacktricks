# macOSタスクポートを介したスレッドインジェクション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

この投稿は、[https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)からコピーされました（詳細はリンク先を参照）。

### コード

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. スレッドハイジャッキング

最初に、リモートタスクのスレッドリストを取得するために、タスクポート上で**`task_threads()`**を呼び出します。そして、その中からハイジャックするスレッドを選択します。従来のコードインジェクションフレームワークとは異なり、**新しいリモートスレッドを作成することはできません**。なぜなら、`thread_create_running()`は新しい防御策によってブロックされるからです。

次に、**`thread_suspend()`**を呼び出してスレッドの実行を停止します。

この時点で、リモートスレッドに対して有用な制御は、スレッドの**停止**、**開始**、**レジスタ**の**値の取得**、および**レジスタ**の**値の設定**のみです。したがって、リモート関数呼び出しを開始するために、リモートスレッドのレジスタ`x0`から`x7`を**引数**に設定し、**`pc`**を実行したい関数に設定し、スレッドを開始します。この時点で、返り値を検出し、スレッドがクラッシュしないようにする必要があります。

これにはいくつかの方法があります。一つの方法は、`thread_set_exception_ports()`を使用してリモートスレッドに例外ハンドラを登録し、関数を呼び出す前に戻りアドレスレジスタ`lr`を無効なアドレスに設定することです。これにより、関数が実行された後に例外が生成され、メッセージが例外ポートに送信されるため、スレッドの状態を検査して返り値を取得できます。ただし、簡単のために、Ian Beerのtriple\_fetch exploitで使用された戦略をコピーしました。これは、**`lr`を無限ループする命令のアドレスに設定**し、スレッドのレジスタを繰り返しポーリングして**`pc`がその命令を指すまで待機**する方法です。

### 2. 通信用のMachポート

次のステップは、**リモートスレッドとの通信に使用するMachポートを作成する**ことです。これらのMachポートは、後でタスク間で任意の送信および受信権を転送するのに役立ちます。

双方向の通信を確立するために、**ローカルタスクとリモートタスクの両方にMach受信権を作成する必要があります**。次に、各ポートを他のタスクに**送信権を転送**する必要があります。これにより、各タスクは他のタスクが受信できるメッセージを送信する方法を持つことになります。

まず、ローカルポートの設定に焦点を当てましょう。つまり、ローカルタスクが受信権を保持しているポートです。`mach_port_allocate()`を呼び出すことで、通常のようにMachポートを作成できます。トリックは、そのポートの送信権をリモートスレッドに取得することです。

基本的な実行プリミティブのみを使用して、現在のタスクから送信権をリモートタスクにコピーするための便利なトリックは、`thread_set_special_port()`を使用して、**ローカルポートの送信権をリモートスレッドの`THREAD_KERNEL_PORT`特殊ポートに格納**することです。その後、リモートスレッドが`mach_thread_self()`を呼び出して送信権を取得できるようにします。

次に、私たちがしたこととほぼ逆の手順でリモートポートを設定します。リモートスレッドが`mach_reply_port()`を呼び出すことで、リモートスレッドがMachポートを割り当てることができます。`mach_port_allocate()`は使用できません。なぜなら、後者は割り当てられたポート名をメモリに返し、まだ読み取りプリミティブがないからです。ポートがあると、`mach_port_insert_right()`をリモートスレッドで呼び出すことで送信権を作成できます。その後、`thread_set_special_port()`を呼び出してポートをカーネルに格納します。最後に、ローカルタスクでリモートスレッド上の`thread_get_special_port()`を呼び出すことで、リモートタスクで割り当てられたMachポートへの送信権を取得できます。

この時点で、双方向通信に使用するMachポートを作成しました。
### 3. 基本的なメモリの読み書き <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

ここでは、実行プリミティブを使用して基本的なメモリの読み書きプリミティブを作成します。これらのプリミティブはあまり使用されません（すぐにより強力なプリミティブにアップグレードします）、しかし、これらはリモートプロセスの制御を拡張するための重要なステップです。

実行プリミティブを使用してメモリの読み書きを行うために、次のような関数を探します：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
以下のアセンブリに対応する可能性があります：
```
_read_func:
ldr     x0, [x0]
ret
_write_func:
str     x1, [x0]
ret
```
いくつかの一般的なライブラリをスキャンした結果、いくつかの良い候補が見つかりました。メモリを読み取るために、[Objective-Cランタイムライブラリ](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)の`property_getName()`関数を使用することができます。
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
どうやら、`prop`は`objc_property_t`の最初のフィールドであることがわかりましたので、これは上記の仮想の`read_func`に直接対応します。単にリモート関数呼び出しを行い、第一引数に読み取りたいアドレスを指定すれば、返り値はそのアドレスのデータになります。

メモリに書き込むための事前に作成された関数を見つけることは少し難しいですが、望ましくない副作用のない優れたオプションがまだあります。libxpcでは、`_xpc_int64_set_value()`関数が以下のアセンブリコードを持っています：
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
したがって、アドレス `address` に対して64ビットの書き込みを行うために、リモートコールを実行することができます。
```c
_xpc_int64_set_value(address - 0x18, value)
```
これらのプリミティブを手に入れたら、共有メモリを作成する準備が整いました。

### 4. 共有メモリ

次のステップは、リモートタスクとローカルタスクの間に共有メモリを作成することです。これにより、プロセス間でデータを簡単に転送できるようになります。共有メモリ領域があれば、任意のメモリの読み書きは、`memcpy()`へのリモートコールとして簡単に行うことができます。さらに、共有メモリ領域があれば、8つ以上の引数を持つ関数を呼び出すためのスタックを簡単に設定することができます。

作業を簡単にするために、libxpcの共有メモリ機能を再利用することができます。Libxpcは、XPCオブジェクトタイプである`OS_xpc_shmem`を提供し、XPCを介して共有メモリ領域を確立することができます。libxpcをリバースエンジニアリングすることで、`OS_xpc_shmem`がMachメモリエントリに基づいていることがわかります。Machメモリエントリは、仮想メモリ領域を表すMachポートです。そして、すでにリモートタスクにMachポートを送信する方法を示しているので、これを使用して簡単に独自の共有メモリを設定することができます。

まず最初に、共有するメモリを`mach_vm_allocate()`を使用して割り当てる必要があります。`mach_vm_allocate()`を使用する必要があるのは、`xpc_shmem_create()`を使用して領域の`OS_xpc_shmem`オブジェクトを作成するためです。`xpc_shmem_create()`は、Machメモリエントリを作成し、そのMachメモリエントリのMach送信権を不透明な`OS_xpc_shmem`オブジェクトのオフセット`0x18`に格納します。

メモリエントリポートを取得したら、同じメモリ領域を表すリモートプロセスに`OS_xpc_shmem`オブジェクトを作成し、`xpc_shmem_map()`を呼び出して共有メモリマッピングを確立することができます。まず、`malloc()`へのリモートコールを実行して`OS_xpc_shmem`のメモリを割り当て、基本的な書き込みプリミティブを使用してローカルの`OS_xpc_shmem`オブジェクトの内容をコピーします。残念ながら、結果として得られるオブジェクトは完全ではありません。オフセット`0x18`のMachメモリエントリフィールドには、ローカルタスクのメモリエントリの名前が含まれています。これを修正するために、`thread_set_special_port()`のトリックを使用して、リモートタスクにMachメモリエントリへの送信権を挿入し、フィールド`0x18`をリモートメモリエントリの名前で上書きします。この時点で、リモートの`OS_xpc_shmem`オブジェクトは有効であり、リモートコール`xpc_shmem_remote()`を使用してメモリマッピングを確立することができます。

### 5. 完全な制御 <a href="#step-5-full-control" id="step-5-full-control"></a>

既知のアドレスに共有メモリと任意の実行プリミティブがあるため、基本的には完了です。任意のメモリの読み取りと書き込みは、それぞれ共有領域への`memcpy()`の呼び出しによって実装されます。8つ以上の引数を持つ関数の呼び出しは、呼び出し規約に従って最初の8つ以降の追加の引数をスタックに配置することによって行われます。タスク間で任意のMachポートを転送するには、前に確立したポートを介してMachメッセージを送信することができます。さらに、ファイルディスクリプタをプロセス間で転送するには、ファイルポートを使用することができます（triple\_fetchでこの技術を実証してくれたIan Beerに特別な感謝を述べます）。

要するに、被害者プロセスに対して完全かつ容易な制御を持つことができます。完全な実装と公開されたAPIは、[threadexec](https://github.com/bazad/threadexec)ライブラリで確認することができます。\






<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に送信してください。**

</details>
