# macOSスレッドポートを介したスレッドインジェクション

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[Telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で**フォロー**する：[**@carlospolopm**](https://twitter.com/carlospolopm)。
- **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

## コード

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. スレッドハイジャッキング

最初に、リモートタスクからスレッドリストを取得するために**`task_threads()`**関数がタスクポートで呼び出されます。ハイジャックするスレッドが選択されます。このアプローチは、新しいミティゲーションによって`thread_create_running()`がブロックされているため、新しいリモートスレッドを作成する従来のコードインジェクション方法とは異なります。

スレッドを制御するために、**`thread_suspend()`**が呼び出され、その実行が停止されます。

リモートスレッドで許可される唯一の操作は、それを**停止**および**開始**し、そのレジスタ値を**取得**および**変更**することです。リモート関数呼び出しは、レジスタ`x0`から`x7`を**引数**に設定し、`pc`を目的の関数に向け、スレッドをアクティブ化することで開始されます。戻り値後にスレッドがクラッシュしないようにするには、戻り値を取得する必要があります。

1つの戦略は、リモートスレッドのために**例外ハンドラを登録**することで、`thread_set_exception_ports()`を使用することです。関数呼び出し前に`lr`レジスタを無効なアドレスに設定します。これにより、関数の実行後に例外が発生し、例外ポートにメッセージが送信され、スレッドの状態を検査して戻り値を回収できます。代替策として、Ian Beerのtriple\_fetch exploitから採用された方法では、`lr`を無限ループに設定します。その後、スレッドのレジスタが**`pc`がその命令を指すまで**継続的に監視されます。

## 2. 通信用のMachポート

次の段階では、Machポートを確立してリモートスレッドとの通信を容易にします。これらのポートは、タスク間で任意の送信および受信権を転送するのに重要です。

双方向通信のために、2つのMach受信権が作成されます：1つはローカルタスクに、もう1つはリモートタスクにあります。その後、各ポートの送信権が対向するタスクに転送され、メッセージの交換が可能になります。

ローカルポートに焦点を当てると、受信権はローカルタスクによって保持されます。ポートは`mach_port_allocate()`で作成されます。課題は、このポートへの送信権をリモートタスクに転送することです。

1つの戦略は、`thread_set_special_port()`を活用して、ローカルポートへの送信権をリモートスレッドの`THREAD_KERNEL_PORT`に配置することです。その後、リモートスレッドに対して`mach_thread_self()`を呼び出して送信権を取得するよう指示します。

リモートポートの場合、プロセスは基本的に逆転します。リモートスレッドに、`mach_port_allocate()`の返り値メカニズムのために適していないため、`mach_reply_port()`を介してMachポートを生成するよう指示します。ポートの作成後、`mach_port_insert_right()`がリモートスレッドで呼び出され、送信権が確立されます。この権利は、`thread_set_special_port()`を使用してカーネルに隠されます。ローカルタスクでは、リモートスレッドに対して`thread_get_special_port()`を使用して、リモートタスク内の新しく割り当てられたMachポートへの送信権を取得します。

これらの手順の完了により、Machポートが確立され、双方向通信の基盤が整います。

## 3. 基本的なメモリ読み取り/書き込みプリミティブ

このセクションでは、基本的なメモリ読み取りおよび書き込みプリミティブを確立するために実行プリミティブを利用することに焦点を当てます。これらの初期ステップは、リモートプロセス上でのより多くの制御を得るために重要ですが、この段階ではプリミティブはあまり多くの目的には役立ちません。すぐに、これらはより高度なバージョンにアップグレードされます。

### 実行プリミティブを使用したメモリ読み取りおよび書き込み

特定の関数を使用してメモリの読み取りおよび書き込みを行うことが目標です。メモリの読み取りには、次の構造に似た関数が使用されます：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
メモリへの書き込みには、次のような構造に似た関数が使用されます：
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
これらの関数は、与えられたアセンブリ命令に対応しています:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 適切な関数の特定

一般的なライブラリのスキャンにより、これらの操作に適した候補が特定されました:

1. **メモリの読み取り:**
[Objective-Cランタイムライブラリ](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)からの`property_getName()`関数がメモリの読み取りに適した関数として特定されました。以下に関数が示されています:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
この関数は、`objc_property_t`の最初のフィールドを返すことで、`read_func`のように効果的に機能します。

2. **メモリの書き込み:**
メモリの書き込み用の事前に構築された関数を見つけることはより困難です。ただし、libxpcからの`_xpc_int64_set_value()`関数は、次の逆アセンブリを持つ適切な候補です:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
特定のアドレスに64ビットの書き込みを行うには、リモートコールは次のように構造化されます：
```c
_xpc_int64_set_value(address - 0x18, value)
```
## 4. 共有メモリのセットアップ

目的は、ローカルとリモートタスク間で共有メモリを確立し、データ転送を簡素化し、複数の引数を持つ関数の呼び出しを容易にすることです。このアプローチには、`libxpc`とその`OS_xpc_shmem`オブジェクトタイプを活用します。これはMachメモリエントリに基づいて構築されています。

### プロセスの概要：

1. **メモリの割り当て**:
- 共有のためのメモリを`mach_vm_allocate()`を使用して割り当てます。
- 割り当てられたメモリ領域のための`OS_xpc_shmem`オブジェクトを作成するために`xpc_shmem_create()`を使用します。この関数はMachメモリエントリの作成を管理し、`OS_xpc_shmem`オブジェクトのオフセット`0x18`にMach送信権を格納します。

2. **リモートプロセスでの共有メモリの作成**:
- リモートプロセスで`malloc()`にリモートコールして`OS_xpc_shmem`オブジェクトのためのメモリを割り当てます。
- ローカルの`OS_xpc_shmem`オブジェクトの内容をリモートプロセスにコピーします。ただし、この初期コピーでは、オフセット`0x18`で正しくないMachメモリエントリ名が含まれます。

3. **Machメモリエントリの修正**:
- `thread_set_special_port()`メソッドを使用して、Machメモリエントリの送信権をリモートタスクに挿入します。
- リモートメモリエントリの名前でオフセット`0x18`のMachメモリエントリフィールドを上書きして修正します。

4. **共有メモリのセットアップの最終化**:
- リモートの`OS_xpc_shmem`オブジェクトを検証します。
- リモートで`xpc_shmem_remote()`にリモートコールして共有メモリマッピングを確立します。

これらの手順に従うことで、ローカルとリモートタスク間で共有メモリが効率的に設定され、簡単なデータ転送や複数の引数を必要とする関数の実行が可能になります。

## 追加のコードスニペット

メモリの割り当てと共有メモリオブジェクトの作成用:
```c
mach_vm_allocate();
xpc_shmem_create();
```
リモートプロセス内で共有メモリオブジェクトを作成および修正するために:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
## 5. 完全な制御の達成

共有メモリを正常に確立し、任意の実行機能を獲得した場合、基本的にはターゲットプロセス上で完全な制御を獲得したことになります。この制御を可能にする主要な機能は次のとおりです：

1. **任意のメモリ操作**：
- 共有領域からデータをコピーするために`memcpy()`を呼び出して任意のメモリ読み取りを実行します。
- 共有領域にデータを転送するために`memcpy()`を使用して任意のメモリ書き込みを実行します。

2. **複数の引数を持つ関数呼び出しの処理**：
- 8つ以上の引数が必要な関数に対して、呼び出し規約に従ってスタック上に追加の引数を配置します。

3. **Machポートの転送**：
- 事前に確立されたポートを介してMachメッセージを介してタスク間でMachポートを転送します。

4. **ファイルディスクリプタの転送**：
- `triple_fetch`でIan Beerによって強調されたファイルポートを使用して、プロセス間でファイルディスクリプタを転送します。

この包括的な制御は、被害者プロセスとのやり取りのための詳細な実装とユーザーフレンドリーなAPIを提供する[threadexec](https://github.com/bazad/threadexec)ライブラリによってカプセル化されています。

## 重要な考慮事項：

- システムの安定性とデータの整合性を維持するために、メモリ読み取り/書き込み操作に`memcpy()`を適切に使用してください。
- Machポートやファイルディスクリプタを転送する際には、適切なプロトコルに従い、リソースを適切に処理して情報漏洩や意図しないアクセスを防止してください。

これらのガイドラインに従い、`threadexec`ライブラリを利用することで、ターゲットプロセス上で完全な制御を効率的に管理し、やり取りすることができます。

## 参考文献
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
