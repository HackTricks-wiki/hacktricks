# macOSスレッドインジェクション via タスクポート

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## コード

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. スレッドハイジャック

初めに、リモートタスクからスレッドリストを取得するために**`task_threads()`**関数がタスクポートに対して呼び出されます。ハイジャックするスレッドが選択されます。このアプローチは、新しいリモートスレッドの作成が`thread_create_running()`をブロックする新しい緩和によって禁止されているため、従来のコードインジェクション方法とは異なります。

スレッドを制御するために、**`thread_suspend()`**が呼び出され、その実行を停止します。

リモートスレッドに対して許可される操作は、**停止**と**開始**、レジスタ値の**取得**と**変更**のみです。レジスタ`x0`から`x7`を**引数**に設定し、**`pc`**を目的の関数に設定し、スレッドをアクティブにすることでリモート関数呼び出しが開始されます。関数の戻り後にスレッドがクラッシュしないようにするには、戻りを検出する必要があります。

一つの戦略は、`thread_set_exception_ports()`を使用してリモートスレッドに**例外ハンドラを登録**し、関数呼び出し前に`lr`レジスタを無効なアドレスに設定することです。これにより、関数実行後に例外が発生し、例外ポートにメッセージが送信され、スレッドの状態を検査して戻り値を回復することができます。または、Ian Beerのtriple\_fetchエクスプロイトから採用されたように、`lr`を無限ループするように設定します。その後、**`pc`がその命令を指すまで**スレッドのレジスタを継続的に監視します。

## 2. 通信のためのMachポート

次の段階では、リモートスレッドとの通信を容易にするためにMachポートを確立します。これらのポートは、タスク間で任意の送信権と受信権を転送するために不可欠です。

双方向通信のために、ローカルとリモートタスクの両方にMach受信権を作成します。その後、各ポートの送信権を対応するタスクに転送し、メッセージ交換を可能にします。

ローカルポートに焦点を当てると、受信権はローカルタスクによって保持されます。ポートは`mach_port_allocate()`で作成されます。課題は、このポートへの送信権をリモートタスクに転送することです。

一つの戦略は、`thread_set_special_port()`を利用してローカルポートへの送信権をリモートスレッドの`THREAD_KERNEL_PORT`に配置し、リモートスレッドに`mach_thread_self()`を呼び出して送信権を取得させることです。

リモートポートについては、プロセスは基本的に逆になります。リモートスレッドに`mach_reply_port()`を介してMachポートを生成させます（`mach_port_allocate()`はその返り値のメカニズムのために不適切です）。ポート作成後、リモートスレッドで`mach_port_insert_right()`を呼び出して送信権を確立します。この権利は`thread_set_special_port()`を使用してカーネルに格納されます。ローカルタスクでは、リモートスレッドに`thread_get_special_port()`を使用して、リモートタスクに新しく割り当てられたMachポートへの送信権を取得します。

これらのステップの完了により、双方向通信のためのMachポートが確立されます。

## 3. 基本的なメモリ読み書きプリミティブ

このセクションでは、実行プリミティブを利用して基本的なメモリ読み書きプリミティブを確立することに焦点を当てます。これらの初期ステップは、リモートプロセスをより制御するために重要ですが、この段階でのプリミティブは多くの目的には役立ちません。しかし、すぐにそれらはより高度なバージョンにアップグレードされます。

### 実行プリミティブを使用したメモリ読み書き

目標は、特定の関数を使用してメモリ読み書きを行うことです。メモリを読むためには、次の構造に似た関数が使用されます：
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
メモリへの書き込みには、この構造に似た関数が使用されます:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
これらの関数は、与えられたアセンブリ命令に対応します：
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 適切な関数の特定

一般的なライブラリのスキャンにより、これらの操作に適した候補が明らかになりました：

1. **メモリ読み取り:**
[Objective-C ランタイムライブラリ](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)からの `property_getName()` 関数は、メモリを読み取るための適切な関数として特定されています。以下にその関数を示します：

```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```

この関数は `objc_property_t` の最初のフィールドを返すことにより、`read_func` のように効果的に機能します。

2. **メモリ書き込み:**
メモリを書き込むための既製の関数を見つけることはより困難です。しかし、libxpcからの `_xpc_int64_set_value()` 関数は、以下のディスアセンブリを持つ適切な候補です：
```
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
64ビットの書き込みを特定のアドレスで実行するために、リモートコールは以下のように構成されます：
```c
_xpc_int64_set_value(address - 0x18, value)
```
これらのプリミティブが確立されると、リモートプロセスを制御する上で重要な進展となる共有メモリの作成の段階に入ります。

## 4. 共有メモリの設定

目的は、ローカルタスクとリモートタスク間で共有メモリを確立し、データ転送を簡素化し、複数の引数を持つ関数の呼び出しを容易にすることです。このアプローチは、`libxpc`とその`OS_xpc_shmem`オブジェクトタイプを活用し、Machメモリエントリに基づいて構築されます。

### プロセスの概要:

1. **メモリ割り当て**:
- `mach_vm_allocate()`を使用して共有用のメモリを割り当てます。
- 割り当てられたメモリ領域に対して`xpc_shmem_create()`を使用し、`OS_xpc_shmem`オブジェクトを作成します。この関数はMachメモリエントリの作成を管理し、`OS_xpc_shmem`オブジェクトのオフセット`0x18`にMach送信権を格納します。

2. **リモートプロセスでの共有メモリの作成**:
- リモートプロセスで`malloc()`をリモート呼び出しして、`OS_xpc_shmem`オブジェクト用のメモリを割り当てます。
- ローカルの`OS_xpc_shmem`オブジェクトの内容をリモートプロセスにコピーします。ただし、この初期コピーにはオフセット`0x18`で不正なMachメモリエントリ名が含まれています。

3. **Machメモリエントリの修正**:
- `thread_set_special_port()`メソッドを利用して、Machメモリエントリの送信権をリモートタスクに挿入します。
- オフセット`0x18`のMachメモリエントリフィールドを、リモートメモリエントリの名前で上書きして修正します。

4. **共有メモリ設定の完了**:
- リモートの`OS_xpc_shmem`オブジェクトを検証します。
- `xpc_shmem_remote()`をリモート呼び出しして、共有メモリマッピングを確立します。

これらのステップに従うことで、ローカルタスクとリモートタスク間の共有メモリが効率的に設定され、データ転送と複数の引数が必要な関数の実行が容易になります。

## 追加のコードスニペット

メモリ割り当てと共有メモリオブジェクトの作成について：
```c
mach_vm_allocate();
xpc_shmem_create();
```
リモートプロセスで共有メモリオブジェクトを作成および修正するために：
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Machポートやメモリエントリ名の詳細を正しく扱い、共有メモリの設定が適切に機能するようにしてください。

## 5. 完全な制御を達成する

共有メモリを確立し、任意の実行能力を獲得することに成功すると、基本的にターゲットプロセスを完全に制御できるようになります。この制御を可能にする主要な機能は以下の通りです：

1. **任意のメモリ操作**：
- 共有領域からデータをコピーするために`memcpy()`を呼び出して任意のメモリ読み取りを実行します。
- 共有領域にデータを転送するために`memcpy()`を使用して任意のメモリ書き込みを実行します。

2. **複数の引数を持つ関数呼び出しの処理**：
- 8つ以上の引数を必要とする関数のために、追加の引数を呼び出し規約に従ってスタック上に配置します。

3. **Machポート転送**：
- 以前に確立されたポートを介してMachメッセージを通じてタスク間でMachポートを転送します。

4. **ファイルディスクリプタ転送**：
- Ian Beerが`triple_fetch`で強調した技術であるfileportsを使用してプロセス間でファイルディスクリプタを転送します。

この包括的な制御は[threadexec](https://github.com/bazad/threadexec)ライブラリ内にカプセル化されており、被害プロセスとの対話のための詳細な実装とユーザーフレンドリーなAPIを提供しています。

## 重要な考慮事項：

- システムの安定性とデータの整合性を維持するために、メモリの読み書き操作に`memcpy()`を適切に使用してください。
- Machポートやファイルディスクリプタを転送する際は、適切なプロトコルに従い、リークや意図しないアクセスを防ぐために資源を責任を持って扱ってください。

これらのガイドラインに従い、`threadexec`ライブラリを利用することで、ターゲットプロセスを細かいレベルで効率的に管理し、対話し、完全な制御を達成することができます。

# 参考文献
* https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
