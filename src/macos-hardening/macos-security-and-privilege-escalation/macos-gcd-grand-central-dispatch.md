# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

**Grand Central Dispatch (GCD)**、別名 **libdispatch** (`libdispatch.dyld`) は、macOS と iOS の両方で利用可能です。これは、Apple が開発した技術で、マルチコアハードウェア上での並行（マルチスレッド）実行のためのアプリケーションサポートを最適化します。

**GCD** は、アプリケーションが **ブロックオブジェクト** の形で **タスクを提出** できる **FIFO キュー** を提供し、管理します。ディスパッチキューに提出されたブロックは、システムによって完全に管理されるスレッドプール上で **実行されます**。GCD は、ディスパッチキュー内のタスクを実行するためのスレッドを自動的に作成し、利用可能なコアでそれらのタスクを実行するようにスケジュールします。

> [!TIP]
> 要約すると、**並行して** コードを実行するために、プロセスは **GCD にコードのブロックを送信** でき、GCD がその実行を管理します。したがって、プロセスは新しいスレッドを作成せず、**GCD が独自のスレッドプールで指定されたコードを実行します**（必要に応じて増減する可能性があります）。

これは、並行実行を成功裏に管理するのに非常に役立ち、プロセスが作成するスレッドの数を大幅に削減し、並行実行を最適化します。これは、**大きな並行性**（ブルートフォース？）を必要とするタスクや、メインスレッドをブロックすべきでないタスクに理想的です。たとえば、iOS のメインスレッドは UI インタラクションを処理するため、アプリをハングさせる可能性のある他の機能（検索、ウェブへのアクセス、ファイルの読み取りなど）はこの方法で管理されます。

### ブロック

ブロックは、**自己完結型のコードセクション**（引数を持ち、値を返す関数のようなもの）であり、バウンド変数を指定することもできます。\
ただし、コンパイラレベルではブロックは存在せず、`os_object` です。これらのオブジェクトは、2 つの構造体で構成されています：

- **ブロックリテラル**:&#x20;
- **`isa`** フィールドで始まり、ブロックのクラスを指します：
- `NSConcreteGlobalBlock`（`__DATA.__const` からのブロック）
- `NSConcreteMallocBlock`（ヒープ内のブロック）
- `NSConcreateStackBlock`（スタック内のブロック）
- **`flags`**（ブロックディスクリプタに存在するフィールドを示す）といくつかの予約バイト
- 呼び出すための関数ポインタ
- ブロックディスクリプタへのポインタ
- インポートされた変数（ある場合）
- **ブロックディスクリプタ**：そのサイズは、前述のフラグで示されるデータに依存します
- いくつかの予約バイト
- そのサイズ
- 通常、パラメータに必要なスペースを知るための Objective-C スタイルのシグネチャへのポインタを持ちます（フラグ `BLOCK_HAS_SIGNATURE`）
- 変数が参照されている場合、このブロックは値を最初にコピーするためのコピー補助関数と解放するための解放補助関数へのポインタも持ちます。

### キュー

ディスパッチキューは、実行のためのブロックの FIFO 順序を提供する名前付きオブジェクトです。

ブロックはキューにセットされて実行され、これには 2 つのモードがサポートされています：`DISPATCH_QUEUE_SERIAL` と `DISPATCH_QUEUE_CONCURRENT`。もちろん、**シリアル**な方は **レースコンディション** の問題を持たず、ブロックは前のものが終了するまで実行されません。しかし、**もう一方のタイプのキューはそれを持つ可能性があります**。

デフォルトのキュー：

- `.main-thread`: `dispatch_get_main_queue()` から
- `.libdispatch-manager`: GCD のキュー管理者
- `.root.libdispatch-manager`: GCD のキュー管理者
- `.root.maintenance-qos`: 最低優先度のタスク
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND` として利用可能
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE` として利用可能
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT` として利用可能
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH` として利用可能
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: 最高優先度
- `.root.background-qos.overcommit`

どのスレッドがどのキューを処理するかは **システムが決定する** ことに注意してください（複数のスレッドが同じキューで作業することもあれば、同じスレッドが異なるキューで作業することもあります）。

#### 属性

**`dispatch_queue_create`** を使用してキューを作成する際、3 番目の引数は `dispatch_queue_attr_t` で、通常は `DISPATCH_QUEUE_SERIAL`（実際には NULL）または `DISPATCH_QUEUE_CONCURRENT` で、これはキューのいくつかのパラメータを制御するための `dispatch_queue_attr_t` 構造体へのポインタです。

### ディスパッチオブジェクト

libdispatch が使用するオブジェクトは複数あり、キューとブロックはそのうちの 2 つです。これらのオブジェクトは `dispatch_object_create` で作成可能です：

- `block`
- `data`: データブロック
- `group`: ブロックのグループ
- `io`: 非同期 I/O リクエスト
- `mach`: Mach ポート
- `mach_msg`: Mach メッセージ
- `pthread_root_queue`: pthread スレッドプールを持つキューで、作業キューではありません
- `queue`
- `semaphore`
- `source`: イベントソース

## Objective-C

Objective-C では、ブロックを並行して実行するために送信するための異なる関数があります：

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): ディスパッチキューで非同期実行のためにブロックを提出し、すぐに戻ります。
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): 実行のためにブロックオブジェクトを提出し、そのブロックの実行が終了した後に戻ります。
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): アプリケーションのライフタイム中にブロックオブジェクトを一度だけ実行します。
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): 実行のために作業項目を提出し、実行が終了するまで戻りません。[**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) とは異なり、この関数はブロックを実行する際にキューのすべての属性を尊重します。

これらの関数は次のパラメータを期待します：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

これが **ブロックの構造体** です：
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
これは**`dispatch_async`**を使用した**parallelism**の例です：
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** は、元々Cで書かれたGrand Central Dispatch (GCD)フレームワークへの**Swiftバインディング**を提供するライブラリです。\
**`libswiftDispatch`** ライブラリは、C GCD APIをよりSwiftに優しいインターフェースでラップし、Swift開発者がGCDを扱いやすく、直感的にすることを可能にします。

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Code example**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

次のFridaスクリプトは、**いくつかの`dispatch`**関数にフックし、キュー名、バックトレース、およびブロックを抽出するために使用できます: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

現在、GhidraはObjectiveC **`dispatch_block_t`** 構造体も、**`swift_dispatch_block`** 構造体も理解していません。

したがって、これらを理解させたい場合は、単に**宣言する**ことができます：

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

次に、コード内でそれらが**使用されている**場所を見つけます：

> [!TIP]
> "block"に関するすべての参照をメモして、構造体がどのように使用されているかを理解してください。

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

変数を右クリック -> 変数の再タイプを選択し、この場合は**`swift_dispatch_block`**を選択します：

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidraは自動的にすべてを書き換えます：

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
