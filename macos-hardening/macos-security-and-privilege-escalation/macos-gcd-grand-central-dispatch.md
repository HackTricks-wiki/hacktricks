# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>を使って、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法:

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れる
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に**参加**💬(https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**🐦で**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## 基本情報

**Grand Central Dispatch (GCD)**、またの名を**libdispatch** (`libdispatch.dyld`) は、macOSとiOSの両方で利用可能です。これは、Appleが開発した技術であり、マルチコアハードウェア上での並行（マルチスレッド）実行を最適化するためのアプリケーションサポートを提供します。

**GCD**は、アプリケーションが**ブロックオブジェクト**の形で**タスクを送信**できる**FIFOキュー**を提供し管理します。ディスパッチキューに送信されたブロックは、システムによって完全に管理されるスレッドプールで実行されます。GCDは、ディスパッチキュー内のタスクを実行するためにスレッドを自動的に作成し、それらのタスクを利用可能なコアで実行するようスケジュールします。

{% hint style="success" %}
要約すると、**並列でコードを実行**するために、プロセスは**GCDにコードブロックを送信**し、その実行を管理します。したがって、プロセスは新しいスレッドを作成しません。**GCDは独自のスレッドプールで指定されたコードを実行**します（必要に応じて増減するかもしれません）。
{% endhint %}

これは、並列実行を成功裏に管理するのに非常に役立ち、プロセスが作成するスレッドの数を大幅に減らし、並列実行を最適化します。これは、**大規模な並列性**（ブルートフォース？）を必要とするタスクや、メインスレッドをブロックすべきでないタスクに最適です。たとえば、iOSのメインスレッドはUIの相互作用を処理するため、アプリがフリーズする可能性のある他の機能（検索、Webへのアクセス、ファイルの読み取りなど）はこの方法で処理されます。

### ブロック

ブロックは**自己完結型のコードセクション**（引数を取り値を返す関数のようなもの）であり、バインド変数を指定することもできます。\
ただし、コンパイラレベルではブロックは存在せず、`os_object`です。これらのオブジェクトのそれぞれは2つの構造体で構成されます:

- **ブロックリテラル**:
  - ブロックのクラスを指す**`isa`**フィールドで始まります:
    - `NSConcreteGlobalBlock`（`__DATA.__const`からのブロック）
    - `NSConcreteMallocBlock`（ヒープ内のブロック）
    - `NSConcreateStackBlock`（スタック内のブロック）
  - ブロック記述子に存在するフィールドを示す**`flags`**（ブロック記述子に存在するフィールドを示す）といくつかの予約バイト
  - 呼び出すための関数ポインタ
  - ブロック記述子へのポインタ
  - インポートされた変数（存在する場合）
- **ブロック記述子**：データに応じてサイズが異なります（前述のフラグで示されているもの）
  - いくつかの予約バイト
  - サイズ
  - 通常、パラメータに必要なスペースの量を知るためにObjective-Cスタイルのシグネチャへのポインタが含まれます（フラグ`BLOCK_HAS_SIGNATURE`）
  - 変数が参照されている場合、このブロックには値をコピーするヘルパー（開始時に値をコピーする）と解放ヘルパー（解放する）へのポインタも含まれます。

### キュー

ディスパッチキューは、ブロックの実行のためのFIFO順序を提供する名前付きオブジェクトです。

ブロックは実行されるためにキューに設定され、これらは`DISPATCH_QUEUE_SERIAL`と`DISPATCH_QUEUE_CONCURRENT`の2つのモードをサポートします。もちろん、**シリアル**は**競合状態が発生しない**ため、前のブロックが終了するまで次のブロックは実行されません。しかし、**もう一つのタイプのキューはそれを持つかもしれません**。

デフォルトのキュー:

- `.main-thread`: `dispatch_get_main_queue()`から
- `.libdispatch-manager`: GCDのキューマネージャ
- `.root.libdispatch-manager`: GCDのキューマネージャ
- `.root.maintenance-qos`: 最低優先度のタスク
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND`として利用可能
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`として利用可能
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT`として利用可能
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH`として利用可能
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: 最高の優先度
- `.root.background-qos.overcommit`

システムが**どのスレッドがいつどのキューを処理するか**を決定します（複数のスレッドが同じキューで作業するか、同じスレッドがある時点で異なるキューで作業するかもしれません）

#### 属性

**`dispatch_queue_create`**でキューを作成する際、3番目の引数は`dispatch_queue_attr_t`であり、通常は`DISPATCH_QUEUE_SERIAL`（実際にはNULL）または`DISPATCH_QUEUE_CONCURRENT`（キューのいくつかのパラメータを制御できる`dispatch_queue_attr_t`構造体へのポインタ）です。

### ディスパッチオブジェクト

libdispatchが使用するオブジェクトにはいくつかあり、キューとブロックはそのうちの2つです。これらのオブジェクトは`dispatch_object_create`を使用して作成できます:

- `block`
- `data`: データブロック
- `group`: ブロックのグループ
- `io`: 非同期I/Oリクエスト
- `mach`: Machポート
- `mach_msg`: Machメッセージ
- `pthread_root_queue`: pthreadスレッドプールとワークキューを持つキュー
- `queue`
- `semaphore`
- `source`: イベントソース

## Objective-C

Objective-Cでは、並列でブロックを送信するための異なる関数があります:

- [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): ディスパッチキューで非同期にブロックを送信し、すぐに返します。
- [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): ブロックオブジェクトを実行するために送信し、そのブロックの実行が終了した後に返ります。
- [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): アプリケーションのライフタイム中にブロックオブジェクトを1回だけ実行します。
- [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): ワークアイテムを実行し、その実行が終了するまでにのみ返ります。[**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)とは異なり、この関数はキューのすべての属性を尊重してブロックを実行します。

これらの関数は、これらのパラメータを期待します: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

これが**ブロックの構造体**です:
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
そして、**`dispatch_async`**を使用して**並列処理**を行う例が以下になります：
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

**`libswiftDispatch`**は、元々Cで書かれたGrand Central Dispatch（GCD）フレームワークへの**Swiftバインディング**を提供するライブラリです。\
**`libswiftDispatch`**ライブラリは、CのGCD APIをよりSwift向けにラップし、Swift開発者がGCDとより簡単かつ直感的に作業できるようにします。

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**コード例**:
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

次のFridaスクリプトを使用して、複数の`dispatch`関数にフックし、キュー名、バックトレース、およびブロックを抽出できます: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

現在、GhidraはObjectiveCの**`dispatch_block_t`**構造体も**`swift_dispatch_block`**構造体も理解していません。

したがって、それらを理解させたい場合は、単に**宣言**することができます：

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

次に、コード内でそれらが**使用**されている場所を見つけます：

{% hint style="success" %}
"block"に関するすべての参照をメモして、構造体がどのように使用されているかを理解する方法を考えてみてください。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

変数を右クリック -> 変数の型を変更 -> この場合は**`swift_dispatch_block`**を選択します：

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidraは自動的にすべてを書き換えます：

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

## 参考文献

* [**\*OS Internals、Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
