# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

**Grand Central Dispatch (GCD)** は **libdispatch** (`libdispatch.dyld`) とも呼ばれ、macOS と iOS の両方で利用できます。これは、マルチコア hardware 上での並行（multithreaded）実行に対するアプリケーションのサポートを最適化するために Apple が開発した technology です。

**GCD** は **FIFO queues** を提供および管理し、アプリケーションは **block objects** の形式で **tasks を送信**できます。dispatch queues に送信された blocks は、system が完全に管理する **thread pool 上で実行**されます。GCD は、dispatch queues 内の tasks を実行するための threads を自動的に作成し、利用可能な cores 上で実行されるように tasks をスケジュールします。

> [!TIP]
> 要約すると、**parallel** に code を実行するために、processes は **blocks of code を GCD に送信**でき、GCD がその実行を処理します。したがって、processes は新しい threads を作成せず、**GCD が独自の thread pool で指定された code を実行します**（必要に応じて増減する可能性があります）。

これは parallel execution を正常に管理するのに非常に役立ち、processes が作成する threads の数を大幅に減らし、parallel execution を最適化できます。これは、**大きな parallelism**（brute-forcing?）を必要とする tasks や、main thread を block すべきでない tasks に最適です。たとえば iOS の main thread は UI interactions を処理するため、アプリを hang させる可能性のあるその他の機能（searching、web への access、file の reading など）はこの方法で管理されます。

### Blocks

block は **self contained な code のセクション**（arguments を受け取り value を返す function のようなもの）であり、bound variables も指定できます。\
ただし、compiler level では blocks は存在せず、`os_object`s です。これらの objects はそれぞれ 2 つの structures で構成されます。

- **block literal**:
- **`isa`** field から始まり、block の class を指します:
- `NSConcreteGlobalBlock` (`__DATA.__const` にある blocks)
- `NSConcreteMallocBlock` (heap にある blocks)
- `NSConcreateStackBlock` (stack にある blocks)
- block descriptor に存在する fields を示す **`flags`** と、いくつかの reserved bytes
- 呼び出す function pointer
- block descriptor への pointer
- block が import した variables（存在する場合）
- **block descriptor**: その size は存在する data に依存します（前述の flags で示されます）
- いくつかの reserved bytes
- その size
- params に必要な space の量を把握するため、通常は Objective-C style signature への pointer を持ちます（flag `BLOCK_HAS_SIGNATURE`）
- variables が参照されている場合、この block は copy helper（開始時に value を copying）と dispose helper（freeing 用）への pointers も持ちます。

### Queues

dispatch queue は、blocks を実行するための FIFO ordering を提供する named object です。

blocks は実行されるよう queues に設定され、queues は `DISPATCH_QUEUE_SERIAL` と `DISPATCH_QUEUE_CONCURRENT` の 2 つの modes をサポートします。当然ながら **serial** queue では、前の block が完了するまで次の block が実行されないため、**race condition** の問題は発生しません。しかし、**もう一方の queue type では発生する可能性があります**。

Default queues:

- `.main-thread`: `dispatch_get_main_queue()` から取得
- `.libdispatch-manager`: GCD の queue manager
- `.root.libdispatch-manager`: GCD の queue manager
- `.root.maintenance-qos`: Lowest priority tasks
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND` として利用可能
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE` として利用可能
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT` として利用可能
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH` として利用可能
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Highest priority
- `.root.background-qos.overcommit`

**どの時点でどの threads がどの queues を処理するか**を決定するのは system である点に注意してください（複数の threads が同じ queue で処理する場合や、同じ thread がある時点で異なる queues を処理する場合があります）。

#### Attributes

**`dispatch_queue_create`** で queue を作成する場合、第 3 引数は `dispatch_queue_attr_t` であり、通常は `DISPATCH_QUEUE_SERIAL`（実際には NULL）または `DISPATCH_QUEUE_CONCURRENT` のいずれかです。`DISPATCH_QUEUE_CONCURRENT` は、queue のいくつかの parameters を制御できる `dispatch_queue_attr_t` struct への pointer です。

### Dispatch objects

libdispatch が使用する objects には複数の種類があり、queues と blocks はそのうちの 2 つにすぎません。これらの objects は `dispatch_object_create` で作成できます。

- `block`
- `data`: Data blocks
- `group`: Blocks の group
- `io`: Async I/O requests
- `mach`: Mach ports
- `mach_msg`: Mach messages
- `pthread_root_queue`: pthread thread pool を持ち、workqueues を持たない queue
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Objective-C には、block を parallel に実行するために送信するさまざまな functions があります。

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): block を dispatch queue 上で asynchronous に実行するために submit し、すぐに return します。
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): block object を実行のために submit し、その block の実行が完了した後に return します。
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): application の lifetime 中に block object を一度だけ実行します。
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): work item を実行のために submit し、実行が完了した後にのみ return します。[**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) とは異なり、この function は block を実行する際に queue のすべての attributes を尊重します。

これらの functions は次の parameters を想定します: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

これは **Block の struct** です:
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
そして、これは **`dispatch_async`** を使って **並列処理** を行う例です：
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

**`libswiftDispatch`**は、もともとCで記述されたGrand Central Dispatch（GCD）frameworkに対する**Swift bindings**を提供するlibraryです。\
**`libswiftDispatch`**libraryは、C GCD APIをよりSwiftに適したinterfaceでラップし、Swift developersがGCDをより簡単かつ直感的に扱えるようにします。

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Code example**：
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

以下の Frida script を使用すると、複数の `dispatch` function に **hook** して、queue name、backtrace、block を抽出できます: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)。
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

現在、Ghidra は ObjectiveC の **`dispatch_block_t`** 構造体も **`swift_dispatch_block`** 構造体も理解できません。

そのため、理解させたい場合は、単に **宣言** します:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

次に、それらが **使用されている** コード内の場所を探します:

> [!TIP]
> 構造体が使用されていることを特定する方法を理解するために、"block" への参照をすべて確認してください。

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

変数を右クリック -> Retype Variable を選択し、この場合は **`swift_dispatch_block`** を選択します:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra がすべてを自動的に書き換えます:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (queue/thread-pool implementation)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
