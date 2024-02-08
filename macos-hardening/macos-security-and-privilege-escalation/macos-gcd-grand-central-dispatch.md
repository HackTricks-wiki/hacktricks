# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学びましょう</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、**ハッキングテクニックを共有**してください。

</details>

## 基本情報

**Grand Central Dispatch（GCD）**、または**libdispatch**は、macOSとiOSの両方で利用可能です。これは、Appleが開発した技術であり、マルチコアハードウェア上での並行（マルチスレッド）実行を最適化するためのアプリケーションサポートを提供します。

**GCD**は、アプリケーションが**ブロックオブジェクト**の形で**タスクを送信**できる**FIFOキュー**を提供し管理します。ディスパッチキューに送信されたブロックは、システムによって完全に管理される**スレッドプール**で実行されます。GCDは、ディスパッチキュー内のタスクを実行するためにスレッドを自動的に作成し、それらのタスクを利用可能なコアで実行するようスケジュールします。

{% hint style="success" %}
要するに、**並列でコードを実行**するために、プロセスは**GCDにコードブロックを送信**し、その実行を管理します。したがって、プロセスは新しいスレッドを作成しません。**GCDは独自のスレッドプールで指定されたコードを実行**します。
{% endhint %}

これは、並列実行を成功裏に管理するのに非常に役立ち、プロセスが作成するスレッドの数を大幅に減らし、並列実行を最適化します。これは、**大規模な並列性**（ブルートフォース？）を必要とするタスクや、メインスレッドをブロックすべきでないタスクに非常に適しています。たとえば、iOSのメインスレッドはUIの相互作用を処理するため、アプリがフリーズする可能性のある機能（検索、Webへのアクセス、ファイルの読み取りなど）はこの方法で管理されます。

## Objective-C

Objective-Cでは、ブロックを並列で実行するために異なる関数があります：

- [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async)：ブロックを非同期でディスパッチキューに送信し、すぐに返します。
- [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)：ブロックオブジェクトを実行するために送信し、そのブロックの実行が終了した後に返ります。
- [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once)：アプリケーションの寿命中にブロックオブジェクトを1回だけ実行します。
- [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait)：作業アイテムを実行し、その実行が終了した後にのみ返ります。[**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)とは異なり、この関数はキューのすべての属性を尊重してブロックを実行します。

これらの関数は、次のパラメータを期待しています：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

これが**ブロックの構造**です：
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
そして、**`dispatch_async`**を使用して**並列処理**を行う例です：
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

現在、GhidraはObjectiveCの**`dispatch_block_t`**構造体や**`swift_dispatch_block`**構造体を理解していません。

したがって、それらを理解させたい場合は、単に**宣言**することができます：

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

次に、それらが**使用**されているコードの場所を見つけます：

{% hint style="success" %}
"block"に言及されているすべての参照を注意して、構造体が使用されている方法を理解できます。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

変数を右クリック -> 変数の型を変更し、この場合は**`swift_dispatch_block`**を選択します：

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidraは自動的にすべてを書き換えます：

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>
