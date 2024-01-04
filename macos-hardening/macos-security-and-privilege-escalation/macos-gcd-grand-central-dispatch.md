# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

**Grand Central Dispatch (GCD)**、または**libdispatch**は、macOSとiOSの両方で利用可能です。これはAppleが開発した技術で、マルチコアハードウェア上でのアプリケーションの並行（マルチスレッド）実行を最適化するためのものです。

**GCD**は、アプリケーションが**ブロックオブジェクト**の形で**タスクを送信**できる**FIFOキュー**を提供し、管理します。ディスパッチキューに送信されたブロックは、システムによって完全に管理されるスレッドプール上で**実行されます**。GCDは自動的にディスパッチキューでタスクを実行するためのスレッドを作成し、利用可能なコア上でそれらのタスクを実行するようにスケジュールします。

{% hint style="success" %}
要約すると、コードを**並行して実行する**ために、プロセスは**コードのブロックをGCDに送信**でき、GCDがその実行を管理します。したがって、プロセスは新しいスレッドを作成せず、**GCDは自身のスレッドプールで与えられたコードを実行します**。
{% endhint %}

これは、並行実行を成功させるために非常に役立ち、プロセスが作成するスレッドの数を大幅に減らし、並行実行を最適化します。これは、**大きな並列性**（ブルートフォース？）が必要なタスクや、メインスレッドをブロックすべきでないタスクに理想的です。例えば、iOSのメインスレッドはUIのインタラクションを処理するため、アプリをハングさせる可能性のある他の機能（検索、ウェブへのアクセス、ファイルの読み取りなど）はこの方法で管理されます。

## Objective-C

Objective-Cでは、ブロックを並行して実行するために送信するさまざまな関数があります：

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): ディスパッチキューに非同期実行用のブロックを送信し、すぐに戻ります。
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): ブロックオブジェクトを実行用に送信し、そのブロックの実行が完了した後に戻ります。
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): アプリケーションの生涯にわたってブロックオブジェクトを一度だけ実行します。
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): 実行用の作業項目を送信し、実行が完了するまで戻りません。[**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)とは異なり、この関数はブロックを実行する際にキューのすべての属性を尊重します。

これらの関数は次のパラメータを期待します：[**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

これが**ブロックの構造体**です：
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
これは **`dispatch_async`** を使用して**並列処理**を行う例です：
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

**`libswiftDispatch`** は、もともとCで書かれたGrand Central Dispatch (GCD) フレームワークへの **Swiftバインディング** を提供するライブラリです。\
**`libswiftDispatch`** ライブラリは、CのGCD APIをSwiftにとってより使いやすく直感的なインターフェースでラップしています。これにより、Swift開発者はGCDを扱う際に容易かつ直感的に作業できます。

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

以下のFridaスクリプトは、いくつかの`dispatch`関数に**フックして**キュー名、バックトレース、ブロックを抽出するために使用できます: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

現在、GhidraはObjectiveCの**`dispatch_block_t`**構造体も、**`swift_dispatch_block`**構造体も理解していません。

それらを理解させたい場合は、単に**宣言する**ことができます：

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

次に、コード内でそれらが**使用されている**場所を見つけます：

{% hint style="success" %}
"block"へのすべての参照に注意して、構造体が使用されていることをどのように判断できるかを理解してください。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

変数を右クリック -> Retype Variableを選択し、この場合は**`swift_dispatch_block`**を選択します：

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidraは自動的にすべてを書き換えます：

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
