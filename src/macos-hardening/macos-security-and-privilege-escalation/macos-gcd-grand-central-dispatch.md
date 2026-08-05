# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

**Grand Central Dispatch (GCD)**는 **libdispatch** (`libdispatch.dyld`)라고도 하며, macOS와 iOS에서 모두 사용할 수 있습니다. 이는 멀티코어 하드웨어에서 동시 실행(멀티스레드)을 지원하도록 애플리케이션을 최적화하기 위해 Apple이 개발한 기술입니다.

**GCD**는 애플리케이션이 **block 객체** 형태로 **task를 제출**할 수 있는 **FIFO queue**를 제공하고 관리합니다. dispatch queue에 제출된 block은 시스템이 완전히 관리하는 **thread pool에서 실행**됩니다. GCD는 dispatch queue의 task를 실행하기 위한 thread를 자동으로 생성하고, 해당 task가 사용 가능한 core에서 실행되도록 스케줄링합니다.

> [!TIP]
> 요약하면, 코드를 **병렬**로 실행하기 위해 process는 **GCD에 code block을 보낼 수 있으며**, GCD가 해당 실행을 처리합니다. 따라서 process는 새로운 thread를 생성하지 않고, **GCD가 자체 thread pool을 사용해 전달받은 code를 실행**합니다(필요에 따라 thread 수가 증가하거나 감소할 수 있음).

이는 병렬 실행을 성공적으로 관리하는 데 매우 유용하며, process가 생성하는 thread 수를 크게 줄이고 병렬 실행을 최적화합니다. **높은 수준의 병렬성**이 필요한 task(Brute-forcing?)나 main thread를 block해서는 안 되는 task에 적합합니다. 예를 들어 iOS의 main thread는 UI 상호작용을 처리하므로, 앱을 멈추게 할 수 있는 다른 기능(검색, web 접근, file 읽기 등)은 이런 방식으로 관리됩니다.

### Blocks

Block은 **독립적으로 동작하는 code section**(인자를 받고 값을 반환하는 function과 유사함)이며, bound variable도 지정할 수 있습니다.\
하지만 compiler 수준에서 block은 존재하지 않고, `os_object`입니다. 이러한 각 객체는 두 개의 structure로 구성됩니다.

- **block literal**:
- **`isa`** field로 시작하며, block의 class를 가리킵니다.
- `NSConcreteGlobalBlock` (`__DATA.__const`의 block)
- `NSConcreteMallocBlock` (heap의 block)
- `NSConcreateStackBlock` (stack의 block)
- block descriptor에 존재하는 field를 나타내는 **`flags`**와 일부 reserved byte가 있습니다.
- 호출할 function pointer
- block descriptor를 가리키는 pointer
- Block이 import한 variable(있는 경우)
- **block descriptor**: 앞의 flags에 표시된 데이터에 따라 크기가 달라집니다.
- 일부 reserved byte가 있습니다.
- size가 있습니다.
- parameter에 필요한 공간을 확인하기 위한 Objective-C style signature를 가리키는 pointer가 일반적으로 포함됩니다(`BLOCK_HAS_SIGNATURE` flag).
- variable이 참조되는 경우, 이 block에는 copy helper(시작 시 값을 복사)와 dispose helper(해제)를 가리키는 pointer도 포함됩니다.

### Queues

Dispatch queue는 block을 실행하기 위한 FIFO 순서를 제공하는 이름이 지정된 객체입니다.

Block은 실행되도록 queue에 설정되며, queue는 `DISPATCH_QUEUE_SERIAL`과 `DISPATCH_QUEUE_CONCURRENT`의 두 가지 mode를 지원합니다. 물론 **serial** queue에서는 이전 block이 완료될 때까지 다음 block이 실행되지 않으므로 **race condition** 문제가 발생하지 않습니다. 하지만 **다른 유형의 queue에서는 race condition이 발생할 수 있습니다**.

Default queue:

- `.main-thread`: `dispatch_get_main_queue()`에서 가져옴
- `.libdispatch-manager`: GCD의 queue manager
- `.root.libdispatch-manager`: GCD의 queue manager
- `.root.maintenance-qos`: 가장 낮은 priority의 task
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND`로 사용 가능
- `.root.background-qos.overcommit`
- `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`로 사용 가능
- `.root.utility-qos.overcommit`
- `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT`로 사용 가능
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH`로 사용 가능
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: 가장 높은 priority
- `.root.background-qos.overcommit`

각 시점에 어떤 thread가 어떤 queue를 처리할지는 **system이 결정한다**는 점에 유의해야 합니다(여러 thread가 동일한 queue에서 작업할 수도 있고, 동일한 thread가 어느 시점에는 서로 다른 queue에서 작업할 수도 있음).

#### Attributtes

**`dispatch_queue_create`**로 queue를 생성할 때 세 번째 인자는 `dispatch_queue_attr_t`이며, 일반적으로 `DISPATCH_QUEUE_SERIAL`(실제로는 NULL)이거나 queue의 일부 parameter를 제어할 수 있는 `dispatch_queue_attr_t` struct를 가리키는 `DISPATCH_QUEUE_CONCURRENT`입니다.

### Dispatch objects

libdispatch가 사용하는 객체에는 여러 종류가 있으며, queue와 block은 그중 두 가지일 뿐입니다. `dispatch_object_create`를 사용해 이러한 객체를 생성할 수 있습니다.

- `block`
- `data`: Data block
- `group`: Block group
- `io`: Async I/O request
- `mach`: Mach port
- `mach_msg`: Mach message
- `pthread_root_queue`: pthread thread pool을 사용하며 workqueue는 사용하지 않는 queue
- `queue`
- `semaphore`
- `source`: Event source

## Objective-C

Objective-C에는 block을 병렬로 실행하기 위해 전송하는 여러 function이 있습니다.

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Dispatch queue에서 비동기 실행을 위해 block을 제출하고 즉시 반환합니다.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): 실행을 위해 block 객체를 제출하고 해당 block의 실행이 완료된 후 반환합니다.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): 애플리케이션의 lifetime 동안 block 객체를 한 번만 실행합니다.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): 실행을 위해 work item을 제출하고 실행이 완료된 후에만 반환합니다. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync)와 달리, 이 function은 block을 실행할 때 queue의 모든 attribute를 준수합니다.

이 function들은 다음 parameter를 필요로 합니다: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

다음은 **Block의 struct**입니다.
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
그리고 다음은 **`dispatch_async`**를 사용한 **병렬 처리**의 예시입니다:
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

**`libswiftDispatch`**는 원래 C로 작성된 Grand Central Dispatch (GCD) framework에 **Swift bindings**를 제공하는 library입니다.\
**`libswiftDispatch`** library는 C GCD API를 보다 Swift 친화적인 interface로 wrapping하여, Swift 개발자가 GCD를 더 쉽고 직관적으로 사용할 수 있도록 합니다.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Code 예시**:
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

다음 Frida script를 사용하면 여러 `dispatch` 함수에 **hook**을 걸고 queue name, backtrace 및 block을 추출할 수 있습니다: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

현재 Ghidra는 ObjectiveC **`dispatch_block_t`** 구조체와 **`swift_dispatch_block`** 구조체를 모두 이해하지 못합니다.

따라서 Ghidra가 이를 이해하도록 하려면, 간단히 **선언**하면 됩니다:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

그런 다음 해당 구조체가 **사용된** 코드 내 위치를 찾습니다:

> [!TIP]
> "block"에 대한 모든 참조를 확인하면 구조체가 사용되고 있음을 어떻게 알아낼 수 있는지 파악하는 데 도움이 됩니다.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

변수를 마우스 오른쪽 버튼으로 클릭하고 -> Retype Variable을 선택한 다음, 이 경우에는 **`swift_dispatch_block`**을 선택합니다:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra가 자동으로 모든 항목을 다시 작성합니다:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [libdispatch — `src/queue.c` (queue/thread-pool 구현)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (public queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
