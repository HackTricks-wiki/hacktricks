# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

**Grand Central Dispatch (GCD),** також відомий як **libdispatch** (`libdispatch.dyld`), доступний як у macOS, так і в iOS. Це технологія, розроблена Apple для оптимізації підтримки застосунків для паралельного (багатопотокового) виконання на багатоядерному обладнанні.<sup>[[4]](#references)</sup>

**GCD** надає та керує **FIFO-чергами**, до яких ваш застосунок може **надсилати завдання** у формі **block-об'єктів**. Blocks, надіслані до dispatch queues, **виконуються в пулі потоків**, яким повністю керує система. GCD автоматично створює потоки для виконання завдань у dispatch queues і планує ці завдання для запуску на доступних ядрах.<sup>[[1]](#references)</sup>

> [!TIP]
> Підсумовуючи, для виконання коду **паралельно** процеси можуть надсилати **блоки коду до GCD**, який подбає про їх виконання. Тому процеси не створюють нові потоки; **GCD виконує наданий код у власному пулі потоків** (який може збільшуватися або зменшуватися за потреби).

Це дуже допомагає успішно керувати паралельним виконанням, значно зменшуючи кількість потоків, які створюють процеси, і оптимізуючи паралельне виконання. Це ідеально підходить для завдань, що потребують **значного паралелізму** (brute-forcing?), або для завдань, які не повинні блокувати головний потік: наприклад, головний потік в iOS обробляє взаємодію з UI, тому будь-яка інша функціональність, яка може призвести до зависання застосунку (пошук, доступ до web, читання файлу...), керується таким чином.

### Blocks

Block — це **самодостатня ділянка коду** (на кшталт функції з аргументами, що повертає значення), яка також може визначати зв'язані змінні.\
Однак на рівні компілятора blocks не існують, вони є `os_object`. Кожен із цих об'єктів складається з двох структур:

- **block literal**:
- Починається з поля **`isa`**, яке вказує на клас block:
- `NSConcreteGlobalBlock` (blocks із `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks у heap)
- `NSConcreateStackBlock` (blocks у stack)
- Містить **`flags`** (що вказують на поля, наявні в block descriptor) і кілька зарезервованих байтів
- Вказівник на функцію, яку потрібно викликати
- Вказівник на block descriptor
- Імпортовані змінні block (якщо є)
- **block descriptor**: його розмір залежить від наявних даних (як зазначено в попередніх flags)
- Містить кілька зарезервованих байтів
- Його розмір
- Зазвичай містить вказівник на сигнатуру в стилі Objective-C, щоб визначити, скільки місця потрібно для параметрів (flag `BLOCK_HAS_SIGNATURE`)
- Якщо є посилання на змінні, цей block також міститиме вказівники на copy helper (копіює значення на початку) і dispose helper (звільняє його).

### Queues

Dispatch queue — це іменований об'єкт, який забезпечує FIFO-порядок виконання blocks.<sup>[[3]](#references)</sup>

Blocks встановлюються в queues для виконання, і вони підтримують 2 режими: `DISPATCH_QUEUE_SERIAL` і `DISPATCH_QUEUE_CONCURRENT`. Звичайно, **serial** queue **не матиме проблем із race condition**, оскільки block не виконуватиметься, доки попередній не завершить виконання. Але **в іншого типу queue такі проблеми можуть виникати**.

Queues за замовчуванням:

- `.main-thread`: з `dispatch_get_main_queue()`
- `.libdispatch-manager`: менеджер queue GCD
- `.root.libdispatch-manager`: менеджер queue GCD
- `.root.maintenance-qos`: завдання з найнижчим пріоритетом
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: доступна як `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: доступна як `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: доступна як `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: доступна як `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: найвищий пріоритет
- `.root.background-qos.overcommit`

Зверніть увагу, що саме система вирішує, **які потоки обробляють які queues у кожен момент часу** (кілька потоків можуть працювати в одній queue, або той самий потік у певний момент може працювати в різних queues).

#### Атрибути

Під час створення queue за допомогою **`dispatch_queue_create`** третій аргумент має тип `dispatch_queue_attr_t`, який зазвичай є або `DISPATCH_QUEUE_SERIAL` (фактично NULL), або `DISPATCH_QUEUE_CONCURRENT` — вказівником на структуру `dispatch_queue_attr_t`, що дає змогу керувати деякими параметрами queue.

### Dispatch objects

Існує кілька об'єктів, які використовує libdispatch; queues і blocks — лише 2 з них. Ці об'єкти можна створювати за допомогою `dispatch_object_create`:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: блоки даних
- `group`: група blocks
- `io`: асинхронні I/O-запити
- `mach`: Mach-порти
- `mach_msg`: Mach-повідомлення
- `pthread_root_queue`: queue із пулом потоків pthread, але без workqueues
- `queue`
- `semaphore`
- `source`: джерело подій

## Objective-C

В Objective-C існують різні функції для надсилання block на паралельне виконання:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): надсилає block для асинхронного виконання в dispatch queue і негайно повертає результат.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): надсилає block-об'єкт на виконання і повертає результат після завершення виконання цього block.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): виконує block-об'єкт лише один раз протягом життєвого циклу застосунку.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): надсилає work item на виконання і повертає результат лише після завершення його виконання. На відміну від [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), ця функція враховує всі атрибути queue під час виконання block.

Ці функції очікують такі параметри: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Це **структура Block**:
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
А ось приклад використання **паралелізму** з **`dispatch_async`**:
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

**`libswiftDispatch`** — це бібліотека, яка надає **Swift bindings** для фреймворку Grand Central Dispatch (GCD), початково написаного мовою C.\
Бібліотека **`libswiftDispatch`** обгортає API C GCD у більш зручний для Swift інтерфейс, спрощуючи та роблячи інтуїтивнішою роботу розробників Swift із GCD.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Приклад коду**:
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

Наведений нижче Frida-скрипт можна використовувати, щоб **підключитися до кількох функцій `dispatch`** і отримати назву черги, backtrace та block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Наразі Ghidra не розуміє ні структуру ObjectiveC **`dispatch_block_t`**, ні структуру **`swift_dispatch_block`**.

Тож якщо ви хочете, щоб вона їх розуміла, просто **оголосіть їх**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Потім знайдіть у коді місце, де вони **використовуються**:

> [!TIP]
> Зверніть увагу на всі посилання на "block", щоб зрозуміти, як можна визначити, що використовується ця структура.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Клацніть правою кнопкою миші змінну -> Retype Variable і в цьому випадку виберіть **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra автоматично перепише все:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Посилання

- [1] [libdispatch — `src/queue.c` (реалізація queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (публічний queue API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
