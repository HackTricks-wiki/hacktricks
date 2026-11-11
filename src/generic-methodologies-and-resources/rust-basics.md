# Rust 基础

{{#include ../banners/hacktricks-training.md}}

### 变量的所有权

内存通过所有权系统进行管理，编译器会在编译时检查以下规则：

1. Rust 中的每个值都有一个称为其所有者的变量。
2. 同一时间只能有一个所有者。
3. 所有者超出作用域时，该值将被丢弃。

```rust
fn main() {
    let student_age: u32 = 20;
    { // Scope of a variable is within the block it is declared in, which is denoted by brackets
        let teacher_age: u32 = 41;
        println!("The student is {} and teacher is {}", student_age, teacher_age);
    } // when an owning variable goes out of scope, it will be dropped

    // println!("the teacher is {}", teacher_age); // this will not work as teacher_age has been dropped
}
```



### 泛型

创建一个结构体，其中一个值可以是任意类型。

```rust
struct Wrapper<T> {
    value: T,
}

impl<T> Wrapper<T> {
    pub fn new(value: T) -> Self {
        Wrapper { value }
    }
}

Wrapper::new(42).value
Wrapper::new("Foo").value, "Foo"
```

### Option, Some & None

Option 类型表示该值可能是 Some（有值）或 None：

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

You 可以使用 `is_some()` 或 `is_none()` 等函数来检查 Option 的值。


### Result, Ok & Err

用于返回和传播错误

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

你可以使用 `is_ok()` 或 `is_err()` 等函数来检查结果的值

在值可能不存在（即为 `None`）时，应使用 `Option` 枚举。
在你执行的操作可能出错时，应使用 `Result` 枚举。


### 宏

宏比函数更强大，因为它们会展开并生成比你手动编写的代码更多的代码。例如，函数签名必须声明函数参数的数量和类型。而宏则可以接受数量可变的参数：我们可以用一个参数调用 `println!("hello")`，也可以用两个参数调用 `println!("hello {}", name)`。此外，宏会在编译器解释代码含义之前展开，因此宏可以在给定类型上实现 trait。函数做不到这一点，因为函数是在运行时调用的，而 trait 必须在编译时实现。

```rust
macro_rules! my_macro {
    () => {
        println!("Check out my macro!");
    };
    ($val:expr) => {
        println!("Look at this other macro: {}", $val);
    }
}
fn main() {
    my_macro!();
    my_macro!(7777);
}

// Export a macro from a module
mod macros {
    #[macro_export]
    macro_rules! my_macro {
        () => {
            println!("Check out my macro!");
        };
    }
}
```

### 迭代

```rust
// Iterate through a vector
let my_fav_fruits = vec!["banana", "raspberry"];
let mut my_iterable_fav_fruits = my_fav_fruits.iter();
assert_eq!(my_iterable_fav_fruits.next(), Some(&"banana"));
assert_eq!(my_iterable_fav_fruits.next(), Some(&"raspberry"));
assert_eq!(my_iterable_fav_fruits.next(), None); // When it's over, it's none
 
// One line iteration with action
my_fav_fruits.iter().map(|x| capitalize_first(x)).collect()

// Hashmap iteration
for (key, hashvalue) in &*map {
for key in map.keys() {
for value in map.values() {
```

### 递归 Box

递归枚举需要间接引用，以便在编译时确定其大小；直接在 `List` 中存储 `List` 无法通过编译。<sup>[[10]](#references)</sup>

```rust
enum List {
    Cons(i32, Box<List>),
    Nil,
}

use List::{Cons, Nil};

fn main() {
    let _list = Cons(1, Box::new(Cons(2, Box::new(Cons(3, Box::new(Nil))))));
}
```

### 条件语句

#### if

```rust
let n = 5;
if n < 0 {
    print!("{} is negative", n);
} else if n > 0 {
    print!("{} is positive", n);
} else {
    print!("{} is zero", n);
}
```

#### match

```rust
match number {
    // Match a single value
    1 => println!("One!"),
    // Match several values
    2 | 3 | 5 | 7 | 11 => println!("This is a prime"),
    // TODO ^ Try adding 13 to the list of prime values
    // Match an inclusive range
    13..=19 => println!("A teen"),
    // Handle the rest of cases
    _ => println!("Ain't special"),
}

let boolean = true;
// Match is an expression too
let binary = match boolean {
    // The arms of a match must cover all the possible values
    false => 0,
    true => 1,
    // TODO ^ Try commenting out one of these arms
};
```

#### loop（无限循环）

```rust
loop {
    count += 1;
    if count == 3 {
        println!("three");
        continue;
    }
    println!("{}", count);
    if count == 5 {
        println!("OK, that's enough");
        break;
    }
}
```

#### while

```rust
let mut n = 1;
while n < 101 {
    if n % 15 == 0 {
        println!("fizzbuzz");
    } else if n % 5 == 0 {
        println!("buzz");
    } else {
        println!("{}", n);
    }
    n += 1;
}
```

#### for

```rust
for n in 1..101 {
    if n % 15 == 0 {
        println!("fizzbuzz");
    } else {
        println!("{}", n);
    }
}

// Use "..=" to make inclusive both ends
for n in 1..=100 {
    if n % 15 == 0 {
        println!("fizzbuzz");
    } else if n % 3 == 0 {
        println!("fizz");
    } else if n % 5 == 0 {
        println!("buzz");
    } else {
        println!("{}", n);
    }
}

// ITERATIONS

let names = vec!["Bob", "Frank", "Ferris"];
//iter - Doesn't consume the collection
for name in names.iter() {
    match name {
        &"Ferris" => println!("There is a rustacean among us!"),
        _ => println!("Hello {}", name),
    }
}
//into_iter - COnsumes the collection
for name in names.into_iter() {
    match name {
        "Ferris" => println!("There is a rustacean among us!"),
        _ => println!("Hello {}", name),
    }
}
//iter_mut - This mutably borrows each element of the collection
for name in names.iter_mut() {
    *name = match name {
        &mut "Ferris" => "There is a rustacean among us!",
        _ => "Hello",
    }
}
```

#### if let

匹配 `Some` 以绑定其内部值；普通变量模式会同时匹配 `Some` 和 `None`，因此 `else` 分支永远不会执行。<sup>[[11]](#references)</sup>

```rust
let optional_word = Some(String::from("rustlings"));
if let Some(word) = optional_word {
    println!("The word is: {}", word);
} else {
    println!("The optional word doesn't contain anything");
}
```

#### while let

```rust
let mut optional = Some(0);
// This reads: "while `let` destructures `optional` into
// `Some(i)`, evaluate the block (`{}`). Else `break`.
while let Some(i) = optional {
    if i > 9 {
        println!("Greater than 9, quit!");
        optional = None;
    } else {
        println!("`i` is `{:?}`. Try again.", i);
        optional = Some(i + 1);
    }
    // ^ Less rightward drift and doesn't require
    // explicitly handling the failing case.
}
```

### 特征

为某个类型创建新方法

```rust
trait AppendBar {
    fn append_bar(self) -> Self;
}

impl AppendBar for String {
    fn append_bar(self) -> Self{
        format!("{}Bar", self)
    }
}

let s = String::from("Foo");
let s = s.append_bar();
println!("s: {}", s);
```

### 测试

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn you_can_assert() {
        assert!(true);
        assert_eq!(true, true);
        assert_ne!(true, false);
    }
}
```

### 线程

#### Arc

Arc 可以使用 Clone 创建对象的更多引用，并将它们传递给线程。当指向某个值的最后一个引用指针超出作用域时，该变量就会被丢弃。

```rust
use std::sync::Arc;
let apple = Arc::new("the same apple");
for _ in 0..10 {
    let apple = Arc::clone(&apple);
    thread::spawn(move || {
        println!("{:?}", apple);
    });
}
```

#### 线程

在这种情况下，我们会向线程传递一个它可以修改的变量。

```rust
fn main() {
    let status = Arc::new(Mutex::new(JobStatus { jobs_completed: 0 }));
    let status_shared = Arc::clone(&status);
    thread::spawn(move || {
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(250));
            let mut status = status_shared.lock().unwrap();
            status.jobs_completed += 1;
        }
    });
    while status.lock().unwrap().jobs_completed < 10 {
        println!("waiting... ");
        thread::sleep(Duration::from_millis(500));
    }
}
```


### 安全要点

Rust 默认提供强大的内存安全保证，但你仍可能通过 `unsafe` 代码、依赖项问题或逻辑错误引入严重漏洞。以下迷你速查表汇总了在对 Rust 软件进行攻防安全审查时最常用到的基础功能。有关其他语言专用工具，请参阅 [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust)。

#### 不安全代码与内存安全

`unsafe` 允许执行编译器无法证明其安全契约的操作；它**不会**关闭常规的借用检查或边界检查。如果不安全操作违反了其契约，就可能导致内存破坏，包括在作为安全 API 暴露的函数内部。<sup>[[3]](#references)</sup>

进行源码审查时，请找出未经检查的操作，并追踪攻击者可控的指针和长度如何从公开调用者传入：<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* 对于 `slice::from_raw_parts`，证明指针非空且对齐，**整个**已初始化范围都位于同一个有效分配中，并且返回的 slice 不会比该分配存活得更久。即使长度为零，slice 也不能使用空指针。
* 对于 `Vec::set_len`，证明新长度不超过实际容量，并且每个新暴露的元素都已初始化。追踪分配大小和任何复制数量；`with_capacity` 不会初始化元素。
* 检查每个 `Send` 或 `Sync` 的 `unsafe impl`，以及每个 FFI 函数签名是否符合对安全调用者所承诺的不变量。`#![forbid(unsafe_code)]` 会拒绝 crate 中的 unsafe 代码；`#![deny(unsafe_op_in_unsafe_fn)]` 则要求在 unsafe 函数**内部**显式使用 unsafe 块，而不是禁止 unsafe 代码。后一个 lint 在 Rust 2024 中默认会发出警告。<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

使用 raw pointers 导致的溢出示例：
```rust
use std::ptr;

fn vuln_copy(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(4);
    unsafe {
        // ❌ copies *src.len()* bytes, the destination only reserves 4.
        ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
        dst.set_len(src.len());
    }
    dst
}
```
长度超过 `dst.capacity()` 的输入会违反上例中的复制边界和 `set_len` 契约。为目标 allocator 添加一个输入超长的测试，然后在 Miri 下运行。Miri 会检查已执行路径中的未定义行为，但不受支持的外部调用可能导致它无法测试 FFI 边界。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### 使用 RustSec / cargo-audit 审计依赖项

现实中的大多数 Rust 漏洞都存在于第三方 crate 中。可以在本地查询 RustSec advisory DB（由社区维护）：<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
将其集成到 CI 中，并在出现 `--deny warnings` 时使构建失败。

`cargo deny check advisories` 提供类似功能，还可检查许可证和禁用列表。

#### 使用 cargo-tarpaulin 进行代码覆盖率检查

`cargo tarpaulin` 是 Cargo 构建系统的代码覆盖率报告工具.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
在 Linux 上，Tarpaulin 默认的 tracing 后端仍是 Ptrace，且仅适用于 x86_64 处理器。可以通过 `--engine llvm` 将其切换为 llvm coverage instrumentation。对于 Mac 和 Windows，这是默认的收集方式。

#### 使用 cargo-vet 验证供应链

`cargo vet` 会根据配置的审计标准，使用本地审计、受信任的导入或显式豁免来检查依赖项。`cargo vet init` 会创建 `supply-chain/` 元数据，并豁免现有的、未经审计的依赖项，因此，初次检查通过**并不**意味着每个 crate 都经过了审查。检查这些豁免项，并使用 `cargo vet suggest` 逐一处理；`--locked` 可避免刷新导入的审计集。<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### 对 API surface 进行 Fuzzing（cargo-fuzz）

Fuzz target 使用生成的输入测试 API，可暴露 panic 和内存安全故障。生成的 target 位于 `fuzz/fuzz_targets/`；运行前，将其默认主体替换为对待审查 API 的调用。<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
将 fuzz target 添加到你的仓库，并在流水线中运行它。

## References

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet：“审计你的 Rust 依赖项”](https://mozilla.github.io/cargo-vet/)
- [3] [The Rust Programming Language：不安全 Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std：slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std：Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024：unsafe_op_in_unsafe_fn 警告](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet 命令](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book：cargo-fuzz 教程](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [The Rust Programming Language：Box 和递归类型](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [The Rust Programming Language：if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024：不安全 extern 块](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
