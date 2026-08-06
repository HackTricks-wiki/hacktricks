# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### 变量的所有权

内存通过所有权系统进行管理，编译器会在编译时检查以下规则：

1. Rust 中的每个值都有一个被称为其所有者的变量。
2. 同一时间只能有一个所有者。
3. 当所有者离开作用域时，该值将被丢弃。
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

创建一个结构体，使其某个值可以是任意类型
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

Option 类型表示该值可能是 Some 类型（存在某个值），也可能是 None：
```rust
pub enum Option<T> {
None,
Some(T),
}
```
你可以使用 `is_some()` 或 `is_none()` 等函数来检查 Option 的值。


### Result、Ok 和 Err

用于返回和传播错误
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
你可以使用 `is_ok()` 或 `is_err()` 等函数来检查 result 的值

`Option` 枚举应当用于值可能不存在（为 `None`）的情况。
`Result` 枚举应当用于你执行的操作可能出错的情况


### 宏

宏比函数更强大，因为它们会展开并生成比你手动编写的代码更多的代码。例如，函数签名必须声明函数所具有的参数数量和类型。而宏则可以接受数量可变的参数：我们可以使用一个参数调用 `println!("hello")`，也可以使用两个参数调用 `println!("hello {}", name)`。此外，宏会在编译器解释代码含义之前展开，因此宏可以实现一些功能，例如为给定类型实现 trait。函数无法做到这一点，因为函数是在运行时调用的，而 trait 需要在编译时实现。
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
### 递归盒子
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
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
#### 匹配
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
#### 无限循环
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
#### 对于
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
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
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
### Traits

为一个类型创建一个新方法
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

Arc 可以使用 Clone 创建对象的更多引用，以便将它们传递给线程。当指向某个值的最后一个引用指针超出作用域时，该变量会被丢弃。
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
#### Threads

在此情况下，我们将向 thread 传递一个变量，该 thread 将能够对其进行修改
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

Rust 默认提供强大的内存安全保证，但你仍然可能通过 `unsafe` 代码、依赖问题或逻辑错误引入严重漏洞。以下 mini-cheatsheet 汇总了你在对 Rust 软件进行 offensive 或 defensive security review 时最常接触的原语。

#### Unsafe 代码与内存安全

`unsafe` 代码块会选择退出编译器的别名检查和边界检查，因此 **所有传统的内存破坏漏洞（OOB、use-after-free、double free 等）都可能再次出现**。快速审计检查清单：

* 查找 `unsafe` 代码块、`extern "C"` 函数、对 `ptr::copy*` 的调用、`std::mem::transmute`、`MaybeUninit`、raw pointers 或 `ffi` 模块。
* 验证传递给低级函数的每个指针运算和长度参数。
* 优先使用 `#![forbid(unsafe_code)]`（crate-wide）或 `#[deny(unsafe_op_in_unsafe_fn)]`（1.68 +），以便在有人重新引入 `unsafe` 时使编译失败。

使用 raw pointers 创建的溢出示例：
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
运行 Miri 是在测试时检测 UB 的一种低成本方法：
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### 使用 RustSec / cargo-audit 审计依赖项

现实世界中的大多数 Rust 漏洞都存在于第三方 crates 中。RustSec advisory DB（由社区维护）可以在本地查询：<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
将其集成到 CI 中，并在使用 `--deny warnings` 时使构建失败。

`cargo deny check advisories` 提供类似功能，此外还会检查 licence 和 ban-list。

#### 使用 cargo-tarpaulin 进行代码覆盖率检查

`cargo tarpaulin` 是 Cargo 构建系统的代码覆盖率报告工具
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
在 Linux 上，Tarpaulin 的默认 tracing backend 仍然是 Ptrace，并且只能在 x86_64 处理器上运行。可以通过 `--engine llvm` 将其更改为 llvm coverage instrumentation。对于 Mac 和 Windows，这是默认的收集方法。

#### 使用 cargo-vet 进行供应链验证（2024）

`cargo vet` 会为你导入的每个 crate 记录一个 review hash，并防止未被注意到的升级：
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
该工具正被 Rust project infrastructure 以及越来越多的组织采用，以缓解 poisoned-package attacks。<sup>[[2]](#references)</sup>

#### Fuzzing your API surface (cargo-fuzz)

Fuzz tests 可以轻松捕获 panic、integer overflow 和 logic bugs，这些问题可能演变为 DoS 或 side-channel issues：
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
将 fuzz target 添加到你的 repo 中，并在 pipeline 中运行它。

## References

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: "Auditing your Rust Dependencies"](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
