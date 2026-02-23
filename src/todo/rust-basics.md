# Rust 基础

{{#include ../banners/hacktricks-training.md}}

### 变量的所有权

内存通过所有权系统来管理，下列规则由编译器在编译时检查：

1. Rust 中的每个值都有一个称为其所有者的变量。
2. 在任一时刻只能有一个所有者。
3. 当所有者超出作用域时，该值会被丢弃。
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
### 泛型类型

创建一个 struct，其中的某个字段可以是任意类型
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

Option 类型意味着该值可能是 Some（存在某个值）或 None：
```rust
pub enum Option<T> {
None,
Some(T),
}
```
你可以使用诸如 `is_some()` 或 `is_none()` 之类的函数来检查 Option 的值。

### Result, Ok & Err

用于返回和传播错误
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
你可以使用诸如 `is_ok()` 或 `is_err()` 的函数来检查结果的值

当一个值可能不存在（为 `None`）时，应使用 `Option` 枚举。
当你执行的操作可能会出错时，应使用 `Result` 枚举


### 宏

宏比函数更强大，因为它们展开后会生成比你手写更多的代码。例如，函数签名必须声明函数的参数数量和类型。宏则可以接受可变数量的参数：我们可以用一个参数调用 `println!("hello")`，也可以用两个参数调用 `println!("hello {}", name)`。另外，宏会在编译器解释代码含义之前被展开，所以宏可以例如在给定类型上实现一个 trait。函数做不到这一点，因为函数在运行时被调用，而 trait 需要在编译时实现。
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
#### 循环 (无限)
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
### 特征

为类型创建一个新方法
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

Arc 可以使用 Clone 来为对象创建更多的引用，以便将它们传递给线程。当指向某个值的最后一个引用指针超出作用域时，该变量会被 drop。
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

在这种情况下，我们会传递一个变量给线程，线程将能够修改它
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

Rust 默认提供强大的内存安全保证，但你仍可能通过 `unsafe` 代码、依赖问题或逻辑错误引入严重漏洞。下面的迷你备忘单汇总了在对 Rust 软件进行攻防安全审查时最常接触到的原语。

#### `unsafe` 代码与内存安全

`unsafe` 块会绕过编译器的别名检测和边界检查，因此 **所有传统的内存损坏漏洞（越界 OOB、use-after-free、双重释放等）可能会重新出现**。快速审计检查清单：

* 查找 `unsafe` 块、`extern "C"` 函数、对 `ptr::copy*`、`std::mem::transmute`、`MaybeUninit` 的调用、原始指针或 `ffi` 模块。
* 验证传入低级函数的每一个指针算术操作和长度参数。
* 优先使用 `#![forbid(unsafe_code)]`（整个 crate）或 `#[deny(unsafe_op_in_unsafe_fn)]`（1.68+），在有人重新引入 `unsafe` 时让编译失败。

Example overflow created with raw pointers:
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
在测试时运行 Miri 是检测 UB 的一种廉价方法：
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### 使用 RustSec / cargo-audit 审计依赖

大多数真实世界的 Rust vulns 存在于第三方 crates 中。RustSec advisory DB（由社区维护）可以在本地查询：
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
将其集成到 CI 中并在 `--deny warnings` 时使构建失败。

`cargo deny check advisories` 提供类似功能，并附带许可证和黑名单检查。

#### 使用 cargo-tarpaulin 进行代码覆盖率

`cargo tarpaulin` 是 Cargo 构建系统的代码覆盖率报告工具。
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
在 Linux 上，Tarpaulin 的默认跟踪后端仍然是 Ptrace，并且仅能在 x86_64 处理器上工作。可以使用 `--engine llvm` 切换到 llvm 覆盖率插装。对于 Mac 和 Windows，这就是默认的收集方法。

#### 使用 cargo-vet 进行供应链验证（2024）

`cargo vet` 会为你导入的每个 crate 记录一个 review hash，并防止未被注意到的升级：
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
该工具正在被 Rust 项目基础设施和越来越多的组织采用，以缓解 poisoned-package attacks。

#### Fuzzing your API surface (cargo-fuzz)

Fuzz tests 可轻松发现 panics、integer overflows 和 logic bugs，这些可能演变成 DoS 或 side-channel 问题：
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
将 fuzz target 添加到你的 repo，并在你的 pipeline 中运行它。

## 参考资料

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "审计你的 Rust 依赖" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
