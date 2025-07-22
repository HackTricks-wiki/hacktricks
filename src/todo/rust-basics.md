# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### 泛型

创建一个结构体，其中一个值可以是任何类型
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

Option类型意味着值可能是Some类型（有某些东西）或None：
```rust
pub enum Option<T> {
None,
Some(T),
}
```
您可以使用 `is_some()` 或 `is_none()` 等函数来检查 Option 的值。

### 宏

宏比函数更强大，因为它们扩展以生成比您手动编写的代码更多的代码。例如，函数签名必须声明函数的参数数量和类型。另一方面，宏可以接受可变数量的参数：我们可以用一个参数调用 `println!("hello")`，或者用两个参数调用 `println!("hello {}", name)`。此外，宏在编译器解释代码含义之前被扩展，因此宏可以在给定类型上实现一个特征。例如，函数不能这样做，因为它在运行时被调用，而特征需要在编译时实现。
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
#### 循环（无限）
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
#### 当
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
### 特性

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

Arc可以使用Clone来创建对对象的更多引用，以将它们传递给线程。当指向一个值的最后一个引用指针超出作用域时，该变量会被丢弃。
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

在这种情况下，我们将传递一个变量给线程，它将能够修改该变量。
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
### 安全基础

Rust 默认提供强大的内存安全保证，但您仍然可以通过 `unsafe` 代码、依赖问题或逻辑错误引入关键漏洞。以下迷你备忘单汇集了您在对 Rust 软件进行攻防安全审查时最常接触的原语。

#### 不安全代码与内存安全

`unsafe` 块选择退出编译器的别名和边界检查，因此 **所有传统的内存损坏漏洞（越界、使用后释放、双重释放等）可能会再次出现**。快速审计检查清单：

* 查找 `unsafe` 块、`extern "C"` 函数、对 `ptr::copy*` 的调用、`std::mem::transmute`、`MaybeUninit`、原始指针或 `ffi` 模块。
* 验证传递给低级函数的每个指针算术和长度参数。
* 优先使用 `#![forbid(unsafe_code)]`（整个 crate）或 `#[deny(unsafe_op_in_unsafe_fn)]`（1.68 +），以在有人重新引入 `unsafe` 时使编译失败。

使用原始指针创建的溢出示例：
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
运行 Miri 是在测试时检测 UB 的一种廉价方法：
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### 使用 RustSec / cargo-audit 审计依赖项

大多数实际的 Rust 漏洞存在于第三方 crate 中。可以在本地查询 RustSec 顾问数据库（社区驱动）：
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
将其集成到 CI 中，并在 `--deny warnings` 时失败。

`cargo deny check advisories` 提供类似的功能，以及许可证和禁用列表检查。

#### 使用 cargo-vet 进行供应链验证 (2024)

`cargo vet` 为您导入的每个 crate 记录一个审查哈希，并防止未注意的升级：
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
该工具正在被Rust项目基础设施和越来越多的组织采用，以减轻被污染包攻击的风险。

#### Fuzzing your API surface (cargo-fuzz)

模糊测试可以轻松捕捉到可能导致DoS或旁路问题的恐慌、整数溢出和逻辑错误：
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
将模糊目标添加到您的仓库并在您的管道中运行它。

## 参考

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "审计您的 Rust 依赖项" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
