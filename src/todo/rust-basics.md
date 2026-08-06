# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### 変数の所有権

メモリは所有権システムによって管理され、コンパイラはコンパイル時に次のルールをチェックします。

1. Rustの各値には、その所有者と呼ばれる変数があります。
2. 一度に存在できる所有者は1つだけです。
3. 所有者がスコープ外に出ると、その値は破棄されます。
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
### ジェネリック型

値の1つが任意の型になり得るstructを作成します
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

Option 型は、値が Some 型（何かが存在する）または None である可能性があることを意味します。
```rust
pub enum Option<T> {
None,
Some(T),
}
```
`is_some()` や `is_none()` などの関数を使用して、Option の値を確認できます。


### Result、Ok、Err

エラーの返却と伝播に使用されます
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
`is_ok()` や `is_err()` などの関数を使用して、result の値を確認できます

`Option` enum は、値が存在しない可能性がある（`None` になる）状況で使用します。
`Result` enum は、何らかの処理が失敗する可能性がある状況で使用します


### マクロ

マクロは、手動で記述したコードよりも多くのコードを生成するよう展開されるため、関数よりも強力です。例えば、関数シグネチャでは、その関数が持つパラメータの数と型を宣言する必要があります。一方、マクロは可変個数のパラメータを受け取れます。`println!("hello")` のように1つの引数で呼び出すことも、`println!("hello {}", name)` のように2つの引数で呼び出すこともできます。また、マクロはコンパイラがコードの意味を解釈する前に展開されるため、例えば、指定した型に trait を実装できます。関数ではこれができません。関数は実行時に呼び出されるのに対し、trait はコンパイル時に実装される必要があるためです。
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
### 反復処理
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
### 再帰的なボックス
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### 条件分岐

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
#### loop（無限）
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
### Traits

型に新しいメソッドを作成する
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
### テスト
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
### スレッド処理

#### Arc

Arc は Clone を使用してオブジェクトへの参照をさらに作成し、それらをスレッドに渡せます。値への最後の参照ポインターがスコープ外になると、変数は破棄されます。
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

この場合、thread が変更できる変数を渡します。
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
### Security Essentials

Rustはデフォルトで強力なmemory-safety保証を提供しますが、`unsafe` code、dependencyの問題、またはlogicのミスによって、依然としてcriticalなvulnerabilityを引き起こす可能性があります。以下のmini-cheatsheetでは、Rust softwareのoffensiveまたはdefensiveなsecurity reviewで最も頻繁に扱うprimitivesをまとめています。

#### Unsafe code & memory safety

`unsafe` blocksはcompilerのaliasingおよびbounds checksを無効化するため、**従来のmemory-corruption bugs（OOB、use-after-free、double freeなど）が再び発生する可能性があります**。簡単なaudit checklist：

* `unsafe` blocks、`extern "C"` functions、`ptr::copy*`のcalls、`std::mem::transmute`、`MaybeUninit`、raw pointers、または`ffi` modulesを探します。
* すべてのpointer arithmeticと、low-level functionsに渡されるlength argumentsを検証します。
* `#![forbid(unsafe_code)]`（crate-wide）または`#[deny(unsafe_op_in_unsafe_fn)]`（1.68 +）を使用して、誰かが`unsafe`を再導入したときにcompilationが失敗するようにします。

raw pointersによって作成されたoverflowの例：
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
テスト時にUBを検出するには、Miriを実行するのが低コストな方法です:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit による依存関係の監査

現実世界の Rust の脆弱性の多くは、サードパーティ製 crate に存在します。RustSec advisory DB（コミュニティによって運営）は、ローカルから照会できます。<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI に統合し、`--deny warnings` で失敗するようにします。

`cargo deny check advisories` は、license と ban-list のチェックに加えて、同様の機能を提供します。

#### cargo-tarpaulin による code coverage

`cargo tarpaulin` は、Cargo build system 向けの code coverage reporting tool です
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linuxでは、Tarpaulinのデフォルトのトレースバックエンドは現在もPtraceであり、x86_64プロセッサでのみ動作します。`--engine llvm`を使用すると、llvm coverage instrumentationに変更できます。MacとWindowsでは、これがデフォルトの収集方法です。

#### cargo-vetによるサプライチェーン検証（2024）

`cargo vet`は、インポートするすべてのcrateについてレビュー用ハッシュを記録し、気付かないアップグレードを防止します。
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
このツールは、poisoned-package attacks を軽減するため、Rust project infrastructure や増加する多くの orgs で導入されています。<sup>[[2]](#references)</sup>

#### API surface の Fuzzing (cargo-fuzz)

Fuzz tests は、DoS や side-channel issues につながる可能性のある panics、integer overflows、logic bugs を容易に検出します：
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Fuzz targetをリポジトリに追加し、pipelineで実行します。

## References

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: 「Rust Dependenciesの監査」](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
