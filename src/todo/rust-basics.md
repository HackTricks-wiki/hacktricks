# Rustの基本

{{#include ../banners/hacktricks-training.md}}

### 変数の所有権

メモリは所有権の仕組みによって管理され、コンパイラは以下のルールをコンパイル時にチェックします:

1. Rustの各値には、その所有者と呼ばれる変数があります。
2. 所有者は同時に1つだけ存在します。
3. 所有者がスコープを抜けると、その値は破棄されます。
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

フィールドの1つが任意の型になり得るstructを作成する
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

Option型は、値がSome（何かがある）またはNoneのいずれかである可能性があることを意味します:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Optionの値をチェックするには、`is_some()` や `is_none()` といった関数を使えます。


### Result, Ok & Err

エラーの返却と伝播に使われます
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
結果の値を確認するために、`is_ok()` や `is_err()` のような関数を使うことができます。

`Option` enum は、値が存在しない（`None` である）可能性がある状況で使用するべきです。  
`Result` enum は、処理が失敗する可能性がある場合に使用します。


### マクロ

マクロは、手動で書いたコードよりも多くのコードを展開して生成するため、関数より強力です。例えば、関数のシグネチャは引数の数と型を宣言しなければなりません。これに対してマクロは可変個の引数を取ることができます。たとえば、`println!("hello")` を1つの引数で呼ぶことも、`println!("hello {}", name)` を2つの引数で呼ぶこともできます。また、マクロはコンパイラがコードの意味を解釈する前に展開されるため、たとえばマクロはある型に対して trait を実装することができます。関数ではこれはできません。関数は実行時に呼ばれ、trait はコンパイル時に実装される必要があるからです。
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
### 繰り返し
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
### 再帰的な Box
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
#### loop (無限)
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
#### for文
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

型に対して新しいメソッドを作成する
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
### スレッド

#### Arc

ArcはCloneを使ってオブジェクトへの参照を増やし、スレッドに渡すことができます。値への最後の参照ポインタがスコープ外になると、その変数は破棄されます。
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
#### スレッド

この場合、スレッドに変数を渡し、スレッドがその変数を変更できるようにします。
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
### セキュリティの基本

Rustはデフォルトで強力なメモリ安全性を提供しますが、`unsafe`コード、依存関係の問題、あるいはロジックミスにより重大な脆弱性を導入することがあります。以下のミニチートシートは、Rustソフトウェアの攻撃側／防御側のセキュリティレビューで最も頻繁に触れるプリミティブをまとめたものです。

#### `unsafe` code とメモリ安全性

`unsafe`ブロックはコンパイラのエイリアスや境界チェックを無効化するため、**従来の全てのメモリ破壊バグ（OOB、use-after-free、double free など）が再び現れ得ます**。簡単な監査チェックリスト：

* `unsafe`ブロック、`extern "C"`関数、`ptr::copy*`、`std::mem::transmute`への呼び出し、`MaybeUninit`、raw pointers、または`ffi`モジュールを探す。
* 低レベル関数に渡される全てのポインタ算術や長さ引数を検証する。
* 誰かが`unsafe`を再導入したときにコンパイルを失敗させるため、`#![forbid(unsafe_code)]`（crate全体）または`#[deny(unsafe_op_in_unsafe_fn)]`（1.68以降）を推奨する。

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
Miriを実行することは、テスト時にUBを検出するための低コストな方法です:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit を使った依存関係の監査

実際の Rust の脆弱性の多くはサードパーティのクレートに存在します。RustSec advisory DB（コミュニティ運用）はローカルで照会できます：
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CIに組み込み、`--deny warnings`で失敗させます。

`cargo deny check advisories` は同様の機能に加え、ライセンスと禁止リストのチェックを提供します。

#### cargo-tarpaulinによるコードカバレッジ

`cargo tarpaulin` はCargoのビルドシステム向けのコードカバレッジ報告ツールです。
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linuxでは、Tarpaulinのデフォルトのトレーシングバックエンドは依然として Ptrace で、x86_64 プロセッサでのみ動作します。これは `--engine llvm` を使って llvm のカバレッジ計測に変更できます。Mac および Windows では、これがデフォルトの収集方法です。

#### cargo-vet によるサプライチェーン検証 (2024)

`cargo vet` はインポートする各 crate に対してレビュー・ハッシュを記録し、見落とされたアップグレードを防ぎます:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
このツールは、Rust project infrastructure と増えつつある複数の組織に採用され、poisoned-package attacks を緩和するために使われています。

#### Fuzzing your API surface (cargo-fuzz)

Fuzz tests は、panics、integer overflows、そして DoS や side-channel 問題になり得るロジックバグを簡単に検出します:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
リポジトリにfuzz targetを追加し、パイプラインで実行してください。

## 参考資料

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
