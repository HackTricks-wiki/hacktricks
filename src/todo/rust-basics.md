# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### ジェネリック型

1つの値が任意の型である可能性がある構造体を作成します。
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

Option型は、値がSome型（何かがある）またはNone型（何もない）である可能性があることを意味します。
```rust
pub enum Option<T> {
None,
Some(T),
}
```
`is_some()`や`is_none()`のような関数を使用して、Optionの値をチェックできます。

### マクロ

マクロは関数よりも強力で、手動で書いたコードよりも多くのコードを生成するために展開されます。たとえば、関数のシグネチャは、関数が持つパラメータの数と型を宣言する必要があります。一方、マクロは可変数のパラメータを受け取ることができます：`println!("hello")`を1つの引数で呼び出すことも、`println!("hello {}", name)`を2つの引数で呼び出すこともできます。また、マクロはコンパイラがコードの意味を解釈する前に展開されるため、マクロは特定の型に対してトレイトを実装することができます。関数は実行時に呼び出されるため、トレイトはコンパイル時に実装する必要があります。
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
### 繰り返す
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
### 再帰ボックス
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### 条件文

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
#### 一致
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
#### ループ（無限）
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
### 特性

型のための新しいメソッドを作成する
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

ArcはCloneを使用して、オブジェクトに対する参照を増やし、それらをスレッドに渡すことができます。値への最後の参照ポインタがスコープ外になると、変数はドロップされます。
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

この場合、スレッドに変更可能な変数を渡します
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

Rustはデフォルトで強力なメモリ安全性の保証を提供しますが、`unsafe`コード、依存関係の問題、または論理的なミスを通じて重大な脆弱性を導入することは依然として可能です。以下のミニチートシートは、Rustソフトウェアの攻撃的または防御的なセキュリティレビュー中に最も一般的に触れるプリミティブをまとめています。

#### Unsafeコードとメモリ安全性

`unsafe`ブロックはコンパイラのエイリアスと境界チェックをオプトアウトするため、**すべての従来のメモリ破損バグ（OOB、use-after-free、ダブルフリーなど）が再び現れる可能性があります**。迅速な監査チェックリスト：

* `unsafe`ブロック、`extern "C"`関数、`ptr::copy*`への呼び出し、`std::mem::transmute`、`MaybeUninit`、生ポインタ、または`ffi`モジュールを探します。
* 低レベル関数に渡されるすべてのポインタ算術と長さ引数を検証します。
* 誰かが`unsafe`を再導入したときにコンパイルを失敗させるために、`#![forbid(unsafe_code)]`（クレート全体）または`#[deny(unsafe_op_in_unsafe_fn)]`（1.68 +）を好みます。

生ポインタで作成されたオーバーフローの例：
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
Miriを実行することは、テスト時にUBを検出するための手頃な方法です：
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditing dependencies with RustSec / cargo-audit

ほとんどの実世界のRustの脆弱性は、サードパーティのクレートに存在します。RustSecアドバイザリーデータベース（コミュニティ主導）は、ローカルでクエリできます：
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CIに統合し、`--deny warnings`で失敗させます。

`cargo deny check advisories`は、ライセンスおよび禁止リストのチェックに加えて、類似の機能を提供します。

#### cargo-vetによるサプライチェーンの検証 (2024)

`cargo vet`は、インポートするすべてのクレートに対してレビューのハッシュを記録し、気づかないアップグレードを防ぎます：
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
このツールは、Rustプロジェクトのインフラストラクチャと、毒入りパッケージ攻撃を軽減するために増加している組織によって採用されています。

#### APIサーフェスのファジング (cargo-fuzz)

ファジテストは、DoSやサイドチャネルの問題になる可能性のあるパニック、整数オーバーフロー、論理バグを簡単にキャッチします。
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
リポジトリにfuzzターゲットを追加し、パイプラインで実行します。

## 参考文献

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
