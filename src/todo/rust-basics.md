# Rust Temelleri

{{#include ../banners/hacktricks-training.md}}

### Değişkenlerin sahipliği

Bellek, derleyicinin derleme zamanında kontrol ettiği aşağıdaki kurallarla bir sahiplik sistemi aracılığıyla yönetilir:

1. Rust'taki her değerin sahibi olarak adlandırılan bir değişkeni vardır.
2. Aynı anda yalnızca bir sahibi olabilir.
3. Sahip kapsam dışına çıktığında, değer serbest bırakılır.
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
### Jenerik Tipler

Değerlerinden biri herhangi bir tür olabilecek bir struct oluşturun
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

Option türü, değerin Some (bir şey var) veya None olabileceği anlamına gelir:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Option değerini kontrol etmek için `is_some()` veya `is_none()` gibi fonksiyonları kullanabilirsiniz.

### Result, Ok & Err

Hataları döndürmek ve iletmek için kullanılır.
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
You can use functions such as `is_ok()` or `is_err()` to check the value of the result

The `Option` enum should be used in situations where a value might not exist (be `None`).
The `Result` enum should be used in situations where you do something that might go wrong

### Macros

Makrolar, yazdığınız koda göre daha fazla kod üretecek şekilde genişleyebildikleri için fonksiyonlardan daha güçlüdür. Örneğin, bir fonksiyon imzası fonksiyonun sahip olduğu parametrelerin sayısını ve türünü belirtmek zorundadır. Diğer yandan, makrolar değişken sayıda parametre alabilir: `println!("hello")` tek argümanla veya `println!("hello {}", name)` iki argümanla çağrılabilir. Ayrıca, makrolar derleyici kodun anlamını yorumlamadan önce genişletilir; bu nedenle bir makro, örneğin, belirli bir tipe bir trait uygulayabilir. Bir fonksiyon bunu yapamaz, çünkü fonksiyon çalışma zamanında çağrılır ve trait'in derleme zamanında uygulanması gerekir.
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
### Yineleme
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
### Özyinelemeli Box
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Koşullar

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
#### loop (sonsuz)
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

Bir tür için yeni bir metot oluştur
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
### Testler
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
### İş parçacıkları

#### Arc

Bir Arc, Clone kullanarak nesne üzerinde daha fazla referans oluşturup bunları iş parçacıklarına aktarabilir. Bir değere işaret eden son referans işaretçisi kapsam dışına çıktığında, değişken yok edilir.
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
#### İş parçacıkları

Bu durumda iş parçacığına değiştirebileceği bir değişken geçireceğiz.
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
### Güvenlik Temelleri

Rust varsayılan olarak güçlü bellek güvenliği garantileri sağlar, ancak `unsafe` kodu, bağımlılık sorunları veya mantık hataları yoluyla hâlâ kritik güvenlik açıkları ortaya çıkabilir. Aşağıdaki mini-cheatsheet, Rust yazılımlarının saldırı ya da savunma amaçlı güvenlik incelemeleri sırasında en sık dokunacağınız ilkel işlemleri toplar.

#### Unsafe kodu & bellek güvenliği

`unsafe` blokları derleyicinin aliasing ve bounds kontrollerinden muafiyet sağlar, bu yüzden **tüm geleneksel bellek bozulması hataları (OOB, use-after-free, double free, vb.) yeniden ortaya çıkabilir**. Hızlı bir denetim kontrol listesi:

* `unsafe` bloklarını, `extern "C"` fonksiyonlarını, `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers veya `ffi` modüllerine yapılan çağrıları arayın.
* Düşük seviyeli fonksiyonlara geçirilen her işaretçi aritmetiğini ve uzunluk argümanını doğrulayın.
* `#![forbid(unsafe_code)]` (crate-genel) veya `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) kullanmayı tercih edin; böylece biri `unsafe`'ı yeniden eklediğinde derleme başarısız olur.

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
Miri'yi çalıştırmak, test sırasında UB'yi tespit etmenin düşük maliyetli bir yoludur:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit ile bağımlılık denetimi

Gerçek dünya Rust zafiyetlerinin çoğu üçüncü taraf crate'lerde bulunur. RustSec advisory DB (topluluk destekli) yerel olarak sorgulanabilir:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Bunu CI'ye entegre edin ve `--deny warnings` ile başarısız olmasını sağlayın.

`cargo deny check advisories` benzer işlevsellik sunar; ayrıca lisans ve yasak-listesi kontrolleri yapar.

#### cargo-tarpaulin ile kod kapsamı

`cargo tarpaulin`, Cargo build sistemi için bir kod kapsamı raporlama aracıdır.
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux'te, Tarpaulin'in varsayılan izleme arka ucu hâlâ Ptrace'tir ve yalnızca x86_64 işlemcilerde çalışır. Bu, `--engine llvm` ile llvm coverage enstrümantasyonuna değiştirilebilir. Mac ve Windows için bu varsayılan toplama yöntemidir.

#### Tedarik zinciri doğrulaması cargo-vet ile (2024)

`cargo vet` içe aktardığınız her crate için bir inceleme hash'i kaydeder ve fark edilmeyen yükseltmeleri engeller:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Bu araç, poisoned-package saldırılarını azaltmak için Rust proje altyapısı ve giderek daha fazla kuruluş tarafından benimseniyor.

#### Fuzzing API yüzeyiniz (cargo-fuzz)

Fuzz testleri, panics, tam sayı taşmaları ve mantık hatalarını kolayca yakalar; bunlar DoS veya side-channel sorunlarına dönüşebilir:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Fuzz target'ı repoya ekleyin ve pipeline'ınızda çalıştırın.

## Referanslar

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
