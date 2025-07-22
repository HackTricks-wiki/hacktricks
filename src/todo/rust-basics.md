# Rust Temelleri

{{#include ../banners/hacktricks-training.md}}

### Genel Türler

Herhangi bir türde olabilecek 1 değer içeren bir yapı oluşturun.
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
`Option` değerini kontrol etmek için `is_some()` veya `is_none()` gibi fonksiyonlar kullanabilirsiniz.

### Makrolar

Makrolar, yazdığınız koddan daha fazla kod üretmek için genişledikleri için fonksiyonlardan daha güçlüdür. Örneğin, bir fonksiyon imzası, fonksiyonun sahip olduğu parametrelerin sayısını ve türünü belirtmelidir. Öte yandan, makrolar değişken sayıda parametre alabilir: `println!("hello")` ile bir argüman veya `println!("hello {}", name)` ile iki argüman çağırabiliriz. Ayrıca, makrolar derleyici kodun anlamını yorumlamadan önce genişletilir, bu nedenle bir makro, örneğin, belirli bir tür üzerinde bir trait uygulayabilir. Bir fonksiyon bunu yapamaz, çünkü çalışma zamanında çağrılır ve bir trait'in derleme zamanında uygulanması gerekir.
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
### Tekrarla
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
### Rekürsif Kutu
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Koşullar

#### eğer
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
#### eşleşme
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
#### döngü (sonsuz)
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
#### için
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
### Özellikler

Bir tür için yeni bir yöntem oluşturun
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
### Threading

#### Arc

Bir Arc, nesne üzerinde daha fazla referans oluşturmak için Clone kullanabilir ve bunları thread'lere iletebilir. Bir değere işaret eden son referans işlev alanından çıktığında, değişken düşürülür.
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

Bu durumda, iş parçacığına değiştirebileceği bir değişken geçeceğiz.
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

Rust, varsayılan olarak güçlü bellek güvenliği garantileri sağlar, ancak yine de `unsafe` kod, bağımlılık sorunları veya mantık hataları yoluyla kritik güvenlik açıkları oluşturabilirsiniz. Aşağıdaki mini-kılavuz, Rust yazılımlarının saldırgan veya savunmacı güvenlik incelemeleri sırasında en sık karşılaşacağınız temel unsurları toplar.

#### Unsafe kod & bellek güvenliği

`unsafe` blokları derleyicinin takma adlandırma ve sınır kontrollerinden feragat eder, bu nedenle **tüm geleneksel bellek bozulma hataları (OOB, kullanımdan sonra serbest bırakma, çift serbest bırakma vb.) tekrar ortaya çıkabilir**. Hızlı bir denetim kontrol listesi:

* `unsafe` bloklarını, `extern "C"` fonksiyonlarını, `ptr::copy*` çağrılarını, `std::mem::transmute`, `MaybeUninit`, ham işaretçileri veya `ffi` modüllerini arayın.
* Düşük seviyeli fonksiyonlara geçirilen her işaretçi aritmetiği ve uzunluk argümanını doğrulayın.
* Birisi `unsafe` kodunu yeniden tanıttığında derlemeyi başarısız kılmak için `#![forbid(unsafe_code)]` (crate genelinde) veya `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) tercih edin.

Ham işaretçilerle oluşturulmuş bir taşma örneği:
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
Miri'yi çalıştırmak, test zamanında UB'yi tespit etmenin ucuz bir yoludur:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit ile bağımlılıkların denetimi

Gerçek dünyadaki çoğu Rust zayıflığı üçüncü taraf crate'lerde bulunur. RustSec danışmanlık DB'si (topluluk destekli) yerel olarak sorgulanabilir:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI'ye entegre edin ve `--deny warnings` ile başarısız olsun.

`cargo deny check advisories`, benzer işlevsellik sunar ve lisans ile yasaklı liste kontrolleri yapar.

#### Cargo-vet ile tedarik zinciri doğrulaması (2024)

`cargo vet`, her bir içe aktardığınız crate için bir inceleme hash'i kaydeder ve fark edilmeden yapılan güncellemeleri engeller:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Araç, zehirli paket saldırılarını azaltmak için Rust proje altyapısı ve artan sayıda organizasyon tarafından benimsenmektedir.

#### API yüzeyinizi Fuzzing (cargo-fuzz)

Fuzz testleri, DoS veya yan kanal sorunlarına dönüşebilecek panik, tam sayı taşmaları ve mantık hatalarını kolayca yakalar:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Fuzz hedefini reposuna ekle ve bunu pipeline'ında çalıştır.

## Referanslar

- RustSec Danışma Veritabanı – <https://rustsec.org>
- Cargo-vet: "Rust Bağımlılıklarını Denetleme" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
