# Rust Temelleri

{{#include ../banners/hacktricks-training.md}}

### Değişkenlerin sahipliği

Bellek, derleme zamanında compiler tarafından denetlenen aşağıdaki kurallara sahip bir sahiplik sistemi aracılığıyla yönetilir:

1. Rust'taki her değerin owner olarak adlandırılan bir değişkeni vardır.
2. Aynı anda yalnızca bir owner olabilir.
3. Owner kapsam dışına çıktığında değer bellekten kaldırılır.
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
### Generic Türler

Değerlerinden birinin herhangi bir tür olabileceği bir struct oluşturun
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

Option türü, değerin Some (bir şey var) veya None türünde olabileceği anlamına gelir:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
`Option` değerini kontrol etmek için `is_some()` veya `is_none()` gibi işlevleri kullanabilirsiniz.


### Result, Ok ve Err

Hataları döndürmek ve yaymak için kullanılır
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Sonucun değerini kontrol etmek için `is_ok()` veya `is_err()` gibi fonksiyonları kullanabilirsiniz.

`Option` enum'u, bir değerin mevcut olmayabileceği (`None` olabileceği) durumlarda kullanılmalıdır.  
`Result` enum'u ise yanlış gidebilecek bir işlem yaptığınız durumlarda kullanılmalıdır.


### Macros

Macros, yazdığınız koddan daha fazla kod üretmek üzere genişletildikleri için functions'tan daha güçlüdür. Örneğin, bir function signature, function'ın sahip olduğu parametrelerin sayısını ve türünü bildirmelidir. Buna karşılık Macros, değişken sayıda parametre alabilir: `println!("hello")` çağrısını tek bir argument ile veya `println!("hello {}", name)` çağrısını iki argument ile yapabiliriz. Ayrıca Macros, compiler kodun anlamını yorumlamadan önce genişletilir; bu nedenle bir macro, örneğin belirli bir type üzerinde bir trait implement edebilir. Bir function bunu yapamaz, çünkü runtime'da çağrılır ve bir trait'in compile time'da implement edilmesi gerekir.
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
### Yinele
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
### Recursive Box
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Koşullu ifadeler

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
### Trait'ler

Bir tür için yeni bir metot oluşturun
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

Bir Arc, nesneye yönelik daha fazla referans oluşturmak ve bunları thread'lere geçirmek için Clone kullanabilir. Bir değere yönelik son referans işaretçisi kapsam dışına çıktığında değişken drop edilir.
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

Bu durumda thread'e değiştirebileceği bir değişken aktaracağız
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

Rust varsayılan olarak güçlü bellek güvenliği garantileri sağlar, ancak `unsafe` code, dependency sorunları veya mantık hataları yoluyla hâlâ kritik güvenlik açıkları oluşturabilirsiniz. Aşağıdaki mini-cheatsheet, Rust yazılımlarının saldırı veya savunma amaçlı güvenlik incelemeleri sırasında en sık kullanacağınız primitive'leri bir araya getirir.

#### `unsafe` code ve bellek güvenliği

`unsafe` blokları derleyicinin aliasing ve sınır kontrollerinden vazgeçer; bu nedenle **geleneksel bellek bozulması hatalarının tamamı (OOB, use-after-free, double free vb.) yeniden ortaya çıkabilir**. Hızlı bir denetim kontrol listesi:

* `unsafe` bloklarını, `extern "C"` fonksiyonlarını, `ptr::copy*` çağrılarını, `std::mem::transmute`, `MaybeUninit`, raw pointer'ları veya `ffi` modüllerini arayın.
* Düşük seviyeli fonksiyonlara aktarılan her pointer arithmetic işlemini ve length argümanını doğrulayın.
* Birisi yeniden `unsafe` eklediğinde derlemenin başarısız olması için `#![forbid(unsafe_code)]` (crate genelinde) veya `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) kullanmayı tercih edin.

Raw pointer'larla oluşturulan örnek overflow:
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
Miri'yi çalıştırmak, test zamanında UB'yi tespit etmenin düşük maliyetli bir yoludur:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit ile bağımlılıkları denetleme

Gerçek dünyadaki Rust zafiyetlerinin çoğu üçüncü taraf crate'lerde bulunur. RustSec advisory DB'si (topluluk destekli) yerel olarak sorgulanabilir:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI'ya entegre edin ve `--deny warnings` durumunda başarısız olun.

`cargo deny check advisories`, benzer işlevin yanı sıra lisans ve ban-list kontrolleri de sunar.

#### cargo-tarpaulin ile kod kapsamı

`cargo tarpaulin`, Cargo build sistemi için bir kod kapsamı raporlama aracıdır
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux'ta Tarpaulin'in varsayılan tracing backend'i hâlâ Ptrace'dir ve yalnızca x86_64 işlemcilerde çalışır. Bu, `--engine llvm` ile llvm coverage instrumentation'a değiştirilebilir. Mac ve Windows'ta bu varsayılan collection method'udur.

#### cargo-vet ile tedarik zinciri doğrulaması (2024)

`cargo vet`, içe aktardığınız her crate için bir review hash kaydeder ve fark edilmeden yapılan sürüm yükseltmelerini önler:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Araç, zehirlenmiş paket saldırılarını azaltmak amacıyla Rust proje altyapısı ve giderek artan sayıda kuruluş tarafından benimseniyor.<sup>[[2]](#references)</sup>

#### API yüzeyinizi fuzzing ile test etme (cargo-fuzz)

Fuzz testleri, DoS veya yan kanal sorunlarına dönüşebilecek panic'leri, integer taşmalarını ve mantık hatalarını kolayca yakalar:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
fuzz target'ı repository'nize ekleyin ve pipeline'ınızda çalıştırın.

## Referanslar

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: Rust Dependencies'lerinizi Denetleme](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
