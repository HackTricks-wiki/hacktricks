# Rust Basiese

{{#include ../banners/hacktricks-training.md}}

### Eienaarskap van veranderlikes

Geheue word bestuur deur 'n stelsel van eienaarskap met die volgende reëls wat die samesteller tydens samestelling kontroleer:

1. Elke waarde in Rust het 'n veranderlike wat sy eienaar genoem word.
2. Daar kan slegs een eienaar op 'n slag wees.
3. Wanneer die eienaar uit scope gaan, sal die waarde verwyder word.
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
### Generieke Tipes

Skep 'n struct waar 1 van sy waardes enige tipe kan wees
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

Die Option-tipe beteken dat die waarde dalk van die tipe Some (daar is iets) of None is:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Jy kan funksies soos `is_some()` of `is_none()` gebruik om die waarde van die Option te kontroleer.

### Result, Ok & Err

Word gebruik om foute terug te gee en deur te gee
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Jy kan funksies soos `is_ok()` of `is_err()` gebruik om die waarde van die resultaat te kontroleer

Die `Option` enum moet gebruik word in situasies waar 'n waarde moontlik nie bestaan nie (wees `None`).
Die `Result` enum moet gebruik word in situasies waar jy iets doen wat verkeerd kan gaan


### Macros

Macros is meer kragtig as funksies omdat hulle uitbrei om meer kode te genereer as die kode wat jy handmatig geskryf het. Byvoorbeeld, 'n funksiehandtekening moet die aantal en tipe parameters wat die funksie het, verklaar. Macros kan daarenteen 'n veranderlike aantal parameters neem: ons kan `println!("hello")` met een argument oproep of `println!("hello {}", name)` met twee argumente. Verder word macros uitgebrei voordat die compiler die betekenis van die kode interpreteer, so 'n macro kan byvoorbeeld 'n trait op 'n gegewe tipe implementeer. 'n Funksie kan dit nie doen nie, omdat dit by runtime aangeroep word en 'n trait by compile time geïmplementeer moet word.
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
### Itereer
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
### Rekursiewe Box
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Voorwaardes

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
#### loop (oneindig)
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

Skep 'n nuwe metode vir 'n tipe
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
### Toetse
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

'n Arc kan Clone gebruik om meer verwysings na die objek te skep sodat hulle aan die drade oorgedra kan word. Wanneer die laaste verwysingswyser na 'n waarde buite die omvang val, word die veranderlike verwyder.
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

In hierdie geval sal ons aan die thread 'n veranderlike deurgee wat dit kan wysig.
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
### Sekuriteitsbeginsels

Rust bied standaard sterk geheue-veiligheidswaarborge, maar jy kan steeds kritieke kwesbaarhede inbring deur `unsafe` kode, afhanklikheidsprobleme of logika-foute. Die volgende mini-cheatsheet versamel die primitives wat jy die meeste sal raak tydens offensiewe of defensiewe sekuriteitsbeoordelings van Rust-sagteware.

#### `unsafe` kode & geheue-veiligheid

`unsafe` blocks skakel die kompilateur se aliasing- en grenskontroles uit, so **alle tradisionele memory-corruption bugs (OOB, use-after-free, double free, etc.) kan weer verskyn**. 'n Vinnige oudit-kontrolelys:

* Soek na `unsafe` blocks, `extern "C"` functions, aanroepe van `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers of `ffi` modules.
* Valideer elke pointer arithmetic en lengte-argument wat aan laagvlak-funksies deurgegee word.
* Verkies `#![forbid(unsafe_code)]` (crate-wide) of `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) sodat kompilasie misluk wanneer iemand `unsafe` weer herintroduseer.

Voorbeeld van overflow geskep met raw pointers:
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
Om Miri te gebruik is 'n goedkoop manier om UB tydens toetsing op te spoor:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Ouditeer afhanklikhede met RustSec / cargo-audit

Die meeste werklike Rust-vulns kom voor in crates van derdepartye. Die RustSec advisory DB (gemeenskapsgedrewe) kan plaaslik bevraagteken word:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integreer dit in CI en laat dit misluk by `--deny warnings`.

`cargo deny check advisories` bied soortgelyke funksionaliteit plus lisensie- en verbodslyskontroles.

#### Kodedekking met cargo-tarpaulin

`cargo tarpaulin` is 'n verslaggewing-instrument vir kodedekking vir die Cargo build-stelsel
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Op Linux is Tarpaulin se standaard tracing-backend steeds Ptrace en sal slegs op x86_64-verwerkers werk. Dit kan verander word na die llvm coverage-instrumentasie met `--engine llvm`. Vir Mac en Windows is dit die standaard versamelmetode.

#### Voorsieningskettingverifikasie met cargo-vet (2024)

`cargo vet` registreer 'n review-hash vir elke crate wat jy importeer en verhoed onopgemerkte opgraderings:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Die gereedskap word deur die Rust-projekinfrastruktuur en 'n groeiende aantal organisasies aangeneem om poisoned-package attacks te beperk.

#### Fuzzing jou API-oppervlak (cargo-fuzz)

Fuzz tests vang maklik panics, integer overflows en logic bugs op wat DoS- of side-channel-kwessies kan veroorsaak:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Voeg die fuzz target by jou repo en voer dit in jou pipeline uit.

## Verwysings

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
