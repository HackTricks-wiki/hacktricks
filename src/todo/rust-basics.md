# Rust-basiese beginsels

{{#include ../banners/hacktricks-training.md}}

### Eienaarskap van veranderlikes

Geheue word bestuur deur ’n stelsel van eienaarskap met die volgende reëls, wat die compiler tydens kompilering nagaan:

1. Elke waarde in Rust het ’n veranderlike wat sy eienaar genoem word.
2. Daar kan slegs een eienaar op ’n slag wees.
3. Wanneer die eienaar buite omvang gaan, sal die waarde laat vaar word.
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
### Generiese Tipes

Skep ’n struct waarvan een van die waardes enige tipe kan wees
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

Die Option-tipe beteken dat die waarde van die tipe Some kan wees (daar is iets) of None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Jy kan funksies soos `is_some()` of `is_none()` gebruik om die waarde van die Option te kontroleer.


### Result, Ok & Err

Word gebruik om foute terug te stuur en te propageer
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Jy kan funksies soos `is_ok()` of `is_err()` gebruik om die waarde van die resultaat na te gaan

Die `Option`-enum moet gebruik word in situasies waar ’n waarde dalk nie bestaan nie (met ander woorde, `None` is).
Die `Result`-enum moet gebruik word in situasies waar iets wat jy doen, dalk verkeerd kan loop


### Makro's

Makro's is kragtiger as funksies omdat hulle uitbrei om meer kode te produseer as die kode wat jy met die hand geskryf het. Byvoorbeeld, ’n funksie-handtekening moet die getal en tipe parameters wat die funksie het, verklaar. Makro's kan daarenteen ’n veranderlike aantal parameters aanvaar: ons kan `println!("hello")` met een argument of `println!("hello {}", name)` met twee argumente aanroep. Makro's word ook uitgebrei voordat die samesteller die betekenis van die kode interpreteer, dus kan ’n makro byvoorbeeld ’n trait op ’n gegewe tipe implementeer. ’n Funksie kan dit nie doen nie, omdat dit tydens runtime aangeroep word en ’n trait tydens compile time geïmplementeer moet word.
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
### Voorwaardelike stellings

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
#### oneindige lus
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
#### terwyl
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
#### vir
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

Skep ’n nuwe metode vir ’n tipe
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

'n Arc kan Clone gebruik om meer verwysings na die objek te skep en dit aan die threads deur te gee. Wanneer die laaste verwysingswyser na 'n waarde buite omvang is, word die veranderlike laat vaar.
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

In hierdie geval sal ons die thread 'n veranderlike gee wat dit sal kan wysig
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

Rust bied standaard sterk waarborge vir geheuesekuriteit, maar jy kan steeds kritieke kwesbaarhede deur `unsafe`-kode, afhanklikheidskwessies of logikafoute bekendstel. Die volgende mini-cheatsheet versamel die primitiewe waarmee jy die meeste sal werk tydens offensiewe of defensiewe sekuriteitsoorsigte van Rust-sagteware.

#### `unsafe`-kode en geheuesekuriteit

`unsafe`-blokke skakel die compiler se aliasing- en grenskontroles uit, dus kan **alle tradisionele geheuekorrupsiefoute (OOB, use-after-free, double free, ens.) weer voorkom**. ’n Vinnige ouditkontrolelys:

* Soek na `unsafe`-blokke, `extern "C"`-funksies, oproepe na `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, rou pointers of `ffi`-modules.
* Valideer elke pointer-berekening en lengte-argument wat aan laevlakfunksies deurgegee word.
* Verkies `#![forbid(unsafe_code)]` (skenkwyd) of `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) om samestelling te laat misluk wanneer iemand `unsafe` weer instel.

Voorbeeld van ’n overflow wat met rou pointers geskep word:
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
Om Miri te laat loop, is ’n goedkoop manier om UB tydens toetsing op te spoor:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Oudit van afhanklikhede met RustSec / cargo-audit

Die meeste werklike Rust-kwesbaarhede kom in derdeparty-crates voor. Die RustSec-advisory DB (deur die gemeenskap aangedryf) kan plaaslik geraadpleeg word:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integreer dit in CI en laat dit faal met `--deny warnings`.

`cargo deny check advisories` bied soortgelyke funksionaliteit, plus lisensie- en verbodlys-kontroles.

#### Kode-dekking met cargo-tarpaulin

`cargo tarpaulin` is ’n kode-dekkingsverslagdoeningshulpmiddel vir die Cargo-boustelsel
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Op Linux is Tarpaulin se verstek-tracing-backend steeds Ptrace en sal dit slegs op x86_64-verwerkers werk. Dit kan verander word na llvm coverage instrumentation met `--engine llvm`. Vir Mac en Windows is dit die verstekversamelingsmetode.

#### Voorsieningskettingverifikasie met cargo-vet (2024)

`cargo vet` teken ’n review hash aan vir elke crate wat jy invoer en voorkom ongemerkte opgraderings:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Die tool word deur die Rust-projekinfrastruktuur en ’n groeiende aantal organisasies aangeneem om aanvalle met vergiftigde pakkette te versag.<sup>[[2]](#references)</sup>

#### Fuzzing van jou API-oppervlak (cargo-fuzz)

Fuzz-toetse vang maklik panics, integer-oorlope en logikafoute op wat tot DoS- of side-channel-kwessies kan lei:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Voeg die fuzz target by jou repo en voer dit in jou pipeline uit.

## Verwysings

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: Auditing your Rust Dependencies](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
