# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### Generiese Tipes

Skep 'n struktuur waar 1 van hul waardes enige tipe kan wees
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
### Opsie, Sommige & Geen

Die Opsie tipe beteken dat die waarde dalk van tipe Sommige (daar is iets) of Geen is:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
U kan funksies soos `is_some()` of `is_none()` gebruik om die waarde van die Opsie te kontroleer.

### Makros

Makros is kragtiger as funksies omdat hulle uitbrei om meer kode te produseer as die kode wat jy handmatig geskryf het. Byvoorbeeld, 'n funksie-handtekening moet die aantal en tipe parameters wat die funksie het, verklaar. Makros, aan die ander kant, kan 'n veranderlike aantal parameters neem: ons kan `println!("hello")` met een argument of `println!("hello {}", name)` met twee argumente aanroep. Ook, makros word uitgebrei voordat die kompilateur die betekenis van die kode interpreteer, so 'n makro kan byvoorbeeld 'n trait op 'n gegewe tipe implementeer. 'n Funksie kan nie, omdat dit tydens uitvoering aangeroep word en 'n trait moet tydens kompilering geïmplementeer word.
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
### Herhaal
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
### Rekursiewe Bok
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Voorwaardes

#### as
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
#### pas aan
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
#### lus (oneindig)
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
#### as dit laat
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### terwyl laat
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
### Kenmerke

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
### Draad

#### Arc

'n Arc kan Clone gebruik om meer verwysings oor die objek te skep om dit aan die drade te oorhandig. Wanneer die laaste verwysingsaanwyser na 'n waarde buite die omvang is, word die veranderlike verwyder.
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

In hierdie geval sal ons die draad 'n veranderlike gee wat dit sal kan wysig
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
### Sekuriteit Essensieel

Rust bied sterk geheue-veilige waarborge standaard, maar jy kan steeds kritieke kwesbaarhede inbring deur `unsafe` kode, afhanklikheidsprobleme of logiese foute. Die volgende mini-cheatsheet versamel die primitiewe wat jy die meeste sal raakloop tydens offensiewe of defensiewe sekuriteitshersienings van Rust sagteware.

#### Unsafe kode & geheue veiligheid

`unsafe` blokke kies uit die kompilator se aliasing en grense kontroles, so **alle tradisionele geheue-korrupsie foute (OOB, gebruik-na-vry, dubbele vry, ens.) kan weer verskyn**. 'n Vinnige oudit kontrolelys:

* Soek vir `unsafe` blokke, `extern "C"` funksies, oproepe na `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, rou wysers of `ffi` modules.
* Valideer elke wysers aritmetiek en lengte argument wat aan lae-vlak funksies deurgegee word.
* Verkies `#![forbid(unsafe_code)]` (crate-wyd) of `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) om kompilasie te laat misluk wanneer iemand `unsafe` weer inbring.

Voorbeeld oorgang geskep met rou wysers:
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
Die uitvoering van Miri is 'n goedkoop manier om UB tydens toetsing te detecteer:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Ouditering van afhanklikhede met RustSec / cargo-audit

Meeste werklike Rust kwesbaarhede bestaan in derdeparty crates. Die RustSec advies DB (gemeenskap-gedrewe) kan plaaslik gevra word:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integreer dit in CI en faal op `--deny warnings`.

`cargo deny check advisories` bied soortgelyke funksionaliteit plus lisensie- en verbodlys kontroles.

#### Verskaffingsketting verifikasie met cargo-vet (2024)

`cargo vet` registreer 'n hersieningshash vir elke crate wat jy invoer en voorkom ongemerkde opgraderings:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Die hulpmiddel word aangeneem deur die Rust-projekinfrastruktuur en 'n groeiende aantal organisasies om vergiftigde-pakket-aanvalle te verminder.

#### Fuzzing jou API-oppervlak (cargo-fuzz)

Fuzz-toetse vang maklik panieks, heelgetal oorgange en logiese foute wat DoS of kantkanaalprobleme kan word:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Voeg die fuzz-teiken by jou repo en voer dit in jou pyplyn uit.

## Verwysings

- RustSec Adviesdatabasis – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
