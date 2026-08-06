# Osnove Rust-a

{{#include ../banners/hacktricks-training.md}}

### Vlasništvo nad promenljivama

Memorijom se upravlja pomoću sistema vlasništva sa sledećim pravilima, koja kompajler proverava tokom kompajliranja:

1. Svaka vrednost u Rust-u ima promenljivu koja se naziva njenim vlasnikom.
2. U datom trenutku može postojati samo jedan vlasnik.
3. Kada vlasnik izađe iz svog opsega važenja, vrednost će biti uklonjena.
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
### Generički tipovi

Kreirajte strukturu u kojoj jedna od njenih vrednosti može biti bilo kog tipa
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

Tip Option znači da vrednost može biti tipa Some (nešto postoji) ili None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Možete koristiti funkcije kao što su `is_some()` ili `is_none()` za proveru vrednosti tipa Option.


### Result, Ok & Err

Koriste se za vraćanje i prosleđivanje grešaka
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Možete koristiti funkcije kao što su `is_ok()` ili `is_err()` da proverite vrednost rezultata

Enum `Option` treba koristiti u situacijama kada vrednost možda ne postoji (kada je `None`).
Enum `Result` treba koristiti u situacijama kada radite nešto što može poći naopako


### Makroi

Makroi su moćniji od funkcija zato što se proširuju i generišu više koda nego što ste ručno napisali. Na primer, potpis funkcije mora da deklariše broj i tip parametara koje funkcija ima. Makroi, s druge strane, mogu prihvatiti promenljiv broj parametara: možemo pozvati `println!("hello")` sa jednim argumentom ili `println!("hello {}", name)` sa dva argumenta. Takođe, makroi se proširuju pre nego što kompajler protumači značenje koda, pa makro može, na primer, implementirati trait za dati tip. Funkcija to ne može, zato što se poziva tokom izvršavanja, a trait mora biti implementiran tokom kompajliranja.
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
### Iteracija
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
### Rekurzivna kutija
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Uslovne naredbe

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
#### petlja (beskonačna)
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
#### za
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

Kreirajte novu metodu za tip
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
### Testovi
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

Arc može da koristi Clone za kreiranje dodatnih referenci na objekat, kako bi ih prosledio nitima. Kada poslednji pokazivač reference na vrednost izađe iz opsega, promenljiva se odbacuje.
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

U ovom slučaju prosledićemo thread-u promenljivu koju će moći da izmeni
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
### Osnove bezbednosti

Rust podrazumevano pruža snažne garancije bezbednosti memorije, ali i dalje možete uvesti kritične ranjivosti kroz `unsafe` kod, probleme sa dependency-jima ili greške u logici. Sledeći mini-cheatsheet prikuplja primitive sa kojima ćete najčešće raditi tokom ofanzivnih ili defanzivnih security pregleda Rust softvera.

#### `unsafe` kod i bezbednost memorije

`unsafe` blokovi isključuju compiler-ove provere aliasing-a i granica, pa se **sve tradicionalne greške koje dovode do korupcije memorije (OOB, use-after-free, double free itd.) mogu ponovo pojaviti**. Kratka audit kontrolna lista:

* Potražite `unsafe` blokove, `extern "C"` funkcije, pozive ka `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers ili `ffi` module.
* Proverite svaku pointer aritmetiku i argument dužine prosleđen low-level funkcijama.
* Dajte prednost direktivi `#![forbid(unsafe_code)]` (na nivou celog crate-a) ili `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) kako bi compilation neuspešno prošao kada neko ponovo uvede `unsafe`.

Primer overflow-a kreiranog pomoću raw pointers:
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
Pokretanje Miri-ja je jeftin način za otkrivanje UB-a tokom testiranja:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Provera zavisnosti pomoću RustSec / cargo-audit

Većina stvarnih Rust ranjivosti nalazi se u crate-ovima trećih strana. Baza bezbednosnih obaveštenja RustSec (koju pokreće zajednica) može se upititi lokalno:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integrate it in CI and fail on `--deny warnings`.

`cargo deny check advisories` nudi sličnu funkcionalnost, kao i provere licenci i liste zabranjenih paketa.

#### Pokrivenost koda pomoću cargo-tarpaulin

`cargo tarpaulin` je alat za izveštavanje o pokrivenosti koda za Cargo build sistem
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Na Linuxu, podrazumevani backend za tracing u alatu Tarpaulin i dalje je Ptrace i radiće samo na x86_64 procesorima. To se može promeniti na llvm coverage instrumentation pomoću opcije `--engine llvm`. Za Mac i Windows, ovo je podrazumevani metod prikupljanja.

#### Provera lanca snabdevanja pomoću cargo-vet (2024)

`cargo vet` beleži review hash za svaki crate koji importujete i sprečava neprimećene nadogradnje:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Alat usvaja Rust projektna infrastruktura i sve veći broj organizacija radi ublažavanja napada trovanjem paketa.<sup>[[2]](#references)</sup>

#### Fuzzing vaše API površine (cargo-fuzz)

Fuzz testovi lako otkrivaju panike, prekoračenja celih brojeva i logičke greške koje mogu prerasti u DoS ili probleme sa side-channel napadima:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Dodajte fuzz target u svoj repo i pokrenite ga u svom pipeline-u.

## Reference

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: „Auditing your Rust Dependencies“](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
