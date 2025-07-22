# Osnove Rusta

{{#include ../banners/hacktricks-training.md}}

### Generički Tipovi

Kreirajte strukturu gde jedna od njihovih vrednosti može biti bilo koji tip
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

Tip Option znači da vrednost može biti tipa Some (ima nešto) ili None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Možete koristiti funkcije kao što su `is_some()` ili `is_none()` da proverite vrednost Opcije.

### Makroi

Makroi su moćniji od funkcija jer se šire da proizvedu više koda nego što ste ručno napisali. Na primer, potpis funkcije mora da deklarira broj i tip parametara koje funkcija ima. Makroi, s druge strane, mogu primiti promenljiv broj parametara: možemo pozvati `println!("hello")` sa jednim argumentom ili `println!("hello {}", name)` sa dva argumenta. Takođe, makroi se šire pre nego što kompajler interpretira značenje koda, tako da makro može, na primer, implementirati trait na datom tipu. Funkcija to ne može, jer se poziva u vreme izvršavanja, a trait mora biti implementiran u vreme kompajliranja.
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
### Iterirati
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
### Rekurzivna Kutija
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Uslovi

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
#### podudaranje
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
#### dok
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
#### за
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
### Osobine

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
### Тестови
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

Arc može koristiti Clone da kreira više referenci na objekat kako bi ih prosledio nitima. Kada poslednji referentni pokazivač na vrednost izađe iz opsega, promenljiva se uklanja.
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

U ovom slučaju ćemo proslediti niti promenljivu koju će moći da modifikuje
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
### Osnovi bezbednosti

Rust pruža jake garancije bezbednosti memorije po defaultu, ali i dalje možete uvesti kritične ranjivosti kroz `unsafe` kod, probleme sa zavisnostima ili logičke greške. Sledeća mini-šema okuplja primitivne tipove koje ćete najčešće koristiti tokom ofanzivnih ili defensivnih bezbednosnih pregleda Rust softvera.

#### Unsafe kod i bezbednost memorije

`unsafe` blokovi isključuju proveru aliasinga i granica od strane kompajlera, tako da **sve tradicionalne greške u korupciji memorije (OOB, upotreba nakon oslobađanja, dvostruko oslobađanje itd.) mogu ponovo da se pojave**. Brza lista za reviziju:

* Potražite `unsafe` blokove, `extern "C"` funkcije, pozive na `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, sirove pokazivače ili `ffi` module.
* Validirajte svaku aritmetiku pokazivača i argument dužine prosleđene niskonivou funkcijama.
* Preferirajte `#![forbid(unsafe_code)]` (na nivou crate-a) ili `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) da bi se prekinula kompilacija kada neko ponovo uvede `unsafe`.

Primer prelivanja stvorenog sa sirovim pokazivačima:
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
Pokretanje Miri je jeftin način za otkrivanje UB u vreme testiranja:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditing dependencies with RustSec / cargo-audit

Većina stvarnih Rust ranjivosti se nalazi u trećim paketima. RustSec savetodavna baza podataka (koju pokreće zajednica) može se pretraživati lokalno:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integrate it in CI and fail on `--deny warnings`.

`cargo deny check advisories` nudi sličnu funkcionalnost plus provere licenci i ban-liste.

#### Verifikacija lanca snabdevanja sa cargo-vet (2024)

`cargo vet` beleži hash revizije za svaku kutiju koju uvozite i sprečava neprimećene nadogradnje:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Alat se usvaja od strane Rust projekta i sve većeg broja organizacija kako bi se umanjili napadi sa zaraženim paketima.

#### Fuzzing vašeg API površine (cargo-fuzz)

Fuzz testovi lako hvataju panike, prelivanja celih brojeva i logičke greške koje bi mogle postati DoS ili problemi sa bočnim kanalima:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Dodajte fuzz cilj u vaš repozitorijum i pokrenite ga u vašem pipeline-u.

## Reference

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
