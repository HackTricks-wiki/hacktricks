# Podstawy Rust

{{#include ../banners/hacktricks-training.md}}

### Własność zmiennych

Pamięć jest zarządzana przez system własności z następującymi regułami, które kompilator sprawdza w czasie kompilacji:

1. Każda wartość w Rust ma zmienną zwaną jej właścicielem.
2. Może istnieć tylko jeden właściciel w danym czasie.
3. Gdy właściciel wychodzi poza zakres, wartość zostanie zwolniona.
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
### Typy generyczne

Utwórz struct, którego jedno z pól może być dowolnego typu.
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

Typ Option oznacza, że wartość może być typu Some (istnieje jakaś wartość) lub None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Możesz użyć funkcji takich jak `is_some()` lub `is_none()`, aby sprawdzić wartość Option.

### Result, Ok & Err

Służy do zwracania i propagowania błędów.
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Możesz użyć funkcji takich jak `is_ok()` lub `is_err()`, aby sprawdzić wartość `Result`

Enum `Option` powinien być używany w sytuacjach, gdzie wartość może nie istnieć (być `None`).
Enum `Result` powinien być używany w sytuacjach, gdy wykonujesz coś, co może pójść nie tak


### Makra

Makra są potężniejsze niż funkcje, ponieważ podczas rozwijania generują więcej kodu niż kod, który napisałeś ręcznie. Na przykład sygnatura funkcji musi deklarować liczbę i typ parametrów, które funkcja posiada. Makra z drugiej strony mogą przyjmować zmienną liczbę parametrów: możemy wywołać `println!("hello")` z jednym argumentem lub `println!("hello {}", name)` z dwoma argumentami. Dodatkowo makra są rozwijane zanim kompilator zinterpretuje znaczenie kodu, więc makro może na przykład zaimplementować trait dla danego typu. Funkcja nie może tego zrobić, ponieważ jest wywoływana w czasie wykonywania, a trait musi być zaimplementowany w czasie kompilacji.
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
### Iteracja
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
### Rekursywny Box
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Instrukcje warunkowe

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
#### pętla (nieskończona)
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

Utwórz nową metodę dla typu
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
### Testy
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
### Wątkowanie

#### Arc

Arc może użyć Clone, aby utworzyć więcej referencji do obiektu i przekazać je do wątków. Gdy ostatni wskaźnik referencyjny do wartości wyjdzie poza zakres, wartość zostaje zwolniona.
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

W tym przypadku przekażemy threadowi zmienną, którą będzie mógł zmodyfikować.
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
### Podstawy bezpieczeństwa

Rust zapewnia domyślnie silne gwarancje bezpieczeństwa pamięci, ale nadal możesz wprowadzić krytyczne podatności przez `unsafe` kod, problemy z zależnościami lub błędy logiczne. Poniższa mini-ściągawka zbiera prymitywy, z którymi najczęściej będziesz mieć do czynienia podczas przeglądów bezpieczeństwa ofensywnych lub defensywnych oprogramowania w Rust.

#### Unsafe code & memory safety

`unsafe` blocks opt-out of the compiler’s aliasing and bounds checks, so **wszystkie tradycyjne błędy powodujące naruszenia pamięci (OOB, use-after-free, double free, etc.) mogą pojawić się ponownie**. Krótka lista kontrolna do szybkiego audytu:

* Szukaj bloków `unsafe`, funkcji `extern "C"`, wywołań `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, surowych wskaźników lub modułów `ffi`.
* Weryfikuj wszystkie operacje arytmetyki wskaźników oraz argumenty długości przekazywane do funkcji niskiego poziomu.
* Stosuj `#![forbid(unsafe_code)]` (dla całego crate) lub `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) aby kompilacja się nie powiodła, gdy ktoś ponownie wprowadzi `unsafe`.

Przykład przepełnienia stworzonego za pomocą surowych wskaźników:
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
Uruchamianie Miri to niedrogi sposób na wykrycie UB podczas testów:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Audyt zależności za pomocą RustSec / cargo-audit

Większość rzeczywistych Rust vulns znajduje się w third-party crates. RustSec advisory DB (oparta na społeczności) można przeszukać lokalnie:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Zintegruj to w CI i wymuś niepowodzenie przy `--deny warnings`.

`cargo deny check advisories` oferuje podobną funkcjonalność oraz sprawdzanie licencji i listy zablokowanych.

#### Pokrycie kodu za pomocą cargo-tarpaulin

`cargo tarpaulin` jest narzędziem do raportowania pokrycia kodu dla systemu budowania Cargo
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Na Linuksie domyślnym backendem śledzenia Tarpaulin wciąż jest Ptrace i działa tylko na procesorach x86_64. Można to zmienić na instrumentację pokrycia llvm przy użyciu `--engine llvm`. Dla Mac i Windows jest to domyślna metoda zbierania.

#### Weryfikacja łańcucha dostaw za pomocą cargo-vet (2024)

`cargo vet` zapisuje hash przeglądu dla każdego crate'a, który importujesz, i zapobiega niezauważonym aktualizacjom:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Narzędzie jest przyjmowane przez infrastrukturę projektu Rust oraz przez coraz większą liczbę organizacji, aby ograniczyć poisoned-package attacks.

#### Fuzzing your API surface (cargo-fuzz)

Fuzz tests łatwo wykrywają panics, integer overflows i logic bugs, które mogą przerodzić się w DoS lub side-channel issues:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Dodaj fuzz target do repozytorium i uruchom go w pipeline.

## Referencje

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
