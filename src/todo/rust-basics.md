# Podstawy Rust

{{#include ../banners/hacktricks-training.md}}

### Własność zmiennych

Pamięć jest zarządzana za pomocą systemu własności zgodnie z następującymi regułami, które kompilator sprawdza w czasie kompilacji:

1. Każda wartość w Rust ma zmienną nazywaną jej właścicielem.
2. W danym momencie może istnieć tylko jeden właściciel.
3. Gdy właściciel wyjdzie poza zakres, wartość zostanie usunięta.
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

Utwórz strukturę, której jedna z wartości może być dowolnego typu
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

Typ Option oznacza, że wartość może być typu Some (coś istnieje) albo None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Możesz używać funkcji takich jak `is_some()` lub `is_none()`, aby sprawdzić wartość Option.


### Result, Ok & Err

Używane do zwracania i propagowania błędów
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Możesz używać funkcji takich jak `is_ok()` lub `is_err()`, aby sprawdzić wartość wyniku

Enuma `Option` należy używać w sytuacjach, w których wartość może nie istnieć (być równa `None`).
Enuma `Result` należy używać w sytuacjach, w których wykonujesz operację, która może się nie powieść


### Makra

Makra są potężniejsze niż funkcje, ponieważ rozwijają się, tworząc więcej kodu niż kod napisany ręcznie. Na przykład sygnatura funkcji musi deklarować liczbę i typ parametrów, które przyjmuje funkcja. Makra natomiast mogą przyjmować zmienną liczbę parametrów: możemy wywołać `println!("hello")` z jednym argumentem lub `println!("hello {}", name)` z dwoma argumentami. Ponadto makra są rozwijane, zanim compiler zinterpretuje znaczenie kodu, więc makro może na przykład zaimplementować trait dla danego typu. Funkcja nie może tego zrobić, ponieważ jest wywoływana w runtime, a trait musi zostać zaimplementowany w czasie kompilacji.
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
### Iteruj
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
### Rekursywne pudełko
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
#### loop (nieskończona)
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
### Threading

#### Arc

Arc może użyć Clone, aby utworzyć więcej referencji do obiektu i przekazać je do wątków. Gdy ostatni wskaźnik referencyjny do wartości wyjdzie poza zakres, zmienna zostaje usunięta.
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
#### Wątki

W tym przypadku przekażemy wątkowi zmienną, którą będzie mógł modyfikować
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

Rust domyślnie zapewnia silne gwarancje bezpieczeństwa pamięci, ale nadal można wprowadzić krytyczne podatności przez kod `unsafe`, problemy z dependencies lub błędy logiczne. Poniższa mini-ściągawka zbiera prymitywy, z którymi najczęściej będziesz mieć do czynienia podczas offensive lub defensive security reviews oprogramowania w Rust.

#### Kod Unsafe i bezpieczeństwo pamięci

Bloki `unsafe` wyłączają sprawdzanie aliasingu i zakresów przez compiler, dlatego **wszystkie tradycyjne błędy prowadzące do corruption pamięci (OOB, use-after-free, double free itd.) mogą ponownie wystąpić**. Szybka checklista audytu:

* Szukaj bloków `unsafe`, funkcji `extern "C"`, wywołań `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers lub modułów `ffi`.
* Zweryfikuj każdą arytmetykę wskaźników i każdy argument length przekazywany do low-level functions.
* Preferuj `#![forbid(unsafe_code)]` (crate-wide) lub `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +), aby compilation kończyła się błędem, gdy ktoś ponownie wprowadzi `unsafe`.

Przykład overflow utworzonego za pomocą raw pointers:
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
Uruchamianie Miri to niedrogi sposób na wykrywanie UB podczas testów:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Audytowanie zależności za pomocą RustSec / cargo-audit

Większość rzeczywistych podatności w Rust występuje w crate'ach innych firm. Bazę ostrzeżeń RustSec (tworzoną przez społeczność) można odpytywać lokalnie:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Zintegruj to z CI i przerywaj działanie przy użyciu `--deny warnings`.

`cargo deny check advisories` oferuje podobną funkcjonalność, a także sprawdzanie licencji i listy zakazanych elementów.

#### Pokrycie kodu za pomocą cargo-tarpaulin

`cargo tarpaulin` to narzędzie do raportowania pokrycia kodu dla systemu budowania Cargo
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
W systemie Linux domyślnym backendem śledzenia Tarpaulin jest nadal Ptrace i będzie on działać wyłącznie na procesorach x86_64. Można to zmienić na instrumentację pokrycia llvm za pomocą `--engine llvm`. W systemach Mac i Windows jest to domyślna metoda zbierania danych.

#### Weryfikacja łańcucha dostaw za pomocą cargo-vet (2024)

`cargo vet` rejestruje hash przeglądu dla każdego importowanego crate'a i zapobiega niezauważonym aktualizacjom:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Narzędzie jest wdrażane w infrastrukturze projektu Rust oraz przez coraz większą liczbę organizacji w celu ograniczania ataków z użyciem zatrutych pakietów.<sup>[[2]](#references)</sup>

#### Fuzzowanie powierzchni API (cargo-fuzz)

Testy fuzzingu z łatwością wykrywają paniki, przepełnienia liczb całkowitych i błędy logiczne, które mogą prowadzić do DoS lub problemów z side-channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Dodaj cel fuzzingu do swojego repozytorium i uruchom go w swoim pipeline.

## Odnośniki

- [1] [Baza danych porad RustSec](https://rustsec.org)
- [2] [Cargo-vet: Audytowanie zależności Rust](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
