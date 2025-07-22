# Podstawy Rust

{{#include ../banners/hacktricks-training.md}}

### Typy ogólne

Utwórz strukturę, w której 1 z ich wartości może być dowolnym typem
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

Typ Option oznacza, że wartość może być typu Some (jest coś) lub None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Możesz używać funkcji takich jak `is_some()` lub `is_none()`, aby sprawdzić wartość opcji.

### Makra

Makra są potężniejsze niż funkcje, ponieważ rozwijają się, aby wygenerować więcej kodu niż ten, który napisałeś ręcznie. Na przykład, sygnatura funkcji musi zadeklarować liczbę i typ parametrów, które ma funkcja. Makra, z drugiej strony, mogą przyjmować zmienną liczbę parametrów: możemy wywołać `println!("hello")` z jednym argumentem lub `println!("hello {}", name)` z dwoma argumentami. Ponadto, makra są rozwijane przed tym, jak kompilator interpretuje znaczenie kodu, więc makro może na przykład zaimplementować trait dla danego typu. Funkcja nie może, ponieważ jest wywoływana w czasie wykonywania, a trait musi być zaimplementowany w czasie kompilacji.
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
### Iterować
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
### Rekursywne Pudełko
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Warunki

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
#### dopasowanie
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
#### podczas
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
#### dla
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
### Cechy

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

Arc może używać Clone do tworzenia większej liczby referencji do obiektu, aby przekazać je do wątków. Gdy ostatni wskaźnik referencyjny do wartości wychodzi z zakresu, zmienna jest usuwana.
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

W tym przypadku przekażemy wątkowi zmienną, którą będzie mógł modyfikować.
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

Rust zapewnia silne gwarancje bezpieczeństwa pamięci domyślnie, ale nadal możesz wprowadzić krytyczne luki poprzez kod `unsafe`, problemy z zależnościami lub błędy logiczne. Poniższa mini-ściągawka zbiera prymitywy, z którymi najczęściej będziesz mieć do czynienia podczas ofensywnych lub defensywnych przeglądów bezpieczeństwa oprogramowania Rust.

#### Kod unsafe i bezpieczeństwo pamięci

Bloki `unsafe` rezygnują z aliasowania i sprawdzania granic przez kompilator, więc **wszystkie tradycyjne błędy korupcji pamięci (OOB, użycie po zwolnieniu, podwójne zwolnienie itp.) mogą się pojawić ponownie**. Szybka lista kontrolna audytu:

* Szukaj bloków `unsafe`, funkcji `extern "C"`, wywołań `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, wskaźników surowych lub modułów `ffi`.
* Waliduj każdą arytmetykę wskaźników i argumenty długości przekazywane do funkcji niskiego poziomu.
* Preferuj `#![forbid(unsafe_code)]` (na poziomie całego crate) lub `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +), aby zakończyć kompilację, gdy ktoś ponownie wprowadzi `unsafe`.

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
Uruchamianie Miri to niedrogi sposób na wykrycie UB w czasie testów:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Audytowanie zależności z RustSec / cargo-audit

Większość rzeczywistych luk w Rust znajduje się w zewnętrznych crate'ach. Baza danych porad RustSec (napędzana przez społeczność) może być przeszukiwana lokalnie:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Zintegruj to w CI i zakończ na `--deny warnings`.

`cargo deny check advisories` oferuje podobną funkcjonalność oraz sprawdzenia licencji i listy zakazów.

#### Weryfikacja łańcucha dostaw z cargo-vet (2024)

`cargo vet` rejestruje hash przeglądu dla każdego crate, który importujesz, i zapobiega niezauważonym aktualizacjom:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Narzędzie jest przyjmowane przez infrastrukturę projektu Rust oraz rosnącą liczbę organizacji w celu złagodzenia ataków z użyciem zainfekowanych pakietów.

#### Fuzzing twojej powierzchni API (cargo-fuzz)

Testy fuzzingowe łatwo wychwytują paniki, przepełnienia liczb całkowitych i błędy logiczne, które mogą stać się problemami DoS lub atakami bocznymi:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Dodaj cel fuzz do swojego repozytorium i uruchom go w swoim pipeline.

## Odniesienia

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Audytowanie swoich zależności Rust" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
