# Fondamenti di Rust

{{#include ../banners/hacktricks-training.md}}

### Tipi Generici

Crea una struct in cui 1 dei loro valori potrebbe essere di qualsiasi tipo
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

Il tipo Option significa che il valore potrebbe essere di tipo Some (c'è qualcosa) o None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Puoi usare funzioni come `is_some()` o `is_none()` per controllare il valore dell'Option.

### Macro

Le macro sono più potenti delle funzioni perché si espandono per produrre più codice di quello che hai scritto manualmente. Ad esempio, una firma di funzione deve dichiarare il numero e il tipo di parametri che la funzione ha. Le macro, d'altra parte, possono prendere un numero variabile di parametri: possiamo chiamare `println!("hello")` con un argomento o `println!("hello {}", name)` con due argomenti. Inoltre, le macro vengono espanse prima che il compilatore interpreti il significato del codice, quindi una macro può, ad esempio, implementare un trait su un dato tipo. Una funzione non può, perché viene chiamata a runtime e un trait deve essere implementato a tempo di compilazione.
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
### Iterare
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
### Box Ricorsiva
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Condizionali

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
#### corrispondenza
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
#### ciclo (infinito)
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
#### mentre
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
#### per
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
#### mentre lascia
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
### Caratteristiche

Crea un nuovo metodo per un tipo
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
### Test
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

Un Arc può utilizzare Clone per creare più riferimenti all'oggetto da passare ai thread. Quando l'ultimo puntatore di riferimento a un valore esce dallo scope, la variabile viene eliminata.
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

In questo caso passeremo al thread una variabile che sarà in grado di modificare
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
### Fondamenti di Sicurezza

Rust fornisce forti garanzie di sicurezza della memoria per impostazione predefinita, ma puoi comunque introdurre vulnerabilità critiche attraverso codice `unsafe`, problemi di dipendenza o errori logici. Il seguente mini-cheatsheet raccoglie i primitivi che toccherai più comunemente durante le revisioni di sicurezza offensive o difensive del software Rust.

#### Codice unsafe e sicurezza della memoria

I blocchi `unsafe` rinunciano ai controlli di aliasing e di limiti del compilatore, quindi **tutti i tradizionali bug di corruzione della memoria (OOB, use-after-free, double free, ecc.) possono riapparire**. Un rapido elenco di controllo per l'audit:

* Cerca blocchi `unsafe`, funzioni `extern "C"`, chiamate a `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, puntatori raw o moduli `ffi`.
* Valida ogni aritmetica dei puntatori e argomento di lunghezza passato a funzioni di basso livello.
* Preferisci `#![forbid(unsafe_code)]` (a livello di crate) o `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) per far fallire la compilazione quando qualcuno reintroduce `unsafe`.

Esempio di overflow creato con puntatori raw:
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
Eseguire Miri è un modo economico per rilevare UB durante il test:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditing dependencies with RustSec / cargo-audit

La maggior parte delle vulnerabilità Rust nel mondo reale si trova in crate di terze parti. Il database delle advisory di RustSec (alimentato dalla comunità) può essere interrogato localmente:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integralo in CI e fallisci su `--deny warnings`.

`cargo deny check advisories` offre funzionalità simili più controlli su licenze e liste di divieto.

#### Verifica della supply-chain con cargo-vet (2024)

`cargo vet` registra un hash di revisione per ogni crate che importi e previene aggiornamenti non notati:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Lo strumento è adottato dall'infrastruttura del progetto Rust e da un numero crescente di organizzazioni per mitigare gli attacchi con pacchetti compromessi.

#### Fuzzing della tua superficie API (cargo-fuzz)

I test di fuzzing catturano facilmente panico, overflow di interi e bug logici che potrebbero diventare problemi di DoS o di canale laterale:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Aggiungi il target di fuzz al tuo repo e eseguilo nella tua pipeline.

## Riferimenti

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
