# Nozioni di base di Rust

{{#include ../banners/hacktricks-training.md}}

### Ownership delle variabili

La memoria è gestita attraverso un sistema di ownership con le seguenti regole, verificate dal compilatore in fase di compilazione:

1. Ogni valore in Rust ha una variabile chiamata owner.
2. Può esserci un solo owner alla volta.
3. Quando l'owner esce dallo scope, il valore verrà eliminato.
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
### Tipi generici

Crea una struct in cui uno dei suoi valori possa essere di qualsiasi tipo
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

Il tipo Option indica che il valore potrebbe essere di tipo Some (c'è qualcosa) oppure None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Puoi usare funzioni come `is_some()` o `is_none()` per verificare il valore di Option.


### Result, Ok e Err

Utilizzato per restituire e propagare gli errori
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Puoi usare funzioni come `is_ok()` o `is_err()` per verificare il valore del risultato

L'enum `Option` dovrebbe essere usato nelle situazioni in cui un valore potrebbe non esistere (essere `None`).
L'enum `Result` dovrebbe essere usato nelle situazioni in cui esegui un'operazione che potrebbe non andare a buon fine


### Macro

Le macro sono più potenti delle funzioni perché si espandono per produrre più codice rispetto a quello scritto manualmente. Ad esempio, la firma di una funzione deve dichiarare il numero e il tipo dei parametri che la funzione accetta. Le macro, invece, possono accettare un numero variabile di parametri: possiamo chiamare `println!("hello")` con un argomento oppure `println!("hello {}", name)` con due argomenti. Inoltre, le macro vengono espanse prima che il compilatore interpreti il significato del codice, quindi una macro può, ad esempio, implementare un trait per un determinato tipo. Una funzione non può farlo, perché viene chiamata a runtime e un trait deve essere implementato a compile time.
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
### Box ricorsivo
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
#### loop (infinito)
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

Un `Arc` può usare `Clone` per creare ulteriori riferimenti all'oggetto e passarli ai thread. Quando l'ultimo puntatore di riferimento a un valore esce dall'ambito, la variabile viene eliminata.
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

In questo caso passeremo al thread una variabile che potrà modificare
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
### Elementi essenziali di sicurezza

Rust offre solide garanzie di memory safety per impostazione predefinita, ma è comunque possibile introdurre vulnerabilità critiche tramite codice `unsafe`, problemi nelle dipendenze o errori logici. La seguente mini-cheatsheet raccoglie le primitive con cui avrai più probabilmente a che fare durante le security review offensive o difensive del software Rust.

#### Codice unsafe e memory safety

I blocchi `unsafe` rinunciano ai controlli del compilatore relativi agli alias e ai limiti, quindi **tutti i bug tradizionali di memory corruption (OOB, use-after-free, double free, ecc.) possono ripresentarsi**. Una rapida checklist di audit:

* Cerca blocchi `unsafe`, funzioni `extern "C"`, chiamate a `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers o moduli `ffi`.
* Convalida ogni operazione aritmetica sui puntatori e ogni argomento relativo alla lunghezza passato alle funzioni low-level.
* Preferisci `#![forbid(unsafe_code)]` (a livello di crate) o `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) per fare in modo che la compilazione fallisca quando qualcuno reintroduce `unsafe`.

Esempio di overflow creato con raw pointers:
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
Eseguire Miri è un modo economico per rilevare l'UB durante i test:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditing delle dipendenze con RustSec / cargo-audit

La maggior parte delle vulnerabilità di Rust nel mondo reale risiede nei crate di terze parti. Il database degli advisory RustSec (gestito dalla community) può essere interrogato localmente:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integralo nella CI e fallisci con `--deny warnings`.

`cargo deny check advisories` offre funzionalità simili, oltre a controlli sulle licenze e sulle ban-list.

#### Copertura del codice con cargo-tarpaulin

`cargo tarpaulin` è uno strumento per generare report sulla copertura del codice per il sistema di build Cargo
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Su Linux, il backend di tracing predefinito di Tarpaulin è ancora Ptrace e funzionerà solo sui processori x86_64. Questo può essere modificato usando la strumentazione llvm coverage con `--engine llvm`. Per Mac e Windows, questo è il metodo di raccolta predefinito.

#### Verifica della supply chain con cargo-vet (2024)

`cargo vet` registra un hash di revisione per ogni crate importato e impedisce upgrade non rilevati:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Lo strumento viene adottato dall'infrastruttura del progetto Rust e da un numero crescente di organizzazioni per mitigare gli attacchi tramite pacchetti compromessi.<sup>[[2]](#references)</sup>

#### Fuzzing della superficie della tua API (cargo-fuzz)

I fuzz test rilevano facilmente panic, integer overflow e bug logici che potrebbero trasformarsi in problemi di DoS o side-channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Aggiungi il fuzz target al tuo repo ed eseguilo nella tua pipeline.

## Riferimenti

- [1] [Database degli avvisi RustSec](https://rustsec.org)
- [2] [Cargo-vet: verifica delle tue dipendenze Rust](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
