# Notions de base de Rust

{{#include ../banners/hacktricks-training.md}}

### Propriété des variables

La mémoire est gérée via un système de propriété avec les règles suivantes, vérifiées par le compilateur à la compilation :

1. Chaque valeur en Rust a une variable appelée son propriétaire.
2. Il ne peut y avoir qu'un seul propriétaire à la fois.
3. Lorsque le propriétaire sort de la portée, la valeur sera libérée.
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
### Types génériques

Créez une struct où l'une de ses valeurs peut être de n'importe quel type
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

Le type Option signifie que la valeur peut être de type Some (il y a quelque chose) ou None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Vous pouvez utiliser des fonctions telles que `is_some()` ou `is_none()` pour vérifier la valeur de l'Option.


### Result, Ok & Err

Utilisés pour renvoyer et propager des erreurs
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Vous pouvez utiliser des fonctions telles que `is_ok()` ou `is_err()` pour vérifier la valeur du résultat.

L'enum `Option` doit être utilisé dans les situations où une valeur pourrait ne pas exister (être `None`).
L'enum `Result` doit être utilisé lorsque vous effectuez une opération qui peut échouer.


### Macros

Les macros sont plus puissantes que les fonctions car elles génèrent plus de code que celui que vous avez écrit manuellement. Par exemple, la signature d'une fonction doit déclarer le nombre et le type de ses paramètres. Les macros, en revanche, peuvent prendre un nombre variable de paramètres : on peut appeler `println!("hello")` avec un argument ou `println!("hello {}", name)` avec deux arguments. De plus, les macros sont développées avant que le compilateur n'interprète le sens du code, donc une macro peut, par exemple, implémenter un trait pour un type donné. Une fonction ne peut pas le faire, car elle est appelée à l'exécution alors qu'un trait doit être implémenté à la compilation.
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
### Itérer
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
### Box récursive
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Structures conditionnelles

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
#### boucle (infinie)
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

Créer une nouvelle méthode pour un type
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
### Tests
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
### Multithreading

#### Arc

Un Arc peut utiliser Clone pour créer davantage de références vers l'objet afin de les transmettre aux threads. Lorsque la dernière référence vers une valeur sort de sa portée, la variable est libérée.
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

Dans ce cas, nous allons passer au thread une variable qu'il pourra modifier.
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
### Éléments essentiels de sécurité

Rust fournit par défaut de fortes garanties de sécurité mémoire, mais vous pouvez toujours introduire des vulnérabilités critiques via du code `unsafe`, des problèmes de dépendances ou des erreurs de logique. La mini-fiche suivante rassemble les primitives que vous serez le plus souvent amené·e·s à manipuler lors d'audits de sécurité offensifs ou défensifs de logiciels Rust.

#### Code `unsafe` & sécurité mémoire

Les blocs `unsafe` désactivent les vérifications d'aliasing et de bornes du compilateur, donc **tous les bugs traditionnels de corruption mémoire (OOB, use-after-free, double free, etc.) peuvent réapparaître**. Checklist rapide d'audit :

* Cherchez les blocs `unsafe`, les fonctions `extern "C"`, les appels à `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, les raw pointers ou les modules `ffi`.
* Validez chaque arithmétique de pointeur et chaque argument de longueur passé à des fonctions bas niveau.
* Privilégiez `#![forbid(unsafe_code)]` (crate-wide) ou `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) pour faire échouer la compilation lorsqu'on réintroduit `unsafe`.

Exemple d'overflow créé avec des raw pointers:
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
Exécuter Miri est un moyen peu coûteux de détecter l'UB lors des tests :
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Audit des dépendances avec RustSec / cargo-audit

La plupart des vulns Rust en conditions réelles se trouvent dans des third-party crates. La RustSec advisory DB (community-powered) peut être consultée localement :
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Intégrez-le dans votre CI et faites échouer le build avec `--deny warnings`.

`cargo deny check advisories` offre une fonctionnalité similaire ainsi que des vérifications de licence et de listes de blocage.

#### Couverture de code avec cargo-tarpaulin

`cargo tarpaulin` est un outil de génération de rapports de couverture de code pour le système de build Cargo
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Sur Linux, le backend de traçage par défaut de Tarpaulin est toujours Ptrace et ne fonctionne que sur les processeurs x86_64. Cela peut être changé pour l'instrumentation de couverture llvm avec `--engine llvm`. Sur Mac et Windows, c'est la méthode de collecte par défaut.

#### Vérification de la chaîne d'approvisionnement avec cargo-vet (2024)

`cargo vet` enregistre un hash de révision pour chaque crate que vous importez et empêche les mises à jour non détectées :
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
L'outil est adopté par l'infrastructure du projet Rust et par un nombre croissant d'organisations pour atténuer les poisoned-package attacks.

#### Fuzzing la surface de votre API (cargo-fuzz)

Les fuzz tests détectent facilement les panics, les integer overflows et les bogues logiques qui pourraient devenir des problèmes de DoS ou des side-channel :
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Ajoutez le fuzz target à votre repo et exécutez-le dans votre pipeline.

## Références

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Audit de vos dépendances Rust" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
