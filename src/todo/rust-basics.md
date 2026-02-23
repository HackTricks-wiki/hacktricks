# Fundamentos de Rust

{{#include ../banners/hacktricks-training.md}}

### Propiedad de las variables

La memoria se gestiona mediante un sistema de propiedad con las siguientes reglas que el compilador verifica en tiempo de compilación:

1. Cada valor en Rust tiene una variable que se llama su propietario.
2. Solo puede haber un propietario a la vez.
3. Cuando el propietario sale de su ámbito, el valor será liberado.
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
### Tipos genéricos

Crea un struct donde 1 de sus valores pueda ser cualquier type
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

El tipo Option significa que el valor puede ser del tipo Some (hay algo) o None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Puedes usar funciones como `is_some()` o `is_none()` para comprobar el valor de la Option.


### Result, Ok & Err

Usados para devolver y propagar errores.
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Puedes usar funciones como `is_ok()` o `is_err()` para comprobar el valor del resultado

El enum `Option` debe usarse en situaciones donde un valor podría no existir (ser `None`).
El enum `Result` debe usarse en situaciones donde haces algo que podría salir mal


### Macros

Las macros son más potentes que las funciones porque se expanden para producir más código del que has escrito manualmente. Por ejemplo, la firma de una función debe declarar el número y el tipo de parámetros que tiene la función. Las macros, en cambio, pueden tomar un número variable de parámetros: podemos llamar a `println!("hello")` con un argumento o `println!("hello {}", name)` con dos argumentos. Además, las macros se expanden antes de que el compilador interprete el significado del código, por lo que una macro puede, por ejemplo, implementar un trait en un tipo dado. Una función no puede, porque se ejecuta en tiempo de ejecución y un trait necesita implementarse en tiempo de compilación.
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
### Iterar
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
### Caja recursiva
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Condicionales

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
#### bucle (infinito)
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

Crear un nuevo método para un tipo
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
### Pruebas
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
### Hilos

#### Arc

Un Arc puede usar Clone para crear más referencias al objeto y pasarlas a los hilos. Cuando el último puntero de referencia a un valor sale del alcance, la variable se destruye.
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
#### Hilos

En este caso le pasaremos al hilo una variable que podrá modificar
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
### Esenciales de seguridad

Rust proporciona garantías sólidas de seguridad de memoria por defecto, pero aún puedes introducir vulnerabilidades críticas mediante código `unsafe`, problemas en dependencias o errores lógicos. La siguiente mini-cheatsheet reúne los primitivos con los que más comúnmente interactuarás durante revisiones de seguridad ofensivas o defensivas de software Rust.

#### Código `unsafe` y seguridad de memoria

Los bloques `unsafe` omiten las comprobaciones de aliasing y de límites del compilador, por lo que **todos los bugs tradicionales de corrupción de memoria (OOB, use-after-free, double free, etc.) pueden reaparecer**. Lista rápida de verificación para auditoría:

* Busca bloques `unsafe`, funciones `extern "C"`, llamadas a `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, punteros crudos o módulos `ffi`.
* Valida cada operación aritmética de punteros y cada argumento de longitud pasado a funciones de bajo nivel.
* Prefiere `#![forbid(unsafe_code)]` (a nivel de crate) o `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) para que falle la compilación cuando alguien reintroduzca `unsafe`.

Ejemplo de desbordamiento creado con punteros crudos:
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
Ejecutar Miri es una forma económica de detectar UB durante las pruebas:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditoría de dependencias con RustSec / cargo-audit

La mayoría de las vulns reales de Rust se encuentran en crates de terceros. La base de datos de avisos de RustSec (mantenida por la comunidad) puede consultarse localmente:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integrarlo en CI y hacer que falle con `--deny warnings`.

`cargo deny check advisories` ofrece funcionalidad similar, además de comprobaciones de licencia y listas de bloqueo.

#### Cobertura de código con cargo-tarpaulin

`cargo tarpaulin` es una herramienta para reportar cobertura de código del sistema de construcción Cargo.
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
En Linux, el backend de trazado predeterminado de Tarpaulin sigue siendo Ptrace y solo funciona en procesadores x86_64. Esto se puede cambiar a la instrumentación de cobertura llvm con `--engine llvm`. En Mac y Windows, este es el método de recopilación predeterminado.

#### Verificación de la cadena de suministro con cargo-vet (2024)

`cargo vet` registra un hash de revisión para cada crate que importas y evita actualizaciones no detectadas:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
La herramienta está siendo adoptada por la infraestructura del proyecto Rust y por un número creciente de organizaciones para mitigar poisoned-package attacks.

#### Fuzzing la superficie de tu API (cargo-fuzz)

Fuzz tests capturan fácilmente panics, desbordamientos de enteros y errores lógicos que podrían convertirse en problemas de DoS o side-channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Agrega el fuzz target a tu repo y ejecútalo en tu pipeline.

## Referencias

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
