# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### Tipos Genéricos

Crie uma struct onde 1 de seus valores pode ser de qualquer tipo
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

O tipo Option significa que o valor pode ser do tipo Some (há algo) ou None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Você pode usar funções como `is_some()` ou `is_none()` para verificar o valor da Option.

### Macros

Macros são mais poderosas do que funções porque se expandem para produzir mais código do que o código que você escreveu manualmente. Por exemplo, uma assinatura de função deve declarar o número e o tipo de parâmetros que a função possui. Macros, por outro lado, podem aceitar um número variável de parâmetros: podemos chamar `println!("hello")` com um argumento ou `println!("hello {}", name)` com dois argumentos. Além disso, as macros são expandidas antes que o compilador interprete o significado do código, então uma macro pode, por exemplo, implementar um trait em um determinado tipo. Uma função não pode, porque é chamada em tempo de execução e um trait precisa ser implementado em tempo de compilação.
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
### Caixa Recursiva
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Condicionais

#### se
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
#### correspondência
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
#### enquanto
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
#### para
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
#### se deixar
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### enquanto deixar
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

Crie um novo método para um tipo
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
### Testes
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

Um Arc pode usar Clone para criar mais referências sobre o objeto para passá-las para as threads. Quando o último ponteiro de referência a um valor sai do escopo, a variável é descartada.
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

Neste caso, passaremos ao thread uma variável que ele poderá modificar.
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
### Essentials de Segurança

Rust fornece fortes garantias de segurança de memória por padrão, mas você ainda pode introduzir vulnerabilidades críticas através de código `unsafe`, problemas de dependência ou erros de lógica. O seguinte mini-cheatsheet reúne os primitivos que você mais comumente encontrará durante revisões de segurança ofensivas ou defensivas de software Rust.

#### Código unsafe & segurança de memória

Blocos `unsafe` optam por não seguir as verificações de aliasing e limites do compilador, então **todos os bugs tradicionais de corrupção de memória (OOB, uso após liberação, liberação dupla, etc.) podem reaparecer**. Uma lista de verificação rápida de auditoria:

* Procure por blocos `unsafe`, funções `extern "C"`, chamadas para `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, ponteiros brutos ou módulos `ffi`.
* Valide toda aritmética de ponteiros e argumentos de comprimento passados para funções de baixo nível.
* Prefira `#![forbid(unsafe_code)]` (em todo o crate) ou `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) para falhar na compilação quando alguém reintroduzir `unsafe`.

Exemplo de estouro criado com ponteiros brutos:
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
Executar Miri é uma maneira econômica de detectar UB durante o tempo de teste:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditoria de dependências com RustSec / cargo-audit

A maioria das vulnerabilidades Rust do mundo real reside em crates de terceiros. O banco de dados de avisos do RustSec (movido pela comunidade) pode ser consultado localmente:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integre isso no CI e falhe em `--deny warnings`.

`cargo deny check advisories` oferece funcionalidade semelhante, além de verificações de licença e lista de proibição.

#### Verificação da cadeia de suprimentos com cargo-vet (2024)

`cargo vet` registra um hash de revisão para cada crate que você importa e impede atualizações não percebidas:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
A ferramenta está sendo adotada pela infraestrutura do projeto Rust e um número crescente de organizações para mitigar ataques de pacotes envenenados.

#### Fuzzing sua superfície de API (cargo-fuzz)

Testes de fuzz facilmente capturam panics, estouros de inteiros e bugs de lógica que podem se tornar problemas de DoS ou de canal lateral:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Adicione o alvo de fuzz ao seu repositório e execute-o em seu pipeline.

## Referências

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
