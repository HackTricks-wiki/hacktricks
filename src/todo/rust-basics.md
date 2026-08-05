# Основи Rust

{{#include ../banners/hacktricks-training.md}}

### Володіння змінними

Пам'ять керується через систему володіння з такими правилами, які компілятор перевіряє під час компіляції:

1. Кожне значення в Rust має змінну, яка називається його власником.
2. Одночасно може бути лише один власник.
3. Коли власник виходить за межі області видимості, значення буде видалено.
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
### Узагальнені типи

Створіть структуру, одне зі значень якої може мати будь-який тип
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

Тип Option означає, що значення може мати тип Some (щось є) або None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Ви можете використовувати такі функції, як `is_some()` або `is_none()`, щоб перевірити значення Option.


### Result, Ok & Err

Використовується для повернення та поширення помилок
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Ви можете використовувати такі функції, як `is_ok()` або `is_err()`, щоб перевірити значення результату

Перерахування `Option` слід використовувати в ситуаціях, коли значення може бути відсутнім (бути `None`).
Перерахування `Result` слід використовувати в ситуаціях, коли ви виконуєте дію, яка може завершитися помилкою


### Макроси

Макроси потужніші за функції, оскільки вони розгортаються та створюють більше коду, ніж той, який ви написали вручну. Наприклад, сигнатура функції має оголошувати кількість і тип параметрів, які має функція. Макроси, натомість, можуть приймати змінну кількість параметрів: ми можемо викликати `println!("hello")` з одним аргументом або `println!("hello {}", name)` із двома аргументами. Крім того, макроси розгортаються до того, як компілятор інтерпретує значення коду, тому макрос може, наприклад, реалізувати trait для певного типу. Функція не може цього зробити, оскільки вона викликається під час виконання, а trait має бути реалізований під час компіляції.
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
### Ітерація
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
### Рекурсивна скринька
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Умовні оператори

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
#### цикл (нескінченний)
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
#### для
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

Створіть новий метод для типу
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
### Тести
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

Arc може використовувати Clone для створення додаткових посилань на об'єкт, щоб передати їх потокам. Коли останній вказівник-посилання на значення виходить за межі області видимості, змінна видаляється.
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

У цьому випадку ми передамо потоку змінну, яку він зможе змінювати
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
### Основи безпеки

Rust за замовчуванням забезпечує надійні гарантії memory safety, але ви все одно можете створити критичні вразливості через код `unsafe`, проблеми із залежностями або помилки в логіці. Наведена нижче міні-шпаргалка містить примітиви, з якими ви найчастіше працюватимете під час offensive або defensive security review програмного забезпечення на Rust.

#### Код `unsafe` і memory safety

Блоки `unsafe` вимикають перевірки aliasing і меж з боку компілятора, тому **всі традиційні баги memory corruption (OOB, use-after-free, double free тощо) можуть знову з'явитися**. Короткий checklist для аудиту:

* Шукайте блоки `unsafe`, функції `extern "C"`, виклики `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers або модулі `ffi`.
* Перевіряйте кожну pointer arithmetic і кожен аргумент length, переданий до low-level функцій.
* Надавайте перевагу `#![forbid(unsafe_code)]` (для всього crate) або `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +), щоб компіляція завершувалася помилкою, коли хтось повторно додає `unsafe`.

Приклад overflow, створеного за допомогою raw pointers:
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
Запуск Miri — недорогий спосіб виявити UB під час тестування:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Аудит залежностей за допомогою RustSec / cargo-audit

Більшість Rust-вразливостей у реальних проєктах міститься у сторонніх crates. Базу даних advisory RustSec (підтримувану спільнотою) можна запитувати локально:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Інтегруйте це в CI і завершуйте виконання з помилкою за наявності `--deny warnings`.

`cargo deny check advisories` пропонує подібну функціональність, а також перевірки ліцензій і ban-list.

#### Перевірка покриття коду за допомогою cargo-tarpaulin

`cargo tarpaulin` — це інструмент для створення звітів про покриття коду для системи збирання Cargo
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
У Linux типовим backend для tracing у Tarpaulin досі є Ptrace, і він працюватиме лише на процесорах x86_64. Це можна змінити на instrumentation для llvm coverage за допомогою `--engine llvm`. Для Mac і Windows це типовий метод збору.

#### Перевірка supply chain за допомогою cargo-vet (2024)

`cargo vet` зберігає review hash для кожного crate, який ви імпортуєте, і запобігає непомітним оновленням:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Інструмент впроваджується інфраструктурою проєкту Rust і дедалі більшою кількістю orgs для протидії атакам із отруєними пакетами.<sup>[[2]](#references)</sup>

#### Fuzzing вашої поверхні API (cargo-fuzz)

Fuzz-тести легко виявляють panics, integer overflows і logic bugs, які можуть призвести до DoS або проблем side-channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Додайте fuzz target до свого repo та запускайте його у своєму pipeline.

## References

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: Auditing your Rust Dependencies](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
