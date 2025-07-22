# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### Generic Types

Створіть структуру, де 1 з їх значень може бути будь-яким типом
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

Тип Option означає, що значення може бути типу Some (є щось) або None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Ви можете використовувати функції, такі як `is_some()` або `is_none()`, щоб перевірити значення Option.

### Макроси

Макроси є більш потужними, ніж функції, оскільки вони розширюються, щоб створити більше коду, ніж код, який ви написали вручну. Наприклад, підпис функції повинен оголошувати кількість і тип параметрів, які має функція. Макроси, з іншого боку, можуть приймати змінну кількість параметрів: ми можемо викликати `println!("hello")` з одним аргументом або `println!("hello {}", name)` з двома аргументами. Крім того, макроси розширюються до того, як компілятор інтерпретує значення коду, тому макрос може, наприклад, реалізувати трей на даному типі. Функція не може, оскільки вона викликається під час виконання, а трей потрібно реалізувати під час компіляції.
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
### Рекурсивна коробка
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Умови

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
#### відповідність
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
#### поки
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
### Риси

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
### Потоки

#### Arc

Arc може використовувати Clone для створення додаткових посилань на об'єкт, щоб передати їх потокам. Коли останній вказівник на значення виходить за межі області видимості, змінна видаляється.
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

У цьому випадку ми передамо потоку змінну, яку він зможе змінювати.
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

Rust забезпечує сильні гарантії безпеки пам'яті за замовчуванням, але ви все ще можете ввести критичні вразливості через `unsafe` код, проблеми з залежностями або логічні помилки. Наступний міні-чернетка збирає примітиви, з якими ви найчастіше стикатиметеся під час наступальних або захисних перевірок безпеки програмного забезпечення Rust.

#### Небезпечний код та безпека пам'яті

`unsafe` блоки відмовляються від перевірок аліасів та меж компілятора, тому **всі традиційні помилки корупції пам'яті (OOB, використання після звільнення, подвійне звільнення тощо) можуть знову з'явитися**. Швидкий контрольний список для аудиту:

* Шукайте `unsafe` блоки, `extern "C"` функції, виклики до `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, сирі вказівники або `ffi` модулі.
* Перевіряйте кожну арифметику вказівників та аргументи довжини, передані низькорівневим функціям.
* Вибирайте `#![forbid(unsafe_code)]` (по всьому крейту) або `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +), щоб зупинити компіляцію, коли хтось знову вводить `unsafe`.

Приклад переповнення, створеного за допомогою сирих вказівників:
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
Запуск Miri є недорогим способом виявлення UB під час тестування:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Аудит залежностей з RustSec / cargo-audit

Більшість вразливостей Rust у реальному світі знаходяться в сторонніх пакетах. Базу даних рекомендацій RustSec (яка підтримується спільнотою) можна запитувати локально:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Інтегруйте це в CI і провалюйте на `--deny warnings`.

`cargo deny check advisories` пропонує подібну функціональність плюс перевірки ліцензій та заборонених списків.

#### Перевірка постачальницького ланцюга з cargo-vet (2024)

`cargo vet` записує хеш огляду для кожного пакету, який ви імпортуєте, і запобігає непоміченим оновленням:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Інструмент приймається інфраструктурою проекту Rust та зростаючою кількістю організацій для пом'якшення атак з отруєними пакетами.

#### Fuzzing вашої API поверхні (cargo-fuzz)

Fuzz-тести легко виявляють паніки, переповнення цілих чисел та логічні помилки, які можуть стати проблемами DoS або побічного каналу:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Додайте ціль для фуззингу до вашого репозиторію та запустіть її у вашому конвеєрі.

## Посилання

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Аудит ваших залежностей Rust" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
