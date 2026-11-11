# Основи Rust

{{#include ../banners/hacktricks-training.md}}

### Володіння змінними

Керування пам’яттю здійснюється за допомогою системи володіння, правила якої компілятор перевіряє під час компіляції:

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

Створіть структуру, одне з полів якої може мати будь-який тип

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

Використовуються для повернення та поширення помилок

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Ви можете використовувати такі функції, як `is_ok()` або `is_err()`, щоб перевірити значення результату

Перелічення `Option` слід використовувати в ситуаціях, коли значення може бути відсутнім (`None`).
Перелічення `Result` слід використовувати в ситуаціях, коли ви виконуєте дію, яка може завершитися помилкою


### Макроси

Макроси потужніші за функції, оскільки вони розгортаються, утворюючи більше коду, ніж ви написали вручну. Наприклад, сигнатура функції має оголошувати кількість і тип параметрів, які вона приймає. Натомість макроси можуть приймати змінну кількість параметрів: ми можемо викликати `println!("hello")` з одним аргументом або `println!("hello {}", name)` із двома аргументами. Крім того, макроси розгортаються до того, як компілятор інтерпретує значення коду, тому макрос може, наприклад, реалізувати trait для заданого типу. Функція цього зробити не може, оскільки її викликають під час виконання, а trait потрібно реалізувати під час компіляції.

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

### Рекурсивний Box

Рекурсивному enum потрібна непряма адресація, щоб його розмір був відомий під час компіляції; безпосереднє зберігання `List` усередині `List` не компілюється.<sup>[[10]](#references)</sup>

```rust
enum List {
    Cons(i32, Box<List>),
    Nil,
}

use List::{Cons, Nil};

fn main() {
    let _list = Cons(1, Box::new(Cons(2, Box::new(Cons(3, Box::new(Nil))))));
}
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

#### нескінченний цикл

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

Зіставте `Some`, щоб прив’язати його внутрішнє значення; звичайний шаблон змінної відповідає і `Some`, і `None`, тому гілка `else` ніколи не виконається.<sup>[[11]](#references)</sup>

```rust
let optional_word = Some(String::from("rustlings"));
if let Some(word) = optional_word {
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

### Трейти

Створення нового методу для типу

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

### Потоковість

#### Arc

Arc може використовувати Clone для створення додаткових посилань на об’єкт, щоб передавати їх потокам. Коли останній вказівник-посилання на значення виходить за межі області видимості, змінна видаляється.

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

#### Потоки

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

Rust за замовчуванням забезпечує надійні гарантії безпеки пам’яті, але критичні вразливості все ще можуть виникнути через код `unsafe`, проблеми із залежностями або помилки в логіці. У цій короткій шпаргалці зібрано примітиви, з якими ви найчастіше матимете справу під час offensive або defensive перевірок безпеки програмного забезпечення на Rust. Інструменти для роботи з іншими мовами див. у розділі [Інструменти для code review](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Код unsafe та безпека пам’яті

`unsafe` дозволяє виконувати операції, контракти безпеки яких компілятор не може довести; він **не** вимикає звичайні перевірки borrow або меж масивів. Пошкодження пам’яті стає можливим, коли операція unsafe порушує свій контракт, зокрема всередині функції, доступної через безпечний API.<sup>[[3]](#references)</sup>

Під час перевірки вихідного коду знайдіть операції без перевірок і простежте, як вказівники та довжини, контрольовані атакувальником, надходять від публічних викликів:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Для `slice::from_raw_parts` доведіть, що вказівник не є нульовим і вирівняний, **увесь** ініціалізований діапазон належить одній чинній алокації, а повернений зріз не може пережити її. Навіть зріз нульової довжини не може використовувати нульовий вказівник.
* Для `Vec::set_len` доведіть, що нова довжина не перевищує фактичну місткість і що кожен новий доступний елемент був ініціалізований. Відстежуйте і розмір алокації, і кількість копій; `with_capacity` не ініціалізує елементи.
* Перевірте кожен `unsafe impl` для `Send` або `Sync` та кожен підпис FFI на відповідність інваріантам, які гарантуються безпечним викликачам. `#![forbid(unsafe_code)]` забороняє небезпечний код у крейті; натомість `#![deny(unsafe_op_in_unsafe_fn)]` вимагає явних unsafe-блоків **усередині** небезпечних функцій, а не забороняє небезпечний код. У Rust 2024 цей lint попереджає за замовчуванням.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

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
Вхідні дані, довші за `dst.capacity()`, порушують і межу копіювання, і контракт `set_len` у наведеному вище прикладі. Додайте тест із завеликими вхідними даними для цільового алокатора, а потім запустіть його під Miri. Miri перевіряє виконані шляхи на невизначену поведінку, але непідтримувані зовнішні виклики можуть завадити їй перевірити межу FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Аудит залежностей за допомогою RustSec / cargo-audit

Більшість реальних уразливостей Rust міститься у сторонніх crates. До бази рекомендацій RustSec (підтримується спільнотою) можна звертатися локально:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Інтегруйте його в CI і завершуйте збірку з помилкою за `--deny warnings`.

`cargo deny check advisories` пропонує подібну функціональність, а також перевірки ліцензій і списку заборон.

#### Перевірка покриття коду за допомогою cargo-tarpaulin

`cargo tarpaulin` — це інструмент для звітування про покриття коду в системі збірки Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
У Linux типовим backend трасування Tarpaulin досі є Ptrace, який працює лише на процесорах x86_64. Його можна змінити на інструментування покриття llvm за допомогою `--engine llvm`. Для Mac і Windows це типовий метод збору даних.

#### Перевірка ланцюга постачання за допомогою cargo-vet

`cargo vet` перевіряє залежності на відповідність налаштованим критеріям аудиту за допомогою локальних аудитів, довірених імпортів або явних винятків. `cargo vet init` створює метадані в `supply-chain/` і додає винятки для наявних неаудованих залежностей, тож успішна початкова перевірка **не** означає, що кожен crate було перевірено. Перегляньте винятки й скористайтеся `cargo vet suggest`, щоб опрацювати їх; `--locked` запобігає оновленню імпортованих наборів аудитів.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Фаззинг поверхні API (cargo-fuzz)

Fuzz-цілі перевіряють API за допомогою згенерованих вхідних даних і можуть виявити паніки та помилки безпеки пам’яті. Згенерована ціль міститься в `fuzz/fuzz_targets/`; перед запуском замініть її стандартне тіло на виклик API, що перевіряється.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Додайте fuzz target до свого репозиторію та запускайте його у своєму pipeline.



## References

- [1] [База даних рекомендацій RustSec](https://rustsec.org)
- [2] [Cargo-vet: «Аудит залежностей Rust»](https://mozilla.github.io/cargo-vet/)
- [3] [Мова програмування Rust: небезпечний Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: попередження unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Команди Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Книга Rust Fuzz: посібник з cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Мова програмування Rust: Box і рекурсивні типи](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Мова програмування Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: блоки unsafe extern](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
