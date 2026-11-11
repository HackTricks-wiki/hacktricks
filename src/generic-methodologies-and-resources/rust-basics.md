# Podstawy Rust

{{#include ../banners/hacktricks-training.md}}

### Własność zmiennych

Pamięcią zarządza system własności, którego reguły kompilator sprawdza podczas kompilacji:

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

Utwórz strukturę, której jedna z wartości może mieć dowolny typ.

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

### Option, Some i None

Typ Option oznacza, że wartość może mieć typ Some (coś istnieje) albo None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Możesz użyć funkcji takich jak `is_some()` lub `is_none()`, aby sprawdzić wartość `Option`.


### Result, Ok & Err

Używane do zwracania i propagowania błędów

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Możesz używać funkcji takich jak `is_ok()` lub `is_err()`, aby sprawdzić wartość wyniku.

Enum `Option` powinien być używany w sytuacjach, gdy wartość może nie istnieć (czyli być `None`).
Enum `Result` powinien być używany w sytuacjach, gdy wykonujesz coś, co może się nie udać.

### Makra

Makra są potężniejsze niż funkcje, ponieważ rozwijają się, generując więcej kodu niż ten, który napisano ręcznie. Na przykład sygnatura funkcji musi określać liczbę i typ parametrów funkcji. Makra mogą natomiast przyjmować zmienną liczbę parametrów: możemy wywołać `println!("hello")` z jednym argumentem lub `println!("hello {}", name)` z dwoma argumentami. Makra są też rozwijane, zanim kompilator zinterpretuje znaczenie kodu, dlatego makro może na przykład zaimplementować trait dla danego typu. Funkcja nie może tego zrobić, ponieważ jest wywoływana w czasie działania programu, a trait musi zostać zaimplementowany w czasie kompilacji.

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

### Iterowanie

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

### Rekurencyjny Box

Rekurencyjny typ wyliczeniowy wymaga pośredniego odwołania, aby jego rozmiar był znany w czasie kompilacji; bezpośrednie przechowywanie `List` wewnątrz `List` nie kompiluje się.<sup>[[10]](#references)</sup>

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

Dopasuj `Some`, aby przypisać jego wewnętrzną wartość; zwykły wzorzec zmiennej pasuje zarówno do `Some`, jak i `None`, więc gałąź `else` nigdy by się nie wykonała.<sup>[[11]](#references)</sup>

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

### Wątki

#### Arc

Arc może używać Clone do tworzenia kolejnych referencji do obiektu, aby przekazać je wątkom. Gdy ostatni wskaźnik referencyjny do wartości wyjdzie poza zakres, zmienna zostaje usunięta.

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

Rust domyślnie zapewnia silne gwarancje bezpieczeństwa pamięci, ale nadal można wprowadzić krytyczne podatności za pomocą kodu `unsafe`, problemów z zależnościami lub błędów logicznych. Poniższa miniściągawka zawiera elementy, z którymi najczęściej można się zetknąć podczas ofensywnych lub defensywnych przeglądów bezpieczeństwa oprogramowania w Rust. Informacje o narzędziach specyficznych dla innych języków znajdziesz w sekcji [Narzędzia do przeglądu kodu](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Kod unsafe i bezpieczeństwo pamięci

`unsafe` pozwala na operacje, których warunków bezpieczeństwa kompilator nie może udowodnić; **nie** wyłącza zwykłych kontroli pożyczania ani zakresów. Uszkodzenie pamięci staje się możliwe, gdy operacja `unsafe` narusza swoje warunki, również wewnątrz funkcji udostępnionej jako bezpieczne API.<sup>[[3]](#references)</sup>

Podczas przeglądu kodu znajdź operacje bez kontroli i prześledź wskaźniki oraz długości kontrolowane przez atakującego aż do ich publicznych wywołujących:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* W przypadku `slice::from_raw_parts` udowodnij, że wskaźnik nie jest pusty i jest odpowiednio wyrównany, cały **zakres** zainicjalizowanych danych znajduje się w jednej aktywnej alokacji, a zwrócony wycinek nie może istnieć dłużej niż ta alokacja. Nawet wycinek o zerowej długości nie może używać pustego wskaźnika.
* W przypadku `Vec::set_len` udowodnij, że nowa długość mieści się w rzeczywistej pojemności, a każdy nowo udostępniony element został zainicjalizowany. Prześledź zarówno rozmiar alokacji, jak i liczbę kopiowanych elementów; `with_capacity` nie inicjalizuje elementów.
* Sprawdź każdą implementację `unsafe impl` dla `Send` lub `Sync` oraz każdą sygnaturę FFI pod kątem niezmienników gwarantowanych bezpiecznym wywołującym. `#![forbid(unsafe_code)]` odrzuca kod `unsafe` w crate; `#![deny(unsafe_op_in_unsafe_fn)]` wymaga natomiast jawnych bloków `unsafe` **wewnątrz** funkcji `unsafe`, ale nie zakazuje kodu `unsafe`. W Rust 2024 to ostatnie lintowanie domyślnie zgłasza ostrzeżenia.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Przykład przepełnienia utworzonego za pomocą surowych wskaźników:
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
Wejście dłuższe niż `dst.capacity()` narusza zarówno limit kopiowania, jak i kontrakt `set_len` w powyższym przykładzie. Dodaj test z wejściem przekraczającym dozwolony rozmiar dla docelowego alokatora, a następnie uruchom go pod Miri. Miri sprawdza wykonane ścieżki pod kątem niezdefiniowanego zachowania, ale nieobsługiwane wywołania obce mogą uniemożliwić mu przetestowanie granicy FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Audytowanie zależności za pomocą RustSec / cargo-audit

Większość podatności w Rust występujących w rzeczywistych systemach znajduje się w zewnętrznych crate’ach. Bazę porad RustSec (wspieraną przez społeczność) można przeszukiwać lokalnie:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Zintegruj to z CI i kończ niepowodzeniem przy `--deny warnings`.

`cargo deny check advisories` oferuje podobne funkcje, a także sprawdzanie licencji i listy zakazanych elementów.

#### Pokrycie kodu za pomocą cargo-tarpaulin

`cargo tarpaulin` to narzędzie do raportowania pokrycia kodu dla systemu budowania Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
W systemie Linux domyślnym backendem śledzenia Tarpaulin nadal jest Ptrace i działa on tylko na procesorach x86_64. Można go zmienić na instrumentację pokrycia kodu llvm za pomocą `--engine llvm`. Na Macu i Windowsie jest to domyślna metoda zbierania danych.

#### Weryfikacja łańcucha dostaw za pomocą cargo-vet

`cargo vet` sprawdza zależności pod kątem skonfigurowanych kryteriów audytu, korzystając z lokalnych audytów, zaufanych importów lub jawnych wyjątków. `cargo vet init` tworzy metadane w `supply-chain/` i wyłącza z audytu istniejące, nieaudytowane zależności, więc początkowo pomyślny wynik sprawdzenia **nie** oznacza, że każdy crate został sprawdzony. Przejrzyj wyjątki i użyj `cargo vet suggest`, aby się nimi zająć; `--locked` zapobiega odświeżaniu importowanych zestawów audytów.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing powierzchni API (cargo-fuzz)

Cele fuzzingu testują API za pomocą wygenerowanych danych wejściowych i mogą ujawnić paniki oraz błędy bezpieczeństwa pamięci. Wygenerowany cel znajduje się w `fuzz/fuzz_targets/`; przed uruchomieniem zastąp jego domyślne ciało wywołaniem sprawdzanego API.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Dodaj fuzz target do swojego repozytorium i uruchamiaj go w swoim pipeline.

## References

- [1] [Baza danych zaleceń RustSec](https://rustsec.org)
- [2] [Cargo-vet: „Audytowanie zależności Rust”](https://mozilla.github.io/cargo-vet/)
- [3] [Język programowania Rust: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: ostrzeżenie unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Polecenia Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: samouczek cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Język programowania Rust: Box i typy rekurencyjne](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Język programowania Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: bloki extern unsafe](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
