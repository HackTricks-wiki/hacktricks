# Rust-Grundlagen

{{#include ../banners/hacktricks-training.md}}

### Besitz von Variablen

Der Speicher wird mithilfe eines Besitzsystems verwaltet, für das die folgenden Regeln gelten und die der Compiler zur Compile-Zeit überprüft:

1. Jeder Wert in Rust hat eine Variable, die als sein Besitzer bezeichnet wird.
2. Es kann jeweils nur einen Besitzer geben.
3. Wenn der Besitzer den Gültigkeitsbereich verlässt, wird der Wert verworfen.

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



### Generische Typen

Erstelle eine Struktur, bei der einer ihrer Werte einen beliebigen Typ haben kann.

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

Der Option-Typ bedeutet, dass der Wert vom Typ Some (es gibt etwas) oder None sein kann:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Du kannst Funktionen wie `is_some()` oder `is_none()` verwenden, um den Wert von `Option` zu überprüfen.


### Result, Ok & Err

Wird zum Zurückgeben und Weitergeben von Fehlern verwendet

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Du kannst Funktionen wie `is_ok()` oder `is_err()` verwenden, um den Wert des Ergebnisses zu prüfen.

Das Enum `Option` sollte in Situationen verwendet werden, in denen ein Wert möglicherweise nicht existiert (`None` ist).
Das Enum `Result` sollte in Situationen verwendet werden, in denen du etwas tust, das schiefgehen könnte.

### Makros

Makros sind mächtiger als Funktionen, weil sie erweitert werden und so mehr Code erzeugen, als du manuell geschrieben hast. Beispielsweise muss eine Funktionssignatur die Anzahl und den Typ der Parameter deklarieren, die die Funktion hat. Makros hingegen können eine variable Anzahl von Parametern annehmen: Wir können `println!("hello")` mit einem Argument oder `println!("hello {}", name)` mit zwei Argumenten aufrufen. Außerdem werden Makros erweitert, bevor der Compiler die Bedeutung des Codes interpretiert. Ein Makro kann beispielsweise ein Trait für einen bestimmten Typ implementieren. Eine Funktion kann das nicht, weil sie zur Laufzeit aufgerufen wird und ein Trait zur Kompilierzeit implementiert werden muss.

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

### Iteration

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

### Rekursive Box

```rust
enum List {
    Cons(i32, List),
    Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```

### Bedingte Anweisungen

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

#### loop (unendlich)

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

Eine neue Methode für einen Typ erstellen

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

### Threading

#### Arc

Ein Arc kann Clone verwenden, um weitere Referenzen auf das Objekt zu erstellen und sie an die Threads weiterzugeben. Wenn der letzte Referenzzeiger auf einen Wert nicht mehr im Gültigkeitsbereich ist, wird die Variable verworfen.

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

In diesem Fall übergeben wir dem Thread eine Variable, die er ändern kann.

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


### Security Essentials

Rust bietet standardmäßig starke Garantien für Speichersicherheit, aber durch `unsafe`-Code, Probleme mit Abhängigkeiten oder Logikfehler können weiterhin kritische Schwachstellen entstehen. Das folgende Mini-Cheatsheet fasst die Primitiven zusammen, mit denen Sie bei offensiven oder defensiven Security-Reviews von Rust-Software am häufigsten zu tun haben.

#### Unsafe-Code & Speichersicherheit

`unsafe`-Blöcke umgehen die Aliasing- und Bounds-Checks des Compilers, sodass **alle klassischen Speicherbeschädigungsfehler (OOB, use-after-free, double free usw.) wieder auftreten können**. Eine kurze Audit-Checkliste:

* Achten Sie auf `unsafe`-Blöcke, `extern "C"`-Funktionen, Aufrufe von `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, Raw Pointers oder `ffi`-Module.
* Überprüfen Sie jede Pointer-Arithmetik und jedes Längenargument, das an Low-Level-Funktionen übergeben wird.
* Verwenden Sie vorzugsweise `#![forbid(unsafe_code)]` (crate-weit) oder `#[deny(unsafe_op_in_unsafe_fn)]` (ab 1.68), damit die Kompilierung fehlschlägt, wenn jemand erneut `unsafe` einführt.

Beispiel für einen mit Raw Pointers verursachten Overflow:
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
Miri auszuführen ist eine kostengünstige Möglichkeit, UB beim Testen zu erkennen:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```

#### Auditing von Dependencies mit RustSec / cargo-audit

Die meisten Rust-Schwachstellen in der Praxis stecken in Crates von Drittanbietern. Die RustSec Advisory DB (von der Community betrieben) lässt sich lokal abfragen:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integriere es in CI und lasse den Build bei `--deny warnings` fehlschlagen.

`cargo deny check advisories` bietet ähnliche Funktionen sowie Prüfungen von Lizenzen und Sperrlisten.

#### Code coverage mit cargo-tarpaulin

`cargo tarpaulin` ist ein Tool zur Berichterstellung über die Codeabdeckung für das Cargo-Buildsystem.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Unter Linux ist Tarpaulins standardmäßiges Tracing-Backend weiterhin Ptrace und funktioniert nur auf x86_64-Prozessoren. Mit `--engine llvm` lässt es sich auf die LLVM-Coverage-Instrumentierung umstellen. Auf Mac und Windows ist dies die standardmäßige Methode zur Erfassung.

#### Verifizierung der Lieferkette mit cargo-vet (2024)

`cargo vet` speichert für jedes importierte Crate einen Review-Hash und verhindert unbemerkte Upgrades:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Das Tool wird von der Rust-Projektinfrastruktur und einer wachsenden Zahl von Organisationen eingeführt, um Angriffe mit vergifteten Paketen einzudämmen.<sup>[[2]](#references)</sup>

#### Fuzzing deiner API-Oberfläche (cargo-fuzz)

Fuzz-Tests erkennen leicht Panics, Integer-Überläufe und Logikfehler, die zu DoS- oder Side-Channel-Problemen führen könnten:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Füge das Fuzz-Target zu deinem Repo hinzu und führe es in deiner Pipeline aus.

## References

- [1] [RustSec-Hinweisdatenbank](https://rustsec.org)
- [2] [Cargo-vet: „Prüfung deiner Rust-Abhängigkeiten“](https://mozilla.github.io/cargo-vet/)
{{#include ../banners/hacktricks-training.md}}
