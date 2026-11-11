# Rust-Grundlagen

{{#include ../banners/hacktricks-training.md}}

### Besitz von Variablen

Der Speicher wird über ein Besitzsystem mit den folgenden Regeln verwaltet, die der Compiler zur Kompilierzeit überprüft:

1. Jeder Wert in Rust hat eine Variable, die als Besitzer bezeichnet wird.
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

Erstelle eine Struct, bei der einer ihrer Werte einen beliebigen Typ haben kann.

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

You kannst Funktionen wie `is_some()` oder `is_none()` verwenden, um den Wert von `Option` zu überprüfen.


### Result, Ok & Err

Wird zum Zurückgeben und Weiterleiten von Fehlern verwendet.

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Du kannst Funktionen wie `is_ok()` oder `is_err()` verwenden, um den Wert des Ergebnisses zu prüfen.

Das `Option`-Enum sollte in Situationen verwendet werden, in denen ein Wert möglicherweise nicht existiert (`None` ist).
Das `Result`-Enum sollte in Situationen verwendet werden, in denen du etwas tust, das schiefgehen könnte.

### Makros

Makros sind leistungsfähiger als Funktionen, weil sie erweitert werden und dabei mehr Code erzeugen, als du manuell geschrieben hast. Beispielsweise muss eine Funktionssignatur die Anzahl und den Typ der Parameter angeben, die die Funktion hat. Makros hingegen können eine variable Anzahl von Parametern annehmen: Wir können `println!("hello")` mit einem Argument oder `println!("hello {}", name)` mit zwei Argumenten aufrufen. Außerdem werden Makros erweitert, bevor der Compiler die Bedeutung des Codes interpretiert. Ein Makro kann beispielsweise ein Trait für einen bestimmten Typ implementieren. Eine Funktion kann das nicht, weil sie zur Laufzeit aufgerufen wird und ein Trait zur Compile-Zeit implementiert werden muss.

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

### Iterieren

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

Ein rekursives Enum benötigt Indirektion, damit seine Größe zur Compile-Zeit bekannt ist; `List` direkt innerhalb von `List` zu speichern, lässt sich nicht kompilieren.<sup>[[10]](#references)</sup>

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

### Bedingungen

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

`Some` abgleichen, um seinen inneren Wert zu binden; ein einfaches Variablenmuster passt sowohl auf `Some` als auch auf `None`, sodass der `else`-Zweig nie ausgeführt würde.<sup>[[11]](#references)</sup>

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

### Traits

Erstelle eine neue Methode für einen Typ

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


### Sicherheitsgrundlagen

Rust bietet standardmäßig starke Garantien für Speichersicherheit, aber durch `unsafe`-Code, Abhängigkeitsprobleme oder Logikfehler können weiterhin kritische Sicherheitslücken entstehen. Dieses kurze Cheat-Sheet fasst die Grundbausteine zusammen, mit denen Sie bei offensiven oder defensiven Sicherheitsprüfungen von Rust-Software am häufigsten zu tun haben. Weitere sprachspezifische Tools finden Sie unter [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Unsicherer Code & Speichersicherheit

`unsafe` erlaubt Operationen, deren Sicherheitsbedingungen der Compiler nicht nachweisen kann; gewöhnliche Borrow- und Bounds-Prüfungen werden dadurch **nicht** deaktiviert. Speicherbeschädigung wird möglich, wenn eine unsichere Operation ihre Bedingungen verletzt, auch innerhalb einer Funktion, die als sichere API bereitgestellt wird.<sup>[[3]](#references)</sup>

Suchen Sie bei einer Quellcodeprüfung nach nicht geprüften Operationen und verfolgen Sie vom Aufrufer aus, ob Angreifer Zeiger und Längen kontrollieren können:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Beweise bei `slice::from_raw_parts`, dass der Pointer nicht null und korrekt ausgerichtet ist, der **gesamte** initialisierte Bereich innerhalb einer einzelnen lebenden Allokation liegt und der zurückgegebene Slice nicht länger lebt als diese Allokation. Selbst ein Slice der Länge null darf keinen Null-Pointer verwenden.
* Beweise bei `Vec::set_len`, dass die neue Länge in die tatsächliche Kapazität passt und jedes neu zugängliche Element initialisiert wurde. Verfolge sowohl die Größe der Allokation als auch die Anzahl der Kopien; `with_capacity` initialisiert keine Elemente.
* Prüfe jedes `unsafe impl` von `Send` oder `Sync` sowie jede FFI-Signatur anhand der Invarianten, die sicheren Aufrufern garantiert werden. `#![forbid(unsafe_code)]` weist unsafe Code in einer Crate zurück; `#![deny(unsafe_op_in_unsafe_fn)]` verlangt stattdessen explizite unsafe-Blöcke **innerhalb** unsafe-Funktionen und verbietet unsafe Code nicht. Das letztere Lint warnt in Rust 2024 standardmäßig.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Beispiel für einen durch Raw Pointer verursachten Überlauf:
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
Eine Eingabe, die länger als `dst.capacity()` ist, verletzt im obigen Beispiel sowohl die Kopiergrenze als auch den Vertrag von `set_len`. Füge einen Test mit einer übergroßen Eingabe für den Ziel-Allocator hinzu und führe ihn unter Miri aus. Miri prüft ausgeführte Pfade auf undefiniertes Verhalten, aber nicht unterstützte Fremdaufrufe können verhindern, dass Miri eine FFI-Grenze durchläuft.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Abhängigkeiten mit RustSec / cargo-audit prüfen

Die meisten Rust-Schwachstellen in der Praxis stecken in Crates von Drittanbietern. Die RustSec-Advisory-Datenbank (von der Community betrieben) lässt sich lokal abfragen:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integriere es in CI und lasse den Build bei `--deny warnings` fehlschlagen.

`cargo deny check advisories` bietet ähnliche Funktionen sowie Prüfungen von Lizenzen und Sperrlisten.

#### Codeabdeckung mit cargo-tarpaulin

`cargo tarpaulin` ist ein Tool zur Berichterstattung über die Codeabdeckung für das Cargo-Buildsystem

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Unter Linux ist Tarpaulins standardmäßiges Tracing-Backend weiterhin Ptrace und funktioniert nur auf x86_64-Prozessoren. Dies lässt sich mit `--engine llvm` auf die llvm-Coverage-Instrumentierung umstellen. Für Mac und Windows ist dies die standardmäßige Methode zur Erfassung.

#### Supply-chain-Verifizierung mit cargo-vet

`cargo vet` prüft Abhängigkeiten anhand konfigurierter Audit-Kriterien mithilfe lokaler Audits, vertrauenswürdiger Imports oder expliziter Ausnahmen. `cargo vet init` erstellt Metadaten unter `supply-chain/` und nimmt bestehende, nicht auditierte Abhängigkeiten von der Prüfung aus. Eine anfangs erfolgreiche Prüfung bedeutet daher **nicht**, dass jedes Crate überprüft wurde. Prüfe die Ausnahmen und arbeite sie mit `cargo vet suggest` ab; `--locked` verhindert, dass importierte Audit-Sets aktualisiert werden.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing deiner API-Oberfläche (cargo-fuzz)

Fuzz-Targets testen die API mit generierten Eingaben und können Panics und Fehler bei der Speichersicherheit aufdecken. Das generierte Target befindet sich unter `fuzz/fuzz_targets/`; ersetze seinen Standardinhalt durch einen Aufruf der zu prüfenden API, bevor du es ausführst.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Füge das Fuzz-Ziel zu deinem Repository hinzu und führe es in deiner Pipeline aus.



## References

- [1] [RustSec-Hinweisdatenbank](https://rustsec.org)
- [2] [Cargo-vet: „Prüfen deiner Rust-Abhängigkeiten“](https://mozilla.github.io/cargo-vet/)
- [3] [Die Programmiersprache Rust: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: Warnung zu unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet-Befehle](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: cargo-fuzz-Tutorial](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Die Programmiersprache Rust: Box und rekursive Typen](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Die Programmiersprache Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: Unsafe-extern-Blöcke](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
