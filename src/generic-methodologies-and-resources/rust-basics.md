# Nozioni di base di Rust

{{#include ../banners/hacktricks-training.md}}

### Ownership delle variabili

La memoria è gestita tramite un sistema di ownership con le seguenti regole, che il compilatore verifica in fase di compilazione:

1. Ogni valore in Rust ha una variabile chiamata owner.
2. Può esserci un solo owner alla volta.
3. Quando l'owner esce dall'ambito, il valore viene eliminato.

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

Crea una struct in cui uno dei valori può essere di qualsiasi tipo

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

Il tipo Option indica che il valore può essere di tipo Some (è presente qualcosa) oppure None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Puoi usare funzioni come `is_some()` o `is_none()` per controllare il valore di `Option`.


### Result, Ok & Err

Usati per restituire e propagare gli errori

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Puoi usare funzioni come `is_ok()` o `is_err()` per controllare il valore del risultato

L'enum `Option` dovrebbe essere usato nei casi in cui un valore potrebbe non esistere (essere `None`).
L'enum `Result` dovrebbe essere usato nei casi in cui fai qualcosa che potrebbe non riuscire


### Macro

Le macro sono più potenti delle funzioni perché si espandono generando più codice di quello che hai scritto manualmente. Per esempio, la firma di una funzione deve dichiarare il numero e il tipo dei parametri che accetta. Le macro, invece, possono accettare un numero variabile di parametri: possiamo chiamare `println!("hello")` con un argomento oppure `println!("hello {}", name)` con due argomenti. Inoltre, le macro vengono espanse prima che il compilatore interpreti il significato del codice, quindi una macro può, per esempio, implementare un trait per un determinato tipo. Una funzione non può farlo, perché viene chiamata a runtime e un trait deve essere implementato a compile time.

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

### Recursive Box

Un enum ricorsivo ha bisogno di indirezione affinché la sua dimensione sia nota in fase di compilazione; memorizzare `List` direttamente all'interno di `List` non compila.<sup>[[10]](#references)</sup>

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

Fai il match su `Some` per associare il valore interno; un pattern con una variabile semplice corrisponde sia a `Some` sia a `None`, quindi il ramo `else` non verrebbe mai eseguito.<sup>[[11]](#references)</sup>

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

Un Arc può usare Clone per creare altri riferimenti all'oggetto e passarli ai thread. Quando l'ultimo puntatore di riferimento a un valore esce dall'ambito, la variabile viene eliminata.

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

#### Thread

In questo caso passeremo al thread una variabile che potrà modificare.

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


### Nozioni essenziali di sicurezza

Rust offre solide garanzie di sicurezza della memoria per impostazione predefinita, ma è comunque possibile introdurre vulnerabilità critiche con codice `unsafe`, problemi nelle dipendenze o errori logici. Il seguente mini-cheatsheet raccoglie le primitive che userai più spesso durante le revisioni di sicurezza offensive o difensive del software Rust. Per altri strumenti specifici per linguaggio, consulta [Strumenti per la revisione del codice](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Codice unsafe e sicurezza della memoria

`unsafe` consente operazioni i cui requisiti di sicurezza il compilatore non può verificare; **non** disattiva i normali controlli di borrow o dei limiti. La corruzione della memoria può verificarsi quando un'operazione unsafe viola i propri requisiti, anche all'interno di una funzione esposta tramite un'API safe.<sup>[[3]](#references)</sup>

Durante la revisione del codice sorgente, individua le operazioni non verificate e segui i puntatori e le lunghezze controllati dall'attaccante a partire dai relativi chiamanti pubblici:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Per `slice::from_raw_parts`, dimostra che il puntatore non è nullo ed è allineato, che **l’intero** intervallo inizializzato si trova in un’unica allocazione attiva e che la slice restituita non può sopravvivere a essa. Anche una slice di lunghezza zero non può usare un puntatore nullo.
* Per `Vec::set_len`, dimostra che la nuova lunghezza rientra nella capacità effettiva e che ogni elemento appena esposto è stato inizializzato. Traccia sia la dimensione dell’allocazione sia il numero di elementi copiati; `with_capacity` non inizializza gli elementi.
* Verifica ogni `unsafe impl` di `Send` o `Sync` e ogni firma FFI rispetto agli invarianti promessi ai chiamanti safe. `#![forbid(unsafe_code)]` rifiuta il codice unsafe in un crate; `#![deny(unsafe_op_in_unsafe_fn)]` richiede invece blocchi unsafe espliciti **all’interno** delle funzioni unsafe, ma non vieta il codice unsafe. Quest’ultimo lint emette un avviso per impostazione predefinita in Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Esempio di overflow creato con puntatori raw:
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
Un input più lungo di `dst.capacity()` viola sia il limite di copia sia il contratto di `set_len` nell’esempio sopra. Aggiungi un test con un input sovradimensionato per l’allocator target, quindi eseguilo con Miri. Miri verifica i percorsi eseguiti alla ricerca di comportamento indefinito, ma le chiamate esterne non supportate potrebbero impedirgli di attraversare un confine FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Verifica delle dipendenze con RustSec / cargo-audit

La maggior parte delle vulnerabilità Rust nel mondo reale si trova in crate di terze parti. È possibile consultare localmente il database degli advisory RustSec (gestito dalla community):<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integralo nella CI e fai fallire la build con `--deny warnings`.

`cargo deny check advisories` offre funzionalità simili, oltre ai controlli delle licenze e delle ban-list.

#### Copertura del codice con cargo-tarpaulin

`cargo tarpaulin` è uno strumento per generare report sulla copertura del codice per il sistema di build Cargo

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Su Linux, il backend di tracing predefinito di Tarpaulin è ancora Ptrace e funziona solo sui processori x86_64. È possibile passare alla strumentazione di coverage di llvm con `--engine llvm`. Su Mac e Windows, questo è il metodo di raccolta predefinito.

#### Verifica della supply chain con cargo-vet

`cargo vet` verifica le dipendenze in base ai criteri di audit configurati, usando audit locali, importazioni attendibili o esenzioni esplicite. `cargo vet init` crea i metadati in `supply-chain/` ed esenta le dipendenze esistenti non sottoposte ad audit; quindi, un controllo inizialmente superato **non** significa che ogni crate sia stato esaminato. Esamina le esenzioni e usa `cargo vet suggest` per valutarle; `--locked` evita di aggiornare gli insiemi di audit importati.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing della superficie API (cargo-fuzz)

I target di fuzzing esercitano l’API con input generati e possono rilevare panic e problemi di memory safety. Il target generato si trova in `fuzz/fuzz_targets/`; sostituisci il suo corpo predefinito con una chiamata all’API in esame prima di eseguirlo.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Aggiungi il target fuzz al tuo repository ed eseguilo nella pipeline.



## References

- [1] [Database degli avvisi RustSec](https://rustsec.org)
- [2] [Cargo-vet: "Verifica delle dipendenze Rust"](https://mozilla.github.io/cargo-vet/)
- [3] [Il linguaggio di programmazione Rust: Rust non sicuro](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README di Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: avviso unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Comandi di Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Manuale di Rust Fuzz: tutorial di cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Il linguaggio di programmazione Rust: Box e tipi ricorsivi](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Il linguaggio di programmazione Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: blocchi extern non sicuri](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
