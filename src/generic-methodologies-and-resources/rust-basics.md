# Rust-basiese beginsels

{{#include ../banners/hacktricks-training.md}}

### Eienaarskap van veranderlikes

Geheue word bestuur deur ’n stelsel van eienaarskap met die volgende reëls, wat die compiler tydens kompilering nagaan:

1. Elke waarde in Rust het ’n veranderlike wat sy eienaar genoem word.
2. Daar kan net een eienaar op ’n slag wees.
3. Wanneer die eienaar buite bereik val, word die waarde laat vaar.

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



### Generiese tipes

Skep ’n struct waarvan een van die waardes enige tipe kan wees.

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

Die Option-tipe beteken dat die waarde óf van die tipe Some (daar is iets) óf None kan wees:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Jy kan funksies soos `is_some()` of `is_none()` gebruik om die waarde van die Option na te gaan.


### Result, Ok & Err

Word gebruik om foute terug te gee en voort te plant

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Jy kan funksies soos `is_ok()` of `is_err()` gebruik om die waarde van die resultaat na te gaan.

Die `Option`-enum moet gebruik word in situasies waar ’n waarde dalk nie bestaan nie (dus `None` is).
Die `Result`-enum moet gebruik word in situasies waar iets wat jy doen dalk verkeerd kan loop.


### Makro's

Makro's is kragtiger as funksies omdat hulle uitbrei om meer kode te produseer as die kode wat jy handmatig geskryf het. Byvoorbeeld, ’n funksiehandtekening moet die aantal en tipe parameters wat die funksie het, verklaar. Makro's kan daarenteen ’n veranderlike aantal parameters aanvaar: ons kan `println!("hello")` met een argument aanroep of `println!("hello {}", name)` met twee argumente. Makro's word ook uitgebrei voordat die samesteller die betekenis van die kode interpreteer, sodat ’n makro byvoorbeeld ’n trait vir ’n gegewe tipe kan implementeer. ’n Funksie kan dit nie doen nie, omdat dit tydens looptyd aangeroep word en ’n trait tydens samestellingstyd geïmplementeer moet word.

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

### Itereer

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

### Rekursiewe Box

’n Rekursiewe enum benodig indireksie sodat die grootte daarvan tydens samestelling bekend is; om `List` direk binne `List` te stoor, werk nie.<sup>[[10]](#references)</sup>

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

### Voorwaardes

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

#### loop (oneindig)

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

Pas `Some` om die waarde daarin te bind; ’n gewone veranderlikepatroon pas by beide `Some` en `None`, dus sal die `else`-tak nooit uitgevoer word nie.<sup>[[11]](#references)</sup>

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

Skep 'n nuwe metode vir 'n tipe

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

### Toetse

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

’n Arc kan Clone gebruik om meer verwysings na die objek te skep en dit aan die drade deur te gee. Wanneer die laaste verwysingswyser na ’n waarde buite omvang raak, word die veranderlike vernietig.

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

#### Drade

In hierdie geval sal ons die draad 'n veranderlike deurgee wat dit sal kan wysig.

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


### Sekuriteitsnoodsaaklikhede

Rust bied by verstek sterk geheueveiligheidswaarborge, maar jy kan steeds kritieke kwesbaarhede invoer deur `unsafe`-kode, afhanklikheidsprobleme of logikafoute. Die volgende mini-kitsgids versamel die primitiewe waarmee jy die meeste te doen sal kry tydens offensiewe of defensiewe sekuriteitshersienings van Rust-sagteware. Vir ander taalspesifieke hulpmiddels, sien [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### `unsafe`-kode en geheueveiligheid

`unsafe` laat bewerkings toe waarvan die veiligheidsvereistes die samesteller nie kan bewys nie; dit skakel nie gewone leen- of grenskontroles af nie. Geheuekorrupsie kan voorkom wanneer ’n onveilige bewerking sy vereistes oortree, insluitend binne ’n funksie wat as ’n veilige API beskikbaar gestel word.<sup>[[3]](#references)</sup>

Soek tydens ’n bronkodehersiening na die ongekontroleerde bewerkings en volg aanvallerbeheerde wysers en lengtes vanaf hul publieke oproepers:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Vir `slice::from_raw_parts`, bewys dat die pointer nie null is nie en belyn is, dat die **hele** geïnisialiseerde reeks binne een lewende geheuetoekenning val, en dat die teruggestuurde slice nie langer as die geheuetoekenning kan bestaan nie. Selfs ’n slice met lengte nul kan nie ’n null pointer gebruik nie.
* Vir `Vec::set_len`, bewys dat die nuwe lengte binne die werklike kapasiteit pas en dat elke nuut blootgestelde element geïnisialiseer is. Volg beide die geheuetoekenningsgrootte en enige kopieertelling na; `with_capacity` inisialiseer nie elemente nie.
* Gaan elke `unsafe impl` van `Send` of `Sync` en elke FFI-signatuur na teen die invariantes wat aan veilige callers beloof word. `#![forbid(unsafe_code)]` verwerp unsafe code in ’n crate; `#![deny(unsafe_op_in_unsafe_fn)]` vereis eerder eksplisiete unsafe blocks **binne** unsafe functions—dit verbied nie unsafe code nie. Laasgenoemde lint waarsku by verstek in Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Voorbeeld van oorloop wat met raw pointers geskep word:
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
'n Invoer wat langer is as `dst.capacity()` skend beide die kopieergrens en die `set_len`-kontrak in die voorbeeld hierbo. Voeg 'n toets met 'n oormaatinvoer vir die teikenallocator by en voer dit dan onder Miri uit. Miri kontroleer uitgevoerde paaie vir ongedefinieerde gedrag, maar onondersteunde foreign calls kan verhoed dat dit 'n FFI-grens toets.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Ouditering van afhanklikhede met RustSec / cargo-audit

Die meeste Rust-kwesbaarhede in die praktyk kom in crates van derde partye voor. Die RustSec-adviesdatabasis (deur die gemeenskap aangedryf) kan plaaslik geraadpleeg word:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integreer dit in CI en laat die proses misluk met `--deny warnings`.

`cargo deny check advisories` bied soortgelyke funksionaliteit, plus lisensie- en banlys-kontroles.

#### Kodedekking met cargo-tarpaulin

`cargo tarpaulin` is ’n verslagdoeningsinstrument vir kodedekking vir die Cargo-boustelsel.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Op Linux is Tarpaulin se verstek-nasporingsagtergrond steeds Ptrace en werk dit net op x86_64-verwerkers. Dit kan verander word na die llvm-dekkingsinstrumentasie met `--engine llvm`. Vir Mac en Windows is dit die verstekversamelingsmetode.

#### Voorsieningskettingverifikasie met cargo-vet

`cargo vet` kontroleer afhanklikhede aan die hand van gekonfigureerde ouditkriteria met behulp van plaaslike oudits, vertroude invoere of uitdruklike vrystellings. `cargo vet init` skep `supply-chain/`-metadata en stel bestaande ongeouditeerde afhanklikhede vry; daarom beteken ’n aanvanklik geslaagde kontrole **nie** dat elke crate nagegaan is nie. Ondersoek die vrystellings en gebruik `cargo vet suggest` om dit deur te werk; `--locked` verhoed dat ingevoerde ouditstelle verfris word.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing van jou API-oppervlak (cargo-fuzz)

Fuzz-targets toets die API met gegenereerde invoer en kan panics en geheueveiligheidsfoute blootlê. Die gegenereerde target is onder `fuzz/fuzz_targets/`; vervang sy verstekliggaam met ’n oproep na die API wat nagegaan word voordat jy dit laat loop.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Voeg die fuzz target by jou repo en voer dit in jou pipeline uit.



## References

- [1] [RustSec-adviesdatabasis](https://rustsec.org)
- [2] [Cargo-vet: "Oudit van jou Rust-afhanklikhede"](https://mozilla.github.io/cargo-vet/)
- [3] [Die Rust-programmeertaal: Onveilige Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: unsafe_op_in_unsafe_fn-waarskuwing](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet-opdragte](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: cargo-fuzz-handleiding](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Die Rust-programmeertaal: Box en rekursiewe tipes](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Die Rust-programmeertaal: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: Unsafe extern-blokke](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
