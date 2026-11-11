# Osnove Rust-a

{{#include ../banners/hacktricks-training.md}}

### Vlasništvo nad promenljivama

Memorijom se upravlja pomoću sistema vlasništva, čija pravila kompajler proverava tokom kompajliranja:

1. Svaka vrednost u Rust-u ima promenljivu koja se naziva njen vlasnik.
2. U jednom trenutku može postojati samo jedan vlasnik.
3. Kada vlasnik izađe iz opsega, vrednost se odbacuje.

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



### Generički tipovi

Napravite strukturu čija jedna vrednost može biti bilo kog tipa.

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

Tip Option znači da vrednost može biti tipa Some (postoji nešto) ili None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Možete koristiti funkcije kao što su `is_some()` ili `is_none()` da biste proverili vrednost tipa Option.


### Result, Ok & Err

Koristi se za vraćanje i prosleđivanje grešaka

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Možete da koristite funkcije kao što su `is_ok()` ili `is_err()` da proverite vrednost rezultata.

Enum `Option` treba koristiti u situacijama kada neka vrednost možda ne postoji (odnosno kada je `None`).
Enum `Result` treba koristiti u situacijama kada radite nešto što može poći po zlu.

### Makroi

Makroi su moćniji od funkcija jer se proširuju i generišu više koda nego što ste ručno napisali. Na primer, potpis funkcije mora da navede broj i tip parametara koje funkcija ima. Makroi, s druge strane, mogu da primaju promenljiv broj parametara: možemo pozvati `println!("hello")` sa jednim argumentom ili `println!("hello {}", name)` sa dva argumenta. Takođe, makroi se proširuju pre nego što kompajler protumači značenje koda, pa makro može, na primer, da implementira trait za određeni tip. Funkcija to ne može, jer se poziva tokom izvršavanja, a trait mora da se implementira tokom kompajliranja.

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

### Iteriranje

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

### Rekurzivni Box

Rekurzivnom enum-u je potrebna indirekcija kako bi njegova veličina bila poznata u vreme kompajliranja; direktno čuvanje `List` unutar `List` ne može da se kompajlira.<sup>[[10]](#references)</sup>

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

### Uslovne naredbe

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

#### petlja (beskonačna)

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

Upari `Some` da bi vezao njegovu unutrašnju vrednost; običan obrazac promenljive poklapa se i sa `Some` i sa `None`, pa se grana `else` nikada ne bi izvršila.<sup>[[11]](#references)</sup>

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

Kreirajte novu metodu za tip

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

### Testovi

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

### Rad sa nitima

#### Arc

Arc može da koristi Clone za kreiranje dodatnih referenci na objekat koje se prosleđuju nitima. Kada poslednji pokazivač reference na vrednost izađe iz opsega važenja, promenljiva se odbacuje.

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

#### Niti

U ovom slučaju ćemo niti proslediti promenljivu koju će moći da izmeni.

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


### Osnove bezbednosti

Rust podrazumevano pruža snažne garancije bezbednosti memorije, ali i dalje možete uneti kritične ranjivosti pomoću `unsafe` koda, problema sa zavisnostima ili logičkih grešaka. Ovaj kratki podsetnik obuhvata primitive koje ćete najčešće koristiti tokom ofanzivnih ili defanzivnih bezbednosnih pregleda Rust softvera. Za alate specifične za druge jezike pogledajte [Alati za pregled koda](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### `unsafe` kod i bezbednost memorije

`unsafe` dozvoljava operacije čije bezbednosne uslove kompajler ne može da dokaže; **ne** isključuje uobičajene provere pozajmljivanja niti provere granica. Do korupcije memorije može doći kada `unsafe` operacija prekrši svoje uslove, uključujući i slučajeve unutar funkcije izložene kao bezbedan API.<sup>[[3]](#references)</sup>

Prilikom pregleda izvornog koda pronađite neproverene operacije i pratite pokazivače i dužine pod kontrolom napadača od njihovih javnih pozivalaca:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Za `slice::from_raw_parts` dokažite da pokazivač nije null i da je poravnat, da se **ceo** inicijalizovani opseg nalazi unutar jedne žive alokacije i da vraćeni slice ne može da nadživi tu alokaciju. Čak ni slice dužine nula ne može da koristi null pokazivač.
* Za `Vec::set_len` dokažite da nova dužina ne prelazi stvarni kapacitet i da je svaki novootkriveni element inicijalizovan. Pratite veličinu alokacije i broj kopiranja; `with_capacity` ne inicijalizuje elemente.
* Proverite svaki `unsafe impl` za `Send` ili `Sync` i svaki FFI potpis u odnosu na invarijante koje su obećane bezbednim pozivaocima. `#![forbid(unsafe_code)]` odbacuje unsafe kod u crate-u; `#![deny(unsafe_op_in_unsafe_fn)]` umesto toga zahteva eksplicitne unsafe blokove **unutar** unsafe funkcija, ali ne zabranjuje unsafe kod. Ovaj lint podrazumevano izdaje upozorenje u Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Primer overflow-a izazvanog sirovim pokazivačima:
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
Ulaz duži od `dst.capacity()` krši i granicu kopiranja i ugovor za `set_len` u gornjem primeru. Dodajte test sa predugačkim ulazom za ciljni alokator, pa ga pokrenite pod Miri-jem. Miri proverava izvršene putanje na neodređeno ponašanje, ali nepodržani strani pozivi mogu da ga spreče da testira FFI granicu.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Provera zavisnosti pomoću RustSec / cargo-audit

Većina ranjivosti u Rustu iz stvarnog sveta nalazi se u paketima nezavisnih autora. Baza bezbednosnih upozorenja RustSec (koju održava zajednica) može se lokalno pretraživati:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integrate ga u CI i neka CI padne na `--deny warnings`.

`cargo deny check advisories` nudi sličnu funkcionalnost, uz provere licenci i liste zabranjenih paketa.

#### Pokrivenost koda pomoću cargo-tarpaulin

`cargo tarpaulin` je alat za izveštavanje o pokrivenosti koda u Cargo sistemu za izgradnju.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Na Linuxu, Tarpaulin-ov podrazumevani tracing backend je i dalje Ptrace i radiće samo na x86_64 procesorima. Može se promeniti u llvm coverage instrumentation pomoću `--engine llvm`. Za Mac i Windows, ovo je podrazumevani način prikupljanja.

#### Provera lanca snabdevanja pomoću cargo-vet

`cargo vet` proverava zavisnosti prema konfigurisanim kriterijumima za audit, koristeći lokalne audite, pouzdane uvoze ili eksplicitna izuzeća. `cargo vet init` kreira metapodatke u `supply-chain/` i izuzima postojeće zavisnosti koje nisu prošle audit, tako da početna uspešna provera **ne** znači da je svaki crate pregledan. Pregledajte izuzeća i koristite `cargo vet suggest` da biste ih obradili; `--locked` sprečava osvežavanje uvezenih skupova audita.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing površine vašeg API-ja (cargo-fuzz)

Fuzz targets testiraju API pomoću generisanih ulaza i mogu da otkriju panike i greške bezbednosti memorije. Generisani target nalazi se u `fuzz/fuzz_targets/`; zamenite njegovo podrazumevano telo pozivom API-ja koji proveravate pre pokretanja.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Dodajte fuzz target u svoj repozitorijum i pokrenite ga u svom pipeline-u.

## References

- [1] [Baza podataka RustSec bezbednosnih saveta](https://rustsec.org)
- [2] [Cargo-vet: „Revizija Rust zavisnosti“](https://mozilla.github.io/cargo-vet/)
- [3] [Programski jezik Rust: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: upozorenje unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet komande](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: vodič za cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Programski jezik Rust: Box i rekurzivni tipovi](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Programski jezik Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: Unsafe extern blokovi](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
