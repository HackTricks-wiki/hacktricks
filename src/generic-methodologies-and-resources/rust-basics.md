# Misingi ya Rust

{{#include ../banners/hacktricks-training.md}}

### Umiliki wa vigezo

Kumbukumbu hudhibitiwa kupitia mfumo wa umiliki wenye kanuni zifuatazo, ambazo compiler hukagua wakati wa compilation:

1. Kila thamani katika Rust ina kigezo kinachoitwa mmiliki wake.
2. Kunaweza kuwa na mmiliki mmoja tu kwa wakati mmoja.
3. Mmiliki anapotoka nje ya scope, thamani itafutwa.

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



### Aina za Jumla

Unda struct ambayo thamani yake moja inaweza kuwa ya aina yoyote

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

Aina ya Option inamaanisha kuwa thamani inaweza kuwa ya aina ya Some (kuna kitu) au None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Unaweza kutumia functions kama `is_some()` au `is_none()` kuangalia thamani ya Option.


### Result, Ok & Err

Hutumika kurejesha na kupitisha makosa.

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Unaweza kutumia functions kama `is_ok()` au `is_err()` kuangalia thamani ya matokeo.

Enum ya `Option` inapaswa kutumiwa katika hali ambapo huenda thamani isiwepo (iwe `None`).
Enum ya `Result` inapaswa kutumiwa katika hali ambapo unafanya jambo ambalo huenda likakosea.


### Macros

Macros zina nguvu zaidi kuliko functions kwa sababu hupanuka na kutoa code zaidi kuliko uliyoandika mwenyewe. Kwa mfano, sahihi ya function lazima itangaze idadi na aina za vigezo vya function hiyo. Kwa upande mwingine, macros zinaweza kupokea idadi tofauti ya vigezo: tunaweza kuita `println!("hello")` kwa hoja moja au `println!("hello {}", name)` kwa hoja mbili. Pia, macros hupanuliwa kabla compiler haijatafsiri maana ya code, kwa hivyo macro inaweza, kwa mfano, kutekeleza trait kwenye aina fulani. Function haiwezi kufanya hivyo, kwa sababu huitwa wakati wa runtime na trait inahitaji kutekelezwa wakati wa compile.

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

### Kurudia

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

Enum ya recursive inahitaji indirection ili ukubwa wake ujulikane wakati wa compile; kuhifadhi `List` moja kwa moja ndani ya `List` hakukompili.<sup>[[10]](#references)</sup>

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

### Masharti

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

#### loop (isiyo na kikomo)

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

Linganisha `Some` ili kufunga thamani yake ya ndani; kigezo cha kawaida cha variable hulingana na `Some` na `None`, kwa hiyo tawi la `else` halitatekelezwa kamwe.<sup>[[11]](#references)</sup>

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

Unda method mpya kwa aina fulani

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

### Majaribio

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

Arc inaweza kutumia Clone kuunda marejeleo zaidi ya kitu hicho na kuyapitisha kwenye threads. Kielekezi cha mwisho cha marejeleo ya thamani kinapotoka nje ya scope, variable hutupwa.

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

Katika hali hii tutakabidhi thread kigezo ambacho itaweza kukirekebisha.

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


### Misingi ya Usalama

Rust hutoa dhamana thabiti za usalama wa kumbukumbu kwa chaguomsingi, lakini bado unaweza kusababisha udhaifu mkubwa kupitia code ya `unsafe`, matatizo ya dependencies au makosa ya mantiki. Cheatsheet hii fupi inakusanya primitives utakazotumia mara nyingi zaidi wakati wa ukaguzi wa usalama wa Rust, wa kiudhalilishaji au wa kiulinzi. Kwa zana nyingine mahususi za lugha, angalia [Zana za Ukaguzi wa Code](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Code ya unsafe na usalama wa kumbukumbu

`unsafe` huruhusu shughuli ambazo masharti yake ya usalama hayawezi kuthibitishwa na compiler; **haizimi** ukaguzi wa kawaida wa borrow au mipaka. Uharibifu wa kumbukumbu unaweza kutokea pale shughuli ya unsafe inapokiuka masharti yake, ikiwemo ndani ya function inayotolewa kama API salama.<sup>[[3]](#references)</sup>

Katika ukaguzi wa source code, tafuta shughuli zisizokaguliwa na ufuatilie pointers na urefu unaodhibitiwa na mshambuliaji kutoka kwa callers zake za umma:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Kwa `slice::from_raw_parts`, thibitisha kuwa pointer si null na imepangiliwa ipasavyo, kwamba **range nzima** iliyoanzishwa iko ndani ya allocation moja hai, na kwamba slice inayorejeshwa haiwezi kuishi muda mrefu kuliko allocation hiyo. Hata slice yenye urefu wa sifuri haiwezi kutumia pointer ya null.
* Kwa `Vec::set_len`, thibitisha kuwa urefu mpya hauzidi capacity halisi na kwamba kila element inayofichuliwa upya ilikuwa imeanzishwa. Fuatilia ukubwa wa allocation na idadi ya nakala; `with_capacity` haianzishi elements.
* Kagua kila `unsafe impl` ya `Send` au `Sync` na kila saini ya FFI ili kuhakikisha zinatimiza invariants zilizoahidiwa kwa callers salama. `#![forbid(unsafe_code)]` hukataa code isiyo salama ndani ya crate; `#![deny(unsafe_op_in_unsafe_fn)]` badala yake huhitaji blocks za unsafe zilizo wazi **ndani ya** functions za unsafe, bali haikatazi code isiyo salama. Lint hii huonya kwa chaguomsingi katika Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Mfano wa overflow uliosababishwa na raw pointers:
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
Ingizo refu kuliko `dst.capacity()` linakiuka kikomo cha kunakili na mkataba wa `set_len` katika mfano ulio hapo juu. Ongeza jaribio lenye ingizo kubwa kupita kiasi kwa allocator lengwa, kisha liendeshe chini ya Miri. Miri hukagua njia zilizotekelezwa ili kubaini tabia isiyobainishwa, lakini huenda simu za kigeni zisizotumika zikazuia Miri kufikia mpaka wa FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Kukagua dependencies kwa kutumia RustSec / cargo-audit

Vulnerabilities nyingi za Rust katika mazingira halisi hupatikana kwenye crates za wahusika wengine. DB ya ushauri ya RustSec (inayoendeshwa na jamii) inaweza kukaguliwa locally:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Ijumuishe kwenye CI na ufanye ukaguzi ushindwe kwa `--deny warnings`.

`cargo deny check advisories` hutoa utendaji unaofanana pamoja na ukaguzi wa leseni na orodha ya vilivyopigwa marufuku.

#### Code coverage with cargo-tarpaulin

`cargo tarpaulin` ni zana ya kuripoti code coverage kwa mfumo wa build wa Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Kwenye Linux, backend chaguomsingi ya tracing ya Tarpaulin bado ni Ptrace na itafanya kazi tu kwenye vichakataji vya x86_64. Hili linaweza kubadilishwa kuwa instrumentation ya llvm coverage kwa kutumia `--engine llvm`. Kwa Mac na Windows, hii ndiyo njia chaguomsingi ya ukusanyaji.

#### Uhakiki wa supply-chain kwa kutumia cargo-vet

`cargo vet` hukagua dependencies dhidi ya vigezo vya ukaguzi vilivyosanidiwa kwa kutumia ukaguzi wa ndani, imports zinazoaminika, au misamaha iliyoainishwa wazi. `cargo vet init` huunda metadata ya `supply-chain/` na kutoa misamaha kwa dependencies zilizopo ambazo hazijakaguliwa, kwa hiyo ukaguzi kufaulu mwanzoni **haimaanishi** kwamba kila crate imekaguliwa. Chunguza misamaha na utumie `cargo vet suggest` ili kuishughulikia; `--locked` huzuia kusasisha seti za ukaguzi zilizoagizwa.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing your API surface (cargo-fuzz)

Fuzz targets hujaribu API kwa kutumia inputs zinazozalishwa na zinaweza kufichua panics na hitilafu za usalama wa kumbukumbu. Target inayozalishwa hupatikana chini ya `fuzz/fuzz_targets/`; badilisha body yake ya default iwe mwito wa API inayokaguliwa kabla ya kuiendesha.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Ongeza fuzz target kwenye repo yako na uiendeshe kwenye pipeline yako.

## References

- [1] [Hifadhidata ya Ushauri ya RustSec](https://rustsec.org)
- [2] [Cargo-vet: "Kukagua Dependencies zako za Rust"](https://mozilla.github.io/cargo-vet/)
- [3] [Lugha ya Rust ya Programu: Rust Isiyo Salama](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README ya Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: onyo la unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Amri za Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Kitabu cha Rust Fuzz: mafunzo ya cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Lugha ya Rust ya Programu: Box na aina za kujirejelea](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Lugha ya Rust ya Programu: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: Unsafe extern blocks](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
