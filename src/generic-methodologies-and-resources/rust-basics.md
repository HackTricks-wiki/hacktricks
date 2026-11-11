# Rust की मूल बातें

{{#include ../banners/hacktricks-training.md}}

### Variables का Ownership

Memory को ownership की एक प्रणाली के ज़रिए manage किया जाता है, जिसके निम्नलिखित rules को compiler compile time पर जाँचता है:

1. Rust में हर value का एक variable होता है, जिसे उसका owner कहा जाता है।
2. एक समय में केवल एक ही owner हो सकता है।
3. जब owner का scope समाप्त होता है, तो value drop हो जाएगी।

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



### Generic Types

ऐसा struct बनाएँ, जिसके एक मान का type कुछ भी हो सकता है.

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

Option टाइप का अर्थ है कि वैल्यू Some (कुछ मौजूद है) या None हो सकती है:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

आप Option की value जाँचने के लिए `is_some()` या `is_none()` जैसे functions का उपयोग कर सकते हैं।

### Result, Ok & Err

errors लौटाने और आगे propagate करने के लिए उपयोग किया जाता है

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

आप result की value जाँचने के लिए `is_ok()` या `is_err()` जैसे functions का उपयोग कर सकते हैं।

`Option` enum का उपयोग उन स्थितियों में करना चाहिए जहाँ कोई value मौजूद न भी हो सकती है (`None`)।
`Result` enum का उपयोग उन स्थितियों में करना चाहिए जहाँ आप कुछ ऐसा करते हैं जिसमें गड़बड़ी हो सकती है।

### Macros

Macros functions से अधिक शक्तिशाली होते हैं, क्योंकि वे आपके मैन्युअल रूप से लिखे गए code से अधिक code उत्पन्न करने के लिए expand होते हैं। उदाहरण के लिए, function signature में function के parameters की संख्या और type घोषित करना आवश्यक है। दूसरी ओर, macros parameters की बदलती संख्या ले सकते हैं: हम `println!("hello")` को एक argument के साथ या `println!("hello {}", name)` को दो arguments के साथ call कर सकते हैं। साथ ही, compiler द्वारा code का अर्थ समझने से पहले macros expand होते हैं, इसलिए कोई macro, उदाहरण के लिए, किसी दिए गए type पर trait implement कर सकता है। कोई function ऐसा नहीं कर सकता, क्योंकि उसे runtime पर call किया जाता है और trait को compile time पर implement करना आवश्यक है।

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

### इटरेट करें

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

### रिकर्सिव Box

एक recursive enum को indirection की आवश्यकता होती है, ताकि उसका आकार compile time पर ज्ञात हो; `List` को सीधे `List` के अंदर स्टोर करने पर compilation नहीं होता।<sup>[[10]](#references)</sup>

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

### शर्तीय कथन

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

#### loop (अनंत)

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

`Some` से match करके उसकी अंदरूनी value को bind करें; एक सामान्य variable pattern `Some` और `None` दोनों से match करता है, इसलिए `else` branch कभी नहीं चलेगी।<sup>[[11]](#references)</sup>

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

किसी type के लिए एक नया method बनाएँ

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

### परीक्षण

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

Arc, ऑब्जेक्ट के और references बनाने के लिए Clone का उपयोग कर सकता है, ताकि उन्हें threads में भेजा जा सके। जब किसी value का आखिरी reference pointer scope से बाहर हो जाता है, तो variable drop हो जाता है।

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

इस मामले में, हम thread को एक variable पास करेंगे, जिसे वह बदल सकेगा.

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


### सुरक्षा संबंधी आवश्यक बातें

Rust डिफ़ॉल्ट रूप से memory safety की मजबूत गारंटी देता है, लेकिन `unsafe` code, dependencies से जुड़ी समस्याओं या logic की गलतियों के ज़रिए अब भी गंभीर vulnerabilities आ सकती हैं। इस छोटी cheatsheet में वे primitives दिए गए हैं जिनका Rust software की offensive या defensive security review के दौरान आप सबसे अधिक उपयोग करेंगे। अन्य language-specific tooling के लिए [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust) देखें।

#### `unsafe` code और memory safety

`unsafe` ऐसे operations की अनुमति देता है जिनके safety contracts को compiler साबित नहीं कर सकता; यह सामान्य borrow या bounds checks को **बंद नहीं** करता। जब कोई unsafe operation अपने contract का उल्लंघन करता है, तब memory corruption संभव हो जाता है—इसमें safe API के रूप में उपलब्ध function के भीतर होने वाला उल्लंघन भी शामिल है।<sup>[[3]](#references)</sup>

Source review के दौरान, unchecked operations खोजें और उनके public callers से attacker-controlled pointers और lengths को trace करें:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* `slice::from_raw_parts` के लिए साबित करें कि pointer non-null और aligned है, पूरी initialized range एक ही live allocation में है, और लौटाई गई slice उस allocation से अधिक समय तक जीवित नहीं रह सकती। zero-length slice के लिए भी null pointer का उपयोग नहीं किया जा सकता।
* `Vec::set_len` के लिए साबित करें कि नई length वास्तविक capacity के भीतर है और हर नया उजागर किया गया element initialized था। Allocation size और किसी भी copy count—दोनों का पता लगाएँ; `with_capacity` elements को initialize नहीं करता।
* प्रत्येक `unsafe impl` of `Send` या `Sync` और हर FFI signature को उन invariants के विरुद्ध जाँचें जिनका safe callers से वादा किया गया है। `#![forbid(unsafe_code)]` किसी crate में unsafe code को अस्वीकार करता है; इसके बजाय `#![deny(unsafe_op_in_unsafe_fn)]` unsafe functions **के अंदर** explicit unsafe blocks अनिवार्य करता है, unsafe code पर प्रतिबंध नहीं लगाता। Rust 2024 में बाद वाला lint डिफ़ॉल्ट रूप से चेतावनी देता है।<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Raw pointers से उत्पन्न overflow का उदाहरण:
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
ऊपर दिए गए उदाहरण में `dst.capacity()` से लंबा input, copy bound और `set_len` contract—दोनों का उल्लंघन करता है। Target allocator के लिए oversized input वाला एक test जोड़ें, फिर उसे Miri के तहत चलाएँ। Miri निष्पादित paths में undefined behavior की जाँच करता है, लेकिन unsupported foreign calls के कारण वह FFI boundary को exercise नहीं कर पाता।<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### RustSec / cargo-audit से dependencies का ऑडिट करना

वास्तविक दुनिया की ज़्यादातर Rust vulnerabilities third-party crates में होती हैं। RustSec advisory DB (community-powered) को locally query किया जा सकता है:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
इसे CI में integrate करें और `--deny warnings` पर fail करें।

`cargo deny check advisories` समान functionality के साथ-साथ licence और ban-list checks भी प्रदान करता है।

#### cargo-tarpaulin से Code coverage

`cargo tarpaulin` Cargo build system के लिए code coverage reporting tool है.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux पर, Tarpaulin का डिफ़ॉल्ट tracing backend अभी भी Ptrace है और यह केवल x86_64 processors पर काम करेगा। इसे `--engine llvm` के साथ llvm coverage instrumentation पर बदला जा सकता है। Mac और Windows के लिए, यह डिफ़ॉल्ट collection method है।

#### cargo-vet के साथ supply-chain verification

`cargo vet` configured audit criteria के अनुसार local audits, trusted imports या explicit exemptions का उपयोग करके dependencies की जाँच करता है। `cargo vet init` `supply-chain/` metadata बनाता है और मौजूदा unaudited dependencies को exempt करता है, इसलिए शुरुआत में check का pass होना **यह नहीं दर्शाता** कि हर crate की समीक्षा की गई है। Exemptions की जाँच करें और उन्हें हल करने के लिए `cargo vet suggest` का उपयोग करें; `--locked` imported audit sets को refresh होने से रोकता है।<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### अपने API surface की Fuzzing (cargo-fuzz)

Fuzz targets generated inputs के साथ API को exercise करते हैं और panics तथा memory-safety faults उजागर कर सकते हैं। Generated target `fuzz/fuzz_targets/` के अंतर्गत होता है; इसे चलाने से पहले इसके default body को review की जा रही API के call से बदलें।<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
अपने repo में fuzz target जोड़ें और उसे अपने pipeline में चलाएँ।

## References

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: "अपनी Rust Dependencies का ऑडिट करना"](https://mozilla.github.io/cargo-vet/)
- [3] [Rust प्रोग्रामिंग भाषा: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: unsafe_op_in_unsafe_fn चेतावनी](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet कमांड](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: cargo-fuzz ट्यूटोरियल](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Rust प्रोग्रामिंग भाषा: Box और recursive types](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Rust प्रोग्रामिंग भाषा: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: Unsafe extern blocks](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
