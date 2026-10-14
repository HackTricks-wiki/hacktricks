# Rust की बुनियादी बातें

{{#include ../banners/hacktricks-training.md}}

### वेरिएबल का स्वामित्व

मेमोरी का प्रबंधन स्वामित्व की एक प्रणाली के ज़रिए किया जाता है, जिसके निम्नलिखित नियमों की जाँच compiler, compile time पर करता है:

1. Rust में हर value का एक वेरिएबल होता है, जिसे उसका owner कहा जाता है।
2. एक समय में केवल एक ही owner हो सकता है।
3. जब owner का scope समाप्त होता है, तो value हटा दी जाती है।

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



### जेनेरिक प्रकार

ऐसा struct बनाएँ जिसका एक मान किसी भी प्रकार का हो શકે है.

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

### Option, Some और None

Option type का मतलब है कि value, Some (कुछ मौजूद है) या None प्रकार की हो सकती है:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

आप Option की value जाँचने के लिए `is_some()` या `is_none()` जैसे functions का उपयोग कर सकते हैं।


### Result, Ok & Err

Errors लौटाने और आगे propagate करने के लिए उपयोग किया जाता है

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

आप result की वैल्यू जाँचने के लिए `is_ok()` या `is_err()` जैसे फ़ंक्शन इस्तेमाल कर सकते हैं।

`Option` enum का इस्तेमाल उन स्थितियों में करना चाहिए जहाँ कोई वैल्यू मौजूद न भी हो सकती है (`None`)।
`Result` enum का इस्तेमाल उन स्थितियों में करना चाहिए जहाँ आप कुछ ऐसा करते हैं जो विफल हो सकता है।

### Macros

Macros फ़ंक्शन्स से अधिक शक्तिशाली होते हैं, क्योंकि वे आपके हाथ से लिखे गए कोड से अधिक कोड बनाने के लिए expand होते हैं। उदाहरण के लिए, फ़ंक्शन के signature में उसके parameters की संख्या और प्रकार घोषित करने होते हैं। दूसरी ओर, macros में parameters की संख्या बदल सकती है: हम `println!("hello")` को एक argument के साथ या `println!("hello {}", name)` को दो arguments के साथ call कर सकते हैं। साथ ही, compiler द्वारा कोड का अर्थ समझने से पहले ही macros expand हो जाते हैं, इसलिए कोई macro, उदाहरण के लिए, किसी दिए गए type पर trait implement कर सकता है। कोई फ़ंक्शन ऐसा नहीं कर सकता, क्योंकि उसे runtime पर call किया जाता है और trait को compile time पर implement करना ज़रूरी होता है।

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

### पुनरावृत्ति

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

```rust
enum List {
    Cons(i32, List),
    Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
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

किसी type के लिए एक नया method बनाएं

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

Arc, object के अधिक references बनाने के लिए Clone का उपयोग कर सकता है, ताकि उन्हें threads में पास किया जा सके। जब किसी value का आखिरी reference pointer scope से बाहर हो जाता है, तो variable drop हो जाता है।

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

इस मामले में, हम thread को एक variable पास करेंगे, जिसे वह संशोधित कर सकेगा.

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


### सुरक्षा की मूल बातें

Rust डिफ़ॉल्ट रूप से memory-safety की मज़बूत गारंटी देता है, लेकिन `unsafe` code, dependencies की समस्याओं या logic की गलतियों से अब भी गंभीर vulnerabilities आ सकती हैं। यह छोटी cheat sheet उन primitives को एकत्र करती है जिनका Rust software की offensive या defensive security reviews के दौरान आप सबसे ज़्यादा इस्तेमाल करेंगे।

#### `unsafe` code और memory safety

`unsafe` blocks compiler के aliasing और bounds checks को छोड़ देते हैं, इसलिए **memory-corruption के सभी पारंपरिक bugs (OOB, use-after-free, double free आदि) फिर से सामने आ सकते हैं**। एक त्वरित audit checklist:

* `unsafe` blocks, `extern "C"` functions, `ptr::copy*` और `std::mem::transmute` के calls, `MaybeUninit`, raw pointers या `ffi` modules खोजें।
* Low-level functions में दिए गए हर pointer arithmetic और length argument को validate करें।
* `#![forbid(unsafe_code)]` (पूरे crate पर) या `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) को प्राथमिकता दें, ताकि कोई `unsafe` दोबारा शामिल करे तो compilation विफल हो जाए।

Raw pointers से होने वाले overflow का उदाहरण:
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
टेस्ट के समय UB का पता लगाने के लिए Miri चलाना एक कम खर्चीला तरीका है:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```

#### RustSec / cargo-audit से dependencies का audit करना

वास्तविक दुनिया की ज़्यादातर Rust vulnerabilities third-party crates में होती हैं। RustSec advisory DB (community-powered) को locally query किया जा सकता है:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
इसे CI में integrate करें और `--deny warnings` पर fail करें।

`cargo deny check advisories` समान functionality के साथ licence और ban-list checks भी प्रदान करता है।

#### cargo-tarpaulin से code coverage

`cargo tarpaulin`, Cargo build system के लिए code coverage reporting tool है.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux पर, Tarpaulin का default tracing backend अब भी Ptrace है और यह केवल x86_64 processors पर काम करेगा। इसे `--engine llvm` के साथ llvm coverage instrumentation में बदला जा सकता है। Mac और Windows के लिए, यह default collection method है।

#### cargo-vet के साथ supply-chain verification (2024)

`cargo vet` आपके द्वारा import किए गए हर crate के लिए एक review hash दर्ज करता है और बिना आपकी जानकारी के होने वाले upgrades को रोकता है:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
इस tool को Rust project infrastructure और बढ़ती संख्या में orgs, poisoned-package attacks को कम करने के लिए अपना रहे हैं।<sup>[[2]](#references)</sup>

#### अपने API surface की fuzzing (cargo-fuzz)

Fuzz tests आसानी से panics, integer overflows और logic bugs पकड़ लेते हैं, जो DoS या side-channel issues बन सकते हैं:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
अपने repo में fuzz target जोड़ें और इसे अपने pipeline में चलाएँ।

## References

- [1] [RustSec सुरक्षा सलाह डेटाबेस](https://rustsec.org)
- [2] [Cargo-vet: "अपनी Rust dependencies का ऑडिट करना"](https://mozilla.github.io/cargo-vet/)
{{#include ../banners/hacktricks-training.md}}
