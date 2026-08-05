# Rust की मूल बातें

{{#include ../banners/hacktricks-training.md}}

### variables का Ownership

Memory को ownership system के माध्यम से manage किया जाता है, जिसके निम्नलिखित rules को compiler compile time पर check करता है:

1. Rust में प्रत्येक value के पास एक variable होता है जिसे उसका owner कहा जाता है।
2. एक समय में केवल एक owner हो सकता है।
3. जब owner scope से बाहर चला जाता है, तो value drop कर दी जाती है।
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

एक ऐसा struct बनाएं जिसमें उसकी 1 value किसी भी type की हो सके
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

Option type का अर्थ है कि value Some type (कुछ मौजूद है) या None हो सकती है:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
आप `Option` की value जाँचने के लिए `is_some()` या `is_none()` जैसे functions का उपयोग कर सकते हैं।


### Result, Ok और Err

Errors को return और propagate करने के लिए उपयोग किया जाता है
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
आप `is_ok()` या `is_err()` जैसे functions का उपयोग result की value को जाँचने के लिए कर सकते हैं

`Option` enum का उपयोग उन स्थितियों में किया जाना चाहिए जहाँ कोई value मौजूद न हो सकती है (`None` हो सकती है)।
`Result` enum का उपयोग उन स्थितियों में किया जाना चाहिए जहाँ आप ऐसा कुछ करते हैं जो गलत हो सकता है


### Macros

Macros functions से अधिक शक्तिशाली होते हैं, क्योंकि वे आपके द्वारा manually लिखे गए code से अधिक code बनाने के लिए expand होते हैं। उदाहरण के लिए, किसी function signature में उस function के parameters की संख्या और type घोषित करना आवश्यक होता है। दूसरी ओर, Macros variable number of parameters ले सकते हैं: हम `println!("hello")` को एक argument के साथ या `println!("hello {}", name)` को दो arguments के साथ call कर सकते हैं। इसके अलावा, compiler code के meaning को interpret करने से पहले Macros expand होते हैं, इसलिए कोई Macro, उदाहरण के लिए, किसी दिए गए type पर trait implement कर सकता है। कोई function ऐसा नहीं कर सकता, क्योंकि उसे runtime पर call किया जाता है और trait को compile time पर implement करना आवश्यक होता है।
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
### दोहराएँ
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
#### के लिए
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

किसी type के लिए एक नई method बनाएँ
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

एक Arc, object पर अधिक references बनाने के लिए Clone का उपयोग कर सकता है, ताकि उन्हें threads में भेजा जा सके। जब किसी value का अंतिम reference pointer scope से बाहर हो जाता है, तो variable drop हो जाता है।
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

इस मामले में हम thread को एक variable देंगे, जिसे वह modify कर सकेगा
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

Rust डिफ़ॉल्ट रूप से memory-safety की मजबूत गारंटी प्रदान करता है, लेकिन `unsafe` code, dependency issues या logic mistakes के माध्यम से आप अभी भी critical vulnerabilities ला सकते हैं। निम्नलिखित mini-cheatsheet उन primitives को एकत्र करती है जिन्हें आप Rust software के offensive या defensive security reviews के दौरान सबसे अधिक उपयोग करेंगे।

#### Unsafe code & memory safety

`unsafe` blocks compiler के aliasing और bounds checks से opt-out करते हैं, इसलिए **सभी traditional memory-corruption bugs (OOB, use-after-free, double free, आदि) फिर से दिखाई दे सकते हैं**। एक quick audit checklist:

* `unsafe` blocks, `extern "C"` functions, `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers या `ffi` modules को खोजें।
* Low-level functions को दिए गए हर pointer arithmetic और length argument को validate करें।
* `#![forbid(unsafe_code)]` (crate-wide) या `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) को प्राथमिकता दें, ताकि कोई व्यक्ति `unsafe` फिर से जोड़ने पर compilation fail हो जाए।

Raw pointers से बनाया गया overflow example:
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
test time पर UB detect करने के लिए Miri चलाना एक किफायती तरीका है:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit के साथ dependencies का Auditing

वास्तविक दुनिया की अधिकांश Rust vulnerabilities third-party crates में रहती हैं। RustSec advisory DB (community-powered) को locally query किया जा सकता है:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
इसे CI में integrate करें और `--deny warnings` पर fail करें।

`cargo deny check advisories` इसी तरह की functionality के साथ licence और ban-list checks भी प्रदान करता है।

#### cargo-tarpaulin के साथ Code coverage

`cargo tarpaulin` Cargo build system के लिए Code coverage reporting tool है
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux पर, Tarpaulin का default tracing backend अभी भी Ptrace है और यह केवल x86_64 processors पर काम करेगा। इसे `--engine llvm` के साथ llvm coverage instrumentation में बदला जा सकता है। Mac और Windows के लिए, यह default collection method है।

#### cargo-vet के साथ Supply-chain verification (2024)

`cargo vet` आपके द्वारा import किए गए प्रत्येक crate के लिए एक review hash रिकॉर्ड करता है और बिना सूचना वाले upgrades को रोकता है:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
इस tool को Rust project infrastructure और बढ़ती संख्या में orgs द्वारा poisoned-package attacks को कम करने के लिए अपनाया जा रहा है।<sup>[[2]](#references)</sup>

#### अपने API surface की Fuzzing (cargo-fuzz)

Fuzz tests आसानी से panics, integer overflows और logic bugs को पकड़ लेते हैं, जो DoS या side-channel issues में बदल सकते हैं:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
अपने repo में fuzz target जोड़ें और इसे अपनी pipeline में चलाएँ।

## References

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: Auditing your Rust Dependencies](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
