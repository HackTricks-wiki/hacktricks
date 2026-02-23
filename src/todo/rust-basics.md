# Rust मूल बातें

{{#include ../banners/hacktricks-training.md}}

### वेरिएबल्स का Ownership

मेमोरी ownership सिस्टम के माध्यम से प्रबंधित होती है, और कंपाइलर निम्नलिखित नियमों को compile time पर जाँचता है:

1. Rust में प्रत्येक value का एक variable होता है जिसे owner कहा जाता है।
2. एक समय में केवल एक ही owner हो सकता है।
3. जब owner scope से बाहर चला जाता है, value dropped हो जाती है।
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
### Generic प्रकार

ऐसा struct बनाइए जहाँ उसकी 1 value किसी भी type की हो सके।
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

Option प्रकार का मतलब है कि मान संभवतः Some (कुछ मौजूद है) या None हो सकता है:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
आप `is_some()` या `is_none()` जैसे फ़ंक्शन का उपयोग Option के मान की जाँच करने के लिए कर सकते हैं।

### Result, Ok & Err

त्रुटियों को लौटाने और प्रसारित करने के लिए उपयोग किया जाता है।
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
आप `is_ok()` या `is_err()` जैसी फ़ंक्शन का उपयोग `Result` के मान की जाँच करने के लिए कर सकते हैं।

`Option` enum का उपयोग उन परिस्थितियों में किया जाना चाहिए जहाँ कोई मान मौजूद न हो (यानी `None`)।
`Result` enum का उपयोग उन परिस्थितियों में किया जाना चाहिए जहाँ आप ऐसा कुछ कर रहे हों जो गलत हो सकता है।

### Macros

Macros फ़ंक्शन की तुलना में अधिक शक्तिशाली होते हैं क्योंकि वे विस्तारित होकर उस कोड से भी अधिक कोड उत्पन्न करते हैं जो आपने मैन्युअली लिखा है। उदाहरण के लिए, एक फ़ंक्शन के signature को उस फ़ंक्शन के parameters की संख्या और प्रकार घोषित करना पड़ता है। दूसरी ओर, macros किसी भी संख्या के parameters ले सकते हैं: हम `println!("hello")` को एक argument के साथ कॉल कर सकते हैं या `println!("hello {}", name)` को दो arguments के साथ। इसके अलावा, macros को compiler द्वारा कोड के अर्थ को व्याख्यायित करने से पहले विस्तारित किया जाता है, इसलिए एक macro, उदाहरण के लिए, किसी दिए गए प्रकार पर trait को implement कर सकता है। एक फ़ंक्शन ऐसा नहीं कर सकता, क्योंकि वह runtime पर कॉल होता है और trait को compile time पर implement किया जाना चाहिए।
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
### दोहराना
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
### आवर्ती Box
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### शर्तें

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
#### loop (infinite)
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
### थ्रेडिंग

#### Arc

Arc Clone का उपयोग करके ऑब्जेक्ट पर और अधिक references बना सकता है ताकि उन्हें threads को पास किया जा सके। जब किसी value के लिए अंतिम reference pointer scope से बाहर हो जाता है, तो variable dropped हो जाता है।
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

इस मामले में हम thread को एक variable पास करेंगे जिसे वह संशोधित कर सकेगा।
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
### सुरक्षा मूल बातें

Rust डिफ़ॉल्ट रूप से मजबूत मेमोरी-सुरक्षा गारंटियाँ देता है, लेकिन आप अभी भी `unsafe` code, dependency issues या logic mistakes के माध्यम से गंभीर कमजोरियाँ जोड़ सकते हैं। नीचे दिया गया मिनी-चीटशीट उन प्रिमिटिव्स को संकलित करता है जिनसे आप Rust सॉफ़्टवेयर के offensive या defensive security reviews के दौरान सबसे ज्यादा संपर्क करेंगे।

#### Unsafe code & memory safety

`unsafe` blocks compiler के aliasing और bounds checks से opt-out करते हैं, इसलिए **सभी पारंपरिक memory-corruption बग्स (OOB, use-after-free, double free, आदि) फिर से प्रकट हो सकते हैं**। एक त्वरित ऑडिट चेकलिस्ट:

* खोजें `unsafe` blocks, `extern "C"` functions, `ptr::copy*` के कॉल, `std::mem::transmute`, `MaybeUninit`, raw pointers या `ffi` modules।
* हर pointer arithmetic और length argument की सत्यापना करें जो low-level functions को पास किए जाते हैं।
* जब कोई `unsafe` फिर से जोड़ता है तो कंपाइल असफल करने के लिये crate-स्तर पर `#![forbid(unsafe_code)]` या `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) का प्रयोग करें।

Example overflow created with raw pointers:
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
Miri चलाना परीक्षण समय पर UB का पता लगाने का सस्ता तरीका है:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit के साथ dependencies का ऑडिट

अधिकांश वास्तविक दुनिया के Rust vulns third-party crates में रहते हैं। RustSec advisory DB (community-powered) को लोकली क्वेरी किया जा सकता है:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
इसे CI में इंटीग्रेट करें और `--deny warnings` पर असफल कर दें।

`cargo deny check advisories` समान कार्यक्षमता प्रदान करता है और साथ में लाइसेंस और ban-list की जाँच भी करता है।

#### कोड कवरेज cargo-tarpaulin के साथ

`cargo tarpaulin` एक कोड कवरेज रिपोर्टिंग टूल है Cargo build system के लिए।
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux पर, Tarpaulin का डिफ़ॉल्ट ट्रेसिंग बैकएंड अभी भी Ptrace है और यह केवल x86_64 प्रोसेसर पर ही काम करेगा। इसे `--engine llvm` के साथ llvm कवरेज इंस्ट्रूमेंटेशन में बदला जा सकता है। Mac और Windows के लिए, यह डिफ़ॉल्ट संग्रह विधि है।

#### सप्लाई-चेन सत्यापन cargo-vet के साथ (2024)

`cargo vet` हर crate के लिए एक review hash रिकॉर्ड करता है जो आप इम्पोर्ट करते हैं और अनदेखे अपग्रेड्स को रोकता है:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
यह टूल Rust project infrastructure और बढ़ती संख्या के संगठनों द्वारा poisoned-package attacks को कम करने के लिए अपनाया जा रहा है।

#### Fuzzing आपकी API सतह (cargo-fuzz)

Fuzz tests आसानी से panics, integer overflows और logic bugs पकड़ लेते हैं जो DoS या side-channel समस्याओं में बदल सकते हैं:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
अपने repo में fuzz target जोड़ें और इसे अपने pipeline में चलाएँ।

## References

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
