# Misingi ya Rust

{{#include ../banners/hacktricks-training.md}}

### Umiliki wa vigezo

Kumbukumbu inasimamiwa kupitia mfumo wa umiliki wenye kanuni zifuatazo ambazo compiler huzikagua wakati wa compile:

1. Kila thamani katika Rust ina kigezo kinachoitwa mmiliki wake.
2. Kunaweza kuwa na mmiliki mmoja tu kwa wakati mmoja.
3. Wakati mmiliki anapotoka nje ya uwigo, thamani itaondolewa.
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
### Aina za jumla

Unda struct ambapo mojawapo ya thamani zake inaweza kuwa aina yoyote.
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

Aina Option ina maana kwamba thamani inaweza kuwa ya aina Some (kuna kitu) au None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Unaweza kutumia kazi kama `is_some()` au `is_none()` ili kukagua thamani ya Option.


### Result, Ok & Err

Zinatumika kurudisha na kusambaza makosa
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Unaweza kutumia functions kama `is_ok()` au `is_err()` kukagua thamani ya matokeo

The `Option` enum inafaa kutumika katika hali ambapo thamani inaweza kutokuwepo (kuwa `None`).
The `Result` enum inafaa kutumika katika hali ambapo unafanya kitu ambacho kinaweza kushindikana


### Macros

Macros ni zenye nguvu zaidi kuliko functions kwa sababu zinapanuka ili kuzalisha msimbo zaidi kuliko ule uliouandika kwa mkono. Kwa mfano, saini ya function lazima itaeleze idadi na aina ya vigezo ambavyo function ina. Macros, kwa upande mwingine, zinaweza kupokea idadi inayobadilika ya vigezo: tunaweza kuita `println!("hello")` na hoja moja au `println!("hello {}", name)` na hoja mbili. Zaidi ya hayo, macros zinapanuliwa kabla compiler itafsiri maana ya msimbo, hivyo macro inaweza, kwa mfano, kutekeleza trait kwa type fulani. Function haiwezi kufanya hivyo, kwa sababu inaitwa wakati wa runtime na trait inahitaji kutekelezwa wakati wa compile time.
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
### Box inayojirudia
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
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
#### mzunguko (usio na mwisho)
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

Unda method mpya kwa type
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

Arc inaweza kutumia Clone kuunda marejeleo zaidi ya object ili kuzipitisha kwa threads. Wakati kiashiria cha mwisho cha marejeleo kwa thamani kiko nje ya wigo, variable inatupwa.
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

Katika kesi hii tutampa thread variable ambayo ataweza kuibadilisha.
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

Rust inatoa dhamana imara za usalama wa kumbukumbu kwa chaguo-msingi, lakini bado unaweza kuleta udhaifu hatari kupitia `unsafe` code, matatizo ya dependency au makosa ya mantiki. Muhtasari mfupi ufuatao unakusanya vijenzi vya msingi utakavyokutana navyo mara kwa mara wakati wa mapitio ya usalama ya kushambulia au ya kujilinda ya programu za Rust.

#### `unsafe` code & usalama wa kumbukumbu

`unsafe` blocks huondoa ukaguzi wa aliasing na bounds wa compiler, kwa hivyo **makosa yote ya jadi ya kuharibu kumbukumbu (OOB, use-after-free, double free, n.k.) yanaweza kuonekana tena**. Orodha ya ukaguzi wa haraka:

* Tafuta `unsafe` blocks, `extern "C"` functions, miito kwa `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers au `ffi` modules.
* Thibitisha kila pointer arithmetic na hoja za urefu zinazopitishwa kwa low-level functions.
* Pendelea `#![forbid(unsafe_code)]` (crate-wide) au `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) ili compilation ishindwe wakati mtu anaporejesha `unsafe`.

Mfano wa overflow uliotengenezwa kwa raw pointers:
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
Kuendesha Miri ni njia nafuu ya kugundua UB wakati wa majaribio:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Kukagua dependencies kwa kutumia RustSec / cargo-audit

Vulns nyingi za Rust katika mazingira ya kweli zipo katika third-party crates. RustSec advisory DB (inayoendeshwa na jamii) inaweza kuhojiwa kwa ndani:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Iweke kwenye CI na kusababisha kushindikana ikiwa `--deny warnings`.

`cargo deny check advisories` inatoa utendaji sawa pamoja na ukaguzi wa leseni na orodha za marufuku.

#### Ufunikaji wa msimbo na cargo-tarpaulin

`cargo tarpaulin` ni chombo cha kuripoti ufunikaji wa msimbo kwa mfumo wa ujenzi wa Cargo.
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Kwenye Linux, backend ya ufuatiliaji ya chaguo-msingi ya Tarpaulin bado ni Ptrace na itafanya kazi tu kwenye prosesa za x86_64. Hii inaweza kubadilishwa kuwa llvm coverage instrumentation kwa kutumia `--engine llvm`. Kwa Mac na Windows, hii ndiyo njia ya ukusanyaji ya chaguo-msingi.

#### Uhakikisho wa mnyororo wa ugavi kwa cargo-vet (2024)

`cargo vet` hurekodi hash ya ukaguzi kwa kila crate unayoiingiza na huzuia masasisho yasiyogunduliwa:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Chombo kinatumika na miundombinu ya mradi wa Rust na idadi inayoongezeka ya mashirika ili kupunguza poisoned-package attacks.

#### Fuzzing uso wa API yako (cargo-fuzz)

Fuzz tests hupata kwa urahisi panics, integer overflows, na logic bugs ambazo zinaweza kusababisha DoS au side-channel issues:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Ongeza fuzz target kwenye repo yako na iendeshe katika pipeline yako.

## Marejeleo

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Ukaguzi wa Dependencies zako za Rust" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
