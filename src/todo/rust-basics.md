# Msingi wa Rust

{{#include ../banners/hacktricks-training.md}}

### Aina za Kijumla

Unda struct ambapo 1 ya thamani zao inaweza kuwa aina yoyote
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
### Chaguo, Baadhi & Hakuna

Aina ya Chaguo inamaanisha kwamba thamani inaweza kuwa ya aina ya Baadhi (kuna kitu) au Hakuna:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Unaweza kutumia kazi kama `is_some()` au `is_none()` kuangalia thamani ya Chaguo.

### Macros

Macros ni zenye nguvu zaidi kuliko kazi kwa sababu zinapanuka kutoa msimbo zaidi kuliko ule ulioandika kwa mikono. Kwa mfano, saini ya kazi lazima itangaze idadi na aina ya vigezo ambavyo kazi hiyo ina. Macros, kwa upande mwingine, zinaweza kuchukua idadi tofauti ya vigezo: tunaweza kuita `println!("hello")` na hoja moja au `println!("hello {}", name)` na hoja mbili. Pia, macros zinapanuliwa kabla ya mkusanyiko kufasiri maana ya msimbo, hivyo macro inaweza, kwa mfano, kutekeleza sifa kwenye aina fulani. Kazi haiwezi, kwa sababu inaitwa wakati wa wakati wa kukimbia na sifa inahitaji kutekelezwa wakati wa mkusanyiko.
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
### Rudia
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
### Sanduku la Kurudi
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Masharti

#### kama
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
#### mechi
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
#### wakati
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
#### kwa
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
#### ikiwa acha
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### wakati acha
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
### Sifa

Unda njia mpya kwa aina
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

Arc inaweza kutumia Clone kuunda marejeleo zaidi juu ya kitu ili kuyapeleka kwa nyuzi. Wakati kiashiria cha mwisho cha rejeleo kwa thamani kinapotoka kwenye upeo, kubadilisha kunafanyika.
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

Katika kesi hii tutapitia nyuzi mabadiliko ya kubadilisha.
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
### Msingi wa Usalama

Rust inatoa dhamana thabiti za usalama wa kumbukumbu kwa chaguo-msingi, lakini bado unaweza kuanzisha udhaifu muhimu kupitia `unsafe` code, matatizo ya utegemezi au makosa ya mantiki. Cheatsheet hii ndogo inakusanya primitives ambazo utagusa mara nyingi wakati wa ukaguzi wa usalama wa mashambulizi au ulinzi wa programu za Rust.

#### Code isiyo salama & usalama wa kumbukumbu

`unsafe` blocks zinakataa ukaguzi wa aliasing na mipaka ya kompyuta, hivyo **makosa yote ya jadi ya kuharibu kumbukumbu (OOB, matumizi baada ya kuachiliwa, kuachiliwa mara mbili, nk.) yanaweza kuonekana tena**. Orodha ya ukaguzi wa haraka:

* Angalia `unsafe` blocks, `extern "C"` functions, simu za `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, viashiria vya kawaida au moduli za `ffi`.
* Thibitisha kila hesabu ya kiashiria na hoja ya urefu inayopitishwa kwa kazi za kiwango cha chini.
* Prefer `#![forbid(unsafe_code)]` (kote kwenye crate) au `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) ili kushindwa kwa uundaji wakati mtu anaporudisha `unsafe`.

Mfano wa overflow ulioanzishwa na viashiria vya kawaida:
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
Kukimbia Miri ni njia ya gharama nafuu kugundua UB wakati wa mtihani:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditing dependencies with RustSec / cargo-audit

Vikosi vingi vya kweli vya Rust vinapatikana katika crates za watu wengine. Hifadhidata ya ushauri ya RustSec (iliyotolewa na jamii) inaweza kuulizwa kwa ndani:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integrate it in CI and fail on `--deny warnings`.

`cargo deny check advisories` offers similar functionality plus licence and ban-list checks.

#### Uthibitisho wa mnyororo wa usambazaji na cargo-vet (2024)

`cargo vet` records a review hash for every crate you import and prevents unnoticed upgrades:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Chombo kinapitishwa na miundombinu ya mradi wa Rust na idadi inayoongezeka ya mashirika ili kupunguza mashambulizi ya vifurushi vilivyo na sumu.

#### Fuzzing uso wako wa API (cargo-fuzz)

Majaribio ya fuzz yanapata kwa urahisi panics, overflows za nambari na makosa ya mantiki ambayo yanaweza kuwa masuala ya DoS au ya upande wa channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Ongeza lengo la fuzz kwenye repo yako na ulifanye katika pipeline yako.

## Marejeleo

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Kukagua Mtegemeo wako wa Rust" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
