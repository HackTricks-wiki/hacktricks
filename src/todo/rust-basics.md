# Βασικές αρχές του Rust

{{#include ../banners/hacktricks-training.md}}

### Ownership των μεταβλητών

Η μνήμη διαχειρίζεται μέσω ενός συστήματος ownership με τους ακόλουθους κανόνες, τους οποίους ο compiler ελέγχει κατά τον χρόνο μεταγλώττισης:

1. Κάθε value στο Rust έχει μια μεταβλητή που ονομάζεται owner του.
2. Μπορεί να υπάρχει μόνο ένας owner κάθε φορά.
3. Όταν ο owner βγει εκτός scope, το value αποδεσμεύεται.
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
### Γενικοί Τύποι

Δημιουργήστε ένα struct όπου μία από τις τιμές του θα μπορούσε να είναι οποιουδήποτε τύπου
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

Ο τύπος Option σημαίνει ότι η τιμή μπορεί να είναι τύπου Some (υπάρχει κάτι) ή None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Μπορείτε να χρησιμοποιήσετε συναρτήσεις όπως οι `is_some()` ή `is_none()` για να ελέγξετε την τιμή του Option.


### Result, Ok & Err

Χρησιμοποιείται για την επιστροφή και τη διάδοση σφαλμάτων
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
Μπορείτε να χρησιμοποιήσετε συναρτήσεις όπως οι `is_ok()` ή `is_err()` για να ελέγξετε την τιμή του αποτελέσματος

Το enum `Option` θα πρέπει να χρησιμοποιείται σε περιπτώσεις όπου μια τιμή μπορεί να μην υπάρχει (να είναι `None`).
Το enum `Result` θα πρέπει να χρησιμοποιείται σε περιπτώσεις όπου κάνετε κάτι που μπορεί να αποτύχει


### Μακροεντολές

Οι μακροεντολές είναι πιο ισχυρές από τις συναρτήσεις, επειδή επεκτείνονται για να παράγουν περισσότερο κώδικα από αυτόν που έχετε γράψει χειροκίνητα. Για παράδειγμα, η υπογραφή μιας συνάρτησης πρέπει να δηλώνει τον αριθμό και τον τύπο των παραμέτρων που έχει η συνάρτηση. Οι μακροεντολές, από την άλλη πλευρά, μπορούν να δέχονται μεταβλητό αριθμό παραμέτρων: μπορούμε να καλέσουμε την `println!("hello")` με ένα όρισμα ή την `println!("hello {}", name)` με δύο ορίσματα. Επίσης, οι μακροεντολές επεκτείνονται πριν ο compiler ερμηνεύσει τη σημασία του κώδικα, επομένως μια μακροεντολή μπορεί, για παράδειγμα, να υλοποιήσει ένα trait για έναν δεδομένο τύπο. Μια συνάρτηση δεν μπορεί να το κάνει, επειδή καλείται στο runtime και ένα trait πρέπει να υλοποιηθεί κατά το compile time.
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
### Επανάληψη
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
### Συνθήκες

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
#### βρόχος (άπειρος)
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
#### για
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

Δημιουργήστε μια νέα μέθοδο για έναν τύπο
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
### Δοκιμές
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

Ένα Arc μπορεί να χρησιμοποιήσει το Clone για να δημιουργήσει περισσότερες αναφορές στο object και να τις περάσει στα threads. Όταν ο τελευταίος pointer αναφοράς σε μια τιμή βγει εκτός scope, η μεταβλητή διαγράφεται.
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

Σε αυτή την περίπτωση θα περάσουμε στο thread μια μεταβλητή που θα μπορεί να τροποποιήσει
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
### Βασικές αρχές ασφάλειας

Η Rust παρέχει από προεπιλογή ισχυρές εγγυήσεις memory safety, αλλά εξακολουθείτε να μπορείτε να εισαγάγετε κρίσιμες ευπάθειες μέσω κώδικα `unsafe`, προβλημάτων dependencies ή λογικών λαθών. Το ακόλουθο mini-cheatsheet συγκεντρώνει τα primitives με τα οποία θα αλληλεπιδράτε συχνότερα κατά τη διάρκεια offensive ή defensive security reviews λογισμικού Rust.

#### Κώδικας `unsafe` και memory safety

Τα blocks `unsafe` παρακάμπτουν τους ελέγχους aliasing και ορίων του compiler, επομένως **όλα τα παραδοσιακά memory-corruption bugs (OOB, use-after-free, double free κ.λπ.) μπορούν να εμφανιστούν ξανά**. Μια σύντομη checklist για audit:

* Αναζητήστε blocks `unsafe`, συναρτήσεις `extern "C"`, κλήσεις σε `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers ή modules `ffi`.
* Επικυρώστε κάθε pointer arithmetic και κάθε length argument που περνά σε low-level functions.
* Προτιμήστε `#![forbid(unsafe_code)]` (σε ολόκληρο το crate) ή `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +), ώστε η compilation να αποτυγχάνει όταν κάποιος εισάγει ξανά `unsafe`.

Παράδειγμα overflow που δημιουργείται με raw pointers:
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
Η εκτέλεση του Miri είναι ένας οικονομικός τρόπος εντοπισμού UB κατά τον χρόνο εκτέλεσης των tests:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditing dependencies with RustSec / cargo-audit

Οι περισσότερες πραγματικές ευπάθειες στο Rust βρίσκονται σε crates τρίτων. Η advisory DB του RustSec (υποστηριζόμενη από την κοινότητα) μπορεί να υποβληθεί σε ερωτήματα τοπικά:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Ενσωματώστε το στο CI και αποτύχετε με το `--deny warnings`.

Το `cargo deny check advisories` προσφέρει παρόμοια λειτουργικότητα, καθώς και ελέγχους αδειών και λιστών απαγορεύσεων.

#### Κάλυψη κώδικα με cargo-tarpaulin

Το `cargo tarpaulin` είναι ένα εργαλείο αναφοράς κάλυψης κώδικα για το σύστημα build του Cargo.
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Στο Linux, το προεπιλεγμένο tracing backend του Tarpaulin εξακολουθεί να είναι το Ptrace και λειτουργεί μόνο σε επεξεργαστές x86_64. Αυτό μπορεί να αλλάξει σε llvm coverage instrumentation με το `--engine llvm`. Για Mac και Windows, αυτή είναι η προεπιλεγμένη μέθοδος συλλογής.

#### Επαλήθευση supply-chain με cargo-vet (2024)

Το `cargo vet` καταγράφει ένα review hash για κάθε crate που κάνετε import και αποτρέπει αναβαθμίσεις χωρίς να γίνουν αντιληπτές:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Το εργαλείο υιοθετείται από την υποδομή του Rust project και έναν αυξανόμενο αριθμό orgs για τον μετριασμό επιθέσεων poisoned-package.<sup>[[2]](#references)</sup>

#### Fuzzing του API surface (cargo-fuzz)

Τα Fuzz tests εντοπίζουν εύκολα panics, integer overflows και logic bugs που ενδέχεται να οδηγήσουν σε DoS ή προβλήματα side-channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Προσθέστε το fuzz target στο repo σας και εκτελέστε το στο pipeline σας.

## Αναφορές

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: Έλεγχος των Rust Dependencies](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
