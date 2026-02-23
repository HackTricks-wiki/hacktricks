# Rust Βασικά

{{#include ../banners/hacktricks-training.md}}

### Ιδιοκτησία μεταβλητών

Η μνήμη διαχειρίζεται μέσω ενός συστήματος ιδιοκτησίας με τους ακόλουθους κανόνες που ο μεταγλωττιστής ελέγχει κατά το χρόνο μεταγλώττισης:

1. Κάθε τιμή στο Rust έχει μια μεταβλητή που ονομάζεται ιδιοκτήτης της.
2. Μπορεί να υπάρχει μόνο ένας ιδιοκτήτης κάθε φορά.
3. Όταν ο ιδιοκτήτης βγαίνει εκτός πεδίου ορατότητας, η τιμή θα αποδεσμευτεί.
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

Δημιούργησε μια struct όπου 1 από τις τιμές της μπορεί να είναι οποιουδήποτε τύπου
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

Ο τύπος Option σημαίνει ότι η τιμή μπορεί να είναι του τύπου Some (υπάρχει κάτι) ή None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Μπορείτε να χρησιμοποιήσετε συναρτήσεις όπως `is_some()` ή `is_none()` για να ελέγξετε την τιμή του Option.


### Result, Ok & Err

Χρησιμοποιούνται για την επιστροφή και τη διάδοση σφαλμάτων
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
You can use functions such as `is_ok()` or `is_err()` to check the value of the result

The `Option` enum should be used in situations where a value might not exist (be `None`).
The `Result` enum should be used in situations where you do something that might go wrong


### Macros

Τα macros είναι πιο ισχυρά από τις συναρτήσεις επειδή επεκτείνονται για να παράγουν περισσότερο κώδικα από αυτόν που έχετε γράψει χειροκίνητα. Για παράδειγμα, η υπογραφή μιας συνάρτησης πρέπει να δηλώνει τον αριθμό και τον τύπο των παραμέτρων που έχει η συνάρτηση. Τα macros, από την άλλη, μπορούν να πάρουν μεταβλητό αριθμό παραμέτρων: μπορούμε να καλέσουμε `println!("hello")` με ένα όρισμα ή `println!("hello {}", name)` με δύο ορίσματα. Επίσης, τα macros επεκτείνονται πριν ο compiler ερμηνεύσει το νόημα του κώδικα, οπότε ένα macro μπορεί, για παράδειγμα, να εφαρμόσει ένα trait σε έναν συγκεκριμένο τύπο. Μια συνάρτηση δεν μπορεί, επειδή καλείται σε runtime και ένα trait πρέπει να υλοποιηθεί σε compile time.
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
### Αναδρομικό Box
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Δομές επιλογής

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
#### βρόχος (ατέρμονος)
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
### Χαρακτηριστικά

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
### Νήματα

#### Arc

Ένα Arc μπορεί να χρησιμοποιήσει Clone για να δημιουργήσει περισσότερες αναφορές προς το αντικείμενο, ώστε να τις περάσει στα νήματα. Όταν ο τελευταίος δείκτης αναφοράς σε μια τιμή βγει εκτός πεδίου ορατότητας, η μεταβλητή απελευθερώνεται.
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
#### Νήματα

Σε αυτή την περίπτωση θα δώσουμε στο νήμα μια μεταβλητή την οποία θα μπορεί να τροποποιήσει
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
### Βασικά στοιχεία ασφάλειας

Η Rust παρέχει ισχυρές εγγυήσεις ασφάλειας μνήμης από προεπιλογή, αλλά μπορείτε να εισαγάγετε κρίσιμες ευπάθειες μέσω `unsafe` κώδικα, προβλημάτων εξαρτήσεων ή λογικών σφαλμάτων. Το παρακάτω σύντομο cheat-sheet συγκεντρώνει τις βασικές έννοιες που θα συναντήσετε πιο συχνά κατά τις επιθετικές ή αμυντικές ανασκοπήσεις ασφαλείας λογισμικού Rust.

#### Κώδικας `unsafe` & ασφάλεια μνήμης

Τα blocks `unsafe` απενεργοποιούν τους ελέγχους aliasing και ορίων του μεταγλωττιστή, οπότε **όλα τα παραδοσιακά σφάλματα διαφθοράς μνήμης (OOB, use-after-free, double free, κ.λπ.) μπορούν να εμφανιστούν ξανά**. Σύντομη λίστα ελέγχου:

* Ψάξτε για `unsafe` blocks, `extern "C"` functions, κλήσεις σε `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers ή `ffi` modules.
* Επαληθεύστε κάθε αριθμητική πράξη δεικτών και κάθε όρισμα μήκους που δίδεται σε χαμηλού επιπέδου συναρτήσεις.
* Προτιμήστε `#![forbid(unsafe_code)]` (σε όλο το crate) ή `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +) ώστε να αποτυγχάνει η μεταγλώττιση όταν κάποιος επανεισάγει `unsafe`.

Παράδειγμα overflow που δημιουργήθηκε με raw pointers:
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
Η εκτέλεση του Miri είναι ένας οικονομικός τρόπος για τον εντοπισμό UB κατά το χρόνο των δοκιμών:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Έλεγχος εξαρτήσεων με RustSec / cargo-audit

Τα περισσότερα πραγματικά Rust vulns βρίσκονται σε crates τρίτων. Το RustSec advisory DB (που τροφοδοτείται από την κοινότητα) μπορεί να ερωτηθεί τοπικά:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Ενσωματώστε το στο CI και κάντε το να αποτυγχάνει με `--deny warnings`.

`cargo deny check advisories` προσφέρει παρόμοια λειτουργικότητα καθώς και ελέγχους αδειών και λίστας αποκλεισμού.

#### Κάλυψη κώδικα με cargo-tarpaulin

`cargo tarpaulin` είναι ένα εργαλείο αναφοράς κάλυψης κώδικα για το σύστημα build του Cargo
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Σε Linux, το προεπιλεγμένο tracing backend του Tarpaulin εξακολουθεί να είναι το Ptrace και θα λειτουργεί μόνο σε επεξεργαστές x86_64. Αυτό μπορεί να αλλάξει στην llvm coverage instrumentation με `--engine llvm`. Σε Mac και Windows, αυτή είναι η προεπιλεγμένη μέθοδος συλλογής.

#### Επαλήθευση αλυσίδας εφοδιασμού με cargo-vet (2024)

`cargo vet` καταγράφει ένα review hash για κάθε crate που εισάγετε και αποτρέπει απαρατήρητες αναβαθμίσεις:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Το εργαλείο υιοθετείται από την υποδομή του έργου Rust και από έναν αυξανόμενο αριθμό οργανισμών για να μετριάσει τα poisoned-package attacks.

#### Fuzzing την επιφάνεια του API σας (cargo-fuzz)

Τα Fuzz tests εντοπίζουν εύκολα panics, integer overflows και logic bugs που μπορεί να εξελιχθούν σε ζητήματα DoS ή side-channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Πρόσθεσε το fuzz target στο repo σου και τρέξε το στο pipeline σου.

## Αναφορές

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
