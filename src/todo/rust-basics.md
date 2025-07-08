# Rust Basics

{{#include /banners/hacktricks-training.md}}

### Γενικοί Τύποι

Δημιουργήστε μια δομή όπου 1 από τις τιμές τους θα μπορούσε να είναι οποιοσδήποτε τύπος
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
Μπορείτε να χρησιμοποιήσετε συναρτήσεις όπως `is_some()` ή `is_none()` για να ελέγξετε την τιμή της Option.

### Μακροεντολές

Οι μακροεντολές είναι πιο ισχυρές από τις συναρτήσεις επειδή επεκτείνονται για να παράγουν περισσότερο κώδικα από τον κώδικα που έχετε γράψει χειροκίνητα. Για παράδειγμα, μια υπογραφή συνάρτησης πρέπει να δηλώνει τον αριθμό και τον τύπο των παραμέτρων που έχει η συνάρτηση. Οι μακροεντολές, από την άλλη πλευρά, μπορούν να δέχονται μεταβλητό αριθμό παραμέτρων: μπορούμε να καλέσουμε `println!("hello")` με ένα επιχείρημα ή `println!("hello {}", name)` με δύο επιχειρήματα. Επίσης, οι μακροεντολές επεκτείνονται πριν ο μεταγλωττιστής ερμηνεύσει τη σημασία του κώδικα, έτσι μια μακροεντολή μπορεί, για παράδειγμα, να υλοποιήσει ένα trait σε έναν δεδομένο τύπο. Μια συνάρτηση δεν μπορεί, επειδή καλείται κατά την εκτέλεση και ένα trait πρέπει να υλοποιείται κατά τη διάρκεια της μεταγλώττισης.
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
### Επαναλάβετε
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
### Αναδρομικό Κουτί
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Συνθήκες

#### αν
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
#### αντιστοιχία
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
#### ενώ
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
#### αν ας
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### ενώ ας
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
### Θρέισινγκ

#### Arc

Ένα Arc μπορεί να χρησιμοποιήσει το Clone για να δημιουργήσει περισσότερες αναφορές πάνω στο αντικείμενο για να τις περάσει στα νήματα. Όταν ο τελευταίος δείκτης αναφοράς σε μια τιμή βγει εκτός πεδίου, η μεταβλητή απορρίπτεται.
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

Σε αυτή την περίπτωση θα περάσουμε στο νήμα μια μεταβλητή που θα μπορεί να τροποποιήσει
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
{{#include /banners/hacktricks-training.md}}
