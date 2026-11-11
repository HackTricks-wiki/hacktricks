# Βασικά στοιχεία της Rust

{{#include ../banners/hacktricks-training.md}}

### Κυριότητα μεταβλητών

Η μνήμη διαχειρίζεται μέσω ενός συστήματος κυριότητας με τους ακόλουθους κανόνες, τους οποίους ελέγχει ο compiler κατά τη μεταγλώττιση:

1. Κάθε τιμή στη Rust έχει μια μεταβλητή που ονομάζεται κάτοχός της.
2. Κάθε φορά μπορεί να υπάρχει μόνο ένας κάτοχος.
3. Όταν ο κάτοχος βγαίνει εκτός εμβέλειας, η τιμή απορρίπτεται.

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



### Γενικοί τύποι

Δημιουργήστε μια struct όπου μία από τις τιμές της μπορεί να είναι οποιουδήποτε τύπου.

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

Μπορείτε να χρησιμοποιήσετε συναρτήσεις όπως `is_some()` ή `is_none()` για να ελέγξετε την τιμή του `Option`.


### Result, Ok & Err

Χρησιμοποιούνται για την επιστροφή και τη διάδοση σφαλμάτων

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Μπορείτε να χρησιμοποιήσετε συναρτήσεις όπως `is_ok()` ή `is_err()` για να ελέγξετε την τιμή του αποτελέσματος.

Το enum `Option` πρέπει να χρησιμοποιείται σε περιπτώσεις όπου μια τιμή μπορεί να μην υπάρχει (να είναι `None`).
Το enum `Result` πρέπει να χρησιμοποιείται σε περιπτώσεις όπου κάνετε κάτι που μπορεί να πάει στραβά.

### Μακροεντολές

Οι μακροεντολές είναι πιο ισχυρές από τις συναρτήσεις, επειδή επεκτείνονται και παράγουν περισσότερο κώδικα από αυτόν που γράψατε χειροκίνητα. Για παράδειγμα, η υπογραφή μιας συνάρτησης πρέπει να δηλώνει τον αριθμό και τον τύπο των παραμέτρων της. Οι μακροεντολές, από την άλλη, μπορούν να δέχονται μεταβλητό αριθμό παραμέτρων: μπορούμε να καλέσουμε την `println!("hello")` με ένα όρισμα ή την `println!("hello {}", name)` με δύο ορίσματα. Επίσης, οι μακροεντολές επεκτείνονται πριν ο compiler ερμηνεύσει τη σημασία του κώδικα, επομένως μια μακροεντολή μπορεί, για παράδειγμα, να υλοποιήσει ένα trait για έναν συγκεκριμένο τύπο. Μια συνάρτηση δεν μπορεί, επειδή καλείται κατά την εκτέλεση και ένα trait πρέπει να υλοποιείται κατά τη μεταγλώττιση.

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

Ένα αναδρομικό enum χρειάζεται έμμεση αναφορά, ώστε το μέγεθός του να είναι γνωστό κατά τη μεταγλώττιση· η απευθείας αποθήκευση ενός `List` μέσα σε ένα `List` δεν μεταγλωττίζεται.<sup>[[10]](#references)</sup>

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

#### loop (ατέρμονος)

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

Κάντε match στο `Some` για να δεσμεύσετε την εσωτερική του τιμή· ένα απλό μοτίβο μεταβλητής ταιριάζει τόσο με το `Some` όσο και με το `None`, επομένως το σκέλος `else` δεν θα εκτελούνταν ποτέ.<sup>[[11]](#references)</sup>

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

Δημιουργήστε μια νέα μέθοδο για έναν τύπο.

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

### Νηματοποίηση

#### Arc

Ένα Arc μπορεί να χρησιμοποιήσει το Clone για να δημιουργήσει περισσότερες αναφορές στο αντικείμενο και να τις περάσει στα threads. Όταν ο τελευταίος δείκτης αναφοράς σε μια τιμή βγει εκτός εμβέλειας, η μεταβλητή αποδεσμεύεται.

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

Σε αυτή την περίπτωση θα περάσουμε στο thread μια μεταβλητή την οποία θα μπορεί να τροποποιήσει.

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

Η Rust παρέχει ισχυρές εγγυήσεις ασφάλειας μνήμης από προεπιλογή, αλλά εξακολουθείτε να μπορείτε να εισαγάγετε κρίσιμες ευπάθειες μέσω κώδικα `unsafe`, προβλημάτων με εξαρτήσεις ή λογικών σφαλμάτων. Το παρακάτω σύντομο σκονάκι συγκεντρώνει τα στοιχεία που θα χρησιμοποιείτε συχνότερα σε επιθετικές ή αμυντικές αξιολογήσεις ασφάλειας λογισμικού Rust. Για εργαλεία ειδικά για άλλες γλώσσες, δείτε τα [Εργαλεία ελέγχου κώδικα](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Κώδικας `unsafe` και ασφάλεια μνήμης

Το `unsafe` επιτρέπει λειτουργίες των οποίων τις συμβάσεις ασφάλειας δεν μπορεί να αποδείξει ο compiler· **δεν** απενεργοποιεί τους συνήθεις ελέγχους δανεισμού ή ορίων. Η αλλοίωση μνήμης καθίσταται δυνατή όταν μια λειτουργία `unsafe` παραβιάζει τη σύμβασή της, ακόμη και μέσα σε μια συνάρτηση που εκτίθεται ως ασφαλές API.<sup>[[3]](#references)</sup>

Κατά την ανασκόπηση του πηγαίου κώδικα, εντοπίστε τις λειτουργίες χωρίς ελέγχους και παρακολουθήστε τους δείκτες και τα μήκη που ελέγχονται από επιτιθέμενο, ξεκινώντας από τις δημόσιες συναρτήσεις που τις καλούν:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Για το `slice::from_raw_parts`, αποδείξτε ότι ο δείκτης δεν είναι null και είναι σωστά ευθυγραμμισμένος, ότι ολόκληρο το αρχικοποιημένο εύρος βρίσκεται σε μία ζωντανή κατανομή μνήμης και ότι το slice που επιστρέφεται δεν μπορεί να επιβιώσει περισσότερο από αυτήν. Ακόμη και ένα slice μηδενικού μήκους δεν μπορεί να χρησιμοποιεί null δείκτη.
* Για το `Vec::set_len`, αποδείξτε ότι το νέο μήκος δεν υπερβαίνει την πραγματική χωρητικότητα και ότι κάθε στοιχείο που γίνεται πλέον ορατό έχει αρχικοποιηθεί. Παρακολουθήστε τόσο το μέγεθος της κατανομής όσο και τον αριθμό των αντιγραφών· η `with_capacity` δεν αρχικοποιεί στοιχεία.
* Ελέγξτε κάθε `unsafe impl` των `Send` ή `Sync` και κάθε υπογραφή FFI ως προς τις αμετάβλητες συνθήκες που εγγυώνται στους ασφαλείς callers. Το `#![forbid(unsafe_code)]` απορρίπτει τον unsafe κώδικα σε ένα crate· αντίθετα, το `#![deny(unsafe_op_in_unsafe_fn)]` απαιτεί ρητά unsafe blocks **μέσα** σε unsafe functions, χωρίς να απαγορεύει τον unsafe κώδικα. Το τελευταίο lint εμφανίζει προειδοποιήσεις από προεπιλογή στο Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

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
Μια είσοδος μεγαλύτερη από το `dst.capacity()` παραβιάζει τόσο το όριο αντιγραφής όσο και το συμβόλαιο του `set_len` στο παραπάνω παράδειγμα. Προσθέστε μια δοκιμή με είσοδο μεγαλύτερη από την αναμενόμενη για τον allocator-στόχο και, στη συνέχεια, εκτελέστε την υπό το Miri. Το Miri ελέγχει τις διαδρομές κώδικα που εκτελέστηκαν για undefined behavior, αλλά μη υποστηριζόμενες εξωτερικές κλήσεις ενδέχεται να μην του επιτρέψουν να ασκήσει ένα όριο FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Έλεγχος εξαρτήσεων με RustSec / cargo-audit

Οι περισσότερες ευπάθειες Rust στον πραγματικό κόσμο βρίσκονται σε crates τρίτων. Μπορείτε να αναζητήσετε τοπικά στη βάση δεδομένων advisories του RustSec, η οποία υποστηρίζεται από την κοινότητα:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Ενσωματώστε το στο CI και κάντε το να αποτυγχάνει με `--deny warnings`.

Το `cargo deny check advisories` προσφέρει παρόμοια λειτουργικότητα, καθώς και ελέγχους αδειών χρήσης και λίστας απαγορεύσεων.

#### Κάλυψη κώδικα με cargo-tarpaulin

Το `cargo tarpaulin` είναι ένα εργαλείο αναφοράς κάλυψης κώδικα για το σύστημα build του Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Στο Linux, το προεπιλεγμένο backend tracing του Tarpaulin εξακολουθεί να είναι το Ptrace και λειτουργεί μόνο σε επεξεργαστές x86_64. Αυτό μπορεί να αλλάξει σε instrumentation κάλυψης llvm με `--engine llvm`. Για Mac και Windows, αυτή είναι η προεπιλεγμένη μέθοδος συλλογής.

#### Επαλήθευση supply-chain με cargo-vet

Το `cargo vet` ελέγχει τις εξαρτήσεις σύμφωνα με διαμορφωμένα κριτήρια audit, χρησιμοποιώντας τοπικά audits, έμπιστες εισαγωγές ή ρητές εξαιρέσεις. Το `cargo vet init` δημιουργεί τα μεταδεδομένα `supply-chain/` και εξαιρεί τις υπάρχουσες εξαρτήσεις που δεν έχουν υποβληθεί σε audit, επομένως ένας αρχικά επιτυχής έλεγχος **δεν** σημαίνει ότι έχει εξεταστεί κάθε crate. Εξετάστε τις εξαιρέσεις και χρησιμοποιήστε το `cargo vet suggest` για να τις ελέγξετε· το `--locked` αποφεύγει την ανανέωση των εισαγόμενων συνόλων audit.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing της επιφάνειας API σας (cargo-fuzz)

Οι στόχοι fuzzing δοκιμάζουν το API με παραγόμενες εισόδους και μπορούν να αποκαλύψουν panics και σφάλματα ασφάλειας μνήμης. Ο παραγόμενος στόχος βρίσκεται στο `fuzz/fuzz_targets/`· αντικαταστήστε το προεπιλεγμένο σώμα του με μια κλήση στο API που εξετάζετε πριν τον εκτελέσετε.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Προσθέστε τον fuzz target στο repo σας και εκτελέστε τον στο pipeline σας.

## References

- [1] [Βάση δεδομένων συμβουλών ασφαλείας RustSec](https://rustsec.org)
- [2] [Cargo-vet: «Έλεγχος των εξαρτήσεων Rust»](https://mozilla.github.io/cargo-vet/)
- [3] [Η γλώσσα προγραμματισμού Rust: Μη ασφαλής Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README του Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: προειδοποίηση unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Εντολές Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Βιβλίο Rust Fuzz: οδηγός cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Η γλώσσα προγραμματισμού Rust: Box και αναδρομικοί τύποι](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Η γλώσσα προγραμματισμού Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: unsafe extern blocks](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
