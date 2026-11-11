# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### Ownership of variables

Memory is managed through a system of ownership with the following rules that the compiler checks at compile time:

1. Each value in Rust has a variable that's called its owner.
2. There can only be one owner at a time.
3. When the owner goes out of scope, the value will be dropped.

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

Create a struct where 1 of their values could be any type

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

The Option type means that the value might by of type Some (there is something) or None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

You can use functions such as `is_some()` or `is_none()` to check the value of the Option.


### Result, Ok & Err

Used for returning and propagating errors

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

Macros are more powerful than functions because they expand to produce more code than the code you’ve written manually. For example, a function signature must declare the number and type of parameters the function has. Macros, on the other hand, can take a variable number of parameters: we can call `println!("hello")` with one argument or `println!("hello {}", name)` with two arguments. Also, macros are expanded before the compiler interprets the meaning of the code, so a macro can, for example, implement a trait on a given type. A function can’t, because it gets called at runtime and a trait needs to be implemented at compile time.

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

### Iterate

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

A recursive enum needs indirection so its size is known at compile time; storing `List` directly inside `List` does not compile.<sup>[[10]](#references)</sup>

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

### Conditionals

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

Match `Some` to bind its inner value; a plain variable pattern matches both `Some` and `None`, so the `else` branch would never run.<sup>[[11]](#references)</sup>

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

Create a new method for a type

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

An Arc can use Clone to create more references over the object to pass them to the threads. When the last reference pointer to a value is out of scope, the variable is dropped.

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

In this case we will pass the thread a variable it will be able to modify

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

Rust provides strong memory-safety guarantees by default, but you can still introduce critical vulnerabilities through `unsafe` code, dependency issues or logic mistakes. The following mini-cheatsheet gathers the primitives you will most commonly touch during offensive or defensive security reviews of Rust software. For other language-specific tooling, see [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Unsafe code & memory safety

`unsafe` permits operations whose safety contracts the compiler cannot prove; it does **not** turn off ordinary borrow or bounds checks. Memory corruption becomes possible when an unsafe operation violates its contract, including inside a function exposed as a safe API.<sup>[[3]](#references)</sup>

For a source review, find the unchecked operations and trace attacker-controlled pointers and lengths from their public callers:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* For `slice::from_raw_parts`, prove the pointer is non-null and aligned, the **whole** initialized range is in one live allocation, and the returned slice cannot outlive it. Even a zero-length slice cannot use a null pointer.
* For `Vec::set_len`, prove the new length fits the actual capacity and every newly exposed element was initialized. Trace both the allocation size and any copy count; `with_capacity` does not initialize elements.
* Check every `unsafe impl` of `Send` or `Sync` and each FFI signature against the invariants promised to safe callers. `#![forbid(unsafe_code)]` rejects unsafe code in a crate; `#![deny(unsafe_op_in_unsafe_fn)]` instead requires explicit unsafe blocks **inside** unsafe functions, not a ban on unsafe code. The latter lint warns by default in Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

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
An input longer than `dst.capacity()` violates both the copy bound and the `set_len` contract in the example above. Add a test with an oversized input for the target allocator, then run it under Miri. Miri checks executed paths for undefined behavior, but unsupported foreign calls may prevent it from exercising an FFI boundary.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Auditing dependencies with RustSec / cargo-audit

Most real-world Rust vulns live in third-party crates. The RustSec advisory DB (community-powered) can be queried locally:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integrate it in CI and fail on `--deny warnings`.

`cargo deny check advisories` offers similar functionality plus licence and ban-list checks.

#### Code coverage with cargo-tarpaulin

`cargo tarpaulin` is a code coverage reporting tool for the Cargo build system

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
On Linux, Tarpaulin's default tracing backend is still Ptrace and will only work on x86_64 processors. This can be changed to the llvm coverage instrumentation with `--engine llvm`. For Mac and Windows, this is the default collection method.

#### Supply-chain verification with cargo-vet

`cargo vet` checks dependencies against configured audit criteria using local audits, trusted imports, or explicit exemptions. `cargo vet init` creates `supply-chain/` metadata and exempts existing unaudited dependencies, so an initially passing check does **not** mean every crate has been reviewed. Examine exemptions and use `cargo vet suggest` to work through them; `--locked` avoids refreshing imported audit sets.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing your API surface (cargo-fuzz)

Fuzz targets exercise the API with generated inputs and can expose panics and memory-safety faults. The generated target lives under `fuzz/fuzz_targets/`; replace its default body with a call to the API under review before running it.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Add the fuzz target to your repo and run it in your pipeline.



## References

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: "Auditing your Rust Dependencies"](https://mozilla.github.io/cargo-vet/)
- [3] [The Rust Programming Language: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: unsafe_op_in_unsafe_fn warning](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet commands](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: cargo-fuzz tutorial](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [The Rust Programming Language: Box and recursive types](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [The Rust Programming Language: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)

- [12] [Rust 2024: Unsafe extern blocks](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
