# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### 변수의 Ownership

Memory는 다음 규칙에 따라 compiler가 compile time에 확인하는 Ownership system을 통해 관리됩니다:

1. Rust의 각 value에는 owner라고 하는 variable이 있습니다.
2. 한 번에 하나의 owner만 존재할 수 있습니다.
3. owner가 scope를 벗어나면 value는 dropped됩니다.
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

값 중 하나가 어떤 타입이든 될 수 있는 struct를 생성합니다
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

Option 타입은 값이 Some 타입(무언가 있음)이거나 None일 수 있음을 의미합니다:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
`is_some()` 또는 `is_none()`과 같은 함수를 사용하여 Option의 값을 확인할 수 있습니다.


### Result, Ok & Err

오류를 반환하고 전파하는 데 사용됩니다.
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
`is_ok()` 또는 `is_err()`와 같은 함수를 사용하여 result의 값을 확인할 수 있습니다.

`Option` enum은 값이 존재하지 않을 수 있는(`None`일 수 있는) 상황에서 사용해야 합니다.
`Result` enum은 수행하려는 작업이 실패할 수 있는 상황에서 사용해야 합니다.


### 매크로

매크로는 작성한 코드보다 더 많은 코드를 생성하도록 확장되기 때문에 함수보다 강력합니다. 예를 들어 함수 시그니처에는 함수가 받는 매개변수의 개수와 타입을 선언해야 합니다. 반면 매크로는 가변 개수의 매개변수를 받을 수 있습니다. `println!("hello")`처럼 인수 하나를 사용하여 호출할 수도 있고, `println!("hello {}", name)`처럼 인수 두 개를 사용하여 호출할 수도 있습니다. 또한 매크로는 compiler가 코드의 의미를 해석하기 전에 확장되므로, 매크로는 예를 들어 주어진 타입에 trait를 구현할 수 있습니다. 함수는 runtime에 호출되고 trait는 compile time에 구현되어야 하므로 그렇게 할 수 없습니다.
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
### 반복하기
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
### 재귀 Box
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### 조건문

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
#### loop (무한)
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

type을 위한 새로운 method를 생성합니다
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
### 스레딩

#### Arc

Arc는 Clone을 사용하여 객체에 대한 참조를 추가로 생성하고, 이를 스레드에 전달할 수 있습니다. 값에 대한 마지막 참조 포인터가 스코프를 벗어나면 변수가 drop됩니다.
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

이 경우 thread가 수정할 수 있는 변수를 thread에 전달합니다.
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
### 보안 필수 사항

Rust는 기본적으로 강력한 memory-safety 보장을 제공하지만, `unsafe` code, dependency 문제 또는 logic 실수를 통해 여전히 치명적인 vulnerability를 도입할 수 있습니다. 다음 mini-cheatsheet는 Rust software에 대한 offensive 또는 defensive security review에서 가장 자주 다루게 될 primitives를 정리한 것입니다.

#### Unsafe code 및 memory safety

`unsafe` blocks는 compiler의 aliasing 및 bounds checks를 비활성화하므로, **모든 전통적인 memory-corruption bugs (OOB, use-after-free, double free 등)가 다시 발생할 수 있습니다**. 빠른 audit checklist:

* `unsafe` blocks, `extern "C"` functions, `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointers 또는 `ffi` modules를 사용하는 부분을 찾습니다.
* low-level functions에 전달되는 모든 pointer arithmetic 및 length arguments를 검증합니다.
* 누군가 `unsafe`를 다시 도입했을 때 compilation이 실패하도록 `#![forbid(unsafe_code)]` (crate 전체) 또는 `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 이상)을 우선 사용합니다.

raw pointers로 생성된 overflow 예제:
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
Miri를 실행하는 것은 테스트 시점에 UB를 감지하는 비용이 적게 드는 방법입니다:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit로 dependencies 감사

실제 환경의 Rust 취약점 대부분은 third-party crates에 존재합니다. 커뮤니티가 관리하는 RustSec advisory DB는 로컬에서 조회할 수 있습니다:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI에 통합하고 `--deny warnings`에서 실패하도록 설정합니다.

`cargo deny check advisories`는 유사한 기능과 함께 라이선스 및 ban-list 검사도 제공합니다.

#### cargo-tarpaulin을 사용한 code coverage

`cargo tarpaulin`은 Cargo 빌드 시스템을 위한 code coverage 보고 도구입니다
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux에서 Tarpaulin의 기본 tracing backend는 여전히 Ptrace이며 x86_64 프로세서에서만 작동합니다. `--engine llvm`을 사용하면 llvm coverage instrumentation으로 변경할 수 있습니다. Mac과 Windows에서는 이것이 기본 collection method입니다.

#### cargo-vet을 사용한 supply-chain verification (2024)

`cargo vet`은 가져오는 모든 crate에 대한 review hash를 기록하고, 인지하지 못한 upgrades를 방지합니다:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
이 tool은 Rust project infrastructure와 점점 더 많은 orgs에서 poisoned-package attacks를 완화하기 위해 도입되고 있습니다.<sup>[[2]](#references)</sup>

#### API surface Fuzzing (cargo-fuzz)

Fuzz tests는 DoS 또는 side-channel issues로 이어질 수 있는 panics, integer overflows 및 logic bugs를 쉽게 탐지합니다:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
리포지토리에 fuzz target을 추가하고 pipeline에서 실행하세요.

## 참고 자료

- [1] [RustSec Advisory Database](https://rustsec.org)
- [2] [Cargo-vet: Auditing your Rust Dependencies](https://mozilla.github.io/cargo-vet/)

{{#include ../banners/hacktricks-training.md}}
