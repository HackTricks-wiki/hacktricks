# Rust 기초

{{#include ../banners/hacktricks-training.md}}

### 변수의 소유권

메모리는 소유권 시스템을 통해 관리되며, 컴파일러가 컴파일 시간에 검사하는 다음 규칙들이 있습니다:

1. Rust의 각 값에는 소유자라고 불리는 변수가 있습니다.
2. 한 번에 하나의 소유자만 있을 수 있습니다.
3. 소유자가 스코프를 벗어나면 해당 값은 해제됩니다.
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

값 중 하나가 어떤 타입이든 될 수 있는 struct를 생성하세요
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

Option 타입은 값이 Some(무언가 있음) 또는 None일 수 있음을 의미합니다:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
`is_some()` 또는 `is_none()` 같은 함수를 사용하여 Option의 값을 확인할 수 있습니다.


### Result, Ok & Err

오류를 반환하고 전파하는 데 사용됩니다.
```rust
pub enum Result<T, E> {
Ok(T),
Err(E),
}
```
You can use functions such as `is_ok()` or `is_err()` to check the value of the result

결과의 값을 확인하려면 `is_ok()` 또는 `is_err()` 같은 함수를 사용할 수 있습니다.

The `Option` enum should be used in situations where a value might not exist (be `None`).
The `Result` enum should be used in situations where you do something that might go wrong

값이 존재하지 않을 수 있는 상황(즉 `None`일 수 있는 경우)에는 `Option` enum을 사용해야 합니다. 문제가 발생할 수 있는 작업을 할 때는 `Result` enum을 사용해야 합니다.

### 매크로

매크로는 수동으로 작성한 코드보다 더 많은 코드를 생성하도록 확장되기 때문에 함수보다 더 강력합니다. 예를 들어, 함수 시그니처는 함수가 갖는 매개변수의 개수와 타입을 선언해야 합니다. 반면 매크로는 가변 개수의 매개변수를 받을 수 있습니다: `println!("hello")`처럼 인수를 하나만 주거나 `println!("hello {}", name)`처럼 두 개를 줄 수 있습니다. 또한 매크로는 컴파일러가 코드의 의미를 해석하기 전에 확장되므로, 예를 들어 매크로는 주어진 타입에 trait을 구현할 수 있습니다. 함수는 그렇지 못한데, 함수는 런타임에 호출되고 trait은 컴파일 타임에 구현되어야 하기 때문입니다.
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
### 반복
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
### 재귀 박스
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
#### 루프 (무한)
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
### 트레잇

타입에 새 메서드 추가
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
### 테스트
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

Arc는 Clone을 사용해 객체에 대한 참조를 더 만들어 스레드에 전달할 수 있다. 값에 대한 마지막 참조가 스코프를 벗어나면 해당 변수는 해제된다.
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

이 경우 thread에 수정 가능한 변수를 전달합니다.
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

Rust는 기본적으로 강력한 메모리 안전 보장을 제공하지만, `unsafe` 코드, 의존성 문제 또는 논리 실수로 인해 여전히 치명적인 취약점을 도입할 수 있습니다. 다음 미니 치트시트는 Rust 소프트웨어의 공격적 또는 방어적 보안 검토에서 가장 자주 접하게 될 기본 요소들을 모은 것입니다.

#### Unsafe 코드 및 메모리 안전

`unsafe` 블록은 컴파일러의 별칭(aliasing) 및 경계(bounds) 검사에서 벗어나므로 **모든 전통적인 메모리 손상 버그 (OOB, use-after-free, double free 등)가 다시 나타날 수 있습니다**. 빠른 감사 체크리스트:

* `unsafe` 블록, `extern "C"` 함수, `ptr::copy*` 호출, `std::mem::transmute`, `MaybeUninit`, 원시 포인터 또는 `ffi` 모듈을 찾아보세요.
* 저수준 함수에 전달되는 모든 포인터 산술(pointer arithmetic) 및 길이 인수를 검증하세요.
* 누군가 `unsafe`를 재도입할 때 컴파일 실패를 유도하려면 crate 전체에 `#![forbid(unsafe_code)]` 또는 (1.68 이상) `#[deny(unsafe_op_in_unsafe_fn)]`를 사용하는 것을 권장합니다.

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
Miri를 실행하는 것은 테스트 시점에 UB를 감지하는 저렴한 방법입니다:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### RustSec / cargo-audit로 종속성 감사

실제 환경의 대부분 Rust vulns는 서드파티 crates에 존재합니다. RustSec advisory DB(community-powered)는 로컬에서 조회할 수 있습니다:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI에 통합하고 `--deny warnings`로 경고 시 실패하도록 설정하세요.

`cargo deny check advisories`는 유사한 기능을 제공하며 라이선스 및 금지 목록 검사를 추가로 수행합니다.

#### cargo-tarpaulin으로 코드 커버리지

`cargo tarpaulin`은 Cargo 빌드 시스템용 코드 커버리지 리포팅 도구입니다.
```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux에서는 Tarpaulin의 기본 트레이싱 백엔드가 여전히 Ptrace이며 x86_64 프로세서에서만 작동합니다. 이는 `--engine llvm`로 llvm coverage instrumentation으로 변경할 수 있습니다. Mac과 Windows에서는 이것이 기본 수집 방법입니다.

#### 공급망 검증 cargo-vet 사용 (2024)

`cargo vet`는 임포트하는 각 crate에 대한 검토 해시를 기록하고 눈치채지 못한 업그레이드를 방지합니다:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
이 도구는 Rust 프로젝트 인프라와 점점 더 많은 조직에서 poisoned-package attacks를 완화하기 위해 채택되고 있습니다.

#### Fuzzing 귀하의 API 표면 (cargo-fuzz)

Fuzz 테스트는 panics, integer overflows 및 논리 버그를 쉽게 찾아내며, 이는 DoS 또는 side-channel 문제로 이어질 수 있습니다:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
fuzz target을 repo에 추가하고 pipeline에서 실행하세요.

## 참고 자료

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
