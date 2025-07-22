# Rust Basics

{{#include ../banners/hacktricks-training.md}}

### Generic Types

값 중 하나가 어떤 타입이 될 수 있는 struct를 만듭니다.
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

Option 타입은 값이 Some 타입일 수도 있고 (무언가가 있음) None일 수도 있음을 의미합니다:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
`is_some()` 또는 `is_none()`와 같은 함수를 사용하여 Option의 값을 확인할 수 있습니다.

### 매크로

매크로는 수동으로 작성한 코드보다 더 많은 코드를 생성하기 때문에 함수보다 더 강력합니다. 예를 들어, 함수 시그니처는 함수가 가진 매개변수의 수와 유형을 선언해야 합니다. 반면에 매크로는 가변 개수의 매개변수를 받을 수 있습니다: `println!("hello")`를 하나의 인수로 호출하거나 `println!("hello {}", name)`을 두 개의 인수로 호출할 수 있습니다. 또한, 매크로는 컴파일러가 코드의 의미를 해석하기 전에 확장되므로, 매크로는 예를 들어 주어진 유형에 대해 트레이트를 구현할 수 있습니다. 함수는 런타임에 호출되기 때문에 트레이트를 컴파일 타임에 구현할 수 없습니다.
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
### 반복하다
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
#### 일치
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
### 특성

타입을 위한 새로운 메서드 생성
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

Arc는 Clone을 사용하여 객체에 대한 더 많은 참조를 생성하고 이를 스레드에 전달할 수 있습니다. 값에 대한 마지막 참조 포인터가 범위를 벗어나면 변수가 삭제됩니다.
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

이 경우 스레드에 수정할 수 있는 변수를 전달할 것입니다.
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

Rust는 기본적으로 강력한 메모리 안전성을 보장하지만, 여전히 `unsafe` 코드, 의존성 문제 또는 논리적 실수를 통해 치명적인 취약점을 도입할 수 있습니다. 다음 미니 치트시트는 Rust 소프트웨어의 공격적 또는 방어적 보안 검토 중 가장 일반적으로 접하게 될 원시 요소들을 모아놓았습니다.

#### Unsafe code & memory safety

`unsafe` 블록은 컴파일러의 별칭 및 경계 검사를 선택 해제하므로 **모든 전통적인 메모리 손상 버그(OOB, use-after-free, double free 등)가 다시 나타날 수 있습니다**. 빠른 감사 체크리스트:

* `unsafe` 블록, `extern "C"` 함수, `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, 원시 포인터 또는 `ffi` 모듈을 찾으세요.
* 저수준 함수에 전달되는 모든 포인터 산술 및 길이 인수를 검증하세요.
* 누군가 `unsafe`를 다시 도입할 때 컴파일이 실패하도록 `#![forbid(unsafe_code)]` (크레이트 전체) 또는 `#[deny(unsafe_op_in_unsafe_fn)]` (1.68 +)를 선호하세요.

원시 포인터로 생성된 오버플로우 예:
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
Miri를 실행하는 것은 테스트 시간에 UB를 감지하는 저렴한 방법입니다:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```
#### Auditing dependencies with RustSec / cargo-audit

대부분의 실제 Rust 취약점은 서드파티 크레이트에 존재합니다. RustSec 자문 DB(커뮤니티 기반)는 로컬에서 쿼리할 수 있습니다:
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI에 통합하고 `--deny warnings`에서 실패합니다.

`cargo deny check advisories`는 유사한 기능을 제공하며 라이센스 및 금지 목록 검사를 포함합니다.

#### cargo-vet을 통한 공급망 검증 (2024)

`cargo vet`는 가져오는 모든 crate에 대한 검토 해시를 기록하고 눈치채지 못한 업그레이드를 방지합니다:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
이 도구는 Rust 프로젝트 인프라와 증가하는 수의 조직에서 오염된 패키지 공격을 완화하기 위해 채택되고 있습니다.

#### API 표면의 퍼징 (cargo-fuzz)

퍼징 테스트는 패닉, 정수 오버플로우 및 DoS 또는 사이드 채널 문제가 될 수 있는 논리 버그를 쉽게 포착합니다:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
리포지토리에 퍼즈 타겟을 추가하고 파이프라인에서 실행하세요.

## References

- RustSec Advisory Database – <https://rustsec.org>
- Cargo-vet: "Auditing your Rust Dependencies" – <https://mozilla.github.io/cargo-vet/>

{{#include ../banners/hacktricks-training.md}}
