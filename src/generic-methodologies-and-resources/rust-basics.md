# Rust 기본 사항

{{#include ../banners/hacktricks-training.md}}

### 변수의 소유권

메모리는 컴파일러가 컴파일 시점에 확인하는 다음 소유권 규칙에 따라 관리됩니다.

1. Rust의 각 값에는 소유자라고 하는 변수가 있습니다.
2. 한 번에 소유자는 하나만 있을 수 있습니다.
3. 소유자의 범위를 벗어나면 값이 해제됩니다.

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



### 제네릭 타입

값 중 하나가 어떤 타입이든 될 수 있는 구조체를 만듭니다.

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

Option 타입은 값이 Some(값이 있음) 또는 None일 수 있음을 의미합니다:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

`is_some()` 또는 `is_none()` 같은 함수를 사용해 Option의 값을 확인할 수 있습니다.


### Result, Ok & Err

오류를 반환하고 전파하는 데 사용됩니다.

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

`is_ok()` 또는 `is_err()` 같은 함수를 사용해 result의 값을 확인할 수 있습니다.

값이 존재하지 않을 수도 있는(`None`일 수도 있는) 상황에서는 `Option` enum을 사용해야 합니다.
작업 중 오류가 발생할 수도 있는 상황에서는 `Result` enum을 사용해야 합니다.


### 매크로

매크로는 작성한 코드보다 더 많은 코드를 생성하도록 확장되므로 함수보다 강력합니다. 예를 들어, 함수 시그니처에는 함수의 매개변수 개수와 타입을 선언해야 합니다. 반면 매크로는 다양한 개수의 매개변수를 받을 수 있습니다. `println!("hello")`처럼 인수를 하나 전달하거나, `println!("hello {}", name)`처럼 인수를 두 개 전달할 수 있습니다. 또한 매크로는 컴파일러가 코드의 의미를 해석하기 전에 확장되므로, 예를 들어 특정 타입에 trait을 구현할 수 있습니다. 함수는 런타임에 호출되고 trait은 컴파일 타임에 구현되어야 하므로 그렇게 할 수 없습니다.

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

### 재귀적 Box

재귀 enum은 컴파일 시점에 크기를 알 수 있도록 간접 참조가 필요합니다. `List` 안에 `List`를 직접 저장하면 컴파일되지 않습니다.<sup>[[10]](#references)</sup>

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

`Some`에 매칭해 내부 값을 바인딩합니다. 일반 변수 패턴은 `Some`과 `None` 모두에 매칭되므로 `else` 분기는 실행되지 않습니다.<sup>[[11]](#references)</sup>

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

### 트레이트

타입에 새 메서드 만들기

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

### 스레딩

#### Arc

Arc는 Clone을 사용해 객체에 대한 참조를 더 만들어 스레드에 전달할 수 있습니다. 값에 대한 마지막 참조 포인터가 스코프를 벗어나면 변수가 삭제됩니다.

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

#### 스레드

이 경우 스레드가 수정할 수 있는 변수를 스레드에 전달합니다.

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

Rust는 기본적으로 강력한 메모리 안전성 보장을 제공하지만, `unsafe` 코드, 의존성 문제 또는 로직 실수를 통해 여전히 치명적인 취약점을 만들 수 있습니다. 다음 미니 치트시트에는 Rust 소프트웨어의 공격 또는 방어 보안 검토에서 가장 자주 접하게 될 기본 요소를 모았습니다. 다른 언어별 도구는 [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust)를 참조하세요.

#### `unsafe` 코드 및 메모리 안전성

`unsafe`는 컴파일러가 안전성 계약을 입증할 수 없는 연산을 허용합니다. 그렇다고 일반적인 borrow 검사나 범위 검사를 끄는 것은 아닙니다. `unsafe` 연산이 계약을 위반하면 메모리 손상이 발생할 수 있으며, 여기에는 안전한 API로 노출된 함수 내부에서의 위반도 포함됩니다.<sup>[[3]](#references)</sup>

소스 검토 시에는 검사되지 않은 연산을 찾아내고, 공격자가 제어하는 포인터와 길이가 공개 호출자에서 어떻게 전달되는지 추적하세요.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* `slice::from_raw_parts`의 경우 포인터가 null이 아니고 정렬되어 있으며, 초기화된 **전체** 범위가 하나의 유효한 할당 영역 안에 있고, 반환된 슬라이스가 해당 영역의 수명보다 오래 유지되지 않음을 입증하세요. 길이가 0인 슬라이스도 null 포인터를 사용할 수 없습니다.
* `Vec::set_len`의 경우 새 길이가 실제 용량을 초과하지 않고, 새로 노출되는 모든 요소가 초기화되었음을 입증하세요. 할당 크기와 복사 횟수를 모두 추적하세요. `with_capacity`는 요소를 초기화하지 않습니다.
* 모든 `Send` 또는 `Sync`의 `unsafe impl`과 각 FFI 시그니처가 안전한 호출자에게 보장하는 불변 조건을 충족하는지 확인하세요. `#![forbid(unsafe_code)]`는 크레이트의 unsafe 코드를 거부합니다. 반면 `#![deny(unsafe_op_in_unsafe_fn)]`는 unsafe 코드를 금지하는 것이 아니라, unsafe 함수 **내부에서** 명시적인 unsafe 블록을 요구합니다. 후자의 lint는 Rust 2024에서 기본적으로 경고합니다.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

원시 포인터로 발생시킨 오버플로 예제:
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
위 예시에서 `dst.capacity()`보다 긴 입력은 복사 범위와 `set_len` 계약을 모두 위반합니다. 대상 allocator에 대해 크기가 초과된 입력을 사용하는 테스트를 추가한 다음 Miri에서 실행하세요. Miri는 실행된 경로에서 정의되지 않은 동작을 검사하지만, 지원되지 않는 외부 함수 호출로 인해 FFI 경계를 실행하지 못할 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### RustSec / cargo-audit로 의존성 감사하기

실제 환경에서 발생하는 Rust 취약점 대부분은 서드파티 crate에 있습니다. RustSec advisory DB(커뮤니티 기반)는 로컬에서 조회할 수 있습니다:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI에 통합하고 `--deny warnings`에서 실패하도록 설정하세요.

`cargo deny check advisories`는 유사한 기능에 더해 라이선스 및 금지 목록 검사도 제공합니다.

#### cargo-tarpaulin을 사용한 코드 커버리지

`cargo tarpaulin`은 Cargo 빌드 시스템용 코드 커버리지 보고 도구입니다.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux에서 Tarpaulin의 기본 tracing 백엔드는 여전히 Ptrace이며 x86_64 프로세서에서만 작동합니다. `--engine llvm`을 사용하면 llvm coverage instrumentation으로 변경할 수 있습니다. Mac과 Windows에서는 이 방식이 기본 수집 방법입니다.

#### cargo-vet을 사용한 공급망 검증

`cargo vet`은 로컬 audit, 신뢰할 수 있는 import 또는 명시적 exemption을 사용해 설정된 audit 기준에 따라 dependencies를 확인합니다. `cargo vet init`은 `supply-chain/` 메타데이터를 생성하고 기존의 audit되지 않은 dependencies를 exemption 처리하므로, 처음에 검사를 통과했다고 해서 모든 crate가 검토된 것은 아닙니다. Exemption을 살펴보고 `cargo vet suggest`를 사용해 하나씩 검토하세요. `--locked`를 사용하면 import된 audit 집합이 새로고침되지 않습니다.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### API 표면 fuzzing (cargo-fuzz)

Fuzz target는 생성된 입력으로 API를 실행해 panic 및 메모리 안전성 오류를 발견할 수 있습니다. 생성된 target은 `fuzz/fuzz_targets/`에 있습니다. 실행하기 전에 기본 본문을 검토 중인 API를 호출하도록 바꾸세요.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Fuzz target을 repo에 추가하고 pipeline에서 실행하세요.



## References

- [1] [RustSec 보안 권고 데이터베이스](https://rustsec.org)
- [2] [Cargo-vet: "Rust 의존성 감사하기"](https://mozilla.github.io/cargo-vet/)
- [3] [Rust 프로그래밍 언어: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: unsafe_op_in_unsafe_fn 경고](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet 명령어](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: cargo-fuzz 튜토리얼](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Rust 프로그래밍 언어: Box와 재귀 타입](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Rust 프로그래밍 언어: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: Unsafe extern 블록](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
