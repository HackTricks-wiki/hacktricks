# Kiến thức cơ bản về Rust

{{#include ../banners/hacktricks-training.md}}

### Quyền sở hữu biến

Bộ nhớ được quản lý thông qua hệ thống quyền sở hữu với các quy tắc sau, được trình biên dịch kiểm tra tại thời điểm biên dịch:

1. Mỗi giá trị trong Rust có một biến được gọi là chủ sở hữu của nó.
2. Tại một thời điểm chỉ có thể có một chủ sở hữu.
3. Khi chủ sở hữu ra khỏi phạm vi, giá trị sẽ bị hủy.

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

Tạo một struct trong đó một giá trị có thể thuộc bất kỳ kiểu nào.

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

Kiểu Option có nghĩa là giá trị có thể thuộc kiểu Some (có giá trị) hoặc None (không có giá trị):

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Bạn có thể dùng các hàm như `is_some()` hoặc `is_none()` để kiểm tra giá trị của Option.


### Result, Ok & Err

Dùng để trả về và lan truyền lỗi

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Bạn có thể dùng các hàm như `is_ok()` hoặc `is_err()` để kiểm tra giá trị của kết quả.

Enum `Option` nên được dùng trong những trường hợp một giá trị có thể không tồn tại (là `None`).
Enum `Result` nên được dùng trong những trường hợp bạn thực hiện việc gì đó có thể gặp lỗi.


### Macros

Macros mạnh hơn functions vì chúng mở rộng để tạo ra nhiều mã hơn phần mã bạn viết thủ công. Ví dụ, chữ ký của function phải khai báo số lượng và kiểu của các tham số. Mặt khác, macros có thể nhận số lượng tham số thay đổi: ta có thể gọi `println!("hello")` với một đối số hoặc `println!("hello {}", name)` với hai đối số. Ngoài ra, macros được mở rộng trước khi compiler diễn giải ý nghĩa của mã, vì vậy macro có thể, chẳng hạn, triển khai một trait cho một kiểu nhất định. Function không thể làm được điều này, vì nó được gọi tại runtime còn trait cần được triển khai tại compile time.

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

### Lặp lại

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

### Hộp đệ quy

```rust
enum List {
    Cons(i32, List),
    Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```

### Câu lệnh điều kiện

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

#### loop (vô hạn)

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

Tạo một phương thức mới cho một kiểu

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

### Kiểm thử

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

### Đa luồng

#### Arc

Arc có thể dùng Clone để tạo thêm các tham chiếu đến đối tượng, rồi truyền chúng cho các luồng. Khi con trỏ tham chiếu cuối cùng đến một giá trị ra khỏi phạm vi, biến sẽ bị hủy.

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

#### Luồng

Trong trường hợp này, chúng ta sẽ truyền cho luồng một biến mà nó có thể sửa đổi.

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


### Những điều cốt yếu về bảo mật

Rust mặc định cung cấp các đảm bảo mạnh mẽ về an toàn bộ nhớ, nhưng bạn vẫn có thể tạo ra các lỗ hổng nghiêm trọng thông qua mã `unsafe`, vấn đề về dependency hoặc sai sót logic. Cheatsheet ngắn sau đây tập hợp các primitive mà bạn thường gặp nhất khi rà soát bảo mật phần mềm Rust theo hướng tấn công hoặc phòng thủ.

#### Mã unsafe & an toàn bộ nhớ

Các khối `unsafe` bỏ qua những bước kiểm tra aliasing và giới hạn của compiler, vì vậy **mọi lỗi gây hỏng bộ nhớ truyền thống (OOB, use-after-free, double free, v.v.) đều có thể xuất hiện trở lại**. Danh sách kiểm tra nhanh:

* Tìm các khối `unsafe`, hàm `extern "C"`, lời gọi `ptr::copy*`, `std::mem::transmute`, `MaybeUninit`, raw pointer hoặc module `ffi`.
* Xác thực mọi phép tính số học trên pointer và đối số độ dài được truyền cho các hàm cấp thấp.
* Ưu tiên `#![forbid(unsafe_code)]` (toàn crate) hoặc `#[deny(unsafe_op_in_unsafe_fn)]` (từ phiên bản 1.68 trở lên) để khiến quá trình biên dịch thất bại nếu ai đó thêm lại `unsafe`.

Ví dụ về lỗi tràn được tạo bằng raw pointer:
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
Chạy Miri là một cách ít tốn kém để phát hiện UB khi chạy kiểm thử:
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```

#### Kiểm tra dependency bằng RustSec / cargo-audit

Phần lớn lỗ hổng Rust trong thực tế nằm trong các crate của bên thứ ba. Có thể truy vấn RustSec advisory DB (do cộng đồng đóng góp) trên máy cục bộ:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Tích hợp vào CI và làm cho quy trình thất bại khi dùng `--deny warnings`.

`cargo deny check advisories` cung cấp chức năng tương tự, cùng với các kiểm tra giấy phép và danh sách cấm.

#### Độ bao phủ mã với cargo-tarpaulin

`cargo tarpaulin` là công cụ báo cáo độ bao phủ mã dành cho hệ thống build Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Trên Linux, backend tracing mặc định của Tarpaulin vẫn là Ptrace và chỉ hoạt động trên các bộ xử lý x86_64. Có thể chuyển sang instrumentation coverage của llvm bằng `--engine llvm`. Đây là phương thức thu thập mặc định trên Mac và Windows.

#### Xác minh chuỗi cung ứng bằng cargo-vet (2024)

`cargo vet` ghi lại hash đánh giá cho mọi crate bạn import và ngăn các lần nâng cấp không được chú ý:
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
Công cụ này đang được hạ tầng của dự án Rust và ngày càng nhiều tổ chức áp dụng để giảm thiểu các cuộc tấn công bằng package bị đầu độc.<sup>[[2]](#references)</sup>

#### Fuzzing bề mặt API của bạn (cargo-fuzz)

Các bài kiểm thử fuzz dễ dàng phát hiện panic, tràn số nguyên và lỗi logic có thể dẫn đến DoS hoặc vấn đề side-channel:
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Thêm fuzz target vào repo của bạn và chạy nó trong pipeline.

## References

- [1] [Cơ sở dữ liệu khuyến cáo RustSec](https://rustsec.org)
- [2] [Cargo-vet: "Kiểm tra các dependency Rust của bạn"](https://mozilla.github.io/cargo-vet/)
{{#include ../banners/hacktricks-training.md}}
