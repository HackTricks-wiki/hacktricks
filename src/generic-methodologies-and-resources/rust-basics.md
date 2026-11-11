# Kiến thức cơ bản về Rust

{{#include ../banners/hacktricks-training.md}}

### Quyền sở hữu biến

Bộ nhớ được quản lý thông qua hệ thống quyền sở hữu với các quy tắc sau, được compiler kiểm tra tại thời điểm biên dịch:

1. Mỗi giá trị trong Rust có một biến được gọi là chủ sở hữu của giá trị đó.
2. Tại một thời điểm chỉ có thể có một chủ sở hữu.
3. Khi chủ sở hữu ra khỏi phạm vi, giá trị sẽ bị loại bỏ.

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



### Kiểu tổng quát

Tạo một struct trong đó một trong các giá trị có thể thuộc bất kỳ kiểu nào.

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

Kiểu Option có nghĩa là giá trị có thể thuộc kiểu Some (có thứ gì đó) hoặc None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Bạn có thể dùng các hàm như `is_some()` hoặc `is_none()` để kiểm tra giá trị của `Option`.


### Result, Ok & Err

Dùng để trả về và truyền tiếp lỗi

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Bạn có thể dùng các hàm như `is_ok()` hoặc `is_err()` để kiểm tra giá trị của kết quả

Nên dùng enum `Option` trong các trường hợp một giá trị có thể không tồn tại (là `None`).
Nên dùng enum `Result` trong các trường hợp bạn thực hiện việc gì đó có thể xảy ra lỗi


### Macros

Macros mạnh hơn functions vì chúng mở rộng để tạo ra nhiều code hơn so với phần code bạn viết thủ công. Ví dụ, chữ ký của một function phải khai báo số lượng và kiểu của các tham số mà function nhận. Mặt khác, macros có thể nhận số lượng tham số thay đổi: ta có thể gọi `println!("hello")` với một đối số hoặc `println!("hello {}", name)` với hai đối số. Ngoài ra, macros được mở rộng trước khi compiler diễn giải ý nghĩa của code, vì vậy macro có thể, chẳng hạn, triển khai một trait cho một kiểu dữ liệu nhất định. Function không thể làm vậy vì nó được gọi tại runtime, còn trait cần được triển khai tại compile time.

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

### Lặp

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

### Box đệ quy

Một enum đệ quy cần có lớp gián tiếp để kích thước của nó được xác định tại thời điểm biên dịch; lưu trực tiếp `List` bên trong `List` sẽ không biên dịch được.<sup>[[10]](#references)</sup>

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

Match `Some` để bind giá trị bên trong; một mẫu biến thông thường khớp cả `Some` và `None`, vì vậy nhánh `else` sẽ không bao giờ chạy.<sup>[[11]](#references)</sup>

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

Tạo một phương thức mới cho một kiểu dữ liệu

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

### Threading

#### Arc

Arc có thể dùng Clone để tạo thêm các tham chiếu đến đối tượng và truyền chúng cho các thread. Khi con trỏ tham chiếu cuối cùng đến một giá trị nằm ngoài phạm vi, biến sẽ bị giải phóng.

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

Trong trường hợp này, chúng ta sẽ truyền cho thread một biến mà nó có thể sửa đổi.

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


### Những nguyên tắc bảo mật cốt lõi

Rust mặc định cung cấp các đảm bảo mạnh về an toàn bộ nhớ, nhưng bạn vẫn có thể tạo ra lỗ hổng nghiêm trọng thông qua mã `unsafe`, vấn đề về dependency hoặc sai sót logic. Bảng tóm tắt ngắn sau đây tập hợp các cấu trúc bạn thường gặp nhất khi đánh giá bảo mật phần mềm Rust theo hướng tấn công hoặc phòng thủ. Để xem các công cụ dành riêng cho từng ngôn ngữ khác, hãy tham khảo [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Mã `unsafe` và an toàn bộ nhớ

`unsafe` cho phép thực hiện những thao tác mà compiler không thể chứng minh là an toàn; nó **không** tắt các kiểm tra borrow hoặc giới hạn thông thường. Hỏng bộ nhớ có thể xảy ra khi thao tác `unsafe` vi phạm hợp đồng an toàn, kể cả bên trong một hàm được cung cấp dưới dạng API an toàn.<sup>[[3]](#references)</sup>

Khi rà soát mã nguồn, hãy tìm các thao tác không kiểm tra và lần theo con trỏ cùng độ dài do kẻ tấn công kiểm soát từ các hàm gọi công khai:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Với `slice::from_raw_parts`, hãy chứng minh con trỏ không null và được căn chỉnh, toàn bộ vùng đã khởi tạo nằm trong một allocation còn hiệu lực, và slice trả về không thể tồn tại lâu hơn vùng đó. Ngay cả slice có độ dài bằng 0 cũng không thể dùng con trỏ null.
* Với `Vec::set_len`, hãy chứng minh độ dài mới không vượt quá capacity thực tế và mọi phần tử mới được đưa vào phạm vi đều đã được khởi tạo. Kiểm tra cả kích thước allocation lẫn số lượng bản sao; `with_capacity` không khởi tạo phần tử.
* Kiểm tra mọi `unsafe impl` của `Send` hoặc `Sync` và từng chữ ký FFI để bảo đảm chúng tuân thủ các bất biến được cam kết với bên gọi an toàn. `#![forbid(unsafe_code)]` từ chối unsafe code trong một crate; thay vào đó, `#![deny(unsafe_op_in_unsafe_fn)]` yêu cầu các unsafe block tường minh **bên trong** các hàm unsafe, chứ không cấm unsafe code. Lint sau được cảnh báo mặc định trong Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Ví dụ về tràn số được tạo bằng raw pointers:
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
Đầu vào dài hơn `dst.capacity()` vi phạm cả giới hạn sao chép lẫn hợp đồng `set_len` trong ví dụ trên. Hãy thêm một bài kiểm thử với đầu vào quá dài cho allocator mục tiêu, rồi chạy bài kiểm thử đó bằng Miri. Miri kiểm tra các đường dẫn đã thực thi để phát hiện hành vi không xác định, nhưng các lời gọi ngoại lai không được hỗ trợ có thể khiến Miri không kiểm tra được ranh giới FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Kiểm tra các dependency bằng RustSec / cargo-audit

Phần lớn lỗ hổng Rust trong thực tế nằm trong các crate của bên thứ ba. Có thể truy vấn RustSec advisory DB (do cộng đồng duy trì) ngay trên máy cục bộ:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Tích hợp nó vào CI và cho quy trình thất bại với `--deny warnings`.

`cargo deny check advisories` cung cấp chức năng tương tự, đồng thời kiểm tra giấy phép và danh sách cấm.

#### Độ bao phủ mã với cargo-tarpaulin

`cargo tarpaulin` là công cụ báo cáo độ bao phủ mã cho hệ thống build Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Trên Linux, backend tracing mặc định của Tarpaulin vẫn là Ptrace và chỉ hoạt động trên bộ xử lý x86_64. Có thể đổi sang instrumentation coverage của llvm bằng `--engine llvm`. Đây là phương thức thu thập mặc định trên Mac và Windows.

#### Xác minh chuỗi cung ứng bằng cargo-vet

`cargo vet` kiểm tra các dependency theo tiêu chí audit đã cấu hình, sử dụng các audit cục bộ, các import đáng tin cậy hoặc các ngoại lệ được chỉ định rõ ràng. `cargo vet init` tạo metadata trong `supply-chain/` và miễn audit cho các dependency hiện có chưa được audit, vì vậy một lượt kiểm tra ban đầu thành công **không** có nghĩa là mọi crate đều đã được xem xét. Kiểm tra các ngoại lệ và dùng `cargo vet suggest` để xử lý chúng; `--locked` tránh làm mới các tập audit đã import.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing bề mặt API của bạn (cargo-fuzz)

Các fuzz target kiểm thử API bằng các đầu vào được tạo tự động và có thể phát hiện panic cùng các lỗi an toàn bộ nhớ. Target được tạo nằm trong `fuzz/fuzz_targets/`; hãy thay phần thân mặc định bằng lời gọi đến API cần xem xét trước khi chạy target đó.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Thêm fuzz target vào repo và chạy nó trong pipeline.



## References

- [1] [Cơ sở dữ liệu tư vấn RustSec](https://rustsec.org)
- [2] [Cargo-vet: "Kiểm tra các dependency Rust của bạn"](https://mozilla.github.io/cargo-vet/)
- [3] [Ngôn ngữ lập trình Rust: Rust không an toàn](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README của Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: cảnh báo unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Các lệnh Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Sách Rust Fuzz: hướng dẫn cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Ngôn ngữ lập trình Rust: Box và kiểu đệ quy](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Ngôn ngữ lập trình Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: các khối extern không an toàn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
