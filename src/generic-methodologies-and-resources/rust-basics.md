# Rust Temelleri

{{#include ../banners/hacktricks-training.md}}

### Değişkenlerin sahipliği

Bellek, derleyicinin derleme zamanında kontrol ettiği aşağıdaki kurallara sahip bir sahiplik sistemi aracılığıyla yönetilir:

1. Rust'taki her değerin sahibi olarak adlandırılan bir değişkeni vardır.
2. Aynı anda yalnızca bir sahibi olabilir.
3. Sahibi kapsam dışına çıktığında değer düşürülür.

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



### Genel Türler

Değerlerinden biri herhangi bir türde olabilecek bir struct oluşturun.

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

Option türü, değerin Some (bir şey var) veya None olabileceği anlamına gelir:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Option değerini kontrol etmek için `is_some()` veya `is_none()` gibi fonksiyonları kullanabilirsiniz.


### Result, Ok & Err

Hataları döndürmek ve yaymak için kullanılır

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

`is_ok()` veya `is_err()` gibi işlevleri kullanarak sonucun değerini kontrol edebilirsiniz.

`Option` enum'u, bir değerin mevcut olmayabileceği (`None` olabileceği) durumlarda kullanılmalıdır.
`Result` enum'u, yanlış gidebilecek bir işlem yaptığınız durumlarda kullanılmalıdır.


### Macros

Macros, yazdığınız koddan daha fazla kod üretmek üzere genişletildikleri için functions'lardan daha güçlüdür. Örneğin, bir function imzası, function'ın parametre sayısını ve türünü belirtmelidir. Öte yandan macros, değişken sayıda parametre alabilir: `println!("hello")` çağrısını bir argümanla veya `println!("hello {}", name)` çağrısını iki argümanla yapabiliriz. Ayrıca macros, derleyici kodun anlamını yorumlamadan önce genişletilir. Bu nedenle bir macro, örneğin, belirli bir tür üzerinde bir trait uygulayabilir. Bir function bunu yapamaz; çünkü çalışma zamanında çağrılır ve bir trait'in derleme zamanında uygulanması gerekir.

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

### Yineleme

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

### Özyinelemeli Box

Özyinelemeli bir enum, boyutunun derleme zamanında bilinmesi için dolaylı yönlendirme gerektirir; `List`'i doğrudan `List` içinde saklamak derleme hatasına neden olur.<sup>[[10]](#references)</sup>

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

### Koşul İfadeleri

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

#### döngü (sonsuz)

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

İçindeki değeri bağlamak için `Some` ile eşleştirin; düz bir değişken kalıbı hem `Some` hem de `None` ile eşleşir, bu nedenle `else` dalı hiçbir zaman çalışmaz.<sup>[[11]](#references)</sup>

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

Bir tür için yeni bir metot oluşturun

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

### Testler

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

Bir Arc, nesneye daha fazla referans oluşturmak ve bunları thread'lere aktarmak için Clone kullanabilir. Bir değere yönelik son referans işaretçisi kapsam dışına çıktığında değişken bellekten düşürülür.

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

Bu durumda thread'e değiştirebileceği bir değişken geçireceğiz.

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


### Güvenlik Temelleri

Rust varsayılan olarak güçlü bellek güvenliği garantileri sağlar; ancak `unsafe` kod, bağımlılık sorunları veya mantık hataları yoluyla yine de kritik güvenlik açıkları oluşturabilirsiniz. Aşağıdaki mini başvuru, Rust yazılımlarının saldırı veya savunma amaçlı güvenlik incelemelerinde en sık karşılaşacağınız temel öğeleri bir araya getiriyor. Diğer dillere özgü araçlar için bkz. [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### `unsafe` kod ve bellek güvenliği

`unsafe`, güvenlik koşullarının derleyici tarafından kanıtlanamadığı işlemlere izin verir; normal ödünç alma veya sınır denetimlerini **devre dışı bırakmaz**. Güvenli olmayan bir işlem, güvenlik koşullarını ihlal ettiğinde bellek bozulması mümkün hâle gelir; buna güvenli bir API olarak sunulan bir işlevin içindeki ihlaller de dahildir.<sup>[[3]](#references)</sup>

Kaynak kodu incelemesinde, denetlenmeyen işlemleri bulun ve saldırganın denetleyebildiği işaretçileri ve uzunlukları herkese açık çağıranlardan başlayarak izleyin:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* `slice::from_raw_parts` için işaretçinin null olmadığını ve hizalı olduğunu, başlatılmış aralığın **tamamının** tek bir canlı allocation içinde bulunduğunu ve döndürülen slice'ın bu allocation'dan daha uzun süre yaşamadığını kanıtlayın. Sıfır uzunluklu bir slice bile null işaretçi kullanamaz.
* `Vec::set_len` için yeni uzunluğun gerçek kapasiteyi aşmadığını ve yeni görünür hâle gelen her öğenin başlatılmış olduğunu kanıtlayın. Hem allocation boyutunu hem de kopyalama sayısını izleyin; `with_capacity` öğeleri başlatmaz.
* Her `unsafe impl` of `Send` or `Sync` ifadesini ve her FFI imzasını, safe callers'a vaat edilen invariant'lara göre denetleyin. `#![forbid(unsafe_code)]` bir crate'teki unsafe code'u reddeder; `#![deny(unsafe_op_in_unsafe_fn)]` ise unsafe code'u yasaklamak yerine unsafe functions **içindeki** explicit unsafe blocks gerektirir. İkinci lint, Rust 2024'te varsayılan olarak uyarı verir.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Raw pointers ile oluşturulan overflow örneği:
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
`dst.capacity()` değerinden uzun bir girdi, yukarıdaki örnekte hem kopyalama sınırını hem de `set_len` sözleşmesini ihlal eder. Hedef allocator için aşırı uzun girdili bir test ekleyin ve bunu Miri altında çalıştırın. Miri, yürütülen yolları undefined behavior açısından denetler; ancak desteklenmeyen foreign çağrılar, bir FFI sınırını test etmesini engelleyebilir.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### RustSec / cargo-audit ile bağımlılıkları denetleme

Gerçek dünyadaki Rust açıklarının çoğu üçüncü taraf crate'lerde bulunur. RustSec advisory DB (topluluk tarafından desteklenir) yerel olarak sorgulanabilir:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI'ye entegre edin ve `--deny warnings` durumunda işlemi başarısız kılın.

`cargo deny check advisories`, lisans ve ban listesi kontrollerinin yanı sıra benzer işlevler sunar.

#### cargo-tarpaulin ile kod kapsamı

`cargo tarpaulin`, Cargo build sistemi için bir kod kapsamı raporlama aracıdır.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux'ta Tarpaulin'in varsayılan tracing backend'i hâlâ Ptrace'tir ve yalnızca x86_64 işlemcilerde çalışır. Bu, `--engine llvm` ile llvm coverage instrumentation olarak değiştirilebilir. Mac ve Windows'ta varsayılan toplama yöntemi budur.

#### cargo-vet ile tedarik zinciri doğrulaması

`cargo vet`, bağımlılıkları yerel denetimler, güvenilir içe aktarımlar veya açık muafiyetler kullanarak yapılandırılmış denetim ölçütlerine göre kontrol eder. `cargo vet init`, `supply-chain/` meta verilerini oluşturur ve mevcut, denetlenmemiş bağımlılıkları muaf tutar; bu nedenle başlangıçta kontrolün başarılı olması, her crate'in incelendiği anlamına **gelmez**. Muafiyetleri inceleyin ve bunları ele almak için `cargo vet suggest` komutunu kullanın; `--locked`, içe aktarılan denetim kümelerinin yenilenmesini önler.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### API yüzeyinizi Fuzzing ile test etme (cargo-fuzz)

Fuzz target’ları, API’yi üretilen girdilerle test eder ve panic’leri ve bellek güvenliği hatalarını ortaya çıkarabilir. Üretilen target, `fuzz/fuzz_targets/` altında bulunur; çalıştırmadan önce varsayılan gövdesini incelenen API’yi çağıracak şekilde değiştirin.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Fuzz target'ı repo'nuza ekleyin ve pipeline'ınızda çalıştırın.



## References

- [1] [RustSec Danışma Veritabanı](https://rustsec.org)
- [2] [Cargo-vet: "Rust Bağımlılıklarınızı Denetleme"](https://mozilla.github.io/cargo-vet/)
- [3] [Rust Programlama Dili: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: unsafe_op_in_unsafe_fn uyarısı](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet komutları](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Kitabı: cargo-fuzz öğreticisi](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Rust Programlama Dili: Box ve özyinelemeli türler](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Rust Programlama Dili: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: Unsafe extern blokları](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
