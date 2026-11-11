# Rustの基本

{{#include ../banners/hacktricks-training.md}}

### 変数の所有権

メモリは所有権システムによって管理されます。このシステムには、コンパイル時にコンパイラがチェックする次のルールがあります。

1. Rustでは、各値には所有者と呼ばれる変数があります。
2. 同時に存在できる所有者は1つだけです。
3. 所有者がスコープ外になると、その値は破棄されます。

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



### ジェネリック型

値の1つが任意の型を取れるstructを作成します。

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

### Option、Some、None

Option型は、値がSome（値が存在する）またはNoneである可能性を表します:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

`is_some()` や `is_none()` などの関数を使って、Option の値を確認できます。


### Result, Ok & Err

エラーを返したり伝播したりするために使用します。

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

`is_ok()` や `is_err()` などの関数を使って、結果の値を確認できます。

値が存在しない可能性がある（`None` になる）状況では、`Option` enum を使います。
何か問題が起きる可能性がある処理を行う状況では、`Result` enum を使います。


### マクロ

マクロは、手動で記述したコードよりも多くのコードを生成するよう展開されるため、関数よりも強力です。たとえば、関数シグネチャでは、関数のパラメータの数と型を宣言する必要があります。一方、マクロは可変個数のパラメータを受け取れます。たとえば、`println!("hello")` は1つの引数で、`println!("hello {}", name)` は2つの引数で呼び出せます。また、マクロはコンパイラがコードの意味を解釈する前に展開されるため、たとえば、特定の型に trait を実装できます。関数ではできません。関数は実行時に呼び出されますが、trait はコンパイル時に実装する必要があるためです。

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

### 反復処理

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

再帰的な enum には、コンパイル時にサイズが確定するよう間接参照が必要です。`List` の中に `List` を直接格納するとコンパイルできません。<sup>[[10]](#references)</sup>

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

### 条件分岐

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

#### loop (無限)

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

`Some` にマッチして内部の値を束縛します。通常の変数パターンは `Some` と `None` の両方にマッチするため、`else` 分岐は実行されません。<sup>[[11]](#references)</sup>

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

### トレイト

型に新しいメソッドを作成する

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

### テスト

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

### スレッド処理

#### Arc

ArcではCloneを使ってオブジェクトへの参照を増やし、それらをスレッドに渡せます。値への最後の参照ポインターがスコープ外になると、変数は破棄されます。

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

この場合、スレッドが変更できる変数を渡します。

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

Rust はデフォルトで強力なメモリ安全性保証を提供しますが、`unsafe` code、依存関係の問題、ロジックのミスによって、依然として重大な脆弱性を生み出す可能性があります。以下のミニチートシートでは、Rust ソフトウェアの攻撃側または防御側のセキュリティレビューで最もよく扱うプリミティブをまとめています。その他の言語固有のツールについては、[Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust) を参照してください。

#### Unsafe code & memory safety

`unsafe` は、コンパイラーが安全性の契約を証明できない操作を許可しますが、通常の借用チェックや境界チェックを無効にはしません。`unsafe` 操作がその契約に違反すると、メモリ破壊が起こり得ます。これは、安全な API として公開された関数の内部でも同様です。<sup>[[3]](#references)</sup>

ソースコードをレビューする際は、チェックなしの操作を見つけ、公開関数の呼び出し元から、攻撃者が制御可能なポインターや長さをたどってください。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* `slice::from_raw_parts` では、ポインターが null ではなく、適切にアラインされていること、初期化済み範囲**全体**が単一の有効なアロケーション内にあること、返されるスライスがそのアロケーションより長く存続しないことを証明してください。長さ 0 のスライスでも、null ポインターは使用できません。
* `Vec::set_len` では、新しい長さが実際の容量内に収まり、新たに公開されるすべての要素が初期化済みであることを証明してください。アロケーションサイズとコピー数の両方を追跡してください。`with_capacity` は要素を初期化しません。
* `Send` または `Sync` のすべての `unsafe impl` と各 FFI シグネチャについて、安全な呼び出し側に保証する不変条件を満たしているか確認してください。`#![forbid(unsafe_code)]` はクレート内の unsafe code を拒否します。一方、`#![deny(unsafe_op_in_unsafe_fn)]` は unsafe code を禁止するのではなく、unsafe 関数の**内部**で明示的な unsafe ブロックを要求します。後者の lint は Rust 2024 ではデフォルトで警告します。<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

raw pointer で発生するオーバーフローの例:
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
上記の例では、`dst.capacity()` より長い入力はコピーの境界条件と `set_len` の契約の両方に違反します。対象の allocator に対して、入力が大きすぎる場合のテストを追加し、Miri で実行してください。Miri は実行された経路の未定義動作をチェックしますが、サポートされていない foreign call によって FFI 境界を検証できない場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### RustSec / cargo-audit による依存関係の監査

実際の環境で発生する Rust の脆弱性の多くは、サードパーティ製 crate に存在します。コミュニティによって運営されている RustSec advisory DB は、ローカルから照会できます。<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI に統合し、`--deny warnings` で失敗するようにします。

`cargo deny check advisories` は、ライセンスや禁止リストのチェックに加えて、同様の機能を提供します。

#### cargo-tarpaulin によるコードカバレッジ

`cargo tarpaulin` は、Cargo ビルドシステム向けのコードカバレッジレポートツールです。

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux では、Tarpaulin のデフォルトの tracing backend は引き続き Ptrace で、x86_64 プロセッサでのみ動作します。`--engine llvm` を指定すると、llvm coverage instrumentation に変更できます。Mac と Windows では、これがデフォルトの収集方法です。

#### cargo-vet によるサプライチェーン検証

`cargo vet` は、ローカル監査、信頼済みインポート、または明示的な免除を使い、設定された監査基準に照らして依存関係をチェックします。`cargo vet init` は `supply-chain/` メタデータを作成し、既存の未監査依存関係を免除するため、最初のチェックに合格しても、すべての crate がレビュー済みという意味ではありません。免除項目を確認し、`cargo vet suggest` を使って対応してください。`--locked` を指定すると、インポート済み監査セットの更新を回避できます。<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### API surface の Fuzzing（cargo-fuzz）

Fuzz target は生成された入力で API を実行し、panic やメモリ安全性の不具合を検出できます。生成された target は `fuzz/fuzz_targets/` にあります。実行する前に、デフォルトの本文をレビュー対象の API を呼び出す処理に置き換えてください。<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
fuzz target をリポジトリに追加し、パイプラインで実行してください。



## References

- [1] [RustSec アドバイザリデータベース](https://rustsec.org)
- [2] [Cargo-vet:「Rust の依存関係を監査する」](https://mozilla.github.io/cargo-vet/)
- [3] [Rust プログラミング言語: Unsafe Rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Miri README](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: unsafe_op_in_unsafe_fn 警告](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Cargo Vet コマンド](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Rust Fuzz Book: cargo-fuzz チュートリアル](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Rust プログラミング言語: Box と再帰型](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Rust プログラミング言語: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: unsafe extern ブロック](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
