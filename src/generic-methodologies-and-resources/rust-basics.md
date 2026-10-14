# Rustの基礎

{{#include ../banners/hacktricks-training.md}}

### 変数の所有権

メモリは、コンパイラがコンパイル時に次のルールをチェックする所有権システムによって管理されます。

1. Rustでは各値に、その値を所有する変数があります。
2. 同時に所有者になれるのは1つだけです。
3. 所有者がスコープを抜けると、その値は破棄されます。

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

値の1つに任意の型を指定できる構造体を作成する。

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

Option型は、値がSome（何かがある）またはNoneである可能性を意味します。

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Optionの値を確認するには、`is_some()`や`is_none()`などの関数を使用できます。


### Result, Ok & Err

エラーを返したり伝播したりするために使用します。

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

`is_ok()`や`is_err()`などの関数を使って、結果の値を確認できます。

値が存在しない可能性がある（`None`になる）場合は、`Option` enumを使います。
何かが失敗する可能性がある処理を行う場合は、`Result` enumを使います。


### マクロ

マクロは、手動で記述したコードよりも多くのコードを生成するため、関数よりも強力です。たとえば、関数のシグネチャでは、関数のパラメーターの数と型を宣言する必要があります。一方、マクロは可変個数のパラメーターを受け取れます。`println!("hello")`のように引数を1つ渡して呼び出すことも、`println!("hello {}", name)`のように2つ渡すこともできます。また、マクロはコンパイラーがコードの意味を解釈する前に展開されるため、たとえば特定の型に対してtraitを実装できます。関数ではできません。関数は実行時に呼び出されるのに対し、traitはコンパイル時に実装する必要があるためです。

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

### 再帰的な Box

```rust
enum List {
    Cons(i32, List),
    Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
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

#### loop（無限）

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

Arcでは、Cloneを使ってオブジェクトへの参照を増やし、それらをスレッドに渡せます。値への最後の参照ポインターがスコープ外になると、その変数はドロップされます。

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

#### スレッド

この場合、スレッドに変更可能な変数を渡します。

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

Rustはデフォルトで強力なメモリ安全性を保証しますが、`unsafe`コード、依存関係の問題、ロジックの誤りによって、依然として重大な脆弱性が生じる可能性があります。以下のミニチートシートでは、Rustソフトウェアの攻撃側または防御側のセキュリティレビューで、最も頻繁に扱うプリミティブをまとめています。

#### Unsafe code & memory safety

`unsafe`ブロックは、コンパイラによるエイリアシングと境界のチェックを無効にするため、**従来型のメモリ破壊バグ（OOB、use-after-free、double freeなど）が再び発生する可能性があります**。簡単な監査チェックリスト:

* `unsafe`ブロック、`extern "C"`関数、`ptr::copy*`の呼び出し、`std::mem::transmute`、`MaybeUninit`、raw pointer、`ffi`モジュールを探します。
* 低レベル関数に渡されるポインター演算と長さの引数をすべて検証します。
* `#![forbid(unsafe_code)]`（crate全体）または`#[deny(unsafe_op_in_unsafe_fn)]`（1.68以降）を優先して、`unsafe`が再導入された場合にコンパイルを失敗させます。

raw pointerによって発生するオーバーフローの例:
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
Miriを実行するのは、テスト時にUBを検出する低コストな方法です。
```bash
rustup component add miri
cargo miri test  # hunts for OOB / UAF during unit tests
```

#### RustSec / cargo-audit を使った依存関係の監査

実際の Rust の脆弱性の多くは、サードパーティ製の crate に存在します。RustSec advisory DB（コミュニティ主導）はローカルで照会できます。<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
CI に統合し、`--deny warnings` で失敗するようにします。

`cargo deny check advisories` は、ライセンスと禁止リストのチェックに加えて、同様の機能を提供します。

#### cargo-tarpaulin によるコードカバレッジ

`cargo tarpaulin` は Cargo ビルドシステム向けのコードカバレッジレポートツールです。

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Linux では、Tarpaulin のデフォルトのトレースバックエンドは引き続き Ptrace であり、x86_64 プロセッサでのみ動作します。`--engine llvm` を指定すると、llvm のカバレッジ計測に変更できます。Mac と Windows では、これがデフォルトの収集方法です。

#### cargo-vet によるサプライチェーン検証（2024）

`cargo vet` は、インポートするすべての crate のレビュー用ハッシュを記録し、気付かないうちにアップグレードされるのを防ぎます。
```bash
cargo install cargo-vet
cargo vet init      # generates vet.toml
cargo vet --locked  # verifies packages referenced in Cargo.lock
```
このツールは、poisoned-package attackを軽減するため、Rustプロジェクトのインフラや増加する多数の組織で採用されています。<sup>[[2]](#references)</sup>

#### API surfaceのfuzzing（cargo-fuzz）

Fuzz testでは、DoSやサイドチャネルの問題につながる可能性のあるpanic、整数オーバーフロー、ロジックバグを簡単に検出できます。
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
fuzz targetをリポジトリに追加し、パイプラインで実行します。

## References

- [1] [RustSec アドバイザリデータベース](https://rustsec.org)
- [2] [Cargo-vet:「Rustの依存関係を監査する」](https://mozilla.github.io/cargo-vet/)
{{#include ../banners/hacktricks-training.md}}
