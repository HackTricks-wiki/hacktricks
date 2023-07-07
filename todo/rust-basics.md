# Rustの基礎

### ジェネリック型

任意の型を持つことができる値を持つ構造体を作成します。
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

Option型は、値がSome（何かがある）またはNoneの型である可能性があることを意味します。
```rust
pub enum Option<T> {
None,
Some(T),
}
```
### マクロ

マクロは、手動で書いたコードよりも多くのコードを生成するため、関数よりも強力です。たとえば、関数のシグネチャは、関数が持つパラメータの数と型を宣言する必要があります。一方、マクロは可変長のパラメータを取ることができます。たとえば、`println!("hello")`を1つの引数で呼び出すことも、`println!("hello {}", name)`を2つの引数で呼び出すこともできます。また、マクロはコンパイラがコードの意味を解釈する前に展開されるため、マクロは、例えば、与えられた型に対してトレイトを実装することができます。関数はできません。なぜなら、関数は実行時に呼び出され、トレイトはコンパイル時に実装する必要があるからです。
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
### 繰り返す

繰り返しは、プログラムで同じ処理を複数回実行するための重要な概念です。Rustでは、いくつかの方法で繰り返しを実現することができます。

#### ループ

最も基本的な繰り返し方法は、`loop`キーワードを使用した無限ループです。このループは、明示的な終了条件がない限り、永遠に続きます。ループ内のコードは、`break`ステートメントを使用して手動で終了する必要があります。

```rust
loop {
    // 繰り返し実行するコード
    if condition {
        break;
    }
}
```

#### whileループ

`while`ループは、指定した条件が真の間、繰り返しを実行します。条件が偽になると、ループは終了します。

```rust
while condition {
    // 繰り返し実行するコード
}
```

#### forループ

`for`ループは、イテレータを使用して要素のコレクションを繰り返し処理します。イテレータは、要素を1つずつ返し、コレクションの終端に達するとループを終了します。

```rust
for item in collection {
    // 繰り返し実行するコード
}
```

#### イテレータメソッド

Rustでは、イテレータに対してさまざまなメソッドを使用して繰り返し処理を行うことができます。これには、`map`、`filter`、`fold`などのメソッドがあります。これらのメソッドを使用することで、より高度な繰り返し処理を実現することができます。

```rust
collection.iter()
    .map(|item| item * 2)
    .filter(|item| item > 10)
    .fold(0, |acc, item| acc + item);
```

繰り返しは、プログラムの効率的な実行やデータの処理において非常に重要です。Rustの繰り返し機能を理解し、適切に活用することで、より効果的なコードを書くことができます。
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
### 再帰的なボックス

A recursive box is a data structure that contains a reference to itself. This can be useful in certain situations where you need to create a data structure that has a recursive relationship.

To create a recursive box in Rust, you can use the `Rc` (reference counting) type provided by the standard library. The `Rc` type allows multiple ownership of a value and keeps track of the number of references to that value. This is useful when you want to create a data structure that can be shared and mutated by multiple parts of your program.

Here's an example of how you can create a recursive box using `Rc`:

```rust
use std::rc::Rc;

struct Node {
    value: i32,
    next: Option<Rc<Node>>,
}

fn main() {
    let node1 = Rc::new(Node {
        value: 1,
        next: None,
    });

    let node2 = Rc::new(Node {
        value: 2,
        next: Some(Rc::clone(&node1)),
    });

    // Update the next field of node1 to point to node2
    if let Some(ref next) = node1.next {
        let mut next_mut = Rc::make_mut(next);
        next_mut.next = Some(Rc::clone(&node2));
    }

    // Print the values of the nodes
    println!("Node 1: {}", node1.value);
    println!("Node 2: {}", node2.value);
}
```

In this example, we create two `Node` instances, `node1` and `node2`. `node1` has a `next` field that is initially set to `None`, while `node2` has a `next` field that points to `node1` using `Rc::clone`. We then update the `next` field of `node1` to point to `node2` using `Rc::make_mut`.

By using `Rc`, we can create a recursive relationship between the two nodes without causing any memory leaks. The reference counting mechanism ensures that the memory is deallocated correctly when there are no more references to a value.

再帰的なボックスは、自身への参照を含むデータ構造です。これは、再帰的な関係を持つデータ構造を作成する必要がある特定の状況で役立ちます。

Rustでは、標準ライブラリで提供される`Rc`（参照カウント）型を使用して、再帰的なボックスを作成することができます。`Rc`型は、値の複数の所有権を許可し、その値への参照の数を追跡します。これは、プログラムの複数の部分で共有および変更可能なデータ構造を作成したい場合に便利です。

以下は、`Rc`を使用して再帰的なボックスを作成する例です：

```rust
use std::rc::Rc;

struct Node {
    value: i32,
    next: Option<Rc<Node>>,
}

fn main() {
    let node1 = Rc::new(Node {
        value: 1,
        next: None,
    });

    let node2 = Rc::new(Node {
        value: 2,
        next: Some(Rc::clone(&node1)),
    });

    // node1のnextフィールドをnode2を指すように更新する
    if let Some(ref next) = node1.next {
        let mut next_mut = Rc::make_mut(next);
        next_mut.next = Some(Rc::clone(&node2));
    }

    // ノードの値を表示する
    println!("Node 1: {}", node1.value);
    println!("Node 2: {}", node2.value);
}
```

この例では、`node1`と`node2`の2つの`Node`インスタンスを作成します。`node1`は最初に`None`に設定された`next`フィールドを持ち、`node2`は`Rc::clone`を使用して`node1`を指す`next`フィールドを持ちます。次に、`Rc::make_mut`を使用して`node1`の`next`フィールドを`node2`を指すように更新します。

`Rc`を使用することで、メモリリークを引き起こすことなく、2つのノード間に再帰的な関係を作成することができます。参照カウントメカニズムにより、値への参照がなくなった場合にメモリが正しく解放されます。
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
#### もし

`if` statements are used to execute a block of code only if a certain condition is true. The syntax for an `if` statement in Rust is as follows:

```rust
if condition {
    // code to be executed if the condition is true
}
```

The `condition` is an expression that evaluates to either `true` or `false`. If the condition is `true`, the code block inside the `if` statement will be executed. If the condition is `false`, the code block will be skipped.

Here's an example:

```rust
fn main() {
    let number = 5;

    if number > 0 {
        println!("The number is positive");
    }
}
```

In this example, the code inside the `if` statement will be executed because the condition `number > 0` is true. The output will be `The number is positive`.

#### もし

`if`文は、特定の条件が真の場合にのみコードブロックを実行するために使用されます。Rustにおける`if`文の構文は次のようになります。

```rust
if 条件 {
    // 条件が真の場合に実行されるコード
}
```

`条件`は、`true`または`false`のいずれかに評価される式です。条件が`true`の場合、`if`文内のコードブロックが実行されます。条件が`false`の場合、コードブロックはスキップされます。

以下に例を示します。

```rust
fn main() {
    let number = 5;

    if number > 0 {
        println!("The number is positive");
    }
}
```

この例では、条件`number > 0`が真であるため、`if`文内のコードが実行されます。出力は`The number is positive`となります。
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
#### マッチ

The `match` expression in Rust is used for pattern matching. It allows you to compare a value against a series of patterns and execute different code based on the pattern that matches. The syntax for `match` is as follows:

```rust
match value {
    pattern1 => {
        // code to execute if pattern1 matches
    },
    pattern2 => {
        // code to execute if pattern2 matches
    },
    // more patterns...
    _ => {
        // code to execute if no pattern matches
    }
}
```

In the above code, `value` is the value that you want to match against the patterns. Each pattern is followed by a `=>` symbol, and the code to execute if the pattern matches is enclosed in curly braces `{}`. The `_` pattern is a catch-all pattern that matches any value.

The `match` expression is often used in Rust to handle different cases or branches of code based on the value of a variable. It is a powerful tool for writing concise and expressive code.
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
#### ループ（無限）

An infinite loop is a loop that continues indefinitely without a specific termination condition. It is often used in programming to repeat a certain block of code until a certain condition is met or until the program is manually interrupted.

In Rust, you can create an infinite loop using the `loop` keyword. Here's an example:

```rust
loop {
    // Code to be repeated indefinitely
}
```

To exit the loop, you can use the `break` keyword. For example, if you want to exit the loop when a certain condition is met, you can do the following:

```rust
loop {
    // Code to be repeated indefinitely

    if condition {
        break;
    }
}
```

In this example, the loop will continue until the `condition` is true, at which point it will break out of the loop and continue with the rest of the program.
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

`while`文は、指定した条件が真である限り、繰り返し実行するための制御構造です。

```rust
while 条件 {
    // 実行するコード
}
```

上記のコードでは、`条件`が真である限り、`// 実行するコード`が繰り返し実行されます。

例えば、1から10までの数値を出力するプログラムを作成する場合、以下のように`while`文を使用することができます。

```rust
let mut i = 1;

while i <= 10 {
    println!("{}", i);
    i += 1;
}
```

上記のコードでは、変数`i`が1から10までの範囲である限り、`println!("{}", i);`が繰り返し実行されます。`i += 1;`は、`i`の値を1ずつ増やすためのコードです。

このように、`while`文を使用することで、特定の条件が満たされるまでコードを繰り返し実行することができます。
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

#### for

`for` is a control flow statement in Rust that allows you to iterate over a collection of items. It is commonly used to perform a set of operations on each item in the collection.

The basic syntax of a `for` loop in Rust is as follows:

```rust
for item in collection {
    // code to be executed for each item
}
```

Here, `item` is a variable that represents each item in the collection, and `collection` is the collection of items to iterate over.

You can use the `for` loop with various types of collections, such as arrays, vectors, and ranges. For example, you can iterate over an array of numbers like this:

```rust
let numbers = [1, 2, 3, 4, 5];

for number in numbers {
    println!("Number: {}", number);
}
```

This will print each number in the array.

You can also use the `for` loop with ranges to iterate over a sequence of numbers. For example:

```rust
for number in 1..=5 {
    println!("Number: {}", number);
}
```

This will print the numbers from 1 to 5.

In addition to iterating over collections, you can use the `for` loop with iterators. Iterators are Rust's way of representing a sequence of values. You can create an iterator using the `iter` method on a collection. For example:

```rust
let numbers = vec![1, 2, 3, 4, 5];

for number in numbers.iter() {
    println!("Number: {}", number);
}
```

This will print each number in the vector.

The `for` loop is a powerful tool for iterating over collections and performing operations on each item. It is a fundamental concept in Rust programming and is widely used in various applications.
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
#### もし let

`if let`は、Rustの制御フローの一部であり、特定のパターンに一致する場合にのみコードを実行するために使用されます。

```rust
if let Some(value) = optional_value {
    // `optional_value`が`Some`の場合にのみ実行されるコード
}
```

このコードは、`optional_value`が`Some`の場合にのみ実行されます。`optional_value`が`None`の場合は、コードは実行されません。

`if let`は、`match`文の短縮形としても使用できます。以下は、`match`文と同等の動作をする`if let`の例です。

```rust
match optional_value {
    Some(value) => {
        // `optional_value`が`Some`の場合に実行されるコード
    },
    None => {
        // `optional_value`が`None`の場合に実行されるコード
    }
}
```

`if let`は、特定のパターンに一致する場合にのみコードを実行するため、コードをより簡潔にするのに役立ちます。
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### while let

`while let`は、Rustの制御フローの一部であり、パターンマッチングを使用して値を取り出すための短縮形です。この構文は、特定の条件が満たされる限り、ループを継続します。

以下は、`while let`の基本的な構文です。

```rust
while let Some(value) = some_option {
    // valueを使用して何かを行う
}
```

このコードでは、`some_option`が`Some`である限り、ループが継続します。`Some`の値が`value`にバインドされ、ループの本体で使用できます。

`while let`は、特にイテレータを処理する際に便利です。イテレータは、次の要素が存在する限り、`Some`を返し、終了時には`None`を返します。`while let`を使用することで、イテレータの要素を順番に処理することができます。

```rust
let numbers = vec![1, 2, 3, 4, 5];
let mut iter = numbers.iter();

while let Some(number) = iter.next() {
    // numberを使用して何かを行う
}
```

この例では、`numbers`ベクタの要素を順番に処理するために`while let`を使用しています。`iter.next()`は、次の要素が存在する限り`Some`を返し、`number`にバインドされます。

`while let`は、特定の条件が満たされる限りループを継続するため、柔軟な制御フローを実現するのに役立ちます。
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

新しいメソッドを型に作成する
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

テストはソフトウェア開発の重要な要素です。テストは、ソフトウェアの品質を確保し、バグを特定し修正するために使用されます。テストは、ソフトウェアの機能やパフォーマンスを検証するために行われます。

#### ユニットテスト

ユニットテストは、ソフトウェアの最小単位である関数やメソッドをテストするために使用されます。ユニットテストは、関数やメソッドが正しく動作するかどうかを確認するために、さまざまな入力値を使用してテストケースを作成します。

#### 統合テスト

統合テストは、複数のユニットを組み合わせてテストするために使用されます。統合テストは、ユニット間の相互作用やデータの流れを確認するために行われます。

#### 受け入れテスト

受け入れテストは、ソフトウェアがユーザーの要件を満たしているかどうかを確認するために使用されます。受け入れテストは、ユーザーが実際のシナリオでソフトウェアを使用することによって行われます。

#### パフォーマンステスト

パフォーマンステストは、ソフトウェアのパフォーマンスを評価するために使用されます。パフォーマンステストは、ソフトウェアが所定の負荷条件下でどのように動作するかを確認するために行われます。

#### セキュリティテスト

セキュリティテストは、ソフトウェアのセキュリティを評価するために使用されます。セキュリティテストは、ソフトウェアに存在する脆弱性やセキュリティ上の問題を特定するために行われます。

#### 自動化テスト

自動化テストは、テストプロセスを自動化するために使用されます。自動化テストは、テストの効率性と一貫性を向上させるために使用されます。
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
### スレッディング

#### Arc

ArcはCloneを使用して、オブジェクトに対してさらに参照を作成し、それらをスレッドに渡すことができます。最後の参照が値を指す場合、変数はスコープ外になると削除されます。
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

この場合、スレッドに変数を渡し、それを変更できるようにします。
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

