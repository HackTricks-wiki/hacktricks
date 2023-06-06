# Rust Básico

### Tipos Genéricos

Crie uma estrutura onde um dos seus valores pode ser de qualquer tipo.
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
### Option, Some e None

O tipo Option significa que o valor pode ser do tipo Some (há algo) ou None (nada):
```rust
pub enum Option<T> {
    None,
    Some(T),
}
```
Você pode usar funções como `is_some()` ou `is_none()` para verificar o valor da Option.

### Macros

Macros são mais poderosos do que funções porque se expandem para produzir mais código do que o código que você escreveu manualmente. Por exemplo, uma assinatura de função deve declarar o número e o tipo de parâmetros que a função possui. Macros, por outro lado, podem receber um número variável de parâmetros: podemos chamar `println!("hello")` com um argumento ou `println!("hello {}", name)` com dois argumentos. Além disso, as macros são expandidas antes do compilador interpretar o significado do código, então uma macro pode, por exemplo, implementar um trait em um determinado tipo. Uma função não pode, porque é chamada em tempo de execução e um trait precisa ser implementado em tempo de compilação.
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
### Iterar
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
### Caixa Recursiva
```rust
enum List {
    Cons(i32, List),
    Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Condicionais

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

O `match` é uma expressão que permite combinar um valor com uma série de padrões e executar o código correspondente ao padrão correspondente. É semelhante a um switch em outras linguagens de programação. O `match` é frequentemente usado em Rust para lidar com enumerações, mas também pode ser usado com outros tipos de dados.
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
#### loop (infinito)
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

Enquanto a condição especificada for verdadeira, o bloco de código dentro do `while` será executado repetidamente. A condição é verificada antes de cada iteração do loop. Se a condição for falsa, o loop será interrompido e a execução continuará após o bloco `while`.

```rust
let mut i = 0;
while i < 5 {
    println!("O valor de i é: {}", i);
    i += 1;
}
```

Este exemplo imprimirá o valor de `i` cinco vezes, começando em 0 e incrementando em 1 a cada iteração, até que `i` seja igual a 5.
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
#### para
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

O `if let` é uma expressão condicional que permite verificar se um valor corresponde a um padrão específico e, em seguida, executar um bloco de código correspondente. É uma forma mais concisa de escrever um `match` que lida apenas com um caso.

A sintaxe básica é a seguinte:

```
if let PATTERN = EXPRESSION {
    // code to execute if the pattern matches
}
```

Onde `PATTERN` é o padrão que estamos verificando e `EXPRESSION` é a expressão que estamos avaliando. Se `EXPRESSION` corresponder a `PATTERN`, o bloco de código dentro das chaves será executado. Caso contrário, o código será ignorado.

O `if let` é frequentemente usado em conjunto com a função `Option`, que representa um valor opcional que pode ser `Some(valor)` ou `None`. Podemos usar o `if let` para verificar se um valor `Option` é `Some` e, em seguida, desempacotá-lo para usar o valor subjacente. Por exemplo:

```
let my_number = Some(42);

if let Some(x) = my_number {
    println!("The number is {}", x);
}
```

Neste exemplo, estamos verificando se `my_number` é `Some` e, em seguida, desempacotando o valor `42` e atribuindo-o a `x`. Se `my_number` fosse `None`, o bloco de código seria ignorado.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
    println!("The word is: {}", word);
} else {
    println!("The optional word doesn't contain anything");
}
```
#### enquanto deixar
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

Criar um novo método para um tipo
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
### Testes
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

Um Arc pode usar Clone para criar mais referências sobre o objeto para passá-las para as threads. Quando a última referência apontando para um valor está fora do escopo, a variável é descartada.
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

Neste caso, passaremos para a thread uma variável que ela poderá modificar.
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

